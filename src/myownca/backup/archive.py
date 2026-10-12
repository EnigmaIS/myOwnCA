from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from argon2.low_level import ARGON2_VERSION, Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"MYOWNCA-BACKUP\x00"
FORMAT_VERSION = 1
ARGON_TIME_COST = 3
ARGON_MEMORY_COST_KIB = 65_536
ARGON_PARALLELISM = 4
ARGON_HASH_LENGTH = 32
SALT_BYTES = 16
NONCE_PREFIX_BYTES = 8
CHUNK_BYTES = 4 * 1024 * 1024
MAX_HEADER_BYTES = 16 * 1024
MAX_MEMBERS = 100_000
MAX_UNCOMPRESSED_BYTES = 64 * 1024 * 1024 * 1024
MAX_COMPRESSION_RATIO = 1000
MAX_MANIFEST_BYTES = 32 * 1024 * 1024
_FRAME = struct.Struct(">IBI")


class BackupArchiveError(ValueError):
    """A backup archive failed structural or safety validation."""


class ArchiveAuthenticationError(BackupArchiveError):
    """The archive shares or authenticated ciphertext were invalid."""


@dataclass(frozen=True, slots=True)
class ArchiveHeader:
    raw: bytes
    document: dict[str, object]
    requester_salt: bytes
    approver_salt: bytes
    nonce_prefix: bytes


def derive_share_key(passphrase: str, salt: bytes) -> bytes:
    if len(passphrase) < 16:
        raise BackupArchiveError("Backup passphrase shares must contain at least 16 characters")
    if len(passphrase) > 1024:
        raise BackupArchiveError("Backup passphrase shares must contain at most 1024 characters")
    if len(salt) != SALT_BYTES:
        raise BackupArchiveError("Backup share salt has an invalid length")
    return hash_secret_raw(
        passphrase.encode("utf-8"),
        salt,
        time_cost=ARGON_TIME_COST,
        memory_cost=ARGON_MEMORY_COST_KIB,
        parallelism=ARGON_PARALLELISM,
        hash_len=ARGON_HASH_LENGTH,
        type=Type.ID,
        version=ARGON2_VERSION,
    )


def combine_share_keys(requester_key: bytes, approver_key: bytes) -> bytes:
    if len(requester_key) != 32 or len(approver_key) != 32:
        raise BackupArchiveError("Backup share keys must be 256 bits")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"myownca-application-backup-v1",
    ).derive(requester_key + approver_key)


def create_header(*, requester_salt: bytes, approver_salt: bytes) -> ArchiveHeader:
    nonce_prefix = os.urandom(NONCE_PREFIX_BYTES)
    document: dict[str, object] = {
        "format": "myownca-application-backup",
        "version": FORMAT_VERSION,
        "cipher": "AES-256-GCM-chunked",
        "chunk_bytes": CHUNK_BYTES,
        "nonce_prefix": _b64(nonce_prefix),
        "shares": [
            _share_parameters("requester", requester_salt),
            _share_parameters("approver", approver_salt),
        ],
    }
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return ArchiveHeader(raw, document, requester_salt, approver_salt, nonce_prefix)


def read_header(handle: BinaryIO) -> ArchiveHeader:
    if handle.read(len(MAGIC)) != MAGIC:
        raise BackupArchiveError("Not a myOwnCA application backup archive")
    encoded_length = handle.read(4)
    if len(encoded_length) != 4:
        raise BackupArchiveError("Backup archive header is truncated")
    length = struct.unpack(">I", encoded_length)[0]
    if length <= 0 or length > MAX_HEADER_BYTES:
        raise BackupArchiveError("Backup archive header length is invalid")
    raw = handle.read(length)
    if len(raw) != length:
        raise BackupArchiveError("Backup archive header is truncated")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupArchiveError("Backup archive header is invalid") from exc
    _validate_header_document(document)
    if json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8") != raw:
        raise BackupArchiveError("Backup archive header is not canonical")
    shares = document["shares"]
    requester_salt = _unb64(shares[0]["salt"], "requester salt")
    approver_salt = _unb64(shares[1]["salt"], "approver salt")
    nonce_prefix = _unb64(document["nonce_prefix"], "nonce prefix")
    if len(requester_salt) != SALT_BYTES or len(approver_salt) != SALT_BYTES:
        raise BackupArchiveError("Backup archive share salt length is invalid")
    if len(nonce_prefix) != NONCE_PREFIX_BYTES:
        raise BackupArchiveError("Backup archive nonce prefix length is invalid")
    return ArchiveHeader(raw, document, requester_salt, approver_salt, nonce_prefix)


class ChunkEncryptingWriter(io.RawIOBase):
    """Non-seekable writer accepted by ZipFile and backed by chunked AEAD."""

    def __init__(self, handle: BinaryIO, *, key: bytes, header: ArchiveHeader) -> None:
        super().__init__()
        self._handle = handle
        self._cipher = AESGCM(key)
        self._header = header
        self._header_digest = hashlib.sha256(MAGIC + header.raw).digest()
        self._buffer = bytearray()
        self._counter = 0
        self._position = 0
        self._finished = False
        handle.write(MAGIC)
        handle.write(struct.pack(">I", len(header.raw)))
        handle.write(header.raw)

    def writable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def tell(self) -> int:
        return self._position

    def write(self, data) -> int:
        if self._finished:
            raise ValueError("Backup archive writer is finalized")
        payload = bytes(data)
        self._buffer.extend(payload)
        self._position += len(payload)
        while len(self._buffer) >= CHUNK_BYTES:
            chunk = bytes(self._buffer[:CHUNK_BYTES])
            del self._buffer[:CHUNK_BYTES]
            self._write_frame(chunk, final=False)
        return len(payload)

    def flush(self) -> None:
        self._handle.flush()

    def finish(self) -> None:
        if self._finished:
            return
        if self._buffer:
            self._write_frame(bytes(self._buffer), final=False)
            self._buffer.clear()
        self._write_frame(b"", final=True)
        self._handle.flush()
        self._finished = True

    def _write_frame(self, plaintext: bytes, *, final: bool) -> None:
        if self._counter > 0xFFFFFFFF:
            raise BackupArchiveError("Backup archive contains too many encrypted chunks")
        flag = 1 if final else 0
        frame_header = _FRAME.pack(self._counter, flag, len(plaintext))
        nonce = self._header.nonce_prefix + struct.pack(">I", self._counter)
        ciphertext = self._cipher.encrypt(
            nonce,
            plaintext,
            self._header_digest + frame_header,
        )
        self._handle.write(frame_header)
        self._handle.write(ciphertext)
        self._counter += 1


def decrypt_archive_to_zip(
    archive_path: str | Path,
    *,
    requester_passphrase: str,
    approver_passphrase: str,
    destination: BinaryIO,
) -> ArchiveHeader:
    try:
        with Path(archive_path).open("rb") as source:
            header = read_header(source)
            requester_key = derive_share_key(requester_passphrase, header.requester_salt)
            approver_key = derive_share_key(approver_passphrase, header.approver_salt)
            cipher = AESGCM(combine_share_keys(requester_key, approver_key))
            header_digest = hashlib.sha256(MAGIC + header.raw).digest()
            expected_counter = 0
            saw_final = False
            while True:
                raw_frame = source.read(_FRAME.size)
                if not raw_frame:
                    break
                if len(raw_frame) != _FRAME.size:
                    raise BackupArchiveError("Backup archive frame header is truncated")
                counter, flag, plaintext_length = _FRAME.unpack(raw_frame)
                if counter != expected_counter or flag not in {0, 1}:
                    raise BackupArchiveError("Backup archive chunk ordering is invalid")
                if plaintext_length > CHUNK_BYTES or (flag == 1 and plaintext_length != 0):
                    raise BackupArchiveError("Backup archive chunk length is invalid")
                ciphertext = source.read(plaintext_length + 16)
                if len(ciphertext) != plaintext_length + 16:
                    raise BackupArchiveError("Backup archive encrypted chunk is truncated")
                nonce = header.nonce_prefix + struct.pack(">I", counter)
                try:
                    plaintext = cipher.decrypt(
                        nonce,
                        ciphertext,
                        header_digest + raw_frame,
                    )
                except Exception as exc:  # cryptography intentionally hides tag details
                    raise ArchiveAuthenticationError(
                        "Backup archive authentication failed"
                    ) from exc
                expected_counter += 1
                if flag == 1:
                    saw_final = True
                    if source.read(1):
                        raise BackupArchiveError("Backup archive has trailing data")
                    break
                destination.write(plaintext)
            if not saw_final:
                raise BackupArchiveError("Backup archive final marker is missing")
            destination.flush()
            return header
    except OSError as exc:
        raise BackupArchiveError(f"Could not read backup archive: {exc}") from exc


def validate_zip(bundle: zipfile.ZipFile) -> dict[str, object]:
    infos = bundle.infolist()
    if len(infos) > MAX_MEMBERS:
        raise BackupArchiveError("Backup archive contains too many members")
    names: set[str] = set()
    total = 0
    total_compressed = 0
    for info in infos:
        if info.filename in names:
            raise BackupArchiveError("Backup archive contains duplicate members")
        names.add(info.filename)
        _validate_member_name(info.filename)
        total += info.file_size
        total_compressed += info.compress_size
        if total > MAX_UNCOMPRESSED_BYTES:
            raise BackupArchiveError("Backup archive exceeds the restore safety limit")
        if info.file_size > max(info.compress_size, 1) * MAX_COMPRESSION_RATIO:
            raise BackupArchiveError("Backup archive member compression ratio is unsafe")
    if total > max(total_compressed, 1) * MAX_COMPRESSION_RATIO:
        raise BackupArchiveError("Backup archive compression ratio is unsafe")
    if "manifest.json" not in names:
        raise BackupArchiveError("Backup archive manifest is missing")
    if bundle.getinfo("manifest.json").file_size > MAX_MANIFEST_BYTES:
        raise BackupArchiveError("Backup archive manifest exceeds the safety limit")
    try:
        manifest = json.loads(bundle.read("manifest.json"))
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupArchiveError("Backup archive manifest is invalid") from exc
    if not isinstance(manifest, dict) or manifest.get("format_version") != FORMAT_VERSION:
        raise BackupArchiveError("Backup archive manifest version is unsupported")
    entries = manifest.get("entries")
    if not isinstance(entries, list):
        raise BackupArchiveError("Backup archive manifest entries are invalid")
    described = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise BackupArchiveError("Backup archive manifest entry is invalid")
        name = str(entry.get("path") or "")
        if name in described or name == "manifest.json" or name not in names:
            raise BackupArchiveError("Backup archive manifest paths are invalid")
        described.add(name)
        digest_builder = hashlib.sha256()
        with bundle.open(name) as member:
            for chunk in iter(lambda: member.read(1024 * 1024), b""):
                digest_builder.update(chunk)
        digest = digest_builder.hexdigest()
        if digest != entry.get("sha256"):
            raise BackupArchiveError(f"Backup member integrity check failed: {name}")
        if bundle.getinfo(name).file_size != entry.get("size"):
            raise BackupArchiveError(f"Backup member size check failed: {name}")
    if described | {"manifest.json"} != names:
        raise BackupArchiveError("Backup archive contains undescribed members")
    return manifest


def _share_parameters(label: str, salt: bytes) -> dict[str, object]:
    if len(salt) != SALT_BYTES:
        raise BackupArchiveError("Backup share salt has an invalid length")
    return {
        "label": label,
        "kdf": "Argon2id",
        "salt": _b64(salt),
        "time_cost": ARGON_TIME_COST,
        "memory_cost_kib": ARGON_MEMORY_COST_KIB,
        "parallelism": ARGON_PARALLELISM,
        "hash_length": ARGON_HASH_LENGTH,
        "argon2_version": ARGON2_VERSION,
    }


def _validate_header_document(document: object) -> None:
    if not isinstance(document, dict):
        raise BackupArchiveError("Backup archive header is invalid")
    if (
        document.get("format") != "myownca-application-backup"
        or document.get("version") != FORMAT_VERSION
        or document.get("cipher") != "AES-256-GCM-chunked"
        or document.get("chunk_bytes") != CHUNK_BYTES
    ):
        raise BackupArchiveError("Backup archive format is unsupported")
    shares = document.get("shares")
    if not isinstance(shares, list) or len(shares) != 2:
        raise BackupArchiveError("Backup archive share parameters are invalid")
    for expected, share in zip(("requester", "approver"), shares, strict=True):
        if not isinstance(share, dict) or share.get("label") != expected:
            raise BackupArchiveError("Backup archive share order is invalid")
        required = {
            "kdf": "Argon2id",
            "time_cost": ARGON_TIME_COST,
            "memory_cost_kib": ARGON_MEMORY_COST_KIB,
            "parallelism": ARGON_PARALLELISM,
            "hash_length": ARGON_HASH_LENGTH,
            "argon2_version": ARGON2_VERSION,
        }
        if any(share.get(key) != value for key, value in required.items()):
            raise BackupArchiveError("Backup archive KDF parameters are unsupported")


def _validate_member_name(name: str) -> None:
    path = Path(name)
    if (
        not name
        or name.startswith(("/", "\\"))
        or "\\" in name
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise BackupArchiveError("Backup archive contains an unsafe member path")


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _unb64(value: object, label: str) -> bytes:
    if not isinstance(value, str):
        raise BackupArchiveError(f"Backup archive {label} is invalid")
    try:
        return base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)
    except Exception as exc:
        raise BackupArchiveError(f"Backup archive {label} is invalid") from exc
