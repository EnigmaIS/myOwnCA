"""Strict signed metadata and first-party file verification.

The OS, Python, cryptography, this verifier and its provisioned trust store are
the trust boundary. No application configuration or application database is read.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path, PurePosixPath

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

PRODUCT = "myownca"
ROOTS = ("myownca", "myownca_core", "myownca_release")
MANIFEST = "myownca_release/release-files.json"
SIGNATURE = MANIFEST + ".sig"
METADATA = {MANIFEST, SIGNATURE}
MAX_METADATA = 16 * 1024 * 1024
HEX = re.compile(r"[0-9a-f]{64}\Z")
VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
DOMAIN = b"EnigmaIS myOwnCA release metadata v1\x00"


class VerificationError(ValueError):
    """Untrusted, malformed, or modified release input."""


def json_bytes(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def parse_json(raw: bytes) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise VerificationError("Duplicate metadata field")
            result[key] = value
        return result

    if len(raw) > MAX_METADATA:
        raise VerificationError("Oversized metadata")
    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, UnicodeError) as exc:
        raise VerificationError("Invalid JSON metadata") from exc
    if not isinstance(value, dict):
        raise VerificationError("Metadata must be an object")
    return value


def read_metadata(path: Path) -> bytes:
    if path.is_symlink():
        raise VerificationError("Metadata must not be a symbolic link")
    with path.open("rb") as stream:
        raw = stream.read(MAX_METADATA + 1)
    if len(raw) > MAX_METADATA:
        raise VerificationError("Oversized metadata")
    return raw


def fingerprint(key: rsa.RSAPublicKey) -> str:
    return hashlib.sha256(key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )).hexdigest()


def public_key(pem: str) -> rsa.RSAPublicKey:
    try:
        key = serialization.load_pem_public_key(pem.encode("ascii"))
    except (ValueError, TypeError, UnicodeError, AttributeError) as exc:
        raise VerificationError("Invalid release public key") from exc
    if (not isinstance(key, rsa.RSAPublicKey) or key.key_size != 4096
            or key.public_numbers().e != 65537):
        raise VerificationError("Release keys must be RSA-4096 with exponent 65537")
    return key


def validate_trust(trust: dict) -> dict:
    if set(trust) != {"schema", "sequence", "keys"} or type(trust["schema"]) is not int:
        raise VerificationError("Invalid trust store schema")
    if (trust["schema"] != 1 or type(trust["sequence"]) is not int
            or trust["sequence"] < 1 or not isinstance(trust["keys"], dict)
            or not 1 <= len(trust["keys"]) <= 16):
        raise VerificationError("Invalid trust store")
    for key_id, pem in trust["keys"].items():
        if fingerprint(public_key(pem)) != key_id:
            raise VerificationError("Trust key fingerprint does not match")
    return trust


def load_trust(path: Path) -> dict:
    return validate_trust(parse_json(read_metadata(path)))


def verify_signed(path: Path, trust: dict, kind: str) -> dict:
    validate_trust(trust)
    raw = read_metadata(path)
    value = parse_json(raw)
    if (type(value.get("schema")) is not int or value["schema"] != 1
            or value.get("product") != PRODUCT or value.get("kind") != kind):
        raise VerificationError("Wrong metadata schema, product, or purpose")
    key_id = value.get("key_id")
    if not isinstance(key_id, str) or key_id not in trust["keys"]:
        raise VerificationError("Unknown release signer")
    try:
        signature = base64.b64decode(read_metadata(Path(str(path) + ".sig")).strip(), validate=True)
        if len(signature) != 512:
            raise VerificationError("Invalid signature length")
        public_key(trust["keys"][key_id]).verify(
            signature, DOMAIN + raw,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256(),
        )
    except (InvalidSignature, ValueError) as exc:
        raise VerificationError("Release signature does not verify") from exc
    return value


def version_tuple(version: str) -> tuple[int, int, int]:
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise VerificationError("A stable X.Y.Z release version is required")
    return tuple(int(part) for part in version.split("."))


def safe_path(name: str) -> str:
    if (not isinstance(name, str) or not name or "\\" in name
            or "\x00" in name or any(ord(char) < 32 for char in name)):
        raise VerificationError("Unsafe manifest path")
    path = PurePosixPath(name)
    if path.is_absolute() or str(path) != name or any(part in (".", "..") for part in path.parts):
        raise VerificationError("Unsafe manifest path")
    return name


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def inventory(root: Path) -> dict[str, str]:
    result = {}
    for namespace in ROOTS:
        directory = root / namespace
        if directory.is_symlink() or not directory.is_dir():
            raise VerificationError(f"Missing or linked namespace: {namespace}")
        for path in sorted(directory.rglob("*")):
            name = path.relative_to(root).as_posix()
            if path.is_symlink():
                raise VerificationError(f"Symbolic link in application inventory: {name}")
            if path.is_dir():
                continue
            if not path.is_file():
                raise VerificationError(f"Non-regular application file: {name}")
            if name in METADATA:
                continue
            if path.suffix in (".pyc", ".pyo"):
                raise VerificationError(f"Unsigned bytecode is forbidden: {name}")
            result[safe_path(name)] = sha256(path)
    return result


def verify_installed(root: Path, trust: dict, *, include_license_keys: bool = False) -> dict:
    from myownca_release.license_keys import LICENSE_KEYS, validate_license_keys

    value = verify_signed(root / MANIFEST, trust, "files")
    if set(value) != {"schema", "product", "kind", "key_id", "version", "commit", "files"}:
        raise VerificationError("Invalid file manifest fields")
    version_tuple(value["version"])
    if not isinstance(value["commit"], str) or not re.fullmatch(r"[0-9a-f]{40,64}", value["commit"]):
        raise VerificationError("Invalid release commit")
    expected = value["files"]
    if not isinstance(expected, dict) or not expected:
        raise VerificationError("Empty or invalid file inventory")
    if LICENSE_KEYS not in expected:
        raise VerificationError("Signed inventory must include the licensing key ring")
    for name, digest in expected.items():
        safe_path(name)
        if (name.split("/")[0] not in ROOTS or name in METADATA
                or not isinstance(digest, str) or not HEX.fullmatch(digest)):
            raise VerificationError("Invalid file inventory entry")
    actual = inventory(root)
    changed = sorted(name for name in expected.keys() | actual.keys()
                     if expected.get(name) != actual.get(name))
    if changed:
        raise VerificationError("Application integrity failure: " + ", ".join(changed[:50]))
    raw_keys = read_metadata(root / LICENSE_KEYS)
    if hashlib.sha256(raw_keys).hexdigest() != expected[LICENSE_KEYS]:
        raise VerificationError("Licensing key ring changed during verification")
    keys = validate_license_keys(parse_json(raw_keys))
    result = {"version": value["version"], "commit": value["commit"],
              "signer": value["key_id"], "files_checked": len(actual)}
    if include_license_keys:
        result["license_public_keys"] = keys
    return result


def verify_release(bundle: Path, trust: dict, version: str) -> dict:
    version_tuple(version)
    value = verify_signed(bundle / "release.json", trust, "release")
    if set(value) != {"schema", "product", "kind", "key_id", "version", "commit",
                      "artifacts", "images"}:
        raise VerificationError("Invalid release manifest fields")
    if value["version"] != version:
        raise VerificationError("Release does not match requested version")
    if not isinstance(value["artifacts"], dict) or not value["artifacts"]:
        raise VerificationError("Missing release artifacts")
    for name, entry in value["artifacts"].items():
        safe_path(name)
        if "/" in name or name in ("release.json", "release.json.sig"):
            raise VerificationError("Invalid artifact name")
        if (not isinstance(entry, dict) or set(entry) != {"sha256", "size"}
                or not isinstance(entry["sha256"], str) or not HEX.fullmatch(entry["sha256"])
                or type(entry["size"]) is not int or entry["size"] < 0):
            raise VerificationError("Invalid artifact digest or size")
        path = bundle / name
        if (path.is_symlink() or not path.is_file() or path.stat().st_size != entry["size"]
                or sha256(path) != entry["sha256"]):
            raise VerificationError(f"Artifact integrity failure: {name}")
    if not isinstance(value["images"], dict):
        raise VerificationError("Invalid image inventory")
    for name, reference in value["images"].items():
        if (not isinstance(name, str) or not isinstance(reference, str)
                or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[0-9a-f]{64}", reference)):
            raise VerificationError("Image must be pinned by SHA-256 digest")
    return value
