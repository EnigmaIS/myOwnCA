"""Offline operator tooling. Private keys and passphrases never enter a build."""

from __future__ import annotations

import argparse
import base64
import configparser
import csv
import getpass
import hashlib
import io
import json
import os
import re
import tempfile
import zipfile
from email.parser import BytesParser
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from myownca_release.verify import (
    DOMAIN, MANIFEST, METADATA, PRODUCT, ROOTS, SIGNATURE, VerificationError,
    fingerprint, json_bytes, safe_path, sha256, validate_trust, version_tuple,
)
from myownca_release.license_keys import LICENSE_KEYS, read_license_keys


def signature(raw: bytes, key: rsa.RSAPrivateKey) -> bytes:
    return base64.b64encode(key.sign(
        DOMAIN + raw, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )) + b"\n"


def key_metadata(key: rsa.RSAPrivateKey, kind: str) -> dict:
    return {"schema": 1, "product": PRODUCT, "kind": kind,
            "key_id": fingerprint(key.public_key())}


def exclusive_write(path: Path, raw: bytes, mode: int = 0o600) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)


def load_private(path: Path) -> rsa.RSAPrivateKey:
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise VerificationError("Private key must be a regular owner-only file (0600)")
    password = getpass.getpass("Release key passphrase: ").encode()
    key = serialization.load_pem_private_key(path.read_bytes(), password=password)
    if (not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 4096
            or key.public_key().public_numbers().e != 65537):
        raise VerificationError("Release signing requires RSA-4096")
    return key


def write_signed(path: Path, value: dict, key: rsa.RSAPrivateKey) -> None:
    if path.exists() or Path(str(path) + ".sig").exists():
        raise VerificationError("Refusing to replace signed metadata")
    raw = json_bytes(value)
    exclusive_write(path, raw, 0o644)
    exclusive_write(Path(str(path) + ".sig"), signature(raw, key), 0o644)


def wheel_contents(path: Path) -> dict[str, bytes]:
    result = {}
    with zipfile.ZipFile(path) as archive:
        if sum(item.file_size for item in archive.infolist()) > 256 * 1024 * 1024:
            raise VerificationError("Oversized application wheel")
        for item in archive.infolist():
            if item.is_dir():
                continue
            name = safe_path(item.filename)
            if name in result or (item.external_attr >> 16) & 0o170000 == 0o120000:
                raise VerificationError("Duplicate or linked wheel member")
            result[name] = archive.read(item)
    return result


def seal_wheel(wheel: Path, output: Path, key: rsa.RSAPrivateKey, commit: str,
               license_public_keys: Path) -> dict:
    if not re.fullmatch(r"[0-9a-f]{40,64}", commit):
        raise VerificationError("A full Git commit is required")
    data = wheel_contents(wheel)
    if any(name in data for name in METADATA):
        raise VerificationError("Wheel is already sealed")
    metadata_names = [name for name in data if name.endswith(".dist-info/METADATA")]
    if len(metadata_names) != 1:
        raise VerificationError("Invalid wheel metadata")
    metadata = BytesParser().parsebytes(data[metadata_names[0]])
    if metadata["Name"] != PRODUCT:
        raise VerificationError("Only the myownca application wheel can be sealed")
    version = metadata["Version"]
    version_tuple(version)
    keys = read_license_keys(license_public_keys)
    if LICENSE_KEYS in data:
        raise VerificationError("Unsealed wheel must not already contain licensing keys")
    data[LICENSE_KEYS] = json_bytes({"schema": 1, "keys": keys})
    # pip's normal console entry point imports a package before we can disable
    # bytecode writes. Ship executable script bodies for sealed production wheels
    # instead, so -B semantics apply before the first package import.
    entry_name = metadata_names[0].rsplit("/", 1)[0] + "/entry_points.txt"
    if entry_name in data:
        config = configparser.ConfigParser(interpolation=None)
        config.read_string(data[entry_name].decode())
        if config.has_section("console_scripts"):
            wheel_data = metadata_names[0].split(".dist-info/")[0] + ".data/scripts/"
            for name, target in config.items("console_scripts"):
                if not re.fullmatch(r"[a-zA-Z0-9_-]+", name):
                    raise VerificationError("Invalid console script name")
                if not re.fullmatch(r"[a-zA-Z0-9_.]+:[a-zA-Z0-9_]+", target):
                    raise VerificationError("Invalid console script target")
                module, function = target.split(":")
                guard = ("from myownca_release.bootstrap import require_verified\n"
                         "require_verified()\n") if module.startswith("myownca.") else ""
                body = ("#!python\nimport sys\nsys.dont_write_bytecode = True\n" + guard +
                        f"from {module} import {function}\nraise SystemExit({function}())\n")
                data[wheel_data + name] = body.encode()
            config.remove_section("console_scripts")
            stream = io.StringIO()
            config.write(stream)
            data[entry_name] = stream.getvalue().encode()
    files = {name: hashlib.sha256(raw).hexdigest() for name, raw in data.items()
             if name.split("/")[0] in ROOTS}
    for namespace in ROOTS:
        if f"{namespace}/__init__.py" not in files:
            raise VerificationError(f"Missing wheel namespace: {namespace}")
    if any(name.endswith((".pyc", ".pyo")) for name in files):
        raise VerificationError("Bytecode is forbidden in release wheels")
    value = {**key_metadata(key, "files"), "version": version, "commit": commit, "files": files}
    data[MANIFEST] = json_bytes(value)
    data[SIGNATURE] = signature(data[MANIFEST], key)
    record_name = metadata_names[0].rsplit("/", 1)[0] + "/RECORD"
    record = io.StringIO(newline="")
    writer = csv.writer(record)
    for name, raw in sorted(data.items()):
        if name == record_name:
            continue
        digest = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
        writer.writerow((name, "sha256=" + digest, len(raw)))
    writer.writerow((record_name, "", ""))
    data[record_name] = record.getvalue().encode()
    if output.exists() or output.name != wheel.name:
        raise VerificationError("Output must be a new path retaining the wheel filename")
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, raw in sorted(data.items()):
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100755 if ".data/scripts/" in name else 0o100644) << 16
            archive.writestr(info, raw)
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline EnigmaIS release signing")
    commands = parser.add_subparsers(dest="command", required=True)
    generate = commands.add_parser("keygen")
    generate.add_argument("--private-key", type=Path, required=True)
    generate.add_argument("--trust-output", type=Path, required=True)
    seal = commands.add_parser("seal-wheel")
    seal.add_argument("--wheel", type=Path, required=True)
    seal.add_argument("--output", type=Path, required=True)
    seal.add_argument("--commit", required=True)
    seal.add_argument("--license-public-keys", type=Path, required=True)
    release = commands.add_parser("release")
    release.add_argument("--bundle", type=Path, required=True)
    release.add_argument("--version", required=True)
    release.add_argument("--commit", required=True)
    release.add_argument("--image", action="append", default=[], metavar="NAME=REF@sha256:DIGEST")
    rotate = commands.add_parser("trust-update")
    rotate.add_argument("--new-trust", type=Path, required=True)
    rotate.add_argument("--output", type=Path, required=True)
    for command in (seal, release, rotate):
        command.add_argument("--private-key", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            if args.private_key.exists() or args.trust_output.exists():
                raise VerificationError("Key output already exists")
            password = getpass.getpass("New release key passphrase (at least 16 characters): ")
            if len(password) < 16 or getpass.getpass("Confirm passphrase: ") != password:
                raise VerificationError("Passphrase too short or confirmation differs")
            key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
            exclusive_write(args.private_key, key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(password.encode()),
            ))
            pem = key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            exclusive_write(args.trust_output, json_bytes(
                {"schema": 1, "sequence": 1, "keys": {fingerprint(key.public_key()): pem}}
            ), 0o644)
            print("Public-key SHA-256 fingerprint:", fingerprint(key.public_key()))
            return 0
        key = load_private(args.private_key)
        if args.command == "seal-wheel":
            value = seal_wheel(args.wheel, args.output, key, args.commit, args.license_public_keys)
        elif args.command == "trust-update":
            from myownca_release.verify import load_trust

            trust = validate_trust(load_trust(args.new_trust))
            value = {**key_metadata(key, "trust"), "trust": trust}
            write_signed(args.output, value, key)
        else:
            from myownca_release.verify import verify_installed, verify_release

            version_tuple(args.version)
            images = {}
            for image in args.image:
                name, ref = image.split("=", 1)
                if name in images:
                    raise VerificationError("Duplicate image name")
                images[name] = ref
            artifacts = {}
            for path in sorted(args.bundle.iterdir()):
                if path.name in ("release.json", "release.json.sig"):
                    raise VerificationError("Bundle is already signed")
                if path.is_symlink() or not path.is_file():
                    raise VerificationError("Bundle must contain only regular artifact files")
                artifacts[path.name] = {"sha256": sha256(path), "size": path.stat().st_size}
            pem = key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            trust = {"schema": 1, "sequence": 1, "keys": {fingerprint(key.public_key()): pem}}
            wheels = [path for path in args.bundle.glob("myownca-*.whl")]
            if len(wheels) != 1 or "requirements.lock" not in artifacts:
                raise VerificationError("Bundle needs one sealed app wheel and requirements.lock")
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for name, raw in wheel_contents(wheels[0]).items():
                    target = root / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(raw)
                checked = verify_installed(root, trust)
            if checked["version"] != args.version or checked["commit"] != args.commit:
                raise VerificationError("Bundle version/commit differs from sealed wheel")
            value = {**key_metadata(key, "release"), "version": args.version,
                     "commit": args.commit, "artifacts": artifacts, "images": images}
            # Validate before exposing output, using a disposable metadata directory.
            with tempfile.TemporaryDirectory() as directory:
                temp = Path(directory)
                for name in artifacts:
                    os.link(args.bundle / name, temp / name)
                write_signed(temp / "release.json", value, key)
                verify_release(temp, trust, args.version)
            write_signed(args.bundle / "release.json", value, key)
        print(json.dumps({"event": "release_signed", "kind": value["kind"],
                          "signer": value["key_id"], "version": value.get("version")}))
        return 0
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        parser.exit(1, f"Release signing failed: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
