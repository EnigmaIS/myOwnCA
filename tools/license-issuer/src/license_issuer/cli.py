"""Vendor-side license tooling.

This package is intentionally separate from the customer application. The
signing key never belongs in the application repository, application image, or
customer configuration.

  myownca-license keygen ...  mint an RSA-4096 signing keypair
  myownca-license sign ...    emit a signed .lic token
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from license_issuer.protocol import LICENSE_PRODUCT, LICENSE_SCHEMA

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def keygen(args: argparse.Namespace) -> int:
    if not _IDENTIFIER_RE.fullmatch(args.key_id):
        print("--key-id must be a safe identifier", file=sys.stderr)
        return 2
    password = os.environ.get(args.password_env, "")
    if not password and not args.unsafe_unencrypted_dev:
        print(
            f"Set ${args.password_env} or pass --unsafe-unencrypted-dev; production "
            "license keys must be encrypted or generated directly in an HSM/KMS",
            file=sys.stderr,
        )
        return 2
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    encryption = (
        serialization.NoEncryption()
        if not password
        else serialization.BestAvailableEncryption(password.encode())
    )
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption,
    ).decode()
    public_raw = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_b64 = base64.b64encode(public_raw).decode()
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(pem)
        os.chmod(args.out, 0o600)
        print(f"private key written to {args.out} (keep it offline)")
    else:
        sys.stdout.write(pem)
    if args.public_out:
        Path(args.public_out).write_text(public_b64 + "\n", encoding="ascii")
        os.chmod(args.public_out, 0o644)
        print(f"public key written to {args.public_out}")
    print(
        "\nMerge this public key into the producer license-public-keys.json and supply it\n"
        "to myownca-release seal-wheel --license-public-keys (never customer configuration):\n"
        f'    {{"schema":1,"keys":{{"{args.key_id}":"{public_b64}"}}}}',
        file=sys.stderr,
    )
    return 0


def sign(args: argparse.Namespace) -> int:
    try:
        installation_id = str(args.installation_id)
        if str(UUID(installation_id)) != installation_id:
            raise ValueError
    except ValueError:
        print("--installation-id must be a canonical UUID", file=sys.stderr)
        return 2
    if (
        not args.licensed_to.strip()
        or args.licensed_to != args.licensed_to.strip()
        or len(args.licensed_to) > 256
    ):
        print(
            "--licensed-to must contain 1–256 characters with no leading or trailing whitespace",
            file=sys.stderr,
        )
        return 2
    if not _IDENTIFIER_RE.fullmatch(args.key_id) or (
        args.license_id is not None and not _IDENTIFIER_RE.fullmatch(args.license_id)
    ):
        print("--key-id and --license-id must be safe identifiers", file=sys.stderr)
        return 2
    if not 1 <= args.max_lineages <= 10_000_000 or not 1 <= args.days <= 3650:
        print(
            "--max-lineages must be 1..10000000 and --days must be 1..3650",
            file=sys.stderr,
        )
        return 2
    password = os.environ.get(args.password_env, "").encode() or None
    with open(args.key, "rb") as handle:
        try:
            private_key = serialization.load_pem_private_key(
                handle.read(), password=password
            )
        except (TypeError, ValueError) as exc:
            print(f"Unable to load encrypted signing key: {exc}", file=sys.stderr)
            return 2
    if (
        not isinstance(private_key, rsa.RSAPrivateKey)
        or private_key.key_size != 4096
        or private_key.public_key().public_numbers().e != 65537
    ):
        print("Signing key must be an RSA-4096 private key with exponent 65537", file=sys.stderr)
        return 2
    now = datetime.now(timezone.utc).replace(microsecond=0)
    payload = {
        "schema": LICENSE_SCHEMA,
        "product": LICENSE_PRODUCT,
        "license_id": args.license_id or f"BB-{now:%Y}-{uuid4().hex[:10]}",
        "licensed_to": args.licensed_to,
        "installation_id": installation_id,
        "issued_at": now.isoformat(),
        "valid_from": now.isoformat(),
        "expires_at": (now + timedelta(days=args.days)).isoformat(),
        "max_certificate_lineages": args.max_lineages,
        "key_id": args.key_id,
    }
    payload_segment = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signature = private_key.sign(
        payload_segment.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.DIGEST_LENGTH,
        ),
        hashes.SHA256(),
    )
    token = f"{payload_segment}.{_b64url(signature)}"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(token + "\n")
        print(f"license for {args.licensed_to!r} written to {args.out}")
    else:
        print(token)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="myOwnCA license signing tools.")
    sub = parser.add_subparsers(dest="command", required=True)

    kg = sub.add_parser("keygen", help="mint an RSA-4096 signing keypair")
    kg.add_argument("--out", help="write the private key PEM here (else stdout)")
    kg.add_argument("--public-out", help="write the Base64 DER/SPKI public key here")
    kg.add_argument("--key-id", default="v1", help="key_id label for the public key")
    kg.add_argument(
        "--password-env",
        default="MYOWNCA_LICENSE_KEY_PASSWORD",
        help="environment variable containing the private-key encryption password",
    )
    kg.add_argument(
        "--unsafe-unencrypted-dev",
        action="store_true",
        help="write an unencrypted development key (never use for production)",
    )
    kg.set_defaults(func=keygen)

    sg = sub.add_parser("sign", help="sign a license token")
    sg.add_argument("--key", required=True, help="RSA-4096 private key PEM")
    sg.add_argument(
        "--licensed-to",
        required=True,
        help=(
            "exact company name embedded in the signed license and displayed in all "
            "authenticated portals (1–256 characters, no leading or trailing whitespace)"
        ),
    )
    sg.add_argument(
        "--installation-id",
        required=True,
        help="installation UUID shown by the customer admin portal",
    )
    sg.add_argument(
        "--max-lineages",
        "--max-certs",
        dest="max_lineages",
        type=int,
        required=True,
        help="active certificate-lineage ceiling",
    )
    sg.add_argument("--days", type=int, default=365, help="validity window in days")
    sg.add_argument("--license-id", help="explicit license id (else generated)")
    sg.add_argument("--key-id", default="v1", help="key_id recorded in the token")
    sg.add_argument(
        "--password-env",
        default="MYOWNCA_LICENSE_KEY_PASSWORD",
        help="environment variable containing the private-key encryption password",
    )
    sg.add_argument("--out", help="write the .lic token here (else stdout)")
    sg.set_defaults(func=sign)

    args = parser.parse_args(argv)
    return int(args.func(args))


def keygen_main(argv: list[str] | None = None) -> int:
    """Entrypoint for ``myownca-license-keygen``."""
    return main(["keygen", *(argv or sys.argv[1:])])


def sign_main(argv: list[str] | None = None) -> int:
    """Entrypoint for ``myownca-license-sign``."""
    return main(["sign", *(argv or sys.argv[1:])])


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
