from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from myownca.ca_hsm import SoftwareHSM
from myownca.domain import CertificateProfile
from myownca.offline.service import OfflineRootService
from myownca.offline.state import OfflineStateRepository


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="myownca-offline",
        description="Offline root ceremony CLI for myOwnCA development workflows.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    root_create = subparsers.add_parser("root-create", help="create the offline root and initial root CRL")
    _add_state_dir(root_create)
    root_create.add_argument("--common-name", required=True)
    root_create.add_argument("--output-dir", required=True, type=Path)
    root_create.add_argument("--algorithm", default="ecdsa-p384")
    root_create.add_argument("--validity-years", type=int, default=20)

    subca_sign = subparsers.add_parser(
        "subca-sign-csr",
        help="sign a PEM sub-CA CSR and emit the PEM certificate",
    )
    _add_state_dir(subca_sign)
    subca_sign.add_argument(
        "--csr",
        type=Path,
        help="read the CSR from this PEM file; omit to read pasted PEM from stdin",
    )
    subca_sign.add_argument(
        "--output",
        type=Path,
        help="write the certificate PEM here; omit to print it to stdout",
    )
    subca_sign.add_argument("--validity-days", type=int, default=365 * 6)
    subca_sign.add_argument(
        "--permitted-dns-suffix",
        action="append",
        default=[],
    )
    subca_sign.add_argument(
        "--allowed-profile",
        action="append",
        choices=[profile.value for profile in CertificateProfile],
    )

    root_crl_sign = subparsers.add_parser(
        "root-crl-sign",
        help="sign a fresh Root CRL and emit PEM",
    )
    _add_state_dir(root_crl_sign)
    root_crl_sign.add_argument(
        "--output",
        type=Path,
        help="write the CRL PEM here; omit to print it to stdout",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    service = _service(args.state_dir)

    if args.command == "root-create":
        artifacts = service.create_root(
            args.common_name,
            algorithm=args.algorithm,
            validity_years=args.validity_years,
        )
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "root-ca.pem").write_text(artifacts.root_certificate_pem)
        (args.output_dir / "root-crl-0001.pem").write_text(artifacts.initial_root_crl.crl_pem)
        print(f"created root CA and root CRL #1 in {args.output_dir}")
        return 0

    if args.command == "subca-sign-csr":
        csr_pem = args.csr.read_text() if args.csr else sys.stdin.read()
        if not csr_pem.strip():
            parser.error("paste a PEM CSR on stdin or provide --csr")
        allowed_profiles = tuple(
            CertificateProfile(value)
            for value in (
                args.allowed_profile
                or [profile.value for profile in CertificateProfile]
            )
        )
        sub_ca = service.sign_sub_ca_csr(
            csr_pem,
            validity_days=args.validity_days,
            permitted_dns_suffixes=tuple(args.permitted_dns_suffix),
            allowed_profiles=allowed_profiles,
        )
        _write_pem(sub_ca.certificate_pem, args.output)
        return 0

    if args.command == "root-crl-sign":
        root_crl = service.sign_root_crl()
        _write_pem(root_crl.crl_pem, args.output)
        return 0

    parser.error(f"unknown command: {args.command}")
    return 2


def _add_state_dir(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--state-dir",
        required=True,
        type=Path,
        help="offline state directory containing offline.sqlite3 and lab software keys",
    )


def _service(state_dir: Path) -> OfflineRootService:
    passphrase = os.getenv("MYOWNCA_OFFLINE_KEY_PASSPHRASE")
    state = OfflineStateRepository(state_dir / "offline.sqlite3")
    hsm = SoftwareHSM(
        state_dir / "keys",
        passphrase=passphrase,
        entropy_source=os.getenv("MYOWNCA_ENTROPY_SOURCE") or None,
    )
    return OfflineRootService(state, hsm)


def _write_pem(pem: str, output: Path | None) -> None:
    if output is None:
        sys.stdout.write(pem)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(pem)
    print(f"wrote {output}", file=sys.stderr)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
