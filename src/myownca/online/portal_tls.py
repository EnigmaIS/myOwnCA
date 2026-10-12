"""Materialize a managed external certificate as the portal's TLS files.

A superuser can point the portal's own HTTPS at an external (service) certificate
by writing its leaf+chain and private key to a stable path under the state dir:

    <state>/tls/portal.crt   # leaf certificate followed by its chain (one PEM file)
    <state>/tls/portal.key   # unencrypted PKCS#8 private key, mode 0600

The operator's TLS terminator (nginx, or the app via MYOWNCA_TLS_CERT/KEY) points
at these paths and reloads to apply. This module never enables HTTPS, restarts the
app, or reloads a proxy — it only writes/validates/removes the files.
"""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from myownca_core.private_files import mkdir_private


class PortalTlsError(RuntimeError):
    """Raised when a certificate/key pair cannot be used as the portal TLS files."""


def portal_paths(state_dir: str | Path) -> tuple[Path, Path]:
    """Return ``(<state>/tls/portal.crt, <state>/tls/portal.key)`` (not created)."""
    tls_dir = Path(state_dir) / "tls"
    return tls_dir / "portal.crt", tls_dir / "portal.key"


def _public_der(public_key) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def validate_pair(certificate_pem: str, key_pem: str) -> None:
    """Raise ``PortalTlsError`` if the leaf and key don't match, or the cert is expired."""
    try:
        cert = x509.load_pem_x509_certificate(certificate_pem.encode())
    except Exception as exc:  # noqa: BLE001 - any parse failure is a bad input
        raise PortalTlsError(f"Invalid certificate PEM: {exc}") from exc
    try:
        key = load_pem_private_key(key_pem.encode(), password=None)
    except Exception as exc:  # noqa: BLE001
        raise PortalTlsError(f"Invalid private key PEM: {exc}") from exc
    if _public_der(cert.public_key()) != _public_der(key.public_key()):
        raise PortalTlsError("Certificate and private key do not match")
    if cert.not_valid_after_utc < datetime.now(timezone.utc):
        raise PortalTlsError("Certificate has expired")


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    # mkstemp creates the temp file 0600, so key material is never world-readable
    # even before the explicit chmod; chmod happens before the rename so the file is
    # at its final mode the instant it appears at `path`. A hard kill (SIGKILL) mid-write
    # can still leave a `.portal-tls-*` temp behind, but it is 0600 — not a disclosure.
    mkdir_private(path.parent)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".portal-tls-")
    try:
        with os.fdopen(fd, "wb") as handle:  # takes ownership of fd; closes it
            handle.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)  # atomic on POSIX
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def materialize(
    certificate_pem: str, chain_pem: str, key_pem: str, state_dir: str | Path
) -> tuple[Path, Path]:
    """Validate the pair, then write ``portal.crt`` (leaf+chain) and ``portal.key`` (0600).

    Returns the two paths. Creates ``<state>/tls/`` if missing. Writes atomically.
    """
    validate_pair(certificate_pem, key_pem)
    crt_path, key_path = portal_paths(state_dir)
    bundle = certificate_pem.strip() + "\n"
    if chain_pem and chain_pem.strip():
        bundle += chain_pem.strip() + "\n"
    _atomic_write(crt_path, bundle.encode(), 0o644)
    _atomic_write(key_path, (key_pem.strip() + "\n").encode(), 0o600)
    return crt_path, key_path


def clear(state_dir: str | Path) -> None:
    """Remove ``portal.crt`` and ``portal.key`` if present (idempotent)."""
    crt_path, key_path = portal_paths(state_dir)
    crt_path.unlink(missing_ok=True)
    key_path.unlink(missing_ok=True)
