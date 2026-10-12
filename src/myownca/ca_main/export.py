"""Serialize issued certificates into standard interchange formats.

Pure functions over PEM inputs: the caller (web layer) supplies the leaf, the
verified chain, and — for key-bearing formats — the vaulted private key. Key
material only ever flows through here in memory.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
from cryptography.x509.oid import NameOID

from myownca.ca_main.crypto import verify_certificate_signature


class ExportError(ValueError):
    """Invalid format/key/password combination for a certificate export."""


class ExportFormat(StrEnum):
    PEM = "pem"
    PEM_CHAIN = "pem-chain"
    PKCS7 = "pkcs7"
    PKCS12 = "pkcs12"
    PEM_KEY = "pem-key"
    PEM_PKCS8 = "pem-pkcs8"
    DER = "der"


KEY_BEARING_FORMATS = frozenset(
    {ExportFormat.PKCS12, ExportFormat.PEM_KEY, ExportFormat.PEM_PKCS8}
)
PASSWORD_FORMATS = KEY_BEARING_FORMATS
MIN_EXPORT_PASSWORD_LENGTH = 8

_EXTENSIONS: dict[ExportFormat, str] = {
    ExportFormat.PEM: "crt",
    ExportFormat.PEM_CHAIN: "pem",
    ExportFormat.PKCS7: "p7b",
    ExportFormat.PKCS12: "pfx",
    ExportFormat.PEM_KEY: "pem",
    ExportFormat.PEM_PKCS8: "pem",
    ExportFormat.DER: "cer",
}

_MEDIA_TYPES: dict[ExportFormat, str] = {
    ExportFormat.PEM: "application/x-pem-file",
    ExportFormat.PEM_CHAIN: "application/x-pem-file",
    ExportFormat.PKCS7: "application/x-pkcs7-certificates",
    ExportFormat.PKCS12: "application/x-pkcs12",
    ExportFormat.PEM_KEY: "application/x-pem-file",
    ExportFormat.PEM_PKCS8: "application/x-pem-file",
    ExportFormat.DER: "application/pkix-cert",
}


@dataclass(frozen=True, slots=True)
class ExportResult:
    content: bytes
    media_type: str
    filename: str


def export_certificate(
    certificate_pem: str,
    fmt: ExportFormat | str,
    *,
    serial_number: str = "",
    chain_pems: Sequence[str] = (),
    private_key_pem: str | None = None,
    password: str | None = None,
) -> ExportResult:
    """Build the requested export. Raises :class:`ExportError` on misuse."""
    try:
        fmt = ExportFormat(fmt)
    except ValueError as exc:
        raise ExportError(f"Unknown export format: {fmt}") from exc
    certificate = _load_certificate(certificate_pem)
    password = password or None
    if fmt in PASSWORD_FORMATS:
        if password is None or len(password) < MIN_EXPORT_PASSWORD_LENGTH:
            raise ExportError(
                f"{fmt.value} export requires a password of at least "
                f"{MIN_EXPORT_PASSWORD_LENGTH} characters"
            )
    elif password is not None:
        raise ExportError(f"{fmt.value} export does not take a password")

    private_key = None
    if fmt in KEY_BEARING_FORMATS:
        if not private_key_pem:
            raise ExportError(f"{fmt.value} export requires the certificate's private key")
        private_key = _load_private_key(private_key_pem)
        if not _key_matches(private_key, certificate):
            raise ExportError("Private key does not match the certificate")
    elif private_key_pem:
        raise ExportError(f"{fmt.value} export does not take a private key")

    content = _build(fmt, certificate, certificate_pem, chain_pems, private_key, password)
    return ExportResult(
        content=content,
        media_type=_MEDIA_TYPES[fmt],
        filename=_filename(certificate, serial_number, _EXTENSIONS[fmt]),
    )


def build_chain_pems(
    certificate_pem: str,
    *,
    issuer_candidates: Iterable[str] = (),
    root_pem: str | None = None,
) -> list[str]:
    """Signature-verified [issuing sub-CA, root] chain for a leaf.

    Best effort: candidates that do not parse, do not match the leaf's issuer
    DN, or fail signature verification are skipped, so the result may be
    shorter than the full chain (or empty) rather than wrong.
    """
    leaf = _load_certificate(certificate_pem)
    chain: list[str] = []
    anchor = leaf
    for candidate_pem in issuer_candidates:
        try:
            candidate = x509.load_pem_x509_certificate(candidate_pem.encode())
        except ValueError:
            continue
        if candidate.subject == leaf.issuer and _signed_by(leaf, candidate):
            chain.append(candidate_pem)
            anchor = candidate
            break
    if root_pem:
        try:
            root = x509.load_pem_x509_certificate(root_pem.encode())
        except ValueError:
            return chain
        already_anchored = anchor.subject == anchor.issuer
        if (
            not already_anchored
            and root.subject == anchor.issuer
            and _signed_by(anchor, root)
        ):
            chain.append(root_pem)
    return chain


# -- internals -----------------------------------------------------------------


def _load_certificate(pem: str) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(pem.encode())
    except ValueError as exc:
        raise ExportError(f"Invalid certificate PEM: {exc}") from exc


def _load_private_key(pem: str) -> CertificateIssuerPrivateKeyTypes:
    try:
        return serialization.load_pem_private_key(pem.encode(), password=None)
    except (ValueError, TypeError) as exc:
        raise ExportError(f"Invalid private key PEM: {exc}") from exc


def _key_matches(private_key, certificate: x509.Certificate) -> bool:
    spki = serialization.PublicFormat.SubjectPublicKeyInfo
    der = serialization.Encoding.DER
    return private_key.public_key().public_bytes(der, spki) == certificate.public_key(
    ).public_bytes(der, spki)


def _signed_by(certificate: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        verify_certificate_signature(certificate, issuer)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _build(
    fmt: ExportFormat,
    certificate: x509.Certificate,
    certificate_pem: str,
    chain_pems: Sequence[str],
    private_key,
    password: str | None,
) -> bytes:
    if fmt is ExportFormat.PEM:
        return _normalize_pem(certificate_pem).encode()
    if fmt is ExportFormat.PEM_CHAIN:
        return "".join(_normalize_pem(pem) for pem in (certificate_pem, *chain_pems)).encode()
    if fmt is ExportFormat.PKCS7:
        return pkcs7.serialize_certificates([certificate], serialization.Encoding.DER)
    if fmt is ExportFormat.DER:
        return certificate.public_bytes(serialization.Encoding.DER)

    assert private_key is not None and fmt in KEY_BEARING_FORMATS
    if fmt is ExportFormat.PKCS12:
        cas = [_load_certificate(pem) for pem in chain_pems]
        return pkcs12.serialize_key_and_certificates(
            name=(_common_name(certificate) or "certificate").encode(),
            key=private_key,
            cert=certificate,
            cas=cas or None,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
        )
    encryption = serialization.BestAvailableEncryption(password.encode())
    key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption,
    ).decode()
    return (_normalize_pem(certificate_pem) + _normalize_pem(key_pem)).encode()


def _normalize_pem(pem: str) -> str:
    return pem.strip() + "\n"


def _common_name(certificate: x509.Certificate) -> str:
    attributes = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attributes[0].value) if attributes else ""


def _filename(certificate: x509.Certificate, serial_number: str, extension: str) -> str:
    name = _slug(_common_name(certificate)) or "certificate"
    serial = _slug(serial_number)
    return f"{name}-{serial}.{extension}" if serial else f"{name}.{extension}"


def _slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-.")
