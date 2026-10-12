"""Stable identity comparison for certificate renewal lineages."""

from __future__ import annotations

import base64
import hashlib
import json

from cryptography import x509


def certificate_identity_digest(
    value: x509.Certificate | x509.CertificateSigningRequest,
) -> str:
    """Hash the fields that define a licensed certificate identity.

    Public-key material and validity are intentionally excluded so a normal key
    rotation remains a renewal. Subject and SANs are canonicalized so harmless
    SAN ordering and DNS-name case changes do not create a new identity.
    """

    payload = {
        "subject_der": base64.b64encode(value.subject.public_bytes()).decode("ascii"),
        "subject_alt_names": _canonical_sans(value),
    }
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def assert_same_certificate_identity(
    certificate: x509.Certificate,
    csr: x509.CertificateSigningRequest,
) -> None:
    if certificate_identity_digest(certificate) != certificate_identity_digest(csr):
        raise ValueError(
            "Renewal subject and subject alternative names must match the existing "
            "certificate; submit identity changes as a new certificate request"
        )


def _canonical_sans(
    value: x509.Certificate | x509.CertificateSigningRequest,
) -> list[tuple[str, str]]:
    try:
        names = value.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return sorted(_canonical_general_name(name) for name in names)


def _canonical_general_name(name: x509.GeneralName) -> tuple[str, str]:
    if isinstance(name, x509.DNSName):
        return "dns", name.value.rstrip(".").lower()
    if isinstance(name, x509.RFC822Name):
        local, separator, domain = name.value.rpartition("@")
        normalized = f"{local}@{domain.lower()}" if separator else name.value
        return "email", normalized
    if isinstance(name, x509.IPAddress):
        return "ip", str(name.value)
    if isinstance(name, x509.UniformResourceIdentifier):
        return "uri", name.value
    if isinstance(name, x509.RegisteredID):
        return "rid", name.value.dotted_string
    if isinstance(name, x509.DirectoryName):
        return "directory", base64.b64encode(name.value.public_bytes()).decode("ascii")
    if isinstance(name, x509.OtherName):
        encoded = base64.b64encode(name.value).decode("ascii")
        return f"other:{name.type_id.dotted_string}", encoded
    raise ValueError(f"Unsupported subject alternative name type: {type(name).__name__}")
