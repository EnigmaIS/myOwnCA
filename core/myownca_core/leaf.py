from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address
from typing import Protocol

from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID


class CSRValidationError(ValueError):
    """Raised when a CSR violates the leaf profile (CN, CA flag, or SAN rules)."""


class IssuerValidityError(ValueError):
    """An issuance rejection with a stable, safe error for operators and APIs."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def validate_issuer_validity(
    issuer_certificate: x509.Certificate, *, now: datetime | None = None
) -> datetime:
    current = _utc_now(now).replace(microsecond=0)
    starts_at = issuer_certificate.not_valid_before_utc
    expires_at = issuer_certificate.not_valid_after_utc
    if current < starts_at:
        raise IssuerValidityError(
            "issuer_not_yet_valid",
            f"The issuing CA is not valid until {starts_at.isoformat()}. "
            "Check the system clock or wait until that time before retrying issuance.",
        )
    if current >= expires_at:
        raise IssuerValidityError(
            "issuer_expired",
            f"The issuing CA expired at {expires_at.isoformat()}. "
            "Contact the CA administrator; this issuer can no longer issue certificates.",
        )
    return current


def validate_leaf_validity(
    profile: LeafProfile,
    issuer_certificate: x509.Certificate,
    *,
    now: datetime | None = None,
) -> tuple[datetime, datetime]:
    """Return encodable leaf bounds without reducing the requested lifetime."""
    current = validate_issuer_validity(issuer_certificate, now=now)
    starts_at = max(
        (current - profile.backdate).replace(microsecond=0),
        issuer_certificate.not_valid_before_utc,
    )
    expires_at = current + timedelta(days=profile.validity_days)
    _validate_leaf_bounds(starts_at, expires_at, issuer_certificate)
    return starts_at, expires_at


def validate_signed_leaf_validity(
    certificate: x509.Certificate,
    issuer_certificate: x509.Certificate,
    *,
    now: datetime | None = None,
) -> None:
    """Recheck after a potentially slow signer, before publishing its result."""
    validate_issuer_validity(issuer_certificate, now=now)
    _validate_leaf_bounds(
        certificate.not_valid_before_utc, certificate.not_valid_after_utc, issuer_certificate
    )


def _validate_leaf_bounds(
    starts_at: datetime, expires_at: datetime, issuer_certificate: x509.Certificate
) -> None:
    if (
        starts_at < issuer_certificate.not_valid_before_utc
        or expires_at > issuer_certificate.not_valid_after_utc
    ):
        raise IssuerValidityError(
            "issuer_validity_exceeded",
            f"The requested certificate validity ({starts_at.isoformat()} to "
            f"{expires_at.isoformat()}) exceeds the issuing CA validity "
            f"({issuer_certificate.not_valid_before_utc.isoformat()} to "
            f"{issuer_certificate.not_valid_after_utc.isoformat()}). "
            "Ask the CA administrator to review the template validity. "
            "The requested lifetime has not been shortened.",
        )


class Signer(Protocol):
    """Signs a prepared CertificateBuilder with the key identified by key_ref."""

    def sign_certificate(
        self, builder: x509.CertificateBuilder, key_ref: str
    ) -> x509.Certificate: ...


@dataclass(frozen=True, slots=True)
class LeafProfile:
    validity_days: int
    key_usage: x509.KeyUsage
    extended_key_usages: tuple[x509.ObjectIdentifier, ...] = ()
    key_usage_critical: bool = True
    eku_critical: bool = False
    required_san_types: tuple[type, ...] = ()
    allowed_san_types: tuple[type, ...] | None = None
    backdate: timedelta = timedelta(minutes=5)


def build_leaf(
    csr: x509.CertificateSigningRequest,
    profile: LeafProfile,
    *,
    issuer_certificate: x509.Certificate,
    issuer_key_ref: str,
    signer: Signer,
    now: datetime | None = None,
    crl_url: str | None = None,
    ocsp_url: str | None = None,
    ca_issuers_url: str | None = None,
) -> x509.Certificate:
    validate_leaf_csr(csr, profile)
    starts_at, expires_at = validate_leaf_validity(profile, issuer_certificate, now=now)
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(issuer_certificate.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(starts_at)
        .not_valid_after(expires_at)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(profile.key_usage, critical=profile.key_usage_critical)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_certificate.public_key()),
            critical=False,
        )
    )
    if profile.extended_key_usages:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(list(profile.extended_key_usages)),
            critical=profile.eku_critical,
        )
    san = _get_san(csr)
    if san is not None:
        builder = builder.add_extension(san, critical=False)
    if crl_url:
        builder = builder.add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(crl_url)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )
    aia_descriptions = []
    if ocsp_url:
        aia_descriptions.append(
            x509.AccessDescription(
                AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(ocsp_url)
            )
        )
    if ca_issuers_url:
        aia_descriptions.append(
            x509.AccessDescription(
                AuthorityInformationAccessOID.CA_ISSUERS,
                x509.UniformResourceIdentifier(ca_issuers_url),
            )
        )
    if aia_descriptions:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess(aia_descriptions), critical=False
        )
    certificate = signer.sign_certificate(builder, issuer_key_ref)
    validate_signed_leaf_validity(certificate, issuer_certificate, now=now)
    return certificate


_SAN_TYPE_LABELS: dict[type, str] = {
    x509.DNSName: "DNS",
    x509.RFC822Name: "email",
    x509.IPAddress: "IP address",
}


def validate_leaf_csr(csr: x509.CertificateSigningRequest, profile: LeafProfile) -> None:
    """Validate a leaf CSR against profile policy without signing a certificate."""
    if not csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        raise CSRValidationError("CSR subject must include a common name")
    try:
        requested = csr.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound:
        requested = None
    if requested and requested.value.ca:
        raise CSRValidationError("End-entity CSRs may not request CA basic constraints")
    san = _get_san(csr)
    for required_type in profile.required_san_types:
        if san is None or not any(isinstance(name, required_type) for name in san):
            label = _SAN_TYPE_LABELS.get(required_type, required_type.__name__)
            raise CSRValidationError(
                f"This certificate profile requires at least one {label} SAN"
            )
    if profile.allowed_san_types is not None and san is not None:
        _assert_only_allowed_san_types(san, profile.allowed_san_types)


def _get_san(csr: x509.CertificateSigningRequest) -> x509.SubjectAlternativeName | None:
    try:
        return csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return None


def _assert_only_allowed_san_types(
    san: x509.SubjectAlternativeName, allowed_types: tuple[type, ...]
) -> None:
    for general_name in san:
        if not isinstance(general_name, allowed_types):
            raise CSRValidationError(
                f"Unsupported SAN type for profile: {general_name.__class__.__name__}"
            )
        if isinstance(general_name, x509.IPAddress) and not isinstance(
            general_name.value, (IPv4Address, IPv6Address)
        ):
            raise CSRValidationError("Only single IP address SANs are supported")


def _utc_now(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        return current.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc)
