"""Parse, validate, and export imported end-entity certificate material.

The module deliberately has no storage or web-layer dependencies.  Parsing a
container and deciding whether its certificate is an acceptable leaf are two
separate operations so the generic parser can also be reused by issuer import
flows.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from myownca.ca_main.crypto import verify_certificate_signature
from myownca.domain import CertificateProfile, CertificateTemplate


class BundleFormat(StrEnum):
    PEM = "pem"
    PKCS12 = "pkcs12"


class LeafImportErrorCode(StrEnum):
    INVALID_INPUT = "invalid_input"
    INVALID_CONTAINER = "invalid_container"
    INVALID_CERTIFICATE = "invalid_certificate"
    INVALID_PRIVATE_KEY = "invalid_private_key"
    NO_CERTIFICATE = "no_certificate"
    NO_LEAF = "no_leaf"
    AMBIGUOUS_LEAF = "ambiguous_leaf"
    MULTIPLE_PRIVATE_KEYS = "multiple_private_keys"
    KEY_MISMATCH = "key_mismatch"
    CERTIFICATE_IS_CA = "certificate_is_ca"
    CERTIFICATE_NOT_YET_VALID = "certificate_not_yet_valid"
    CERTIFICATE_EXPIRED = "certificate_expired"
    WRONG_ISSUER = "wrong_issuer"
    INVALID_SIGNATURE = "invalid_signature"
    INVALID_CHAIN = "invalid_chain"
    MISSING_PRIVATE_KEY = "missing_private_key"
    WEAK_EXPORT_PASSWORD = "weak_export_password"
    EXPORT_FAILED = "export_failed"
    CSR_FAILED = "csr_failed"


class LeafImportError(ValueError):
    """A safe, user-presentable certificate import error with a stable code."""

    def __init__(self, code: LeafImportErrorCode, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class SubjectAlternativeNameSignal:
    kind: str
    value: str
    oid: str | None = None


@dataclass(frozen=True, slots=True)
class LeafTemplateSignals:
    """JSON-friendly extension values used to suggest a certificate template."""

    key_usages: tuple[str, ...]
    extended_key_usages: tuple[str, ...]
    extended_key_usage_oids: tuple[str, ...]
    subject_alt_names: tuple[SubjectAlternativeNameSignal, ...]
    key_usage_critical: bool | None
    extended_key_usage_critical: bool | None
    subject_alt_name_critical: bool | None

    @property
    def dns_names(self) -> tuple[str, ...]:
        return tuple(item.value for item in self.subject_alt_names if item.kind == "dns")

    @property
    def email_addresses(self) -> tuple[str, ...]:
        return tuple(item.value for item in self.subject_alt_names if item.kind == "email")

    @property
    def ip_addresses(self) -> tuple[str, ...]:
        return tuple(item.value for item in self.subject_alt_names if item.kind == "ip")


@dataclass(frozen=True, slots=True)
class ParsedCertificateBundle:
    """Cryptographic material decoded from PEM or PKCS#12, but not trusted yet."""

    source_format: BundleFormat
    certificates: tuple[x509.Certificate, ...]
    private_key: CertificateIssuerPrivateKeyTypes | None = field(repr=False)
    preferred_certificate: x509.Certificate | None = None

    @property
    def certificate_pems(self) -> tuple[str, ...]:
        return tuple(_certificate_pem(certificate) for certificate in self.certificates)


@dataclass(frozen=True, slots=True)
class ValidatedLeafBundle:
    """A currently valid leaf and its signature-verified issuer chain."""

    source_format: BundleFormat
    certificate: x509.Certificate
    chain: tuple[x509.Certificate, ...]
    private_key: CertificateIssuerPrivateKeyTypes | None = field(repr=False)
    signals: LeafTemplateSignals

    @property
    def certificate_pem(self) -> str:
        return _certificate_pem(self.certificate)

    @property
    def chain_pems(self) -> tuple[str, ...]:
        return tuple(_certificate_pem(certificate) for certificate in self.chain)

    @property
    def has_private_key(self) -> bool:
        return self.private_key is not None

    @property
    def fingerprint_sha256(self) -> str:
        return self.certificate.fingerprint(hashes.SHA256()).hex()


MIN_EXPORT_PASSWORD_LENGTH = 8

_PEM_BLOCK_RE = re.compile(
    rb"-----BEGIN ([A-Z0-9][A-Z0-9 ]*)-----\s+.*?-----END \1-----",
    re.DOTALL,
)
_PRIVATE_KEY_LABELS = frozenset(
    {
        b"PRIVATE KEY",
        b"ENCRYPTED PRIVATE KEY",
        b"RSA PRIVATE KEY",
        b"EC PRIVATE KEY",
        b"DSA PRIVATE KEY",
    }
)


def parse_bundle(
    data: bytes | str,
    *,
    private_key_data: bytes | str | None = None,
    password: bytes | str | None = None,
) -> ParsedCertificateBundle:
    """Decode a PEM or PKCS#12 bundle without applying leaf/issuer policy.

    PEM may contain the certificate, chain, and key in one document or the key
    may be supplied separately.  A bundle containing more than one private key
    is rejected rather than choosing one heuristically.
    """
    payload = _as_bytes(data, "certificate bundle")
    key_payload = (
        _as_bytes(private_key_data, "private key") if private_key_data is not None else None
    )
    password_bytes = _password_bytes(password, empty_is_none=True)

    if _looks_like_pem(payload):
        documents = [payload]
        if key_payload is not None:
            if not _looks_like_pem(key_payload):
                raise LeafImportError(
                    LeafImportErrorCode.INVALID_PRIVATE_KEY,
                    "A separately uploaded private key must be PEM encoded",
                )
            documents.append(key_payload)
        certificates, key_blocks = _parse_pem_documents(documents)
        private_key = _load_single_private_key(key_blocks, password_bytes)
        certificates = _deduplicate_certificates(certificates)
        if not certificates:
            raise LeafImportError(
                LeafImportErrorCode.NO_CERTIFICATE,
                "PEM bundle does not contain an X.509 certificate",
            )
        return ParsedCertificateBundle(
            source_format=BundleFormat.PEM,
            certificates=certificates,
            private_key=private_key,
            preferred_certificate=_preferred_certificate(certificates, private_key),
        )

    if key_payload is not None:
        raise LeafImportError(
            LeafImportErrorCode.INVALID_INPUT,
            "A separate private key cannot be combined with a PKCS#12 bundle",
        )
    try:
        private_key, primary, additional = pkcs12.load_key_and_certificates(payload, password_bytes)
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise LeafImportError(
            LeafImportErrorCode.INVALID_CONTAINER,
            "PKCS#12 bundle is invalid, unsupported, or protected by a different password",
        ) from exc
    certificates = _deduplicate_certificates(
        tuple(certificate for certificate in (primary, *(additional or ())) if certificate)
    )
    if not certificates:
        raise LeafImportError(
            LeafImportErrorCode.NO_CERTIFICATE,
            "PKCS#12 bundle does not contain an X.509 certificate",
        )
    preferred = primary or _preferred_certificate(certificates, private_key)
    return ParsedCertificateBundle(
        source_format=BundleFormat.PKCS12,
        certificates=certificates,
        private_key=private_key,
        preferred_certificate=preferred,
    )


def validate_leaf_bundle(
    bundle: ParsedCertificateBundle,
    active_sub_ca: x509.Certificate | bytes | str,
    *,
    now: datetime | None = None,
) -> ValidatedLeafBundle:
    """Select and validate exactly one leaf issued directly by ``active_sub_ca``."""
    issuer = _load_one_certificate(active_sub_ca, label="active Sub-CA")
    leaf = _select_leaf(bundle, issuer)
    current = _utc(now)
    _validate_leaf(leaf, bundle.private_key, issuer, now=current)
    remaining = tuple(
        certificate
        for certificate in bundle.certificates
        if _certificate_der(certificate) != _certificate_der(leaf)
    )
    chain = _validated_chain(issuer, remaining, now=current)
    return ValidatedLeafBundle(
        source_format=bundle.source_format,
        certificate=leaf,
        chain=chain,
        private_key=bundle.private_key,
        signals=extract_template_signals(leaf),
    )


def import_leaf_bundle(
    data: bytes | str,
    active_sub_ca: x509.Certificate | bytes | str,
    *,
    private_key_data: bytes | str | None = None,
    password: bytes | str | None = None,
    now: datetime | None = None,
) -> ValidatedLeafBundle:
    """Convenience wrapper combining :func:`parse_bundle` and leaf validation."""
    return validate_leaf_bundle(
        parse_bundle(data, private_key_data=private_key_data, password=password),
        active_sub_ca,
        now=now,
    )


def extract_template_signals(certificate: x509.Certificate) -> LeafTemplateSignals:
    key_usage_extension = _extension(certificate, x509.KeyUsage)
    if key_usage_extension is None:
        key_usages: tuple[str, ...] = ()
        key_usage_critical = None
    else:
        usage = key_usage_extension.value
        usage_values = (
            ("digital_signature", usage.digital_signature),
            ("content_commitment", usage.content_commitment),
            ("key_encipherment", usage.key_encipherment),
            ("data_encipherment", usage.data_encipherment),
            ("key_agreement", usage.key_agreement),
            ("encipher_only", usage.encipher_only if usage.key_agreement else False),
            ("decipher_only", usage.decipher_only if usage.key_agreement else False),
            ("key_cert_sign", usage.key_cert_sign),
            ("crl_sign", usage.crl_sign),
        )
        key_usages = tuple(name for name, enabled in usage_values if enabled)
        key_usage_critical = key_usage_extension.critical

    eku_extension = _extension(certificate, x509.ExtendedKeyUsage)
    if eku_extension is None:
        extended_key_usages: tuple[str, ...] = ()
        extended_key_usage_oids: tuple[str, ...] = ()
        extended_key_usage_critical = None
    else:
        extended_key_usage_oids = tuple(oid.dotted_string for oid in eku_extension.value)
        extended_key_usages = tuple(
            _EKU_NAMES.get(oid.dotted_string, oid.dotted_string) for oid in eku_extension.value
        )
        extended_key_usage_critical = eku_extension.critical

    san_extension = _extension(certificate, x509.SubjectAlternativeName)
    if san_extension is None:
        subject_alt_names: tuple[SubjectAlternativeNameSignal, ...] = ()
        subject_alt_name_critical = None
    else:
        subject_alt_names = tuple(_san_signal(name) for name in san_extension.value)
        subject_alt_name_critical = san_extension.critical

    return LeafTemplateSignals(
        key_usages=key_usages,
        extended_key_usages=extended_key_usages,
        extended_key_usage_oids=extended_key_usage_oids,
        subject_alt_names=subject_alt_names,
        key_usage_critical=key_usage_critical,
        extended_key_usage_critical=extended_key_usage_critical,
        subject_alt_name_critical=subject_alt_name_critical,
    )


def leaf_matches_template(
    bundle: ValidatedLeafBundle,
    template: CertificateTemplate,
    *,
    allowed_profiles: tuple[CertificateProfile, ...] | None = None,
) -> bool:
    """Return whether an imported leaf satisfies a usable template policy.

    In addition to exact KU/EKU and criticality matching, profile-specific SAN
    rules are applied in the same way as during normal issuance.  Passing an
    issuer profile allow-list prevents analysis from suggesting a template the
    active Sub-CA is not permitted to issue.
    """
    if allowed_profiles is not None and template.profile not in allowed_profiles:
        return False
    signals = bundle.signals
    if set(signals.key_usages) != {usage.value for usage in template.key_usages}:
        return False
    if set(signals.extended_key_usages) != {
        usage.value for usage in template.extended_key_usages
    }:
        return False
    if (
        signals.key_usage_critical is not None
        and signals.key_usage_critical != template.key_usage_critical
    ):
        return False
    if (
        signals.extended_key_usage_critical is not None
        and signals.extended_key_usage_critical
        != template.extended_key_usage_critical
    ):
        return False

    san_kinds = {item.kind for item in signals.subject_alt_names}
    if template.profile is CertificateProfile.HOST_TLS:
        return "dns" in san_kinds and san_kinds <= {"dns", "ip"}
    if template.profile is CertificateProfile.SMIME:
        return "email" in san_kinds and san_kinds <= {"email"}
    if template.profile is CertificateProfile.USER_AUTH:
        return san_kinds <= {"dns", "email"}
    return False


def export_leaf_pkcs12(
    bundle: ValidatedLeafBundle,
    password: bytes | str,
    *,
    friendly_name: bytes | str | None = None,
) -> bytes:
    """Serialize a validated key-bearing leaf and chain as encrypted PKCS#12."""
    private_key = _require_export_key(bundle)
    password_bytes = _export_password(password)
    if friendly_name is None:
        common_names = bundle.certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        name = str(common_names[0].value).encode() if common_names else b"certificate"
    elif isinstance(friendly_name, str):
        name = friendly_name.encode()
    else:
        name = friendly_name
    try:
        return pkcs12.serialize_key_and_certificates(
            name=name,
            key=private_key,
            cert=bundle.certificate,
            cas=bundle.chain or None,
            encryption_algorithm=serialization.BestAvailableEncryption(password_bytes),
        )
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise LeafImportError(
            LeafImportErrorCode.EXPORT_FAILED,
            "The certificate key cannot be exported as PKCS#12",
        ) from exc


def export_leaf_encrypted_pem(
    bundle: ValidatedLeafBundle,
    password: bytes | str,
) -> bytes:
    """Serialize encrypted PKCS#8 followed by the leaf and verified chain."""
    private_key = _require_export_key(bundle)
    password_bytes = _export_password(password)
    try:
        key_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password_bytes),
        )
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise LeafImportError(
            LeafImportErrorCode.EXPORT_FAILED,
            "The certificate key cannot be exported as encrypted PEM",
        ) from exc
    certificates = (bundle.certificate, *bundle.chain)
    return key_pem + b"".join(
        certificate.public_bytes(serialization.Encoding.PEM) for certificate in certificates
    )


def build_csr_from_certificate(
    private_key: CertificateIssuerPrivateKeyTypes,
    certificate: x509.Certificate,
) -> str:
    """Build a CSR with the certificate's full subject and SAN using its key."""
    if not private_key_matches_certificate(private_key, certificate):
        raise LeafImportError(
            LeafImportErrorCode.KEY_MISMATCH,
            "Private key does not match the certificate",
        )
    return _identity_csr(private_key, certificate)


def build_rotated_csr_from_certificate(
    private_key: CertificateIssuerPrivateKeyTypes,
    certificate: x509.Certificate,
) -> str:
    """Build a CSR preserving identity while deliberately rotating the key."""

    return _identity_csr(private_key, certificate)


def create_identity_csr(certificate: x509.Certificate) -> str:
    """Build an identity-only CSR with a disposable P-256 key for cert-only imports."""
    return _identity_csr(ec.generate_private_key(ec.SECP256R1()), certificate)


def private_key_matches_certificate(
    private_key: CertificateIssuerPrivateKeyTypes,
    certificate: x509.Certificate,
) -> bool:
    return _public_key_der(private_key.public_key()) == _public_key_der(certificate.public_key())


def certificate_matches_public_key(certificate: x509.Certificate, public_key) -> bool:
    return _public_key_der(certificate.public_key()) == _public_key_der(public_key)


# -- parsing and validation internals -----------------------------------------


def _as_bytes(value: bytes | str, label: str) -> bytes:
    payload = value.encode() if isinstance(value, str) else value
    if not isinstance(payload, bytes) or not payload.strip():
        raise LeafImportError(
            LeafImportErrorCode.INVALID_INPUT,
            f"{label.capitalize()} is empty",
        )
    return payload


def _password_bytes(password: bytes | str | None, *, empty_is_none: bool) -> bytes | None:
    if password is None:
        return None
    value = password.encode() if isinstance(password, str) else password
    if not isinstance(value, bytes):
        raise LeafImportError(
            LeafImportErrorCode.INVALID_INPUT,
            "Password must be text or bytes",
        )
    return None if empty_is_none and not value else value


def _looks_like_pem(data: bytes) -> bool:
    return b"-----BEGIN " in data


def _parse_pem_documents(
    documents: list[bytes],
) -> tuple[tuple[x509.Certificate, ...], tuple[bytes, ...]]:
    certificates: list[x509.Certificate] = []
    key_blocks: list[bytes] = []
    found_block = False
    for document in documents:
        for match in _PEM_BLOCK_RE.finditer(document):
            found_block = True
            label = match.group(1)
            block = match.group(0).strip() + b"\n"
            if label == b"CERTIFICATE":
                try:
                    certificates.append(x509.load_pem_x509_certificate(block))
                except ValueError as exc:
                    raise LeafImportError(
                        LeafImportErrorCode.INVALID_CERTIFICATE,
                        "PEM bundle contains an invalid X.509 certificate",
                    ) from exc
            elif label in _PRIVATE_KEY_LABELS:
                key_blocks.append(block)
            elif label.endswith(b"PRIVATE KEY"):
                raise LeafImportError(
                    LeafImportErrorCode.INVALID_PRIVATE_KEY,
                    f"Unsupported PEM private-key type: {label.decode(errors='replace')}",
                )
    if not found_block:
        raise LeafImportError(
            LeafImportErrorCode.INVALID_CONTAINER,
            "PEM input does not contain a complete PEM block",
        )
    return tuple(certificates), tuple(key_blocks)


def _load_single_private_key(
    key_blocks: tuple[bytes, ...], password: bytes | None
) -> CertificateIssuerPrivateKeyTypes | None:
    if not key_blocks:
        return None
    if len(key_blocks) > 1:
        raise LeafImportError(
            LeafImportErrorCode.MULTIPLE_PRIVATE_KEYS,
            "PEM bundle contains more than one private key",
        )
    block = key_blocks[0]
    try:
        return serialization.load_pem_private_key(block, password=password)
    except TypeError as first_error:
        if password is not None:
            try:
                return serialization.load_pem_private_key(block, password=None)
            except (TypeError, ValueError, UnsupportedAlgorithm):
                pass
        raise LeafImportError(
            LeafImportErrorCode.INVALID_PRIVATE_KEY,
            "Private key is invalid, unsupported, or requires a password",
        ) from first_error
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise LeafImportError(
            LeafImportErrorCode.INVALID_PRIVATE_KEY,
            "Private key is invalid, unsupported, or protected by a different password",
        ) from exc


def _preferred_certificate(
    certificates: tuple[x509.Certificate, ...],
    private_key: CertificateIssuerPrivateKeyTypes | None,
) -> x509.Certificate | None:
    if private_key is not None:
        matching = tuple(
            certificate
            for certificate in certificates
            if private_key_matches_certificate(private_key, certificate)
        )
        if len(matching) == 1:
            return matching[0]
        return None
    return certificates[0] if len(certificates) == 1 else None


def _select_leaf(bundle: ParsedCertificateBundle, issuer: x509.Certificate) -> x509.Certificate:
    if bundle.preferred_certificate is not None:
        return bundle.preferred_certificate
    issuer_der = _certificate_der(issuer)
    candidates = tuple(
        certificate
        for certificate in bundle.certificates
        if _certificate_der(certificate) != issuer_der
    )
    if not candidates:
        raise LeafImportError(
            LeafImportErrorCode.NO_LEAF,
            "Bundle does not contain a leaf certificate",
        )

    direct_leaves = tuple(
        certificate
        for certificate in candidates
        if not _is_ca(certificate)
        and certificate.issuer == issuer.subject
        and _signed_by(certificate, issuer)
    )
    if bundle.private_key is not None:
        matching = tuple(
            certificate
            for certificate in direct_leaves
            if private_key_matches_certificate(bundle.private_key, certificate)
        )
        if len(matching) == 1:
            return matching[0]
        if len(matching) > 1:
            raise _ambiguous_leaf()
    if len(direct_leaves) == 1:
        return direct_leaves[0]
    if len(direct_leaves) > 1:
        raise _ambiguous_leaf()

    non_ca = tuple(certificate for certificate in candidates if not _is_ca(certificate))
    if len(non_ca) == 1:
        return non_ca[0]
    if len(candidates) == 1:
        return candidates[0]
    raise _ambiguous_leaf()


def _ambiguous_leaf() -> LeafImportError:
    return LeafImportError(
        LeafImportErrorCode.AMBIGUOUS_LEAF,
        "Bundle does not identify exactly one leaf certificate",
    )


def _validate_leaf(
    certificate: x509.Certificate,
    private_key: CertificateIssuerPrivateKeyTypes | None,
    issuer: x509.Certificate,
    *,
    now: datetime | None,
) -> None:
    if _is_ca(certificate):
        raise LeafImportError(
            LeafImportErrorCode.CERTIFICATE_IS_CA,
            "Imported certificate is a CA certificate, not an end-entity certificate",
        )
    current = _utc(now)
    if current < certificate.not_valid_before_utc:
        raise LeafImportError(
            LeafImportErrorCode.CERTIFICATE_NOT_YET_VALID,
            "Imported certificate is not valid yet",
        )
    if current >= certificate.not_valid_after_utc:
        raise LeafImportError(
            LeafImportErrorCode.CERTIFICATE_EXPIRED,
            "Imported certificate has expired",
        )
    if private_key is not None and not private_key_matches_certificate(private_key, certificate):
        raise LeafImportError(
            LeafImportErrorCode.KEY_MISMATCH,
            "Private key does not match the imported certificate",
        )
    if certificate.issuer != issuer.subject:
        raise LeafImportError(
            LeafImportErrorCode.WRONG_ISSUER,
            "Imported certificate was not issued directly by the active Sub-CA",
        )
    if not _signed_by(certificate, issuer):
        raise LeafImportError(
            LeafImportErrorCode.INVALID_SIGNATURE,
            "Imported certificate signature does not verify with the active Sub-CA",
        )


def _validated_chain(
    issuer: x509.Certificate,
    supplied: tuple[x509.Certificate, ...],
    *,
    now: datetime | None,
) -> tuple[x509.Certificate, ...]:
    current_time = _utc(now)
    _validate_chain_parent(issuer, current_time)
    issuer_der = _certificate_der(issuer)
    candidates = list(
        _deduplicate_certificates(
            tuple(
                certificate
                for certificate in supplied
                if _certificate_der(certificate) != issuer_der
            )
        )
    )
    chain = [issuer]
    current = issuer
    seen = {issuer_der}
    while candidates:
        matches = [
            certificate
            for certificate in candidates
            if current.issuer == certificate.subject and _signed_by(current, certificate)
        ]
        if not matches:
            break
        if len(matches) != 1:
            raise LeafImportError(
                LeafImportErrorCode.INVALID_CHAIN,
                "Certificate bundle contains an ambiguous issuer chain",
            )
        parent = matches[0]
        parent_der = _certificate_der(parent)
        if parent_der in seen:
            raise LeafImportError(
                LeafImportErrorCode.INVALID_CHAIN,
                "Certificate bundle contains a cyclic issuer chain",
            )
        _validate_chain_parent(parent, current_time)
        seen.add(parent_der)
        chain.append(parent)
        candidates.remove(parent)
        current = parent
    if candidates:
        raise LeafImportError(
            LeafImportErrorCode.INVALID_CHAIN,
            "Certificate bundle contains certificates outside the imported leaf's issuer chain",
        )
    return tuple(chain)


def _validate_chain_parent(certificate: x509.Certificate, now: datetime) -> None:
    if not (certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc):
        raise LeafImportError(
            LeafImportErrorCode.INVALID_CHAIN,
            "Imported certificate issuer chain contains a certificate that is not currently valid",
        )
    try:
        constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except x509.ExtensionNotFound as exc:
        raise LeafImportError(
            LeafImportErrorCode.INVALID_CHAIN,
            "Imported certificate issuer chain is missing BasicConstraints",
        ) from exc
    if not constraints.ca:
        raise LeafImportError(
            LeafImportErrorCode.INVALID_CHAIN,
            "Imported certificate issuer chain requires CA=true",
        )
    try:
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise LeafImportError(
            LeafImportErrorCode.INVALID_CHAIN,
            "Imported certificate issuer chain is missing KeyUsage",
        ) from exc
    if not usage.key_cert_sign:
        raise LeafImportError(
            LeafImportErrorCode.INVALID_CHAIN,
            "Imported certificate issuer chain requires keyCertSign",
        )


def _load_one_certificate(value: x509.Certificate | bytes | str, *, label: str) -> x509.Certificate:
    if isinstance(value, x509.Certificate):
        return value
    payload = _as_bytes(value, label)
    try:
        if _looks_like_pem(payload):
            certificates, _ = _parse_pem_documents([payload])
            if len(certificates) != 1:
                raise LeafImportError(
                    LeafImportErrorCode.INVALID_CERTIFICATE,
                    f"{label.capitalize()} input must contain exactly one certificate",
                )
            return certificates[0]
        return x509.load_der_x509_certificate(payload)
    except LeafImportError:
        raise
    except ValueError as exc:
        raise LeafImportError(
            LeafImportErrorCode.INVALID_CERTIFICATE,
            f"{label.capitalize()} is not a valid X.509 certificate",
        ) from exc


def _deduplicate_certificates(
    certificates: tuple[x509.Certificate, ...],
) -> tuple[x509.Certificate, ...]:
    result: list[x509.Certificate] = []
    seen: set[bytes] = set()
    for certificate in certificates:
        der = _certificate_der(certificate)
        if der not in seen:
            seen.add(der)
            result.append(certificate)
    return tuple(result)


def _is_ca(certificate: x509.Certificate) -> bool:
    extension = _extension(certificate, x509.BasicConstraints)
    # RFC 5280 treats an absent BasicConstraints extension as a non-CA cert.
    return bool(extension and extension.value.ca)


def _signed_by(certificate: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        verify_certificate_signature(certificate, issuer)
        return True
    except (InvalidSignature, TypeError, ValueError, UnsupportedAlgorithm):
        return False


def _extension(certificate: x509.Certificate, extension_type):
    try:
        return certificate.extensions.get_extension_for_class(extension_type)
    except x509.ExtensionNotFound:
        return None


def _san_signal(name: x509.GeneralName) -> SubjectAlternativeNameSignal:
    if isinstance(name, x509.DNSName):
        return SubjectAlternativeNameSignal("dns", name.value)
    if isinstance(name, x509.RFC822Name):
        return SubjectAlternativeNameSignal("email", name.value)
    if isinstance(name, x509.IPAddress):
        return SubjectAlternativeNameSignal("ip", str(name.value))
    if isinstance(name, x509.UniformResourceIdentifier):
        return SubjectAlternativeNameSignal("uri", name.value)
    if isinstance(name, x509.DirectoryName):
        return SubjectAlternativeNameSignal("directory_name", name.value.rfc4514_string())
    if isinstance(name, x509.RegisteredID):
        return SubjectAlternativeNameSignal("registered_id", name.value.dotted_string)
    if isinstance(name, x509.OtherName):
        return SubjectAlternativeNameSignal(
            "other_name",
            base64.b64encode(name.value).decode("ascii"),
            oid=name.type_id.dotted_string,
        )
    value = getattr(name, "value", name)
    return SubjectAlternativeNameSignal(type(name).__name__.lower(), str(value))


_EKU_NAMES = {
    ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string: "client_auth",
    ExtendedKeyUsageOID.SERVER_AUTH.dotted_string: "server_auth",
    ExtendedKeyUsageOID.EMAIL_PROTECTION.dotted_string: "email_protection",
    ExtendedKeyUsageOID.CODE_SIGNING.dotted_string: "code_signing",
    ExtendedKeyUsageOID.TIME_STAMPING.dotted_string: "time_stamping",
    ExtendedKeyUsageOID.OCSP_SIGNING.dotted_string: "ocsp_signing",
    ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE.dotted_string: "any_extended_key_usage",
}


def _require_export_key(bundle: ValidatedLeafBundle) -> CertificateIssuerPrivateKeyTypes:
    if bundle.private_key is None:
        raise LeafImportError(
            LeafImportErrorCode.MISSING_PRIVATE_KEY,
            "Certificate-only imports cannot be exported with a private key",
        )
    if not private_key_matches_certificate(bundle.private_key, bundle.certificate):
        raise LeafImportError(
            LeafImportErrorCode.KEY_MISMATCH,
            "Private key does not match the imported certificate",
        )
    return bundle.private_key


def _export_password(password: bytes | str) -> bytes:
    value = _password_bytes(password, empty_is_none=False)
    assert value is not None
    if len(value) < MIN_EXPORT_PASSWORD_LENGTH:
        raise LeafImportError(
            LeafImportErrorCode.WEAK_EXPORT_PASSWORD,
            f"Export password must contain at least {MIN_EXPORT_PASSWORD_LENGTH} bytes",
        )
    return value


def _identity_csr(
    private_key: CertificateIssuerPrivateKeyTypes,
    certificate: x509.Certificate,
) -> str:
    builder = x509.CertificateSigningRequestBuilder().subject_name(certificate.subject)
    san_extension = _extension(certificate, x509.SubjectAlternativeName)
    if san_extension is not None:
        builder = builder.add_extension(san_extension.value, critical=san_extension.critical)
    try:
        csr = builder.sign(private_key, hashes.SHA256())
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise LeafImportError(
            LeafImportErrorCode.CSR_FAILED,
            "Unable to build an identity CSR with this private key",
        ) from exc
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def _public_key_der(public_key) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _certificate_der(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.DER)


def _certificate_pem(certificate: x509.Certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode()


def _utc(value: datetime | None) -> datetime:
    current = value or datetime.now(timezone.utc)
    return (
        current.replace(tzinfo=timezone.utc)
        if current.tzinfo is None
        else current.astimezone(timezone.utc)
    )
