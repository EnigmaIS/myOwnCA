from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from myownca_core.keygen import KeygenError, certificate_algorithm_for_public_key
from myownca_core.leaf import (
    CSRValidationError,
    LeafProfile,
    build_leaf,
    validate_leaf_csr,
    validate_leaf_validity,
)

from myownca.ca_hsm.base import HSMBackend
from myownca.domain import (
    CertificateProfile,
    CertificateTemplate,
    ExtendedKeyUsageName,
    KeyUsageName,
    Revocation,
    RevocationReason,
)


@dataclass(frozen=True, slots=True)
class IssuerMaterial:
    key_ref: str
    certificate: x509.Certificate
    allowed_profiles: tuple[CertificateProfile, ...] | None = None


@dataclass(frozen=True, slots=True)
class LabCAChain:
    root: IssuerMaterial
    issuer: IssuerMaterial


@dataclass(frozen=True, slots=True)
class RootCA:
    material: IssuerMaterial
    certificate_pem: str


_MIN_RSA_BITS = 2048
_MIN_EC_BITS = 256


def _require_strong_key(public_key) -> None:
    """Refuse to certify a trivially-weak or deprecated subject key.

    A CA accepts only the explicit certificate algorithm catalogue. Raises
    CSRValidationError (a ValueError) on a disallowed key.
    """
    try:
        certificate_algorithm_for_public_key(public_key)
    except KeygenError as exc:
        raise CSRValidationError(str(exc)) from exc


def parse_csr(csr_pem: str | bytes) -> x509.CertificateSigningRequest:
    payload = csr_pem.encode() if isinstance(csr_pem, str) else csr_pem
    csr = x509.load_pem_x509_csr(payload)
    if not csr.is_signature_valid:
        raise CSRValidationError("CSR signature is invalid")
    return csr


def validate_end_entity_csr(
    csr: x509.CertificateSigningRequest,
    template: CertificateTemplate,
) -> None:
    """Validate request content that does not depend on a particular issuer."""
    _require_strong_key(csr.public_key())
    if certificate_algorithm_for_public_key(csr.public_key()) not in template.allowed_key_algorithms:
        raise CSRValidationError("Subject key algorithm is not allowed by the certificate template")
    validate_leaf_csr(csr, _template_to_leaf_profile(template))


def build_end_entity_certificate(
    csr: x509.CertificateSigningRequest,
    template: CertificateTemplate,
    issuer: IssuerMaterial,
    hsm: HSMBackend,
    now: datetime | None = None,
    crl_url: str | None = None,
    ocsp_url: str | None = None,
    ca_issuers_url: str | None = None,
) -> x509.Certificate:
    validate_end_entity_csr(csr, template)
    return build_leaf(
        csr,
        _template_to_leaf_profile(template),
        issuer_certificate=issuer.certificate,
        issuer_key_ref=issuer.key_ref,
        signer=hsm,
        now=now,
        crl_url=crl_url,
        ocsp_url=ocsp_url,
        ca_issuers_url=ca_issuers_url,
    )


def validate_end_entity_validity(
    template: CertificateTemplate,
    issuer: IssuerMaterial,
    now: datetime | None = None,
) -> tuple[datetime, datetime]:
    return validate_leaf_validity(_template_to_leaf_profile(template), issuer.certificate, now=now)


def _template_to_leaf_profile(template: CertificateTemplate) -> LeafProfile:
    required, allowed = _san_rules_for_profile(template.profile)
    return LeafProfile(
        validity_days=template.validity_days,
        key_usage=_key_usage_for(template),
        extended_key_usages=tuple(_eku_for(template)),
        key_usage_critical=template.key_usage_critical,
        eku_critical=template.extended_key_usage_critical,
        required_san_types=required,
        allowed_san_types=allowed,
    )


def _san_rules_for_profile(
    profile: CertificateProfile,
) -> tuple[tuple[type, ...], tuple[type, ...] | None]:
    if profile is CertificateProfile.HOST_TLS:
        return (x509.DNSName,), (x509.DNSName, x509.IPAddress)
    if profile is CertificateProfile.SMIME:
        return (x509.RFC822Name,), (x509.RFC822Name,)
    if profile is CertificateProfile.USER_AUTH:
        return (), (x509.RFC822Name, x509.DNSName)
    return (), None


def build_crl(
    issuer: IssuerMaterial,
    revocations: list[Revocation],
    crl_number: int,
    hsm: HSMBackend,
    now: datetime | None = None,
    validity_days: int = 7,
) -> x509.CertificateRevocationList:
    current_time = _utc_now(now)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer.certificate.subject)
        .last_update(current_time)
        .next_update(current_time + timedelta(days=validity_days))
        .add_extension(x509.CRLNumber(crl_number), critical=False)
    )
    for revocation in revocations:
        revoked_builder = (
            x509.RevokedCertificateBuilder()
            .serial_number(int(revocation.serial_number, 16))
            .revocation_date(_utc_now(revocation.revoked_at))
            .add_extension(x509.CRLReason(_reason_flag(revocation.reason)), critical=False)
        )
        if revocation.invalidity_date is not None:
            revoked_builder = revoked_builder.add_extension(
                x509.InvalidityDate(_utc_now(revocation.invalidity_date)),
                critical=False,
            )
        builder = builder.add_revoked_certificate(revoked_builder.build())
    return hsm.sign_crl(builder, issuer.key_ref)


def create_root_ca(
    hsm: HSMBackend,
    common_name: str,
    *,
    key_ref: str = "root-ca",
    algorithm: str = "ecdsa-p384",
    validity_years: int = 20,
    now: datetime | None = None,
) -> RootCA:
    current_time = _utc_now(now)
    root_key_ref = hsm.generate_key(key_ref, algorithm)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(hsm.public_key(root_key_ref))
        .serial_number(generate_serial_number())
        .not_valid_before(current_time - timedelta(minutes=5))
        .not_valid_after(current_time + timedelta(days=365 * validity_years))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(_ca_key_usage(), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(hsm.public_key(root_key_ref)),
            critical=False,
        )
    )
    certificate = hsm.sign_certificate(builder, root_key_ref)
    return RootCA(
        material=IssuerMaterial(key_ref=root_key_ref, certificate=certificate),
        certificate_pem=certificate_to_pem(certificate),
    )


def build_sub_ca_csr(
    hsm: HSMBackend,
    key_ref: str,
    common_name: str,
) -> x509.CertificateSigningRequest:
    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_ca_key_usage(), critical=True)
    )
    return hsm.sign_csr(builder, key_ref)


def build_sub_ca_certificate(
    csr: x509.CertificateSigningRequest,
    root: IssuerMaterial,
    hsm: HSMBackend,
    *,
    validity_days: int = 365 * 6,
    permitted_dns_suffixes: tuple[str, ...] = (),
    now: datetime | None = None,
) -> x509.Certificate:
    if not csr.is_signature_valid:
        raise CSRValidationError("Sub-CA CSR signature is invalid")
    if not csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        raise CSRValidationError("Sub-CA CSR subject must include a common name")
    _require_strong_key(csr.public_key())
    current_time = _utc_now(now)
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(root.certificate.subject)
        .public_key(csr.public_key())
        .serial_number(generate_serial_number())
        .not_valid_before(current_time - timedelta(minutes=5))
        .not_valid_after(current_time + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_ca_key_usage(), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root.certificate.public_key()),
            critical=False,
        )
    )
    if permitted_dns_suffixes:
        builder = builder.add_extension(
            x509.NameConstraints(
                permitted_subtrees=[x509.DNSName(suffix) for suffix in permitted_dns_suffixes],
                excluded_subtrees=None,
            ),
            critical=True,
        )
    return hsm.sign_certificate(builder, root.key_ref)


def public_key_to_pem(public_key) -> str:
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def public_keys_equal(left, right) -> bool:
    return public_key_to_pem(left) == public_key_to_pem(right)


def verify_certificate_signature(
    certificate: x509.Certificate,
    issuer_certificate: x509.Certificate,
) -> None:
    public_key = issuer_certificate.public_key()
    signature_hash_algorithm = certificate.signature_hash_algorithm
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            certificate.signature_algorithm_parameters,
            signature_hash_algorithm,
        )
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            certificate.signature_algorithm_parameters,
        )
    else:  # pragma: no cover - supported issuers are constrained above
        raise ValueError("Unsupported issuer public key type")


def create_lab_ca_chain(
    hsm: HSMBackend,
    common_name: str = "myOwnCA Lab Issuing CA",
    now: datetime | None = None,
    *,
    root_key_ref: str = "lab-root",
    issuer_key_ref: str = "lab-issuer",
) -> LabCAChain:
    current_time = _utc_now(now)
    hsm.generate_key(root_key_ref, "ecdsa-p256")
    root_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "myOwnCA Lab Root CA")])
    root_builder = (
        x509.CertificateBuilder()
        .subject_name(root_subject)
        .issuer_name(root_subject)
        .public_key(hsm.public_key(root_key_ref))
        .serial_number(generate_serial_number())
        .not_valid_before(current_time - timedelta(minutes=5))
        .not_valid_after(current_time + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(_ca_key_usage(), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(hsm.public_key(root_key_ref)),
            critical=False,
        )
    )
    root_certificate = hsm.sign_certificate(root_builder, root_key_ref)

    hsm.generate_key(issuer_key_ref, "ecdsa-p256")
    issuer_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer_builder = (
        x509.CertificateBuilder()
        .subject_name(issuer_subject)
        .issuer_name(root_certificate.subject)
        .public_key(hsm.public_key(issuer_key_ref))
        .serial_number(generate_serial_number())
        .not_valid_before(current_time - timedelta(minutes=5))
        .not_valid_after(current_time + timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_ca_key_usage(), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(hsm.public_key(issuer_key_ref)),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_certificate.public_key()),
            critical=False,
        )
    )
    issuer_certificate = hsm.sign_certificate(issuer_builder, root_key_ref)
    return LabCAChain(
        root=IssuerMaterial(key_ref=root_key_ref, certificate=root_certificate),
        issuer=IssuerMaterial(key_ref=issuer_key_ref, certificate=issuer_certificate),
    )


def create_lab_ca_chain_from_existing_keys(
    hsm: HSMBackend,
    common_name: str = "myOwnCA Lab Issuing CA",
    now: datetime | None = None,
    *,
    root_key_ref: str = "lab-root",
    issuer_key_ref: str = "lab-issuer",
) -> LabCAChain:
    current_time = _utc_now(now)
    root_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "myOwnCA Lab Root CA")])
    root_builder = (
        x509.CertificateBuilder()
        .subject_name(root_subject)
        .issuer_name(root_subject)
        .public_key(hsm.public_key(root_key_ref))
        .serial_number(generate_serial_number())
        .not_valid_before(current_time - timedelta(minutes=5))
        .not_valid_after(current_time + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(_ca_key_usage(), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(hsm.public_key(root_key_ref)),
            critical=False,
        )
    )
    root_certificate = hsm.sign_certificate(root_builder, root_key_ref)

    issuer_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer_builder = (
        x509.CertificateBuilder()
        .subject_name(issuer_subject)
        .issuer_name(root_certificate.subject)
        .public_key(hsm.public_key(issuer_key_ref))
        .serial_number(generate_serial_number())
        .not_valid_before(current_time - timedelta(minutes=5))
        .not_valid_after(current_time + timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_ca_key_usage(), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(hsm.public_key(issuer_key_ref)),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_certificate.public_key()),
            critical=False,
        )
    )
    issuer_certificate = hsm.sign_certificate(issuer_builder, root_key_ref)
    return LabCAChain(
        root=IssuerMaterial(key_ref=root_key_ref, certificate=root_certificate),
        issuer=IssuerMaterial(key_ref=issuer_key_ref, certificate=issuer_certificate),
    )


def generate_serial_number() -> int:
    return x509.random_serial_number()


def certificate_to_pem(certificate: x509.Certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode()


def crl_to_pem(crl: x509.CertificateRevocationList) -> str:
    return crl.public_bytes(serialization.Encoding.PEM).decode()


def crl_pem_to_der(crl_pem: str) -> bytes:
    """Convert a PEM-encoded CRL to DER (the form HTTP clients fetch)."""
    return x509.load_pem_x509_crl(crl_pem.encode()).public_bytes(serialization.Encoding.DER)


def cert_pem_to_der(cert_pem: str) -> bytes:
    """Convert a PEM-encoded certificate to DER (the form AIA/HTTP clients fetch)."""
    return x509.load_pem_x509_certificate(cert_pem.encode()).public_bytes(serialization.Encoding.DER)


def _key_usage_for(template: CertificateTemplate) -> x509.KeyUsage:
    usages = set(template.key_usages)
    key_agreement = KeyUsageName.KEY_AGREEMENT in usages
    return x509.KeyUsage(
        digital_signature=KeyUsageName.DIGITAL_SIGNATURE in usages,
        content_commitment=KeyUsageName.CONTENT_COMMITMENT in usages,
        key_encipherment=KeyUsageName.KEY_ENCIPHERMENT in usages,
        data_encipherment=KeyUsageName.DATA_ENCIPHERMENT in usages,
        key_agreement=key_agreement,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=KeyUsageName.ENCIPHER_ONLY in usages if key_agreement else None,
        decipher_only=KeyUsageName.DECIPHER_ONLY in usages if key_agreement else None,
    )


def _ca_key_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=None,
        decipher_only=None,
    )


def _eku_for(template: CertificateTemplate) -> x509.ExtendedKeyUsage:
    oid_by_usage = {
        ExtendedKeyUsageName.CLIENT_AUTH: ExtendedKeyUsageOID.CLIENT_AUTH,
        ExtendedKeyUsageName.SERVER_AUTH: ExtendedKeyUsageOID.SERVER_AUTH,
        ExtendedKeyUsageName.EMAIL_PROTECTION: ExtendedKeyUsageOID.EMAIL_PROTECTION,
    }
    return x509.ExtendedKeyUsage([oid_by_usage[usage] for usage in template.extended_key_usages])


def _signature_algorithm(private_key):
    return hashes.SHA256()


def _reason_flag(reason: RevocationReason) -> x509.ReasonFlags:
    mapping = {
        RevocationReason.UNSPECIFIED: x509.ReasonFlags.unspecified,
        RevocationReason.KEY_COMPROMISE: x509.ReasonFlags.key_compromise,
        RevocationReason.CA_COMPROMISE: x509.ReasonFlags.ca_compromise,
        RevocationReason.AFFILIATION_CHANGED: x509.ReasonFlags.affiliation_changed,
        RevocationReason.SUPERSEDED: x509.ReasonFlags.superseded,
        RevocationReason.CESSATION_OF_OPERATION: x509.ReasonFlags.cessation_of_operation,
        RevocationReason.CERTIFICATE_HOLD: x509.ReasonFlags.certificate_hold,
        RevocationReason.PRIVILEGE_WITHDRAWN: x509.ReasonFlags.privilege_withdrawn,
        RevocationReason.AA_COMPROMISE: x509.ReasonFlags.aa_compromise,
    }
    return mapping[reason]


def _utc_now(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        return current.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc)
