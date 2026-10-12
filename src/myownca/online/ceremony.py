from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable
from uuid import uuid4

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from myownca.ca_hsm.base import HSMBackend
from myownca.ca_main.crypto import (
    IssuerMaterial,
    build_sub_ca_csr,
    public_keys_equal,
    verify_certificate_signature,
)
from myownca.domain import CertificateProfile, PendingSubCARequest, SubCA
from myownca.storage.repositories import PKIRepository


class OnlineCeremonyService:
    def __init__(
        self,
        repository: PKIRepository,
        hsm: HSMBackend,
    ) -> None:
        self.repository = repository
        self.hsm = hsm

    def create_sub_ca_request(
        self,
        *,
        common_name: str,
        allowed_profiles: tuple[CertificateProfile, ...] = tuple(CertificateProfile),
        algorithm: str = "ecdsa-p384",
        existing_key_ref: str | None = None,
        prepared_key_ref: str | None = None,
        key_backend: str | None = None,
        token_label: str | None = None,
        pending_id: str | None = None,
        now: datetime | None = None,
    ) -> PendingSubCARequest:
        """Create and persist a pending PEM CSR."""

        if not allowed_profiles:
            raise ValueError("Sub-CA requests must allow at least one certificate profile")
        if len(set(allowed_profiles)) != len(allowed_profiles):
            raise ValueError("Sub-CA allowed profiles must not contain duplicates")
        current_time = _utc_now(now)
        pending_id = pending_id or str(uuid4())

        try:
            existing_pending = self.repository.get_pending_sub_ca(pending_id)
        except RuntimeError:
            existing_pending = None
        if existing_pending is not None:
            return existing_pending

        if prepared_key_ref:
            key_ref = prepared_key_ref
            self.hsm.public_key(key_ref)
        elif existing_key_ref:
            attach = getattr(self.hsm, "attach_key", None)
            if attach is None:
                # Local and PKCS#11 backends already identify keys by their
                # stable local reference; resolving the public key validates it.
                self.hsm.public_key(existing_key_ref)
                key_ref = existing_key_ref
            else:
                key_ref = attach(existing_key_ref, expected_algorithm=algorithm)
        else:
            label = f"subca-{pending_id.replace('-', '')}"
            key_ref = self.hsm.generate_key(label, algorithm)
        csr = build_sub_ca_csr(self.hsm, key_ref, common_name)
        pending = PendingSubCARequest(
            id=pending_id,
            key_ref=key_ref,
            csr_pem=csr.public_bytes(serialization.Encoding.PEM).decode(),
            subject=csr.subject.rfc4514_string(),
            created_at=current_time,
            allowed_profiles=allowed_profiles,
            key_backend=key_backend or _backend_name(self.hsm),
            token_label=token_label or _token_label(self.hsm),
        )
        self.repository.add_pending_sub_ca(pending)
        return pending

    def import_sub_ca_certificate(
        self,
        certificate_pem: str,
        *,
        root_certificate_pem: str,
        pending_id: str,
        activate: bool = True,
        now: datetime | None = None,
        backend: HSMBackend | None = None,
        backend_resolver: Callable[[PendingSubCARequest], HSMBackend] | None = None,
    ) -> SubCA:
        """Activate a signed certificate after binding it to a pending local CSR."""

        pending = self.repository.get_pending_sub_ca(pending_id)
        return self._activate_pending_sub_ca(
            pending,
            certificate_pem=certificate_pem,
            root_certificate_pem=root_certificate_pem,
            activate=activate,
            now=_utc_now(now),
            backend=backend,
            backend_resolver=backend_resolver,
        )

    def _activate_pending_sub_ca(
        self,
        pending: PendingSubCARequest,
        *,
        certificate_pem: str,
        root_certificate_pem: str,
        activate: bool,
        now: datetime,
        backend: HSMBackend | None,
        backend_resolver: Callable[[PendingSubCARequest], HSMBackend] | None,
    ) -> SubCA:
        root_certificate = x509.load_pem_x509_certificate(root_certificate_pem.encode())
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode())
        _validate_sub_ca_chain(certificate, root_certificate, now=now)
        pending_csr = x509.load_pem_x509_csr(pending.csr_pem.encode())
        if not pending_csr.is_signature_valid:
            raise ValueError("Stored pending Sub-CA CSR signature is invalid")
        if certificate.subject != pending_csr.subject:
            raise ValueError("Signed Sub-CA certificate subject does not match the pending CSR")
        if not public_keys_equal(certificate.public_key(), pending_csr.public_key()):
            raise ValueError("Signed Sub-CA certificate does not match the pending CSR key")
        stored_root_pem = self.repository.get_root_certificate_pem()
        if stored_root_pem:
            stored_root = x509.load_pem_x509_certificate(stored_root_pem.encode())
            if stored_root.public_bytes(serialization.Encoding.DER) != (
                root_certificate.public_bytes(serialization.Encoding.DER)
            ):
                raise ValueError("Uploaded root does not match the configured Root CA")
        verification_backend = backend or (
            backend_resolver(pending) if backend_resolver is not None else self.hsm
        )
        if not public_keys_equal(
            certificate.public_key(), verification_backend.public_key(pending.key_ref)
        ):
            raise ValueError("Signed sub-CA certificate does not match local pending key")
        sub_ca = SubCA(
            id=pending.id,
            certificate_pem=certificate_pem,
            key_ref=pending.key_ref,
            subject=certificate.subject.rfc4514_string(),
            created_at=now,
            allowed_profiles=pending.allowed_profiles,
            key_backend=pending.key_backend or _backend_name(verification_backend),
            token_label=pending.token_label or _token_label(verification_backend),
        )
        # Store the verified trust anchor, issuer and activation in one DB
        # transaction so a late persistence failure cannot leave half an issuer.
        self.repository.add_sub_ca(
            sub_ca,
            root_certificate_pem=root_certificate_pem,
            activate=activate,
            remove_pending_id=pending.id,
        )
        return sub_ca

    def import_existing_sub_ca(
        self,
        *,
        certificate_pem: str,
        root_certificate_pem: str,
        key_ref: str,
        allowed_profiles: tuple[CertificateProfile, ...] = tuple(CertificateProfile),
        activate: bool = True,
        sub_ca_id: str | None = None,
        now: datetime | None = None,
        backend: HSMBackend | None = None,
        key_backend: str | None = None,
        token_label: str | None = None,
    ) -> SubCA:
        """Register an existing issuer only after full chain and key validation.

        The caller has already attached, imported or restored ``key_ref`` on the
        active backend. No certificate import is allowed to replace an existing
        root trust anchor as a side effect.
        """
        if not allowed_profiles:
            raise ValueError("An imported Sub-CA must allow at least one profile")
        if len(set(allowed_profiles)) != len(allowed_profiles):
            raise ValueError("Sub-CA allowed profiles must not contain duplicates")
        try:
            certificate = x509.load_pem_x509_certificate(certificate_pem.encode())
            root = x509.load_pem_x509_certificate(root_certificate_pem.encode())
        except ValueError as exc:
            raise ValueError(f"Invalid Sub-CA or root certificate PEM: {exc}") from exc

        moment = _utc_now(now)
        _validate_sub_ca_chain(
            certificate,
            root,
            now=moment,
            allow_legacy_missing_path_length=True,
        )
        stored_root_pem = self.repository.get_root_certificate_pem()
        if stored_root_pem:
            stored_root = x509.load_pem_x509_certificate(stored_root_pem.encode())
            if stored_root.public_bytes(serialization.Encoding.DER) != root.public_bytes(
                serialization.Encoding.DER
            ):
                raise ValueError("Uploaded root does not match the configured Root CA")
        public_key = certificate.public_key()
        verification_backend = backend or self.hsm
        if not public_keys_equal(public_key, verification_backend.public_key(key_ref)):
            raise ValueError("Imported Sub-CA certificate does not match the selected key")

        sub_ca = SubCA(
            id=sub_ca_id or str(uuid4()),
            certificate_pem=certificate.public_bytes(serialization.Encoding.PEM).decode(),
            key_ref=key_ref,
            subject=certificate.subject.rfc4514_string(),
            created_at=moment,
            allowed_profiles=allowed_profiles,
            key_backend=key_backend or _backend_name(verification_backend),
            token_label=token_label or _token_label(verification_backend),
        )
        self.repository.add_sub_ca(
            sub_ca,
            root_certificate_pem=root.public_bytes(serialization.Encoding.PEM).decode(),
            activate=activate,
        )
        return sub_ca

    def issuer_material(self, sub_ca_id: str) -> IssuerMaterial:
        sub_ca = self.repository.get_sub_ca(sub_ca_id)
        certificate = x509.load_pem_x509_certificate(sub_ca.certificate_pem.encode())
        return IssuerMaterial(
            key_ref=sub_ca.key_ref,
            certificate=certificate,
            allowed_profiles=sub_ca.allowed_profiles,
        )

    def active_issuer_material(self) -> IssuerMaterial | None:
        active_sub_ca = self.repository.get_active_sub_ca()
        if active_sub_ca is None:
            return None
        certificate = x509.load_pem_x509_certificate(active_sub_ca.certificate_pem.encode())
        return IssuerMaterial(
            key_ref=active_sub_ca.key_ref,
            certificate=certificate,
            allowed_profiles=active_sub_ca.allowed_profiles,
        )

def _backend_name(backend: HSMBackend) -> str | None:
    active_backend_name = getattr(backend, "active_backend_name", None)
    if callable(active_backend_name):
        return str(active_backend_name())
    modules = {base.__module__ for base in type(backend).__mro__}
    for module_name, persisted_name in (
        ("myownca.ca_hsm.software", "software"),
        ("myownca.ca_hsm.pkcs11", "pkcs11"),
        ("myownca.ca_hsm.aws_kms", "aws_kms"),
        ("myownca.ca_hsm.azure_key_vault", "azure_key_vault"),
    ):
        if module_name in modules:
            return persisted_name
    return None


def _token_label(backend: HSMBackend) -> str | None:
    concrete_backend = getattr(backend, "backend", backend)
    value = getattr(concrete_backend, "_token_label", None)
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _validate_sub_ca_chain(
    certificate: x509.Certificate,
    root: x509.Certificate,
    *,
    now: datetime,
    allow_legacy_missing_path_length: bool = False,
) -> None:
    """Validate a Sub CA chain, with an explicit legacy exception for existing issuers."""

    if root.subject != root.issuer:
        raise ValueError("Root certificate must be self-issued")
    try:
        verify_certificate_signature(root, root)
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise ValueError("Root certificate self-signature is invalid") from exc
    if not (root.not_valid_before_utc <= now < root.not_valid_after_utc):
        raise ValueError("Root certificate is not currently valid")
    try:
        root_constraints = root.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("Root certificate is missing BasicConstraints") from exc
    if not root_constraints.ca:
        raise ValueError("Root certificate requires CA=true")
    try:
        root_usage = root.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("Root certificate is missing KeyUsage") from exc
    if not root_usage.key_cert_sign:
        raise ValueError("Root certificate requires keyCertSign")

    if certificate.issuer != root.subject:
        raise ValueError("Imported Sub-CA must be issued directly by the configured Root CA")
    try:
        verify_certificate_signature(certificate, root)
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise ValueError("Root certificate did not sign the imported Sub-CA") from exc
    if not (
        certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc
    ):
        raise ValueError("Imported Sub-CA certificate is not currently valid")
    if certificate.not_valid_before_utc < root.not_valid_before_utc:
        raise ValueError(
            f"Sub-CA validity starts at {certificate.not_valid_before_utc.isoformat()}, "
            f"before the Root CA validity starts at {root.not_valid_before_utc.isoformat()}. "
            "Obtain a corrected Root-signed Sub-CA certificate whose entire validity "
            "interval fits within the Root CA validity."
        )
    if certificate.not_valid_after_utc > root.not_valid_after_utc:
        raise ValueError(
            f"Sub-CA expires at {certificate.not_valid_after_utc.isoformat()}, "
            f"after the Root CA expires at {root.not_valid_after_utc.isoformat()}. "
            "Obtain a corrected Root-signed Sub-CA certificate whose entire validity "
            "interval fits within the Root CA validity."
        )
    try:
        constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("Imported Sub-CA is missing BasicConstraints") from exc
    if not constraints.ca or (
        constraints.path_length != 0
        and not (allow_legacy_missing_path_length and constraints.path_length is None)
    ):
        raise ValueError("Imported Sub-CA requires CA=true and pathLength=0")
    try:
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("Imported Sub-CA is missing KeyUsage") from exc
    if not usage.key_cert_sign or not usage.crl_sign:
        raise ValueError("Imported Sub-CA requires keyCertSign and cRLSign")

    public_key = certificate.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size < 2048:
            raise ValueError("Imported Sub-CA RSA key must be at least 2048 bits")
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        if public_key.key_size < 256:
            raise ValueError("Imported Sub-CA EC key must be at least 256 bits")
    else:
        raise ValueError("Imported Sub-CA must use a supported RSA or EC key")


def _utc_now(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        return current.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc)
