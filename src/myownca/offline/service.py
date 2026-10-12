from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4

from cryptography import x509

from myownca.ca_hsm.base import HSMBackend
from myownca.ca_main.crypto import (
    IssuerMaterial,
    build_crl,
    build_sub_ca_certificate,
    certificate_to_pem,
    create_root_ca,
    crl_to_pem,
)
from myownca.domain import (
    CertificateProfile,
    OfflineCeremonyRecord,
    OfflineRootAuthority,
    RootCRL,
    SubCA,
)
from myownca.offline.state import OfflineStateRepository


@dataclass(frozen=True, slots=True)
class RootBootstrapArtifacts:
    root_certificate_pem: str
    initial_root_crl: RootCRL


class OfflineRootService:
    def __init__(self, state: OfflineStateRepository, hsm: HSMBackend) -> None:
        self.state = state
        self.hsm = hsm
        self.state.migrate()

    def create_root(
        self,
        common_name: str,
        *,
        algorithm: str = "ecdsa-p384",
        validity_years: int = 20,
        operator_ids: tuple[str, ...] = (),
        now: datetime | None = None,
    ) -> RootBootstrapArtifacts:
        current_time = _utc_now(now)
        root_ca = create_root_ca(
            self.hsm,
            common_name,
            algorithm=algorithm,
            validity_years=validity_years,
            now=current_time,
        )
        root = OfflineRootAuthority(
            certificate_pem=root_ca.certificate_pem,
            key_ref=root_ca.material.key_ref,
            subject=root_ca.material.certificate.subject.rfc4514_string(),
            created_at=current_time,
        )
        self.state.add_root(root)
        self._record(
            "root_create",
            operator_ids,
            current_time,
            {"subject": root.subject},
        )
        initial_crl = self.sign_root_crl(operator_ids=operator_ids, now=current_time)
        return RootBootstrapArtifacts(
            root_certificate_pem=root_ca.certificate_pem,
            initial_root_crl=initial_crl,
        )

    def sign_sub_ca_csr(
        self,
        csr_pem: str,
        *,
        validity_days: int = 365 * 6,
        permitted_dns_suffixes: tuple[str, ...] = (),
        allowed_profiles: tuple[CertificateProfile, ...] = tuple(CertificateProfile),
        operator_ids: tuple[str, ...] = (),
        now: datetime | None = None,
    ) -> SubCA:
        current_time = _utc_now(now)
        if not allowed_profiles:
            raise ValueError("Sub-CA requests must allow at least one certificate profile")
        if len(set(allowed_profiles)) != len(allowed_profiles):
            raise ValueError("Sub-CA allowed profiles must not contain duplicates")
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        certificate = build_sub_ca_certificate(
            csr,
            self._root_material(),
            self.hsm,
            validity_days=validity_days,
            permitted_dns_suffixes=permitted_dns_suffixes,
            now=current_time,
        )
        certificate_pem = certificate_to_pem(certificate)
        sub_ca = SubCA(
            id=str(uuid4()),
            certificate_pem=certificate_pem,
            key_ref="external",
            subject=certificate.subject.rfc4514_string(),
            created_at=current_time,
            allowed_profiles=allowed_profiles,
        )
        self.state.add_sub_ca(sub_ca)
        self._record(
            "sub_ca_sign",
            operator_ids,
            current_time,
            {
                "sub_ca_id": sub_ca.id,
                "subject": sub_ca.subject,
                "allowed_profiles": [profile.value for profile in allowed_profiles],
            },
        )
        return sub_ca

    def sign_root_crl(
        self,
        *,
        operator_ids: tuple[str, ...] = (),
        now: datetime | None = None,
    ) -> RootCRL:
        current_time = _utc_now(now)
        number = self.state.next_root_crl_number()
        crl = build_crl(
            issuer=self._root_material(),
            revocations=self.state.list_root_revocations(),
            crl_number=number,
            hsm=self.hsm,
            now=current_time,
            validity_days=365,
        )
        root_crl = RootCRL(number=number, crl_pem=crl_to_pem(crl), generated_at=current_time)
        self.state.add_root_crl(root_crl)
        self._record(
            "root_crl_sign",
            operator_ids,
            current_time,
            {"root_crl_number": root_crl.number},
        )
        return root_crl

    def _root_material(self) -> IssuerMaterial:
        root = self.state.get_root()
        certificate = x509.load_pem_x509_certificate(root.certificate_pem.encode())
        return IssuerMaterial(key_ref=root.key_ref, certificate=certificate)

    def _record(
        self,
        operation_type: str,
        operator_ids: tuple[str, ...],
        occurred_at: datetime,
        details: dict[str, object],
    ) -> None:
        self.state.add_ceremony_record(
            OfflineCeremonyRecord(
                id=str(uuid4()),
                operation_type=operation_type,
                occurred_at=occurred_at,
                operator_ids=operator_ids,
            ),
            details,
        )

def _utc_now(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        return current.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc)
