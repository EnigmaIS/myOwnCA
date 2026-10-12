from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Protocol
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from myownca_core.leaf import validate_signed_leaf_validity

from myownca.ca_hsm.base import HSMBackend
from myownca.ca_main.crypto import (
    IssuerMaterial,
    build_crl,
    build_end_entity_certificate,
    certificate_to_pem,
    crl_to_pem,
    parse_csr,
    validate_end_entity_csr,
)
from myownca.ca_main.policy import assert_request_is_approved
from myownca.ca_main.identity import assert_same_certificate_identity
from myownca.domain import (
    ApprovalRecord,
    CertificateRequest,
    CertificateSource,
    CertificateStatus,
    IssuedCertificate,
    IssuerCRL,
    RequestKind,
    RequestSource,
    RequestStatus,
    Revocation,
    RevocationReason,
    Role,
)
from myownca.storage.repositories import PKIRepository, RepositoryError

logger = logging.getLogger(__name__)


class IssuancePolicy(Protocol):
    def authorize_issuance(self, request: CertificateRequest, now: datetime | None = None): ...
    def release_issuance(self, authorization) -> None: ...


class CAMainService:
    def __init__(
        self,
        repository: PKIRepository,
        hsm: HSMBackend,
        crl_url_resolver: Callable[[IssuerMaterial], str | None] | None = None,
        aia_resolver: Callable[[IssuerMaterial], tuple[str | None, str | None]] | None = None,
        cert_change_listener: Callable[[str], None] | None = None,
        crl_change_listener: Callable[[str], None] | None = None,
        issuance_policy: IssuancePolicy | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.repository = repository
        self.hsm = hsm
        # Optional: resolves the CRL distribution URL to embed in issued leaves.
        # None (the default) means no CRLDistributionPoints extension is added.
        self.crl_url_resolver = crl_url_resolver
        # Optional: resolves (ocsp_url, ca_issuers_url) to embed as AIA in issued leaves.
        # None (the default) means no AuthorityInformationAccess extension is added.
        self.aia_resolver = aia_resolver
        # Invoked (best-effort) with a serial after a cert is issued or revoked,
        # so dependents (e.g. the OCSP responder) can refresh that serial.
        self.cert_change_listener = cert_change_listener
        # The durable CRL job is written by the repository in the same
        # transaction as revocation. This callback only wakes the local worker.
        self.crl_change_listener = crl_change_listener
        self.issuance_policy = issuance_policy
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def _notify_cert_change(self, serial_number: str) -> None:
        if self.cert_change_listener is None:
            return
        try:
            self.cert_change_listener(serial_number)
        except Exception:  # noqa: BLE001 - a listener must never break issuance/revocation
            logger.warning("cert_change_listener failed for serial %s", serial_number, exc_info=True)

    def _notify_crl_change(self, issuer_id: str | None) -> None:
        if issuer_id is None or self.crl_change_listener is None:
            return
        try:
            self.crl_change_listener(issuer_id)
        except Exception:  # noqa: BLE001 - durable DB work must survive a missed wakeup
            logger.warning("crl_change_listener failed for issuer %s", issuer_id, exc_info=True)

    def submit_request(
        self,
        template_id: str,
        csr_pem: str,
        kind: RequestKind = RequestKind.FIRST_ISSUANCE,
        requested_by_user_id: str | None = None,
        renewal_of_serial_number: str | None = None,
        renewal_of_certificate_id: str | None = None,
        request_id: str | None = None,
        now: datetime | None = None,
        via_link_auth: str | None = None,
        source: RequestSource = RequestSource.REQUEST,
    ) -> CertificateRequest:
        template = self.repository.get_template(template_id)
        csr = parse_csr(csr_pem)
        validate_end_entity_csr(csr, template)
        renewal_of_serial_number = renewal_of_serial_number or None
        renewal_of_certificate_id = renewal_of_certificate_id or None
        lineage_id = None
        if kind is RequestKind.RENEWAL:
            anchor = self._assert_valid_renewal_anchor(
                template_id=template.id,
                renewal_of_serial_number=renewal_of_serial_number,
                renewal_of_certificate_id=renewal_of_certificate_id,
                requested_by_user_id=requested_by_user_id,
            )
            assert_same_certificate_identity(
                x509.load_pem_x509_certificate(anchor.certificate_pem.encode()), csr
            )
            lineage_id = anchor.lineage_id
            renewal_of_serial_number = anchor.serial_number
            renewal_of_certificate_id = anchor.certificate_id
        elif renewal_of_serial_number is not None or renewal_of_certificate_id is not None:
            raise ValueError("First-issuance requests may not reference an existing certificate")
        request = CertificateRequest(
            id=request_id or str(uuid4()),
            template_id=template.id,
            csr_pem=csr_pem,
            kind=kind,
            status=RequestStatus.PENDING,
            created_at=_utc_now(now),
            requested_by_user_id=requested_by_user_id,
            renewal_of_serial_number=renewal_of_serial_number,
            renewal_of_certificate_id=renewal_of_certificate_id,
            lineage_id=lineage_id,
            via_link_auth=via_link_auth,
            source=source,
        )
        self.repository.add_request(request)
        return request

    def approve_request(
        self,
        request_id: str,
        superuser_id: str,
        now: datetime | None = None,
    ) -> ApprovalRecord:
        request = self.repository.get_request(request_id)
        if request.status is not RequestStatus.PENDING:
            raise RepositoryError("Only pending requests may be approved")
        user = self.repository.get_user(superuser_id)
        if user.role is not Role.SUPERUSER:
            raise RepositoryError(
                "Only Certificate Operators may approve certificate requests"
            )
        approval = ApprovalRecord(
            request_id=request_id,
            superuser_id=superuser_id,
            approved_at=_utc_now(now),
        )
        self.repository.add_approval(approval)
        return approval

    def assign_request_holder(
        self,
        request_id: str,
        *,
        person_id: str | None = None,
        device_id: str | None = None,
    ) -> CertificateRequest:
        """Bind a pending request to exactly one holder (a person or a device)."""
        request = self.repository.get_request(request_id)
        if request.status is not RequestStatus.PENDING:
            raise RepositoryError("Only pending requests may have their holder changed")
        person_id = person_id or None
        device_id = device_id or None
        if (person_id is None) == (device_id is None):
            raise ValueError("Assign exactly one holder: a person or a device")
        if person_id is not None:
            self.repository.get_person(person_id)  # existence check
        else:
            self.repository.get_device(device_id)  # existence check
        if request.kind is RequestKind.RENEWAL:
            anchor = (
                self.repository.get_certificate_by_id(request.renewal_of_certificate_id)
                if request.renewal_of_certificate_id
                else self.repository.get_issued_certificate(request.renewal_of_serial_number)
            )
            if (person_id, device_id) != (
                anchor.holder_person_id,
                anchor.holder_device_id,
            ):
                raise ValueError("Renewals must retain the existing certificate holder")
        self.repository.set_request_holder(
            request_id,
            holder_person_id=person_id,
            holder_device_id=device_id,
        )
        return self.repository.get_request(request_id)

    def reject_request(self, request_id: str) -> CertificateRequest:
        request = self.repository.get_request(request_id)
        if request.status is not RequestStatus.PENDING:
            raise RepositoryError("Only pending requests may be rejected")
        self.repository.set_request_status(request.id, RequestStatus.REJECTED)
        return self.repository.get_request(request.id)

    def issue_certificate(
        self,
        request_id: str,
        issuer: IssuerMaterial,
        now: datetime | None = None,
    ) -> IssuedCertificate:
        moment = _utc_now(now if now is not None else self.clock())
        request = self.repository.get_request(request_id)
        if request.status is not RequestStatus.PENDING:
            raise RepositoryError("Only pending requests may be issued")
        template = self.repository.get_template(request.template_id)
        if request.kind is RequestKind.RENEWAL:
            anchor = self._assert_valid_renewal_anchor(
                template_id=template.id,
                renewal_of_serial_number=request.renewal_of_serial_number,
                renewal_of_certificate_id=request.renewal_of_certificate_id,
                requested_by_user_id=request.requested_by_user_id,
            )
            assert_same_certificate_identity(
                x509.load_pem_x509_certificate(anchor.certificate_pem.encode()),
                parse_csr(request.csr_pem),
            )
            if (request.holder_person_id, request.holder_device_id) != (
                anchor.holder_person_id,
                anchor.holder_device_id,
            ):
                raise RepositoryError("Renewals must retain the existing certificate holder")
        if issuer.allowed_profiles is not None and template.profile not in issuer.allowed_profiles:
            raise RepositoryError(
                f"Issuer is not allowed to issue {template.profile.value} certificates"
            )
        approvals = self.repository.list_approvals(request_id)
        assert_request_is_approved(request, template, approvals)
        if (request.holder_person_id is None) == (request.holder_device_id is None):
            raise RepositoryError(
                "A certificate holder (person or device) must be assigned before issuance"
            )
        authorization = None
        try:
            if self.issuance_policy is not None:
                authorization = self.issuance_policy.authorize_issuance(
                    request, moment
                )
            lineage_id = (
                authorization.lineage_id if authorization is not None else request.lineage_id
            )
            csr = parse_csr(request.csr_pem)
            validate_end_entity_csr(csr, template)
            crl_url = self.crl_url_resolver(issuer) if self.crl_url_resolver is not None else None
            ocsp_url, ca_issuers_url = (
                self.aia_resolver(issuer) if self.aia_resolver is not None else (None, None)
            )
            certificate = build_end_entity_certificate(
                csr=csr,
                template=template,
                issuer=issuer,
                hsm=self.hsm,
                now=moment,
                crl_url=crl_url,
                ocsp_url=ocsp_url,
                ca_issuers_url=ca_issuers_url,
            )
            # Signing may outlast issuer validity, especially with cloud providers.
            # An explicit `now` remains a frozen clock for deterministic callers.
            validate_signed_leaf_validity(
                certificate,
                issuer.certificate,
                now=now if now is not None else self.clock(),
            )
            issued = IssuedCertificate(
                serial_number=format(certificate.serial_number, "x"),
                request_id=request.id,
                template_id=template.id,
                certificate_pem=certificate_to_pem(certificate),
                subject=certificate.subject.rfc4514_string(),
                issued_at=certificate.not_valid_before_utc,
                expires_at=certificate.not_valid_after_utc,
                status=CertificateStatus.ACTIVE,
                holder_person_id=request.holder_person_id,
                holder_device_id=request.holder_device_id,
                lineage_id=lineage_id,
                certificate_id=str(uuid4()),
                source=CertificateSource.ISSUED,
                issuer_id=issuer.certificate.fingerprint(hashes.SHA256()).hex(),
            )
            self.repository.finalize_issued_certificate(
                issued,
                reservation_request_id=(
                    authorization.reservation_request_id
                    if authorization is not None
                    else None
                ),
                supersede_serial_number=(
                    request.renewal_of_serial_number
                    if request.kind is RequestKind.RENEWAL
                    else None
                ),
                supersede_certificate_id=(
                    request.renewal_of_certificate_id
                    if request.kind is RequestKind.RENEWAL
                    else None
                ),
                superseded_at=(moment if request.kind is RequestKind.RENEWAL else None),
            )
        except Exception:
            if self.issuance_policy is not None and authorization is not None:
                self.issuance_policy.release_issuance(authorization)
            raise
        self._notify_cert_change(issued.serial_number)
        if request.kind is RequestKind.RENEWAL and request.renewal_of_serial_number:
            self._notify_cert_change(request.renewal_of_serial_number)
            self._notify_crl_change(issued.issuer_id)
        return issued

    def revoke_certificate(
        self,
        serial_number: str,
        reason: RevocationReason = RevocationReason.UNSPECIFIED,
        now: datetime | None = None,
    ) -> Revocation:
        certificate = self.repository.get_issued_certificate(serial_number)
        return self.revoke_certificate_by_id(
            certificate.certificate_id, reason=reason, now=now
        )

    def revoke_certificate_by_id(
        self,
        certificate_id: str,
        reason: RevocationReason = RevocationReason.UNSPECIFIED,
        now: datetime | None = None,
    ) -> Revocation:
        certificate = self.repository.get_certificate_by_id(certificate_id)
        if certificate.status is CertificateStatus.REVOKED:
            raise RepositoryError("Certificate is already revoked")
        revocation = Revocation(
            serial_number=certificate.serial_number,
            reason=reason,
            revoked_at=_utc_now(now),
            certificate_id=certificate.certificate_id,
        )
        self.repository.add_revocation(revocation)
        self._notify_cert_change(revocation.serial_number)
        self._notify_crl_change(certificate.issuer_id)
        return revocation

    def generate_crl(
        self,
        issuer: IssuerMaterial,
        now: datetime | None = None,
        *,
        crl_number: int | None = None,
    ) -> IssuerCRL:
        issuer_subject = issuer.certificate.subject.rfc4514_string()
        issuer_id = issuer.certificate.fingerprint(hashes.SHA256()).hex()
        number = crl_number or self.repository.next_issuer_crl_number(
            issuer_subject, issuer_id
        )
        current_time = _utc_now(now)
        issuer_revocations = self.repository.list_issuer_revocations(issuer_id)
        crl = build_crl(
            issuer=issuer,
            revocations=issuer_revocations,
            crl_number=number,
            hsm=self.hsm,
            now=current_time,
        )
        issuer_crl = IssuerCRL(
            issuer_subject=issuer_subject,
            number=number,
            crl_pem=crl_to_pem(crl),
            generated_at=current_time,
            issuer_id=issuer_id,
            this_update=current_time,
            next_update=current_time + timedelta(days=7),
            source="local",
            sha256=hashlib.sha256(
                crl.public_bytes(serialization.Encoding.DER)
            ).hexdigest(),
        )
        self.repository.add_issuer_crl(issuer_crl)
        return issuer_crl

    def _assert_valid_renewal_anchor(
        self,
        *,
        template_id: str,
        renewal_of_serial_number: str | None,
        renewal_of_certificate_id: str | None,
        requested_by_user_id: str | None,
    ) -> IssuedCertificate:
        if renewal_of_certificate_id is None and renewal_of_serial_number is None:
            raise ValueError("Renewal requests must reference an issued certificate")
        certificate = (
            self.repository.get_certificate_by_id(renewal_of_certificate_id)
            if renewal_of_certificate_id is not None
            else self.repository.get_issued_certificate(str(renewal_of_serial_number))
        )
        if (
            renewal_of_serial_number is not None
            and certificate.serial_number != renewal_of_serial_number
        ):
            raise RepositoryError(
                "Renewal certificate_id does not match its serial number"
            )
        if certificate.status is not CertificateStatus.ACTIVE:
            raise RepositoryError("Only active certificates may be renewed")
        if certificate.template_id != template_id:
            raise RepositoryError("Renewal requests must use the original certificate template")
        original_request = self.repository.get_request(certificate.request_id)
        if requested_by_user_id is None:
            raise RepositoryError("Renewal requests must have an authenticated owner")
        if original_request.requested_by_user_id != requested_by_user_id:
            raise RepositoryError("Cannot renew a certificate owned by another user")
        return certificate


def _utc_now(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        return current.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc)
