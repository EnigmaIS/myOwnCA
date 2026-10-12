from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization

from myownca.domain import (
    ApprovalRecord,
    CertificateProfile,
    CertificateRequest,
    CertificateSource,
    CertificateStatus,
    CertificateTemplate,
    CRLJob,
    Device,
    ExtendedKeyUsageName,
    IssuedCertificate,
    IssuerCRL,
    KeyUsageName,
    OcspResponder,
    OcspStoredResponse,
    PendingSubCARequest,
    Person,
    RequestKind,
    RequestSource,
    RequestStatus,
    Revocation,
    RevocationReason,
    RootCRL,
    Role,
    SubCA,
    User,
)
from myownca.storage.database import Database, IntegrityError


class RepositoryError(RuntimeError):
    pass


class AmbiguousCertificateSerialError(RepositoryError):
    """A legacy serial-only lookup matches certificates from multiple issuers."""


class DuplicateApprovalError(RepositoryError):
    pass


class PKIRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def add_user(self, user: User) -> None:
        with self.database.connect() as connection:
            connection.execute(
                "INSERT INTO users(id, email, role, is_active) VALUES (?, ?, ?, ?)",
                (user.id, user.email, user.role.value, int(user.is_active)),
            )

    def get_user(self, user_id: str) -> User:
        with self.database.connect() as connection:
            row = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            raise RepositoryError(f"Unknown user: {user_id}")
        return User(
            id=row["id"],
            email=row["email"],
            role=Role(row["role"]),
            is_active=bool(row["is_active"]),
        )

    def list_users(self) -> list[User]:
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM users ORDER BY role, lower(email), id"
            ).fetchall()
        return [
            User(
                id=row["id"],
                email=row["email"],
                role=Role(row["role"]),
                is_active=bool(row["is_active"]),
            )
            for row in rows
        ]

    # -- people ---------------------------------------------------------------

    def add_person(self, person: Person) -> None:
        try:
            with self.database.connect() as connection:
                connection.execute(
                    """
                    INSERT INTO people(
                        id, name, surname, email, phone, slack_handle,
                        company, comments, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        person.id,
                        person.name,
                        person.surname,
                        person.email,
                        person.phone,
                        person.slack_handle,
                        person.company,
                        person.comments,
                        _dump_dt(person.created_at),
                    ),
                )
        except IntegrityError as exc:
            raise RepositoryError(f"A person with email {person.email!r} already exists") from exc

    def get_person(self, person_id: str) -> Person:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM people WHERE id = ?", (person_id,)
            ).fetchone()
        if row is None:
            raise RepositoryError(f"Unknown person: {person_id}")
        return _person_from_row(row)

    def get_person_by_email(self, email: str) -> Person | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM people WHERE lower(email) = lower(?)",
                (email,),
            ).fetchone()
        return None if row is None else _person_from_row(row)

    def list_people(self) -> list[Person]:
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM people ORDER BY lower(surname), lower(name), id"
            ).fetchall()
        return [_person_from_row(row) for row in rows]

    def update_person(self, person: Person) -> None:
        try:
            with self.database.connect() as connection:
                cursor = connection.execute(
                    """
                    UPDATE people
                    SET name = ?, surname = ?, email = ?, phone = ?,
                        slack_handle = ?, company = ?, comments = ?
                    WHERE id = ?
                    """,
                    (
                        person.name,
                        person.surname,
                        person.email,
                        person.phone,
                        person.slack_handle,
                        person.company,
                        person.comments,
                        person.id,
                    ),
                )
                if cursor.rowcount == 0:
                    raise RepositoryError(f"Unknown person: {person.id}")
        except IntegrityError as exc:
            raise RepositoryError(f"A person with email {person.email!r} already exists") from exc

    def delete_person(self, person_id: str) -> None:
        try:
            with self.database.connect() as connection:
                cursor = connection.execute("DELETE FROM people WHERE id = ?", (person_id,))
                if cursor.rowcount == 0:
                    raise RepositoryError(f"Unknown person: {person_id}")
        except IntegrityError as exc:
            raise RepositoryError(
                "Cannot delete a person still linked to a device or certificate"
            ) from exc

    # -- devices --------------------------------------------------------------

    def add_device(self, device: Device) -> None:
        try:
            with self.database.connect() as connection:
                connection.execute(
                    """
                    INSERT INTO devices(
                        id, device_name, fqdn, admin_id, comments, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        device.id,
                        device.device_name,
                        device.fqdn,
                        device.admin_id,
                        device.comments,
                        _dump_dt(device.created_at),
                    ),
                )
        except IntegrityError as exc:
            raise RepositoryError(f"Unknown admin person: {device.admin_id}") from exc

    def get_device(self, device_id: str) -> Device:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM devices WHERE id = ?", (device_id,)
            ).fetchone()
        if row is None:
            raise RepositoryError(f"Unknown device: {device_id}")
        return _device_from_row(row)

    def list_devices(self) -> list[Device]:
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM devices ORDER BY lower(device_name), id"
            ).fetchall()
        return [_device_from_row(row) for row in rows]

    def update_device(self, device: Device) -> None:
        try:
            with self.database.connect() as connection:
                cursor = connection.execute(
                    """
                    UPDATE devices
                    SET device_name = ?, fqdn = ?, admin_id = ?, comments = ?
                    WHERE id = ?
                    """,
                    (
                        device.device_name,
                        device.fqdn,
                        device.admin_id,
                        device.comments,
                        device.id,
                    ),
                )
                if cursor.rowcount == 0:
                    raise RepositoryError(f"Unknown device: {device.id}")
        except IntegrityError as exc:
            raise RepositoryError(f"Unknown admin person: {device.admin_id}") from exc

    def delete_device(self, device_id: str) -> None:
        try:
            with self.database.connect() as connection:
                cursor = connection.execute("DELETE FROM devices WHERE id = ?", (device_id,))
                if cursor.rowcount == 0:
                    raise RepositoryError(f"Unknown device: {device_id}")
        except IntegrityError as exc:
            raise RepositoryError(
                "Cannot delete a device still linked to a certificate"
            ) from exc

    def add_template(self, template: CertificateTemplate) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO certificate_templates(
                    id, name, profile, validity_days,
                    first_issuance_approvals, renewal_approvals,
                    key_usages_json, extended_key_usages_json,
                    key_usage_critical, extended_key_usage_critical,
                    allowed_key_algorithms_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    template.id,
                    template.name,
                    template.profile.value,
                    template.validity_days,
                    template.first_issuance_approvals,
                    template.renewal_approvals,
                    json.dumps([usage.value for usage in template.key_usages]),
                    json.dumps([usage.value for usage in template.extended_key_usages]),
                    int(template.key_usage_critical),
                    int(template.extended_key_usage_critical),
                    json.dumps(template.allowed_key_algorithms),
                ),
            )

    def get_template(self, template_id: str) -> CertificateTemplate:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM certificate_templates WHERE id = ?", (template_id,)
            ).fetchone()
        if row is None:
            raise RepositoryError(f"Unknown certificate template: {template_id}")
        return CertificateTemplate(
            id=row["id"],
            name=row["name"],
            profile=CertificateProfile(row["profile"]),
            validity_days=row["validity_days"],
            first_issuance_approvals=row["first_issuance_approvals"],
            renewal_approvals=row["renewal_approvals"],
            key_usages=tuple(KeyUsageName(value) for value in json.loads(row["key_usages_json"])),
            extended_key_usages=tuple(
                ExtendedKeyUsageName(value)
                for value in json.loads(row["extended_key_usages_json"])
            ),
            key_usage_critical=bool(row["key_usage_critical"]),
            extended_key_usage_critical=bool(row["extended_key_usage_critical"]),
            allowed_key_algorithms=tuple(json.loads(row["allowed_key_algorithms_json"])),
        )

    def has_templates(self) -> bool:
        """Whether any certificate template row exists.

        Deliberately does not hydrate rows: legacy databases can hold templates
        that predate the usage-policy rules and would fail validation, so callers
        that only need an existence check must not pay that cost or that risk.
        """
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM certificate_templates LIMIT 1"
            ).fetchone()
        return row is not None

    def list_templates(self) -> list[CertificateTemplate]:
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM certificate_templates ORDER BY profile, lower(name), id"
            ).fetchall()
        return [
            CertificateTemplate(
                id=row["id"],
                name=row["name"],
                profile=CertificateProfile(row["profile"]),
                validity_days=row["validity_days"],
                first_issuance_approvals=row["first_issuance_approvals"],
                renewal_approvals=row["renewal_approvals"],
                key_usages=tuple(
                    KeyUsageName(value) for value in json.loads(row["key_usages_json"])
                ),
                extended_key_usages=tuple(
                    ExtendedKeyUsageName(value)
                    for value in json.loads(row["extended_key_usages_json"])
                ),
                key_usage_critical=bool(row["key_usage_critical"]),
                extended_key_usage_critical=bool(row["extended_key_usage_critical"]),
                allowed_key_algorithms=tuple(json.loads(row["allowed_key_algorithms_json"])),
            )
            for row in rows
        ]

    def update_template(self, template: CertificateTemplate) -> None:
        with self.database.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE certificate_templates
                SET name = ?, profile = ?, validity_days = ?,
                    first_issuance_approvals = ?, renewal_approvals = ?,
                    key_usages_json = ?, extended_key_usages_json = ?,
                    key_usage_critical = ?, extended_key_usage_critical = ?,
                    allowed_key_algorithms_json = ?
                WHERE id = ?
                """,
                (
                    template.name,
                    template.profile.value,
                    template.validity_days,
                    template.first_issuance_approvals,
                    template.renewal_approvals,
                    json.dumps([usage.value for usage in template.key_usages]),
                    json.dumps([usage.value for usage in template.extended_key_usages]),
                    int(template.key_usage_critical),
                    int(template.extended_key_usage_critical),
                    json.dumps(template.allowed_key_algorithms),
                    template.id,
                ),
            )
            if cursor.rowcount == 0:
                raise RepositoryError(f"Unknown certificate template: {template.id}")

    def delete_template(self, template_id: str) -> None:
        try:
            with self.database.connect() as connection:
                cursor = connection.execute(
                    "DELETE FROM certificate_templates WHERE id = ?", (template_id,)
                )
                if cursor.rowcount == 0:
                    raise RepositoryError(f"Unknown certificate template: {template_id}")
        except IntegrityError as exc:
            raise RepositoryError(
                "Cannot delete a template still referenced by requests or certificates"
            ) from exc

    def add_request(self, request: CertificateRequest) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO certificate_requests(
                    id, template_id, csr_pem, kind, status, created_at,
                    requested_by_user_id, renewal_of_serial_number,
                    holder_person_id, holder_device_id, via_link_auth, lineage_id,
                    source, key_registry_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request.id,
                    request.template_id,
                    request.csr_pem,
                    request.kind.value,
                    request.status.value,
                    _dump_dt(request.created_at),
                    request.requested_by_user_id,
                    request.renewal_of_serial_number,
                    request.holder_person_id,
                    request.holder_device_id,
                    request.via_link_auth,
                    request.lineage_id,
                    request.source.value,
                    request.key_registry_id,
                ),
            )
            renewal_id = request.renewal_of_certificate_id
            if renewal_id is None and request.renewal_of_serial_number is not None:
                renewal_id = _certificate_row_for_serial(
                    connection, request.renewal_of_serial_number
                )["certificate_id"]
            if renewal_id is not None:
                anchor = connection.execute(
                    "SELECT serial_number FROM certificate_inventory "
                    "WHERE certificate_id = ?",
                    (renewal_id,),
                ).fetchone()
                if anchor is None:
                    raise RepositoryError(f"Unknown certificate id: {renewal_id}")
                if (
                    request.renewal_of_serial_number is not None
                    and anchor["serial_number"] != request.renewal_of_serial_number
                ):
                    raise RepositoryError(
                        "Renewal certificate_id does not match its serial number"
                    )
                connection.execute(
                    "INSERT INTO certificate_request_renewal_refs(request_id, certificate_id) "
                    "VALUES (?, ?)",
                    (request.id, renewal_id),
                )

    def get_request(self, request_id: str) -> CertificateRequest:
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT r.*, refs.certificate_id AS renewal_of_certificate_id
                FROM certificate_requests r
                LEFT JOIN certificate_request_renewal_refs refs ON refs.request_id = r.id
                WHERE r.id = ?
                """,
                (request_id,),
            ).fetchone()
        if row is None:
            raise RepositoryError(f"Unknown certificate request: {request_id}")
        return _request_from_row(row)

    def list_requests(self, *, include_imports: bool = False) -> list[CertificateRequest]:
        with self.database.connect() as connection:
            if include_imports:
                rows = connection.execute(
                    """
                    SELECT r.*, refs.certificate_id AS renewal_of_certificate_id
                    FROM certificate_requests r
                    LEFT JOIN certificate_request_renewal_refs refs ON refs.request_id = r.id
                    ORDER BY r.created_at DESC, r.id
                    """
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT r.*, refs.certificate_id AS renewal_of_certificate_id
                    FROM certificate_requests r
                    LEFT JOIN certificate_request_renewal_refs refs ON refs.request_id = r.id
                    WHERE r.source = ?
                    ORDER BY r.created_at DESC, r.id
                    """,
                    (RequestSource.REQUEST.value,),
                ).fetchall()
        return [_request_from_row(row) for row in rows]

    def set_request_status(self, request_id: str, status: RequestStatus) -> None:
        with self.database.connect() as connection:
            connection.execute(
                "UPDATE certificate_requests SET status = ? WHERE id = ?",
                (status.value, request_id),
            )

    def set_request_holder(
        self,
        request_id: str,
        *,
        holder_person_id: str | None,
        holder_device_id: str | None,
    ) -> None:
        try:
            with self.database.connect() as connection:
                cursor = connection.execute(
                    """
                    UPDATE certificate_requests
                    SET holder_person_id = ?, holder_device_id = ?
                    WHERE id = ?
                    """,
                    (holder_person_id, holder_device_id, request_id),
                )
                if cursor.rowcount == 0:
                    raise RepositoryError(f"Unknown certificate request: {request_id}")
        except IntegrityError as exc:
            raise RepositoryError("Unknown holder person or device") from exc

    def set_request_key_registry_id(
        self, request_id: str, key_registry_id: str | None
    ) -> None:
        with self.database.connect() as connection:
            updated = connection.execute(
                "UPDATE certificate_requests SET key_registry_id = ? WHERE id = ?",
                (key_registry_id, request_id),
            )
        if updated.rowcount == 0:
            raise RepositoryError(f"Unknown certificate request: {request_id}")

    def add_approval(self, approval: ApprovalRecord) -> None:
        try:
            with self.database.connect() as connection:
                connection.execute(
                    """
                    INSERT INTO approvals(request_id, superuser_id, approved_at)
                    VALUES (?, ?, ?)
                    """,
                    (
                        approval.request_id,
                        approval.superuser_id,
                        _dump_dt(approval.approved_at),
                    ),
                )
        except IntegrityError as exc:
            raise DuplicateApprovalError(
                "Each Certificate Operator may approve a request only once"
            ) from exc

    def list_approvals(self, request_id: str) -> list[ApprovalRecord]:
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM approvals WHERE request_id = ? ORDER BY approved_at", (request_id,)
            ).fetchall()
        return [
            ApprovalRecord(
                request_id=row["request_id"],
                superuser_id=row["superuser_id"],
                approved_at=_load_dt(row["approved_at"]),
            )
            for row in rows
        ]

    def add_issued_certificate(self, certificate: IssuedCertificate) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO certificate_inventory(
                    certificate_id, serial_number, request_id, template_id, certificate_pem,
                    subject, issued_at, expires_at, status,
                    holder_person_id, holder_device_id, lineage_id,
                    source, issuer_id, chain_pem,
                    archived_at, key_registry_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                _certificate_inventory_values(certificate),
            )
            _insert_legacy_certificate_shadow(connection, certificate)
            if (
                certificate.status is CertificateStatus.REVOKED
                and certificate.issuer_id is not None
            ):
                imported_revocation = connection.execute(
                    "SELECT * FROM issuer_revocations "
                    "WHERE issuer_id = ? AND serial_number = ?",
                    (certificate.issuer_id, certificate.serial_number.casefold()),
                ).fetchone()
                if imported_revocation is None:
                    raise RepositoryError(
                        "A revoked imported certificate requires issuer revocation history"
                    )
                connection.execute(
                    """
                    INSERT INTO certificate_revocations(
                        certificate_id, serial_number, reason, revoked_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        certificate.certificate_id,
                        certificate.serial_number,
                        imported_revocation["reason"],
                        imported_revocation["revoked_at"],
                    ),
                )
                _insert_legacy_revocation_shadow(
                    connection,
                    certificate_id=certificate.certificate_id,
                    serial_number=certificate.serial_number,
                    reason=imported_revocation["reason"],
                    revoked_at=imported_revocation["revoked_at"],
                )

    def finalize_issued_certificate(
        self,
        certificate: IssuedCertificate,
        *,
        reservation_request_id: str | None = None,
        supersede_serial_number: str | None = None,
        supersede_certificate_id: str | None = None,
        superseded_at: datetime | None = None,
    ) -> None:
        """Persist issuance, quota consumption and renewal replacement atomically."""

        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO certificate_inventory(
                    certificate_id, serial_number, request_id, template_id, certificate_pem,
                    subject, issued_at, expires_at, status,
                    holder_person_id, holder_device_id, lineage_id,
                    source, issuer_id, chain_pem,
                    archived_at, key_registry_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                _certificate_inventory_values(certificate),
            )
            _insert_legacy_certificate_shadow(connection, certificate)
            if (
                certificate.status is CertificateStatus.REVOKED
                and certificate.issuer_id is not None
            ):
                imported_revocation = connection.execute(
                    "SELECT * FROM issuer_revocations "
                    "WHERE issuer_id = ? AND serial_number = ?",
                    (certificate.issuer_id, certificate.serial_number.casefold()),
                ).fetchone()
                if imported_revocation is None:
                    raise RepositoryError(
                        "A revoked imported certificate requires issuer revocation history"
                    )
                connection.execute(
                    """
                    INSERT INTO certificate_revocations(
                        certificate_id, serial_number, reason, revoked_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        certificate.certificate_id,
                        certificate.serial_number,
                        imported_revocation["reason"],
                        imported_revocation["revoked_at"],
                    ),
                )
                _insert_legacy_revocation_shadow(
                    connection,
                    certificate_id=certificate.certificate_id,
                    serial_number=certificate.serial_number,
                    reason=imported_revocation["reason"],
                    revoked_at=imported_revocation["revoked_at"],
                )
            updated = connection.execute(
                """
                UPDATE certificate_requests
                SET status = ?, lineage_id = ?
                WHERE id = ? AND status = ?
                """,
                (
                    RequestStatus.ISSUED.value,
                    certificate.lineage_id,
                    certificate.request_id,
                    RequestStatus.PENDING.value,
                ),
            )
            if updated.rowcount != 1:
                raise RepositoryError("Certificate request changed before issuance completed")
            if reservation_request_id is not None:
                deleted = connection.execute(
                    "DELETE FROM license_quota_reservations WHERE request_id = ?",
                    (reservation_request_id,),
                )
                if deleted.rowcount != 1:
                    raise RepositoryError("Certificate quota reservation was lost before issuance")
            if supersede_certificate_id is not None or supersede_serial_number is not None:
                if superseded_at is None:
                    raise RepositoryError("Renewal replacement time is required")
                anchor = (
                    connection.execute(
                        "SELECT certificate_id, serial_number, status, issuer_id "
                        "FROM certificate_inventory "
                        "WHERE certificate_id = ? AND status = ?",
                        (supersede_certificate_id, CertificateStatus.ACTIVE.value),
                    ).fetchone()
                    if supersede_certificate_id is not None
                    else _certificate_row_for_serial(
                        connection,
                        str(supersede_serial_number),
                    )
                )
                if anchor is None:
                    raise RepositoryError(
                        "Renewal anchor changed before issuance completed"
                    )
                if (
                    supersede_serial_number is not None
                    and anchor["serial_number"] != supersede_serial_number
                ):
                    raise RepositoryError(
                        "Renewal certificate_id does not match its serial number"
                    )
                if anchor["status"] != CertificateStatus.ACTIVE.value:
                    raise RepositoryError(
                        "Renewal anchor changed before issuance completed"
                    )
                connection.execute(
                    """
                    INSERT INTO certificate_revocations(
                        certificate_id, serial_number, reason, revoked_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        anchor["certificate_id"],
                        anchor["serial_number"],
                        RevocationReason.SUPERSEDED.value,
                        _dump_dt(superseded_at),
                    ),
                )
                _insert_legacy_revocation_shadow(
                    connection,
                    certificate_id=anchor["certificate_id"],
                    serial_number=anchor["serial_number"],
                    reason=RevocationReason.SUPERSEDED.value,
                    revoked_at=_dump_dt(superseded_at),
                )
                updated_anchor = connection.execute(
                    """
                    UPDATE certificate_inventory SET status = ?
                    WHERE certificate_id = ? AND status = ?
                    """,
                    (
                        CertificateStatus.REVOKED.value,
                        anchor["certificate_id"],
                        CertificateStatus.ACTIVE.value,
                    ),
                )
                connection.execute(
                    "UPDATE issued_certificates SET status = ? "
                    "WHERE certificate_id = ? AND status = ?",
                    (
                        CertificateStatus.REVOKED.value,
                        anchor["certificate_id"],
                        CertificateStatus.ACTIVE.value,
                    ),
                )
                if updated_anchor.rowcount != 1:
                    raise RepositoryError(
                        "Renewal anchor changed before issuance completed"
                    )
                if anchor.get("issuer_id"):
                    superseded = Revocation(
                        serial_number=anchor["serial_number"],
                        reason=RevocationReason.SUPERSEDED,
                        revoked_at=superseded_at,
                        certificate_id=anchor["certificate_id"],
                    )
                    _upsert_issuer_revocation(
                        connection,
                        issuer_id=anchor["issuer_id"],
                        revocation=superseded,
                        source="local",
                        source_crl_number=None,
                    )
                    issuer_subject = _issuer_subject_for_inventory_row(
                        connection, anchor["certificate_id"]
                    )
                    if issuer_subject:
                        _enqueue_crl_job(
                            connection,
                            issuer_id=anchor["issuer_id"],
                            issuer_subject=issuer_subject,
                            now=superseded_at,
                        )

    def rollback_import_workflow(
        self,
        request_id: str,
        *,
        created_person_id: str | None = None,
        created_device_id: str | None = None,
    ) -> None:
        """Make a failed leaf-import workflow non-live in one transaction.

        Imported key material may deliberately remain referenced by the hidden,
        rejected request until lifecycle cleanup is due.  The user-visible
        certificate and an owner created by the atomic import wizard must not
        survive a failed commit.
        """

        try:
            with self.database.connect() as connection:
                request = connection.execute(
                    "SELECT source, lineage_id FROM certificate_requests WHERE id = ?",
                    (request_id,),
                ).fetchone()
                if request is None:
                    return
                if request["source"] != RequestSource.IMPORT.value:
                    raise RepositoryError("Only import workflows may be rolled back")
                lineage_id = request["lineage_id"]
                certificates = connection.execute(
                    """
                    SELECT certificate_id, serial_number, source
                    FROM certificate_inventory
                    WHERE request_id = ?
                    """,
                    (request_id,),
                ).fetchall()
                if any(
                    row["source"] != CertificateSource.IMPORTED.value
                    for row in certificates
                ):
                    raise RepositoryError(
                        "Import rollback encountered a non-imported certificate"
                    )
                for certificate in certificates:
                    connection.execute(
                        "DELETE FROM certificate_revocations WHERE certificate_id = ?",
                        (certificate["certificate_id"],),
                    )
                    connection.execute(
                        "DELETE FROM revocations WHERE certificate_id = ?",
                        (certificate["certificate_id"],),
                    )
                connection.execute(
                    "DELETE FROM certificate_inventory WHERE request_id = ?",
                    (request_id,),
                )
                connection.execute(
                    "DELETE FROM issued_certificates WHERE request_id = ?",
                    (request_id,),
                )
                reservation = connection.execute(
                    """
                    SELECT lineage_id FROM license_quota_reservations
                    WHERE request_id = ?
                    """,
                    (request_id,),
                ).fetchone()
                if lineage_id is None and reservation is not None:
                    lineage_id = reservation["lineage_id"]
                connection.execute(
                    "DELETE FROM license_quota_reservations WHERE request_id = ?",
                    (request_id,),
                )
                connection.execute(
                    """
                    UPDATE certificate_requests
                    SET status = ?, holder_person_id = NULL,
                        holder_device_id = NULL, lineage_id = NULL
                    WHERE id = ?
                    """,
                    (RequestStatus.REJECTED.value, request_id),
                )
                if lineage_id is not None:
                    connection.execute(
                        """
                        DELETE FROM certificate_lineages
                        WHERE id = ?
                          AND NOT EXISTS (
                              SELECT 1 FROM certificate_inventory WHERE lineage_id = ?
                          )
                          AND NOT EXISTS (
                              SELECT 1 FROM certificate_requests WHERE lineage_id = ?
                          )
                          AND NOT EXISTS (
                              SELECT 1 FROM license_quota_reservations WHERE lineage_id = ?
                          )
                        """,
                        (lineage_id, lineage_id, lineage_id, lineage_id),
                    )
                if created_device_id is not None:
                    connection.execute(
                        "DELETE FROM devices WHERE id = ?", (created_device_id,)
                    )
                if created_person_id is not None:
                    connection.execute(
                        "DELETE FROM people WHERE id = ?", (created_person_id,)
                    )
        except IntegrityError as exc:
            raise RepositoryError("Failed import could not be rolled back safely") from exc

    def get_issued_certificate(self, serial_number: str) -> IssuedCertificate:
        with self.database.connect() as connection:
            row = _certificate_row_for_serial(connection, serial_number)
        return _issued_certificate_from_row(row)

    def get_certificate_by_issuer_and_serial(
        self, issuer_id: str, serial_number: str
    ) -> IssuedCertificate:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM certificate_inventory "
                "WHERE issuer_id = ? AND serial_number = ?",
                (issuer_id, serial_number),
            ).fetchone()
        if row is None:
            raise RepositoryError(
                f"Unknown certificate for issuer {issuer_id}: {serial_number}"
            )
        return _issued_certificate_from_row(row)

    def get_issued_certificate_by_request_id(
        self, request_id: str
    ) -> IssuedCertificate | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM certificate_inventory WHERE request_id = ?", (request_id,)
            ).fetchone()
        return None if row is None else _issued_certificate_from_row(row)

    def get_certificate_by_id(self, certificate_id: str) -> IssuedCertificate:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM certificate_inventory WHERE certificate_id = ?",
                (certificate_id,),
            ).fetchone()
        if row is None:
            raise RepositoryError(f"Unknown certificate id: {certificate_id}")
        return _issued_certificate_from_row(row)

    def list_issued_certificates(
        self, *, include_archived: bool = False
    ) -> list[IssuedCertificate]:
        with self.database.connect() as connection:
            if include_archived:
                rows = connection.execute(
                    "SELECT * FROM certificate_inventory "
                    "ORDER BY issued_at DESC, issuer_id, serial_number"
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM certificate_inventory WHERE archived_at IS NULL "
                    "ORDER BY issued_at DESC, issuer_id, serial_number"
                ).fetchall()
        return [_issued_certificate_from_row(row) for row in rows]

    def archive_certificate(self, serial_number: str, archived_at: datetime) -> None:
        certificate = self.get_issued_certificate(serial_number)
        self.archive_certificate_by_id(certificate.certificate_id, archived_at)

    def archive_certificate_by_id(
        self, certificate_id: str, archived_at: datetime
    ) -> None:
        with self.database.connect() as connection:
            updated = connection.execute(
                "UPDATE certificate_inventory SET archived_at = ? "
                "WHERE certificate_id = ? AND archived_at IS NULL",
                (_dump_dt(archived_at), certificate_id),
            )
            connection.execute(
                "UPDATE issued_certificates SET archived_at = ? "
                "WHERE certificate_id = ? AND archived_at IS NULL",
                (_dump_dt(archived_at), certificate_id),
            )
        if updated.rowcount == 0:
            raise RepositoryError(
                f"Unknown or already archived certificate: {certificate_id}"
            )

    def set_certificate_key_registry_id(
        self, serial_number: str, key_registry_id: str | None
    ) -> None:
        certificate = self.get_issued_certificate(serial_number)
        self.set_certificate_key_registry_id_by_id(
            certificate.certificate_id, key_registry_id
        )

    def set_certificate_key_registry_id_by_id(
        self, certificate_id: str, key_registry_id: str | None
    ) -> None:
        with self.database.connect() as connection:
            updated = connection.execute(
                "UPDATE certificate_inventory SET key_registry_id = ? "
                "WHERE certificate_id = ?",
                (key_registry_id, certificate_id),
            )
            connection.execute(
                "UPDATE issued_certificates SET key_registry_id = ? "
                "WHERE certificate_id = ?",
                (key_registry_id, certificate_id),
            )
        if updated.rowcount == 0:
            raise RepositoryError(f"Unknown certificate id: {certificate_id}")

    def update_certificate_inventory_metadata(
        self,
        serial_number: str,
        *,
        issuer_id: str,
        chain_pem: str | None = None,
    ) -> None:
        certificate = self.get_issued_certificate(serial_number)
        self.update_certificate_inventory_metadata_by_id(
            certificate.certificate_id, issuer_id=issuer_id, chain_pem=chain_pem
        )

    def update_certificate_inventory_metadata_by_id(
        self,
        certificate_id: str,
        *,
        issuer_id: str,
        chain_pem: str | None = None,
    ) -> None:
        assignments = "issuer_id = ?"
        parameters: list[str] = [issuer_id]
        if chain_pem is not None:
            assignments += ", chain_pem = ?"
            parameters.append(chain_pem)
        parameters.append(certificate_id)
        with self.database.connect() as connection:
            existing_revocation = connection.execute(
                "SELECT serial_number, reason, revoked_at "
                "FROM certificate_revocations WHERE certificate_id = ?",
                (certificate_id,),
            ).fetchone()
            updated = connection.execute(
                f"UPDATE certificate_inventory SET {assignments} "  # noqa: S608
                "WHERE certificate_id = ?",
                parameters,
            )
            connection.execute(
                f"UPDATE issued_certificates SET {assignments} "  # noqa: S608
                "WHERE certificate_id = ?",
                parameters,
            )
            if existing_revocation is not None:
                _upsert_issuer_revocation(
                    connection,
                    issuer_id=issuer_id,
                    revocation=Revocation(
                        serial_number=existing_revocation["serial_number"],
                        reason=RevocationReason(existing_revocation["reason"]),
                        revoked_at=_load_dt(existing_revocation["revoked_at"]),
                        certificate_id=certificate_id,
                    ),
                    source="local",
                    source_crl_number=None,
                )
        if updated.rowcount == 0:
            raise RepositoryError(f"Unknown certificate id: {certificate_id}")

    def add_revocation(self, revocation: Revocation) -> None:
        with self.database.connect() as connection:
            certificate = (
                connection.execute(
                    "SELECT certificate_id, serial_number, issuer_id FROM certificate_inventory "
                    "WHERE certificate_id = ?",
                    (revocation.certificate_id,),
                ).fetchone()
                if revocation.certificate_id is not None
                else _certificate_row_for_serial(connection, revocation.serial_number)
            )
            if certificate is None:  # pragma: no cover - defensive
                raise RepositoryError("Unknown certificate")
            certificate_id = certificate["certificate_id"]
            if certificate["serial_number"] != revocation.serial_number:
                raise RepositoryError(
                    "Revocation certificate_id does not match its serial number"
                )
            if revocation.certificate_id not in (None, certificate_id):
                raise RepositoryError(
                    "Revocation certificate_id does not match its serial number"
                )
            connection.execute(
                "INSERT INTO certificate_revocations("
                "certificate_id, serial_number, reason, revoked_at) "
                "VALUES (?, ?, ?, ?)",
                (
                    certificate_id,
                    revocation.serial_number,
                    revocation.reason.value,
                    _dump_dt(revocation.revoked_at),
                ),
            )
            _insert_legacy_revocation_shadow(
                connection,
                certificate_id=certificate_id,
                serial_number=revocation.serial_number,
                reason=revocation.reason.value,
                revoked_at=_dump_dt(revocation.revoked_at),
            )
            connection.execute(
                "UPDATE certificate_inventory SET status = ? WHERE certificate_id = ?",
                (CertificateStatus.REVOKED.value, certificate_id),
            )
            connection.execute(
                "UPDATE issued_certificates SET status = ? WHERE certificate_id = ?",
                (CertificateStatus.REVOKED.value, certificate_id),
            )
            issuer_id = certificate.get("issuer_id")
            if issuer_id:
                _upsert_issuer_revocation(
                    connection,
                    issuer_id=issuer_id,
                    revocation=revocation,
                    source="local",
                    source_crl_number=None,
                )
                issuer_subject = _issuer_subject_for_inventory_row(
                    connection, certificate_id
                )
                if issuer_subject:
                    _enqueue_crl_job(
                        connection,
                        issuer_id=issuer_id,
                        issuer_subject=issuer_subject,
                        now=revocation.revoked_at,
                    )

    def list_revocations(self) -> list[Revocation]:
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM certificate_revocations ORDER BY revoked_at, certificate_id"
            ).fetchall()
        return [
            Revocation(
                serial_number=row["serial_number"],
                reason=RevocationReason(row["reason"]),
                revoked_at=_load_dt(row["revoked_at"]),
                certificate_id=row.get("certificate_id"),
            )
            for row in rows
        ]

    def get_issuer_revocation(
        self, issuer_id: str, serial_number: str
    ) -> Revocation | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM issuer_revocations "
                "WHERE issuer_id = ? AND serial_number = ?",
                (issuer_id, serial_number.casefold()),
            ).fetchone()
        return None if row is None else _issuer_revocation_from_row(row)

    def reconcile_issuer_revocations(self) -> int:
        """Move revocations onto the issuer fingerprint their certificate now carries.

        ``issuer_id`` was added nullable in 0032, so certificates predating it were
        backfilled by 0035 with a synthetic value (the row's own serial), and 0037
        copied their revocations under that same synthetic key.

        On the normal upgrade path the CRL is *already* correct without this:
        ``update_certificate_inventory_metadata_by_id`` upserts the revocation under
        the corrected fingerprint from ``certificate_revocations``, which 0037 copies
        from but never deletes. This cleans up after that — it removes the orphaned
        synthetic-keyed rows, which otherwise persist forever and make the table
        unreadable by SQL alone, and it recovers a revocation that has no
        ``certificate_revocations`` source row, where that upsert cannot fire and the
        entry would never reach any CRL.

        Only rows whose serial maps to exactly one inventory entry carrying a real
        fingerprint are moved: a serial is unique only *within* an issuer, so an
        ambiguous one is left alone rather than guessed at. An unattributable row is
        also left in place — losing a revocation is far worse than keeping a stale
        key. Idempotent, and safe to run on every boot.
        """
        moved = 0
        with self.database.connect() as connection:
            known = {
                row["issuer_id"]
                for row in connection.execute(
                    "SELECT DISTINCT issuer_id FROM certificate_inventory"
                ).fetchall()
                if _is_issuer_fingerprint(row["issuer_id"])
            }
            if not known:
                return 0
            stale = [
                row
                for row in connection.execute(
                    "SELECT issuer_id, serial_number FROM issuer_revocations"
                ).fetchall()
                if row["issuer_id"] not in known
            ]
            for row in stale:
                serial = row["serial_number"]
                targets = {
                    candidate["issuer_id"]
                    for candidate in connection.execute(
                        "SELECT issuer_id FROM certificate_inventory WHERE serial_number = ?",
                        (serial,),
                    ).fetchall()
                    if _is_issuer_fingerprint(candidate["issuer_id"])
                }
                if len(targets) != 1:
                    continue  # unattributable or ambiguous: never guess
                target = targets.pop()
                already = connection.execute(
                    "SELECT 1 FROM issuer_revocations WHERE issuer_id = ? AND serial_number = ?",
                    (target, serial),
                ).fetchone()
                if already is None:
                    connection.execute(
                        "UPDATE issuer_revocations SET issuer_id = ? "
                        "WHERE issuer_id = ? AND serial_number = ?",
                        (target, row["issuer_id"], serial),
                    )
                else:
                    # The correct row already exists; drop the stale duplicate
                    # rather than overwrite a record that is already right.
                    connection.execute(
                        "DELETE FROM issuer_revocations "
                        "WHERE issuer_id = ? AND serial_number = ?",
                        (row["issuer_id"], serial),
                    )
                moved += 1
        return moved

    def list_issuer_revocations(self, issuer_id: str) -> list[Revocation]:
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM issuer_revocations WHERE issuer_id = ? "
                "ORDER BY revoked_at, serial_number",
                (issuer_id,),
            ).fetchall()
        return [_issuer_revocation_from_row(row) for row in rows]

    def import_issuer_crl(
        self,
        issuer_crl: IssuerCRL,
        revocations: tuple[Revocation, ...] | list[Revocation],
    ) -> None:
        if not issuer_crl.issuer_id:
            raise RepositoryError("Imported CRL requires an issuer fingerprint")
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO issuer_crls(
                    issuer_subject, number, crl_pem, generated_at,
                    issuer_id, this_update, next_update, source, sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                _issuer_crl_values(issuer_crl),
            )
            for revocation in revocations:
                _upsert_issuer_revocation(
                    connection,
                    issuer_id=issuer_crl.issuer_id,
                    revocation=revocation,
                    source="imported",
                    source_crl_number=issuer_crl.number,
                )

    def reconcile_issuer_crl_history(
        self,
        issuer_certificate: x509.Certificate,
    ) -> int:
        """Attach pre-ledger CRL rows to their verified issuer fingerprint."""

        issuer_subject = issuer_certificate.subject.rfc4514_string()
        issuer_id = issuer_certificate.fingerprint(hashes.SHA256()).hex()
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM issuer_crls "
                "WHERE issuer_id IS NULL AND issuer_subject = ?",
                (issuer_subject,),
            ).fetchall()
            updated = 0
            for row in rows:
                try:
                    crl = x509.load_pem_x509_crl(row["crl_pem"].encode())
                    if (
                        crl.issuer != issuer_certificate.subject
                        or not crl.is_signature_valid(issuer_certificate.public_key())
                    ):
                        continue
                    this_update = _crl_datetime(crl, "last_update")
                    next_update = _crl_datetime(crl, "next_update")
                    der = crl.public_bytes(serialization.Encoding.DER)
                except (TypeError, UnsupportedAlgorithm, ValueError):
                    continue
                result = connection.execute(
                    """
                    UPDATE issuer_crls
                    SET issuer_id = ?, this_update = ?, next_update = ?, sha256 = ?
                    WHERE issuer_id IS NULL AND issuer_subject = ? AND number = ?
                    """,
                    (
                        issuer_id,
                        _dump_dt(this_update),
                        _dump_dt(next_update) if next_update is not None else None,
                        hashlib.sha256(der).hexdigest(),
                        issuer_subject,
                        row["number"],
                    ),
                )
                updated += result.rowcount
        return updated

    def enqueue_crl_refresh(
        self,
        issuer_id: str,
        issuer_subject: str,
        now: datetime | None = None,
    ) -> CRLJob:
        current = _utc(now)
        with self.database.connect() as connection:
            _enqueue_crl_job(
                connection,
                issuer_id=issuer_id,
                issuer_subject=issuer_subject,
                now=current,
            )
            row = connection.execute(
                "SELECT * FROM crl_jobs WHERE issuer_id = ?", (issuer_id,)
            ).fetchone()
        return _crl_job_from_row(row)

    def get_crl_job(self, issuer_id: str) -> CRLJob | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM crl_jobs WHERE issuer_id = ?", (issuer_id,)
            ).fetchone()
        return None if row is None else _crl_job_from_row(row)

    def recover_expired_crl_jobs(self, now: datetime | None = None) -> int:
        current = _utc(now)
        with self.database.connect() as connection:
            updated = connection.execute(
                """
                UPDATE crl_jobs
                SET status = ?, lease_owner = NULL, lease_expires_at = NULL,
                    next_attempt_at = ?, updated_at = ?
                WHERE status = ? AND lease_expires_at IS NOT NULL
                  AND lease_expires_at <= ?
                """,
                (
                    "pending",
                    _dump_dt(current),
                    _dump_dt(current),
                    "running",
                    _dump_dt(current),
                ),
            )
        return updated.rowcount

    def claim_crl_job(
        self,
        issuer_id: str,
        *,
        lease_owner: str,
        now: datetime | None = None,
        lease_seconds: int = 120,
    ) -> CRLJob | None:
        current = _utc(now)
        lease_expires = current + timedelta(seconds=lease_seconds)
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM crl_jobs WHERE issuer_id = ? "
                "AND status = ? AND next_attempt_at <= ?",
                (issuer_id, "pending", _dump_dt(current)),
            ).fetchone()
            if row is None:
                return None
            reserved = row["reserved_number"]
            if reserved is None:
                number_row = connection.execute(
                    "SELECT MAX(number) AS current FROM issuer_crls "
                    "WHERE issuer_id = ? OR (issuer_id IS NULL AND issuer_subject = ?)",
                    (issuer_id, row["issuer_subject"]),
                ).fetchone()
                reserved = (number_row["current"] or 0) + 1
            claimed = connection.execute(
                """
                UPDATE crl_jobs
                SET status = ?, reserved_number = ?, lease_owner = ?,
                    lease_expires_at = ?, attempt_count = attempt_count + 1,
                    updated_at = ?
                WHERE issuer_id = ? AND status = ?
                  AND requested_generation = ?
                """,
                (
                    "running",
                    reserved,
                    lease_owner,
                    _dump_dt(lease_expires),
                    _dump_dt(current),
                    issuer_id,
                    "pending",
                    row["requested_generation"],
                ),
            )
            if claimed.rowcount != 1:
                return None
            claimed_row = connection.execute(
                "SELECT * FROM crl_jobs WHERE issuer_id = ?", (issuer_id,)
            ).fetchone()
        return _crl_job_from_row(claimed_row)

    def complete_crl_job(
        self,
        issuer_id: str,
        *,
        lease_owner: str,
        completed_generation: int,
        now: datetime | None = None,
    ) -> CRLJob:
        current = _utc(now)
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT requested_generation FROM crl_jobs "
                "WHERE issuer_id = ? AND status = ? AND lease_owner = ?",
                (issuer_id, "running", lease_owner),
            ).fetchone()
            if row is None:
                raise RepositoryError("CRL job lease was lost")
            has_more = row["requested_generation"] > completed_generation
            connection.execute(
                """
                UPDATE crl_jobs
                SET status = ?, completed_generation = ?,
                    next_attempt_at = ?, reserved_number = NULL,
                    attempt_count = 0, lease_owner = NULL,
                    lease_expires_at = NULL, last_error = NULL, updated_at = ?
                WHERE issuer_id = ? AND lease_owner = ?
                """,
                (
                    "pending" if has_more else "complete",
                    completed_generation,
                    _dump_dt(current),
                    _dump_dt(current),
                    issuer_id,
                    lease_owner,
                ),
            )
            updated = connection.execute(
                "SELECT * FROM crl_jobs WHERE issuer_id = ?", (issuer_id,)
            ).fetchone()
        return _crl_job_from_row(updated)

    def fail_crl_job(
        self,
        issuer_id: str,
        *,
        lease_owner: str,
        error: str,
        now: datetime | None = None,
    ) -> CRLJob:
        current = _utc(now)
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT attempt_count FROM crl_jobs "
                "WHERE issuer_id = ? AND lease_owner = ?",
                (issuer_id, lease_owner),
            ).fetchone()
            if row is None:
                raise RepositoryError("CRL job lease was lost")
            delay = min(3600, 2 ** min(int(row["attempt_count"]), 10))
            connection.execute(
                """
                UPDATE crl_jobs
                SET status = ?, next_attempt_at = ?, lease_owner = NULL,
                    lease_expires_at = NULL, last_error = ?, updated_at = ?
                WHERE issuer_id = ? AND lease_owner = ?
                """,
                (
                    "pending",
                    _dump_dt(current + timedelta(seconds=delay)),
                    error[:500],
                    _dump_dt(current),
                    issuer_id,
                    lease_owner,
                ),
            )
            updated = connection.execute(
                "SELECT * FROM crl_jobs WHERE issuer_id = ?", (issuer_id,)
            ).fetchone()
        return _crl_job_from_row(updated)

    def add_pending_sub_ca(self, pending: PendingSubCARequest) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO pending_sub_cas(
                    id, key_ref, csr_pem, subject, created_at,
                    allowed_profiles_json, key_backend, token_label
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    pending.id,
                    pending.key_ref,
                    pending.csr_pem,
                    pending.subject,
                    _dump_dt(pending.created_at),
                    json.dumps([profile.value for profile in pending.allowed_profiles]),
                    pending.key_backend,
                    pending.token_label,
                ),
            )

    def get_pending_sub_ca(self, pending_id: str) -> PendingSubCARequest:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM pending_sub_cas WHERE id = ?", (pending_id,)
            ).fetchone()
        if row is None:
            raise RepositoryError(f"Unknown pending sub-CA request: {pending_id}")
        return PendingSubCARequest(
            id=row["id"],
            key_ref=row["key_ref"],
            csr_pem=row["csr_pem"],
            subject=row["subject"],
            created_at=_load_dt(row["created_at"]),
            allowed_profiles=tuple(
                CertificateProfile(value) for value in json.loads(row["allowed_profiles_json"])
            ),
            key_backend=row["key_backend"],
            token_label=row["token_label"],
        )

    def list_pending_sub_cas(self) -> list[PendingSubCARequest]:
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM pending_sub_cas ORDER BY created_at"
            ).fetchall()
        return [
            PendingSubCARequest(
                id=row["id"],
                key_ref=row["key_ref"],
                csr_pem=row["csr_pem"],
                subject=row["subject"],
                created_at=_load_dt(row["created_at"]),
                allowed_profiles=tuple(
                    CertificateProfile(value)
                    for value in json.loads(row["allowed_profiles_json"])
                ),
                key_backend=row["key_backend"],
                token_label=row["token_label"],
            )
            for row in rows
        ]

    def delete_pending_sub_ca(self, pending_id: str) -> None:
        with self.database.connect() as connection:
            cursor = connection.execute(
                "DELETE FROM pending_sub_cas WHERE id = ?", (pending_id,)
            )
            if cursor.rowcount == 0:
                raise RepositoryError(
                    f"Unknown pending sub-CA request: {pending_id}"
                )

    def add_sub_ca(
        self,
        sub_ca: SubCA,
        *,
        root_certificate_pem: str | None = None,
        activate: bool = False,
        remove_pending_id: str | None = None,
    ) -> None:
        """Persist issuer metadata, trust anchor and activation atomically."""

        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO sub_cas(
                    id, certificate_pem, key_ref, subject, created_at,
                    allowed_profiles_json, key_backend, token_label
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sub_ca.id,
                    sub_ca.certificate_pem,
                    sub_ca.key_ref,
                    sub_ca.subject,
                    _dump_dt(sub_ca.created_at),
                    json.dumps([profile.value for profile in sub_ca.allowed_profiles]),
                    sub_ca.key_backend,
                    sub_ca.token_label,
                ),
            )
            if root_certificate_pem is not None:
                stored_root = connection.execute(
                    "SELECT value FROM online_settings WHERE key = ?",
                    ("root_certificate_pem",),
                ).fetchone()
                if stored_root is None:
                    connection.execute(
                        "INSERT INTO online_settings(key, value) VALUES (?, ?)",
                        ("root_certificate_pem", root_certificate_pem),
                    )
            if activate:
                connection.execute(
                    """
                    INSERT INTO online_settings(key, value) VALUES (?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value
                    """,
                    ("active_sub_ca_id", sub_ca.id),
                )
            if remove_pending_id is not None:
                cursor = connection.execute(
                    "DELETE FROM pending_sub_cas WHERE id = ?",
                    (remove_pending_id,),
                )
                if cursor.rowcount == 0:
                    raise RepositoryError(
                        f"Unknown pending sub-CA request: {remove_pending_id}"
                    )

    def get_sub_ca(self, sub_ca_id: str) -> SubCA:
        with self.database.connect() as connection:
            row = connection.execute("SELECT * FROM sub_cas WHERE id = ?", (sub_ca_id,)).fetchone()
        if row is None:
            raise RepositoryError(f"Unknown sub-CA: {sub_ca_id}")
        return SubCA(
            id=row["id"],
            certificate_pem=row["certificate_pem"],
            key_ref=row["key_ref"],
            subject=row["subject"],
            created_at=_load_dt(row["created_at"]),
            allowed_profiles=tuple(
                CertificateProfile(value) for value in json.loads(row["allowed_profiles_json"])
            ),
            key_backend=row["key_backend"],
            token_label=row["token_label"],
        )

    def list_sub_cas(self) -> list[SubCA]:
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM sub_cas ORDER BY created_at"
            ).fetchall()
        return [
            SubCA(
                id=row["id"],
                certificate_pem=row["certificate_pem"],
                key_ref=row["key_ref"],
                subject=row["subject"],
                created_at=_load_dt(row["created_at"]),
                allowed_profiles=tuple(
                    CertificateProfile(value)
                    for value in json.loads(row["allowed_profiles_json"])
                ),
                key_backend=row["key_backend"],
                token_label=row["token_label"],
            )
            for row in rows
        ]

    def set_setting(self, key: str, value: str) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO online_settings(key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, value),
            )

    def get_setting(self, key: str) -> str | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT value FROM online_settings WHERE key = ?", (key,)
            ).fetchone()
        return None if row is None else row["value"]

    def set_active_sub_ca(self, sub_ca_id: str) -> None:
        self.get_sub_ca(sub_ca_id)
        self.set_setting("active_sub_ca_id", sub_ca_id)

    def get_active_sub_ca(self) -> SubCA | None:
        active_sub_ca_id = self.get_setting("active_sub_ca_id")
        if active_sub_ca_id is None:
            return None
        return self.get_sub_ca(active_sub_ca_id)

    def assert_initial_ca_resettable(self) -> None:
        with self.database.connect() as connection:
            certificate_count = connection.execute(
                "SELECT COUNT(*) AS count FROM certificate_inventory"
            ).fetchone()["count"]
        if certificate_count:
            raise RepositoryError(
                "Initial CA provisioning cannot be reset after certificates exist"
            )

    def reset_initial_ca_provisioning(self) -> None:
        """Remove pre-launch issuer state as one transaction.

        This is intentionally narrower than a general issuer deletion API.  It
        is used only by the token-gated first-run setup before the completion
        latch exists, when no certificate can have been issued by the online
        service yet.
        """

        self.assert_initial_ca_resettable()
        with self.database.connect() as connection:
            connection.execute(
                "DELETE FROM online_settings WHERE key IN (?, ?)",
                ("active_sub_ca_id", "root_certificate_pem"),
            )
            connection.execute("DELETE FROM crl_jobs")
            connection.execute("DELETE FROM issuer_revocations")
            connection.execute("DELETE FROM issuer_crls")
            connection.execute("DELETE FROM pending_sub_cas")
            connection.execute("DELETE FROM sub_cas")

    def set_root_certificate_pem(self, pem: str) -> None:
        self.set_setting("root_certificate_pem", pem)

    def get_root_certificate_pem(self) -> str | None:
        return self.get_setting("root_certificate_pem")

    def add_request_private_key(
        self,
        request_id: str,
        *,
        key_pem_encrypted: str,
        algorithm: str,
        created_at: datetime,
    ) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO request_private_keys(
                    request_id, key_pem_encrypted, algorithm, created_at
                ) VALUES (?, ?, ?, ?)
                """,
                (request_id, key_pem_encrypted, algorithm, _dump_dt(created_at)),
            )

    def get_request_private_key(self, request_id: str):
        with self.database.connect() as connection:
            return connection.execute(
                "SELECT r.key_pem_encrypted, r.algorithm, r.created_at "
                "FROM request_private_keys AS r "
                "LEFT JOIN certificate_requests AS q ON q.id = r.request_id "
                "LEFT JOIN key_lifecycle_keys AS k ON k.id = q.key_registry_id "
                "WHERE r.request_id = ? AND (k.id IS NULL OR k.status = 'active')",
                (request_id,),
            ).fetchone()

    def has_request_private_key(self, request_id: str) -> bool:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM request_private_keys AS r "
                "LEFT JOIN certificate_requests AS q ON q.id = r.request_id "
                "LEFT JOIN key_lifecycle_keys AS k ON k.id = q.key_registry_id "
                "WHERE r.request_id = ? AND (k.id IS NULL OR k.status = 'active')",
                (request_id,),
            ).fetchone()
        return row is not None

    def list_request_private_key_ids_for_registry(self, key_registry_id: str) -> list[str]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT r.request_id FROM request_private_keys AS r
                JOIN certificate_requests AS q ON q.id = r.request_id
                WHERE q.key_registry_id = ?
                ORDER BY r.request_id
                """,
                (key_registry_id,),
            ).fetchall()
        return [row["request_id"] for row in rows]

    def list_request_private_keys(self) -> list[dict[str, str]]:
        with self.database.connect() as connection:
            return connection.execute(
                "SELECT request_id, algorithm, created_at FROM request_private_keys "
                "ORDER BY created_at, request_id"
            ).fetchall()

    def delete_request_private_key(self, request_id: str) -> bool:
        with self.database.connect() as connection:
            result = connection.execute(
                "DELETE FROM request_private_keys WHERE request_id = ?",
                (request_id,),
            )
        return result.rowcount > 0

    def next_issuer_crl_number(
        self, issuer_subject: str, issuer_id: str | None = None
    ) -> int:
        with self.database.connect() as connection:
            if issuer_id:
                row = connection.execute(
                    "SELECT MAX(number) AS current FROM issuer_crls "
                    "WHERE issuer_id = ? OR (issuer_id IS NULL AND issuer_subject = ?)",
                    (issuer_id, issuer_subject),
                ).fetchone()
            else:
                row = connection.execute(
                    "SELECT MAX(number) AS current FROM issuer_crls WHERE issuer_subject = ?",
                    (issuer_subject,),
                ).fetchone()
        return (row["current"] or 0) + 1

    def add_issuer_crl(self, issuer_crl: IssuerCRL) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO issuer_crls(
                    issuer_subject, number, crl_pem, generated_at,
                    issuer_id, this_update, next_update, source, sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                _issuer_crl_values(issuer_crl),
            )

    def get_latest_issuer_crl(
        self, issuer_subject: str, issuer_id: str | None = None
    ) -> IssuerCRL | None:
        with self.database.connect() as connection:
            if issuer_id:
                row = connection.execute(
                    "SELECT * FROM issuer_crls "
                    "WHERE issuer_id = ? OR (issuer_id IS NULL AND issuer_subject = ?) "
                    "ORDER BY number DESC LIMIT 1",
                    (issuer_id, issuer_subject),
                ).fetchone()
            else:
                row = connection.execute(
                    "SELECT * FROM issuer_crls WHERE issuer_subject = ? "
                    "ORDER BY number DESC LIMIT 1",
                    (issuer_subject,),
                ).fetchone()
        if row is None:
            return None
        return _issuer_crl_from_row(row)

    def get_issuer_crl_by_number(
        self,
        issuer_subject: str,
        issuer_id: str,
        number: int,
    ) -> IssuerCRL | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM issuer_crls "
                "WHERE number = ? AND "
                "(issuer_id = ? OR (issuer_id IS NULL AND issuer_subject = ?)) "
                "ORDER BY issuer_id DESC LIMIT 1",
                (number, issuer_id, issuer_subject),
            ).fetchone()
        return None if row is None else _issuer_crl_from_row(row)

    def upsert_ocsp_responder(self, responder: OcspResponder) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO ocsp_responders(issuer_subject, cert_pem, key_ref, not_after, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(issuer_subject) DO UPDATE SET
                    cert_pem = excluded.cert_pem,
                    key_ref = excluded.key_ref,
                    not_after = excluded.not_after,
                    created_at = excluded.created_at
                """,
                (responder.issuer_subject, responder.cert_pem, responder.key_ref,
                 _dump_dt(responder.not_after), _dump_dt(responder.created_at)),
            )

    def get_ocsp_responder(self, issuer_subject: str) -> OcspResponder | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM ocsp_responders WHERE issuer_subject = ?", (issuer_subject,)
            ).fetchone()
        if row is None:
            return None
        return OcspResponder(
            issuer_subject=row["issuer_subject"], cert_pem=row["cert_pem"], key_ref=row["key_ref"],
            not_after=_load_dt(row["not_after"]), created_at=_load_dt(row["created_at"]),
        )

    def upsert_ocsp_response(self, response: OcspStoredResponse) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO ocsp_responses(issuer_subject, serial_number, cert_id_hash,
                    response_b64, this_update, next_update, produced_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(issuer_subject, serial_number, cert_id_hash) DO UPDATE SET
                    response_b64 = excluded.response_b64,
                    this_update = excluded.this_update,
                    next_update = excluded.next_update,
                    produced_at = excluded.produced_at
                """,
                (response.issuer_subject, response.serial_number, response.cert_id_hash,
                 response.response_b64, _dump_dt(response.this_update),
                 _dump_dt(response.next_update), _dump_dt(response.produced_at)),
            )

    def get_ocsp_response(self, issuer_subject: str, serial_number: str,
                          cert_id_hash: str) -> OcspStoredResponse | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM ocsp_responses WHERE issuer_subject = ? AND serial_number = ? "
                "AND cert_id_hash = ?",
                (issuer_subject, serial_number, cert_id_hash),
            ).fetchone()
        if row is None:
            return None
        return OcspStoredResponse(
            issuer_subject=row["issuer_subject"], serial_number=row["serial_number"],
            cert_id_hash=row["cert_id_hash"], response_b64=row["response_b64"],
            this_update=_load_dt(row["this_update"]), next_update=_load_dt(row["next_update"]),
            produced_at=_load_dt(row["produced_at"]),
        )

    def add_root_crl(self, root_crl: RootCRL) -> None:
        with self.database.connect() as connection:
            connection.execute(
                "INSERT INTO root_crls(number, crl_pem, generated_at) VALUES (?, ?, ?)",
                (root_crl.number, root_crl.crl_pem, _dump_dt(root_crl.generated_at)),
            )


def _person_from_row(row) -> Person:
    return Person(
        id=row["id"],
        name=row["name"],
        surname=row["surname"],
        email=row["email"],
        created_at=_load_dt(row["created_at"]),
        phone=row["phone"],
        slack_handle=row["slack_handle"],
        company=row["company"],
        comments=row["comments"],
    )


def _device_from_row(row) -> Device:
    return Device(
        id=row["id"],
        device_name=row["device_name"],
        admin_id=row["admin_id"],
        created_at=_load_dt(row["created_at"]),
        fqdn=row["fqdn"],
        comments=row["comments"],
    )


def _request_from_row(row) -> CertificateRequest:
    return CertificateRequest(
        id=row["id"],
        template_id=row["template_id"],
        csr_pem=row["csr_pem"],
        kind=RequestKind(row["kind"]),
        status=RequestStatus(row["status"]),
        created_at=_load_dt(row["created_at"]),
        requested_by_user_id=row["requested_by_user_id"],
        renewal_of_serial_number=row["renewal_of_serial_number"],
        renewal_of_certificate_id=row.get("renewal_of_certificate_id"),
        holder_person_id=row["holder_person_id"],
        holder_device_id=row["holder_device_id"],
        via_link_auth=row["via_link_auth"],
        lineage_id=row.get("lineage_id"),
        source=RequestSource(row.get("source") or RequestSource.REQUEST.value),
        key_registry_id=row.get("key_registry_id"),
    )


def _issued_certificate_from_row(row) -> IssuedCertificate:
    return IssuedCertificate(
        serial_number=row["serial_number"],
        request_id=row["request_id"],
        template_id=row["template_id"],
        certificate_pem=row["certificate_pem"],
        subject=row["subject"],
        issued_at=_load_dt(row["issued_at"]),
        expires_at=_load_dt(row["expires_at"]),
        status=CertificateStatus(row["status"]),
        holder_person_id=row["holder_person_id"],
        holder_device_id=row["holder_device_id"],
        lineage_id=row.get("lineage_id"),
        certificate_id=row.get("certificate_id") or row["serial_number"],
        source=CertificateSource(row.get("source") or CertificateSource.ISSUED.value),
        issuer_id=row.get("issuer_id"),
        chain_pem=row.get("chain_pem") or "",
        archived_at=(
            _load_dt(row["archived_at"]) if row.get("archived_at") else None
        ),
        key_registry_id=row.get("key_registry_id"),
    )


def _certificate_inventory_values(certificate: IssuedCertificate) -> tuple[object, ...]:
    certificate_id = certificate.certificate_id or certificate.serial_number
    return (
        certificate_id,
        certificate.serial_number,
        certificate.request_id,
        certificate.template_id,
        certificate.certificate_pem,
        certificate.subject,
        _dump_dt(certificate.issued_at),
        _dump_dt(certificate.expires_at),
        certificate.status.value,
        certificate.holder_person_id,
        certificate.holder_device_id,
        certificate.lineage_id,
        certificate.source.value,
        certificate.issuer_id or certificate_id,
        certificate.chain_pem,
        _dump_dt(certificate.archived_at) if certificate.archived_at else None,
        certificate.key_registry_id,
    )


def _insert_legacy_certificate_shadow(connection, certificate: IssuedCertificate) -> None:
    """Populate the serial-keyed compatibility table only when unambiguous."""

    existing = connection.execute(
        "SELECT certificate_id FROM issued_certificates WHERE serial_number = ?",
        (certificate.serial_number,),
    ).fetchone()
    if existing is not None:
        return
    connection.execute(
        """
        INSERT INTO issued_certificates(
            serial_number, request_id, template_id, certificate_pem,
            subject, issued_at, expires_at, status,
            holder_person_id, holder_device_id, lineage_id,
            certificate_id, source, issuer_id, chain_pem,
            archived_at, key_registry_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            certificate.serial_number,
            certificate.request_id,
            certificate.template_id,
            certificate.certificate_pem,
            certificate.subject,
            _dump_dt(certificate.issued_at),
            _dump_dt(certificate.expires_at),
            certificate.status.value,
            certificate.holder_person_id,
            certificate.holder_device_id,
            certificate.lineage_id,
            certificate.certificate_id or certificate.serial_number,
            certificate.source.value,
            certificate.issuer_id,
            certificate.chain_pem,
            _dump_dt(certificate.archived_at) if certificate.archived_at else None,
            certificate.key_registry_id,
        ),
    )


def _certificate_row_for_serial(
    connection,
    serial_number: str,
):
    query = "SELECT * FROM certificate_inventory WHERE serial_number = ?"
    parameters: list[object] = [serial_number]
    rows = connection.execute(query + " ORDER BY certificate_id LIMIT 2", parameters).fetchall()
    if not rows:
        raise RepositoryError(f"Unknown certificate serial: {serial_number}")
    if len(rows) > 1:
        raise AmbiguousCertificateSerialError(
            f"Certificate serial {serial_number!r} is ambiguous; use certificate_id"
        )
    return rows[0]


def _insert_legacy_revocation_shadow(
    connection,
    *,
    certificate_id: str,
    serial_number: str,
    reason: str,
    revoked_at: str,
) -> None:
    shadow = connection.execute(
        "SELECT certificate_id FROM issued_certificates WHERE serial_number = ?",
        (serial_number,),
    ).fetchone()
    if shadow is None or shadow["certificate_id"] != certificate_id:
        return
    connection.execute(
        "INSERT INTO revocations(serial_number, reason, revoked_at, certificate_id) "
        "VALUES (?, ?, ?, ?)",
        (serial_number, reason, revoked_at, certificate_id),
    )


def _upsert_issuer_revocation(
    connection,
    *,
    issuer_id: str,
    revocation: Revocation,
    source: str,
    source_crl_number: int | None,
) -> None:
    serial = revocation.serial_number.casefold()
    existing = connection.execute(
        "SELECT reason, revoked_at FROM issuer_revocations "
        "WHERE issuer_id = ? AND serial_number = ?",
        (issuer_id, serial),
    ).fetchone()
    if existing is not None:
        if (
            existing["reason"] != revocation.reason.value
            or _load_dt(existing["revoked_at"]) != _utc(revocation.revoked_at)
        ):
            raise RepositoryError(
                f"Conflicting revocation already exists for issuer serial {serial}"
            )
        return
    connection.execute(
        """
        INSERT INTO issuer_revocations(
            issuer_id, serial_number, reason, revoked_at,
            invalidity_date, source, source_crl_number, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            issuer_id,
            serial,
            revocation.reason.value,
            _dump_dt(revocation.revoked_at),
            (
                _dump_dt(revocation.invalidity_date)
                if revocation.invalidity_date is not None
                else None
            ),
            source,
            source_crl_number,
            _dump_dt(datetime.now(timezone.utc)),
        ),
    )


def _issuer_revocation_from_row(row) -> Revocation:
    return Revocation(
        serial_number=row["serial_number"],
        reason=RevocationReason(row["reason"]),
        revoked_at=_load_dt(row["revoked_at"]),
        invalidity_date=(
            _load_dt(row["invalidity_date"]) if row.get("invalidity_date") else None
        ),
    )


def _issuer_subject_for_inventory_row(connection, certificate_id: str) -> str | None:
    row = connection.execute(
        "SELECT certificate_pem FROM certificate_inventory WHERE certificate_id = ?",
        (certificate_id,),
    ).fetchone()
    if row is None:
        return None
    try:
        return x509.load_pem_x509_certificate(
            row["certificate_pem"].encode()
        ).issuer.rfc4514_string()
    except ValueError:
        return None


def _enqueue_crl_job(
    connection,
    *,
    issuer_id: str,
    issuer_subject: str,
    now: datetime,
) -> None:
    current = _utc(now)
    timestamp = _dump_dt(current)
    connection.execute(
        """
        INSERT INTO crl_jobs(
            issuer_id, issuer_subject, job_id, status,
            requested_generation, completed_generation,
            requested_at, next_attempt_at, reserved_number,
            attempt_count, lease_owner, lease_expires_at,
            last_error, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(issuer_id) DO UPDATE SET
            issuer_subject = excluded.issuer_subject,
            requested_generation = requested_generation + 1,
            requested_at = excluded.requested_at,
            status = CASE
                WHEN status = 'running' THEN status
                ELSE 'pending'
            END,
            next_attempt_at = CASE
                WHEN status = 'running' THEN next_attempt_at
                ELSE excluded.next_attempt_at
            END,
            last_error = CASE
                WHEN status = 'running' THEN last_error
                ELSE NULL
            END,
            updated_at = excluded.updated_at
        """,
        (
            issuer_id,
            issuer_subject,
            str(uuid4()),
            "pending",
            1,
            0,
            timestamp,
            timestamp,
            None,
            0,
            None,
            None,
            None,
            timestamp,
        ),
    )


def _issuer_crl_values(issuer_crl: IssuerCRL) -> tuple[object, ...]:
    return (
        issuer_crl.issuer_subject,
        issuer_crl.number,
        issuer_crl.crl_pem,
        _dump_dt(issuer_crl.generated_at),
        issuer_crl.issuer_id,
        (
            _dump_dt(issuer_crl.this_update)
            if issuer_crl.this_update is not None
            else None
        ),
        (
            _dump_dt(issuer_crl.next_update)
            if issuer_crl.next_update is not None
            else None
        ),
        issuer_crl.source,
        issuer_crl.sha256,
    )


def _issuer_crl_from_row(row) -> IssuerCRL:
    return IssuerCRL(
        issuer_subject=row["issuer_subject"],
        number=row["number"],
        crl_pem=row["crl_pem"],
        generated_at=_load_dt(row["generated_at"]),
        issuer_id=row.get("issuer_id"),
        this_update=(
            _load_dt(row["this_update"]) if row.get("this_update") else None
        ),
        next_update=(
            _load_dt(row["next_update"]) if row.get("next_update") else None
        ),
        source=row.get("source") or "local",
        sha256=row.get("sha256") or "",
    )


def _crl_job_from_row(row) -> CRLJob:
    return CRLJob(
        issuer_id=row["issuer_id"],
        issuer_subject=row["issuer_subject"],
        job_id=row["job_id"],
        status=row["status"],
        requested_generation=row["requested_generation"],
        completed_generation=row["completed_generation"],
        next_attempt_at=_load_dt(row["next_attempt_at"]),
        attempt_count=row["attempt_count"],
        reserved_number=row.get("reserved_number"),
        lease_owner=row.get("lease_owner"),
        lease_expires_at=(
            _load_dt(row["lease_expires_at"]) if row.get("lease_expires_at") else None
        ),
        last_error=row.get("last_error"),
    )


def _utc(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        return current.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc)


def _crl_datetime(
    crl: x509.CertificateRevocationList,
    name: str,
) -> datetime | None:
    value = getattr(crl, f"{name}_utc", None)
    if value is None:
        value = getattr(crl, name)
    return _utc(value) if value is not None else None


def _dump_dt(value: datetime) -> str:
    return _utc(value).isoformat()


def _load_dt(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _is_issuer_fingerprint(value: str | None) -> bool:
    """A real issuer id is a SHA-256 hex digest, not a serial or a certificate id."""
    return bool(value) and len(value) == 64 and all(c in "0123456789abcdef" for c in value.lower())
