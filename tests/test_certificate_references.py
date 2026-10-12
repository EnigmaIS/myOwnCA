from __future__ import annotations

import shutil
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi import HTTPException

from myownca.comms import DeliveryResult, NotificationChannel
from myownca.domain import (
    CertificateProfile,
    CertificateRequest,
    CertificateStatus,
    CertificateTemplate,
    IssuedCertificate,
    Person,
    RequestKind,
    RequestStatus,
    RevocationReason,
    Role,
)
from myownca.holder import LinkPurpose, SecureLinkError, SecureLinkRepository, SecureLinkService
from myownca.notifications import (
    NotificationAudience,
    NotificationEvent,
    NotificationLogEntry,
    NotificationRepository,
    NotificationRule,
    NotificationService,
    NotificationTemplate,
)
from myownca.storage.database import Database
from myownca.storage.repositories import (
    AmbiguousCertificateSerialError,
    PKIRepository,
)
from myownca_core.storage.database import Database as CoreDatabase
from myownca.online.app import (
    CertificateArchive,
    CertificateRenewalCreate,
    LinkCreate,
    RevocationCreate,
    create_app,
)
from tests.helpers import (
    TempPKI,
    add_login_ready_user,
    create_active_session,
    make_csr,
    request_with_session,
    route_endpoint,
)

NOW = datetime(2026, 7, 1, 12, 0, tzinfo=timezone.utc)
MIGRATIONS = Path(__file__).parents[1] / "src/myownca/storage/migrations"


class _Comms:
    def __init__(self) -> None:
        self.sent: list[tuple] = []

    def send(self, channel, recipient, message):
        self.sent.append((channel, recipient, message))
        return DeliveryResult(channel=channel, recipient=recipient, success=True, detail="ok")


class CertificateReferenceMigrationTests(unittest.TestCase):
    def test_migration_backfills_revocations_and_secure_links(self) -> None:
        with TemporaryDirectory() as tempdir:
            database_path = Path(tempdir) / "legacy.sqlite3"
            old_migrations = Path(tempdir) / "old-migrations"
            old_migrations.mkdir()
            for source in sorted(MIGRATIONS.glob("*.sql")):
                if source.name < "0033_canonical_certificate_references.sql":
                    shutil.copy(source, old_migrations / source.name)

            legacy = CoreDatabase(database_path)
            legacy.migrate(old_migrations)
            timestamp = NOW.isoformat()
            with legacy.connect() as connection:
                connection.execute(
                    "INSERT INTO certificate_templates("
                    "id, name, profile, validity_days, first_issuance_approvals, "
                    "renewal_approvals) VALUES (?, ?, ?, ?, ?, ?)",
                    ("host", "Host", "host_tls", 365, 0, 0),
                )
                connection.execute(
                    "INSERT INTO certificate_requests("
                    "id, template_id, csr_pem, kind, status, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "request-1",
                        "host",
                        "csr",
                        "first_issuance",
                        "issued",
                        timestamp,
                    ),
                )
                connection.execute(
                    "INSERT INTO issued_certificates("
                    "serial_number, request_id, template_id, certificate_pem, subject, "
                    "issued_at, expires_at, status, certificate_id) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        "serial-1",
                        "request-1",
                        "host",
                        "certificate",
                        "CN=host",
                        timestamp,
                        (NOW + timedelta(days=365)).isoformat(),
                        "revoked",
                        "certificate-1",
                    ),
                )
                connection.execute(
                    "INSERT INTO revocations(serial_number, reason, revoked_at) VALUES (?, ?, ?)",
                    ("serial-1", "superseded", timestamp),
                )
                connection.execute(
                    "INSERT INTO secure_links("
                    "id, token_hash, purpose, serial_number, created_by, created_at, "
                    "expires_at, max_uses) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        "link-1",
                        "hash-1",
                        "renewal",
                        "serial-1",
                        "system",
                        timestamp,
                        (NOW + timedelta(days=7)).isoformat(),
                        1,
                    ),
                )

            database = Database(database_path)
            database.migrate()
            revocation = PKIRepository(database).list_revocations()[0]
            link = SecureLinkRepository(database).get_link("link-1")
            self.assertEqual(revocation.certificate_id, "certificate-1")
            self.assertEqual(link.certificate_id, "certificate-1")
            self.assertEqual(link.serial_number, "serial-1")

    def test_authoritative_inventory_accepts_same_serial_from_two_issuers(self) -> None:
        with TemporaryDirectory() as tempdir:
            database_path = Path(tempdir) / "legacy.sqlite3"
            old_migrations = Path(tempdir) / "old-migrations"
            old_migrations.mkdir()
            for source in sorted(MIGRATIONS.glob("*.sql")):
                if source.name < "0035_authoritative_certificate_inventory.sql":
                    shutil.copy(source, old_migrations / source.name)

            legacy = CoreDatabase(database_path)
            legacy.migrate(old_migrations)
            timestamp = NOW.isoformat()
            with legacy.connect() as connection:
                connection.execute(
                    "INSERT INTO certificate_templates("
                    "id, name, profile, validity_days, first_issuance_approvals, "
                    "renewal_approvals) VALUES (?, ?, ?, ?, ?, ?)",
                    ("host", "Host", "host_tls", 365, 0, 0),
                )
                connection.execute(
                    "INSERT INTO certificate_requests("
                    "id, template_id, csr_pem, kind, status, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    ("request-a", "host", "csr-a", "first_issuance", "issued", timestamp),
                )
                connection.execute(
                    "INSERT INTO issued_certificates("
                    "serial_number, request_id, template_id, certificate_pem, subject, "
                    "issued_at, expires_at, status, certificate_id, issuer_id) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        "same-serial",
                        "request-a",
                        "host",
                        "certificate-a",
                        "CN=a",
                        timestamp,
                        (NOW + timedelta(days=365)).isoformat(),
                        "active",
                        "certificate-a",
                        "issuer-a",
                    ),
                )

            database = Database(database_path)
            database.migrate()
            repository = PKIRepository(database)
            repository.add_request(
                CertificateRequest(
                    id="request-b",
                    template_id="host",
                    csr_pem="csr-b",
                    kind=RequestKind.FIRST_ISSUANCE,
                    status=RequestStatus.ISSUED,
                    created_at=NOW,
                )
            )
            repository.add_issued_certificate(
                IssuedCertificate(
                    serial_number="same-serial",
                    request_id="request-b",
                    template_id="host",
                    certificate_pem="certificate-b",
                    subject="CN=b",
                    issued_at=NOW,
                    expires_at=NOW + timedelta(days=365),
                    status=CertificateStatus.ACTIVE,
                    certificate_id="certificate-b",
                    issuer_id="issuer-b",
                )
            )

            self.assertEqual(
                repository.get_certificate_by_id("certificate-a").issuer_id,
                "issuer-a",
            )
            self.assertEqual(
                repository.get_certificate_by_id("certificate-b").issuer_id,
                "issuer-b",
            )
            with self.assertRaises(AmbiguousCertificateSerialError):
                repository.get_issued_certificate("same-serial")
            with database.connect() as connection:
                canonical = connection.execute(
                    "SELECT COUNT(*) AS n FROM certificate_inventory "
                    "WHERE serial_number = ?",
                    ("same-serial",),
                ).fetchone()["n"]
                shadow = connection.execute(
                    "SELECT COUNT(*) AS n FROM issued_certificates "
                    "WHERE serial_number = ?",
                    ("same-serial",),
                ).fetchone()["n"]
            self.assertEqual(canonical, 2)
            self.assertEqual(shadow, 1)


class CanonicalCertificateReferenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pki = TempPKI()
        self.pki.add_template("host", CertificateProfile.HOST_TLS)
        self.pki.repository.add_person(
            Person(
                id="person-1",
                name="Alice",
                surname="Holder",
                email="alice@example.test",
                created_at=NOW,
            )
        )
        request = self.pki.service.submit_request(
            "host", make_csr("host.example.test", dns_names=("host.example.test",))
        )
        self.certificate = IssuedCertificate(
            serial_number="serial-1",
            request_id=request.id,
            template_id="host",
            certificate_pem="certificate",
            subject="CN=host.example.test",
            issued_at=NOW,
            expires_at=NOW + timedelta(days=20),
            status=CertificateStatus.ACTIVE,
            holder_person_id="person-1",
            certificate_id="certificate-1",
        )
        self.pki.repository.add_issued_certificate(self.certificate)
        self.links = SecureLinkService(SecureLinkRepository(self.pki.database), self.pki.repository)

    def tearDown(self) -> None:
        self.pki.close()

    def test_link_accepts_canonical_id_and_keeps_serial_compatibility(self) -> None:
        link, _ = self.links.mint(
            LinkPurpose.DELIVERY,
            created_by="admin-1",
            certificate_id="certificate-1",
            now=NOW,
        )
        self.assertEqual(link.certificate_id, "certificate-1")
        self.assertEqual(link.serial_number, "serial-1")
        self.assertEqual(self.links.repository.list_links_for_serial("serial-1")[0].id, link.id)
        self.assertEqual(
            self.links.repository.list_links_for_certificate(
                "certificate-1", serial_number="serial-1"
            )[0].id,
            link.id,
        )

    def test_link_rejects_mismatched_id_and_serial(self) -> None:
        with self.assertRaises(SecureLinkError):
            self.links.mint(
                LinkPurpose.RENEWAL,
                created_by="admin-1",
                certificate_id="certificate-1",
                serial_number="different",
                now=NOW,
            )

    def test_revocation_records_canonical_id(self) -> None:
        revocation = self.pki.service.revoke_certificate(
            "serial-1", RevocationReason.CESSATION_OF_OPERATION, now=NOW
        )
        self.assertEqual(revocation.certificate_id, "certificate-1")
        self.assertEqual(self.pki.repository.list_revocations()[0].certificate_id, "certificate-1")

    def test_notification_logs_use_canonical_id(self) -> None:
        repository = NotificationRepository(self.pki.database)
        repository.add_template(
            NotificationTemplate(
                name="expiring",
                event_type=NotificationEvent.EXPIRING,
                subject="Certificate expires",
                body="Renew $serial",
            )
        )
        rule = NotificationRule(
            id="rule-1",
            event_type=NotificationEvent.EXPIRING,
            template_name="expiring",
            channel=NotificationChannel.EMAIL,
            audience=NotificationAudience.HOLDER,
        )
        repository.add_rule(rule)
        service = NotificationService(repository, self.pki.repository, _Comms())
        entries = service.notify_certificate(rule, self.certificate, now=NOW)
        self.assertEqual(entries[0].object_ref, "certificate-1")

    def test_scheduled_dedup_honours_legacy_serial_log(self) -> None:
        repository = NotificationRepository(self.pki.database)
        repository.add_template(
            NotificationTemplate(
                name="expiring",
                event_type=NotificationEvent.EXPIRING,
                subject="Certificate expires",
                body="Renew $serial",
            )
        )
        repository.add_rule(
            NotificationRule(
                id="rule-1",
                event_type=NotificationEvent.EXPIRING,
                template_name="expiring",
                channel=NotificationChannel.EMAIL,
                audience=NotificationAudience.HOLDER,
                threshold_days=30,
                period_days=7,
            )
        )
        repository.add_log(
            NotificationLogEntry(
                id="legacy-log",
                rule_id="rule-1",
                event_type="expiring",
                template_name="expiring",
                channel="email",
                recipient="alice@example.test",
                object_ref="serial-1",
                success=True,
                sent_at=NOW - timedelta(days=1),
            )
        )
        comms = _Comms()
        summary = NotificationService(repository, self.pki.repository, comms).run_scheduled(
            NOW, force=True
        )
        self.assertEqual(summary["rules"][0]["skipped"], 1)
        self.assertEqual(comms.sent, [])


class DuplicateSerialAPITests(unittest.TestCase):
    def test_canonical_routes_remain_exact_and_legacy_serial_conflicts(self) -> None:
        with TemporaryDirectory() as tempdir:
            with mock.patch("myownca.ca_main.crypto._utc_now", return_value=NOW):
                app = create_app(Path(tempdir) / "canonical.sqlite3", lab_mode=True)
            admin_secret = add_login_ready_user(
                app,
                user_id="admin-1",
                email="admin@example.test",
                role=Role.ADMIN,
            )
            token, csrf = create_active_session(
                app, email="admin@example.test", totp_secret=admin_secret
            )
            repository = app.state.repository
            repository.add_template(
                CertificateTemplate(
                    id="host",
                    name="Host",
                    profile=CertificateProfile.HOST_TLS,
                    first_issuance_approvals=0,
                    renewal_approvals=0,
                )
            )
            repository.add_person(
                Person(
                    id="person-1",
                    name="Alice",
                    surname="Holder",
                    email="alice@example.test",
                    created_at=NOW,
                )
            )
            csr = make_csr(
                "same.example.test", dns_names=("same.example.test",)
            )
            request_a = app.state.service.submit_request(
                "host", csr, requested_by_user_id="admin-1"
            )
            app.state.service.assign_request_holder(request_a.id, person_id="person-1")
            certificate_a = app.state.service.issue_certificate(
                request_a.id, app.state.lab_chain.issuer, now=NOW
            )

            request_b = app.state.service.submit_request(
                "host", csr, requested_by_user_id="admin-1"
            )
            app.state.service.assign_request_holder(request_b.id, person_id="person-1")
            repository.set_request_status(request_b.id, RequestStatus.ISSUED)
            certificate_b = IssuedCertificate(
                serial_number=certificate_a.serial_number,
                request_id=request_b.id,
                template_id=certificate_a.template_id,
                certificate_pem=certificate_a.certificate_pem,
                subject=certificate_a.subject,
                issued_at=certificate_a.issued_at,
                expires_at=certificate_a.expires_at,
                status=CertificateStatus.ACTIVE,
                holder_person_id="person-1",
                certificate_id="certificate-from-other-issuer",
                issuer_id="issuer-b",
            )
            repository.add_issued_certificate(certificate_b)

            get_by_id = route_endpoint(
                app, "/internal/certificate-inventory/{certificate_id}", "GET"
            )
            canonical = get_by_id(
                certificate_b.certificate_id, request_with_session(token)
            )
            self.assertEqual(canonical["certificate_id"], certificate_b.certificate_id)
            self.assertEqual(canonical["issuer_id"], "issuer-b")

            get_by_serial = route_endpoint(
                app, "/internal/certificates/{serial_number}", "GET"
            )
            with self.assertRaises(HTTPException) as ambiguous:
                get_by_serial(certificate_a.serial_number, request_with_session(token))
            self.assertEqual(ambiguous.exception.status_code, 409)

            export_by_id = route_endpoint(
                app,
                "/internal/certificate-inventory/{certificate_id}/export",
                "GET",
            )
            exported = export_by_id(
                certificate_b.certificate_id, request_with_session(token), "pem"
            )
            self.assertEqual(exported.body.decode(), certificate_b.certificate_pem)

            renew_by_id = route_endpoint(
                app,
                "/internal/certificate-inventory/{certificate_id}/renew",
                "POST",
            )
            renewed = renew_by_id(
                certificate_b.certificate_id,
                request_with_session(token, csrf, method="POST"),
                CertificateRenewalCreate(mode="reuse"),
            )
            self.assertEqual(
                renewed["renewal_of_certificate_id"], certificate_b.certificate_id
            )

            create_link = route_endpoint(app, "/internal/links", "POST")
            with self.assertRaises(HTTPException) as ambiguous_link:
                create_link(
                    LinkCreate(
                        purpose="delivery",
                        serial_number=certificate_b.serial_number,
                        send_email=False,
                    ),
                    request_with_session(token, csrf, method="POST"),
                )
            self.assertEqual(ambiguous_link.exception.status_code, 409)
            link = create_link(
                LinkCreate(
                    purpose="delivery",
                    certificate_id=certificate_b.certificate_id,
                    send_email=False,
                ),
                request_with_session(token, csrf, method="POST"),
            )
            stored_link = app.state.secure_links.repository.get_link(link["id"])
            self.assertEqual(stored_link.certificate_id, certificate_b.certificate_id)

            revoke_by_id = route_endpoint(
                app,
                "/internal/certificate-inventory/{certificate_id}/revoke",
                "POST",
            )
            revoke_by_id(
                certificate_b.certificate_id,
                RevocationCreate(reason="cessation_of_operation"),
                request_with_session(token, csrf, method="POST"),
            )
            self.assertEqual(
                repository.get_certificate_by_id(certificate_b.certificate_id).status,
                CertificateStatus.REVOKED,
            )
            self.assertEqual(
                repository.get_certificate_by_id(certificate_a.certificate_id).status,
                CertificateStatus.ACTIVE,
            )
            self.assertEqual(
                repository.list_revocations()[-1].certificate_id,
                certificate_b.certificate_id,
            )

            archive_by_id = route_endpoint(
                app,
                "/internal/certificate-inventory/{certificate_id}",
                "DELETE",
            )
            archived = archive_by_id(
                certificate_b.certificate_id,
                CertificateArchive(
                    reason="retired in duplicate-serial test",
                    confirmation=(
                        f"ARCHIVE CERTIFICATE {certificate_b.serial_number}"
                    ),
                ),
                request_with_session(token, csrf, method="DELETE"),
            )
            self.assertIsNotNone(archived["archived_at"])
            self.assertIsNone(
                repository.get_certificate_by_id(certificate_a.certificate_id).archived_at
            )


if __name__ == "__main__":
    unittest.main()
