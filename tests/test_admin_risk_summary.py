from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import HTTPException

from myownca.comms import NotificationChannel
from myownca.domain import (
    CertificateProfile,
    CertificateTemplate,
    CertificateRequest,
    CertificateStatus,
    IssuedCertificate,
    RequestKind,
    RequestStatus,
    Revocation,
    RevocationReason,
    Role,
)
from myownca.notifications import NotificationEvent, NotificationLogEntry
from myownca.online.app import create_app
from tests.helpers import (
    add_login_ready_user,
    create_active_session,
    request_with_session,
    route_endpoint,
)


def _app(tempdir: str):
    app = create_app(Path(tempdir) / "risk.sqlite3", lab_mode=True)
    admin_secret = add_login_ready_user(
        app, user_id="admin-1", email="admin@example.test", role=Role.ADMIN
    )
    add_login_ready_user(app, user_id="user-1", email="user@example.test", role=Role.USER)
    tokens = {
        "admin": create_active_session(
            app, email="admin@example.test", totp_secret=admin_secret
        ),
        "user": create_active_session(app, email="user@example.test"),
    }
    app.state.repository.add_template(
        CertificateTemplate(id="host", name="Host TLS", profile=CertificateProfile.HOST_TLS)
    )
    return app, tokens


def _request(request_id: str, *, status: RequestStatus, created_at: datetime) -> CertificateRequest:
    return CertificateRequest(
        id=request_id,
        template_id="host",
        csr_pem="-----BEGIN CERTIFICATE REQUEST-----\n-----END CERTIFICATE REQUEST-----\n",
        kind=RequestKind.FIRST_ISSUANCE,
        status=status,
        created_at=created_at,
    )


def _certificate(
    serial: str,
    *,
    request_id: str,
    expires_at: datetime,
    status: CertificateStatus = CertificateStatus.ACTIVE,
) -> IssuedCertificate:
    return IssuedCertificate(
        serial_number=serial,
        request_id=request_id,
        template_id="host",
        certificate_pem="-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n",
        subject=f"CN={serial}",
        issued_at=expires_at - timedelta(days=365),
        expires_at=expires_at,
        status=status,
    )


class AdminRiskSummaryTests(unittest.TestCase):
    def test_summary_counts_certificate_risk_and_recent_failures(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, tokens = _app(tempdir)
            repository = app.state.repository
            current = datetime.now(timezone.utc)

            seeded = [
                (
                    "req-expired",
                    RequestStatus.ISSUED,
                    "cert-expired",
                    current - timedelta(days=1),
                    CertificateStatus.ACTIVE,
                ),
                (
                    "req-5",
                    RequestStatus.ISSUED,
                    "cert-5",
                    current + timedelta(days=5),
                    CertificateStatus.ACTIVE,
                ),
                (
                    "req-20",
                    RequestStatus.ISSUED,
                    "cert-20",
                    current + timedelta(days=20),
                    CertificateStatus.ACTIVE,
                ),
                (
                    "req-45",
                    RequestStatus.ISSUED,
                    "cert-45",
                    current + timedelta(days=45),
                    CertificateStatus.ACTIVE,
                ),
                (
                    "req-90",
                    RequestStatus.ISSUED,
                    "cert-90",
                    current + timedelta(days=90),
                    CertificateStatus.ACTIVE,
                ),
                (
                    "req-revoked-now",
                    RequestStatus.ISSUED,
                    "cert-revoked-now",
                    current + timedelta(days=3),
                    CertificateStatus.REVOKED,
                ),
                (
                    "req-revoked-old",
                    RequestStatus.ISSUED,
                    "cert-revoked-old",
                    current + timedelta(days=3),
                    CertificateStatus.REVOKED,
                ),
            ]
            for request_id, request_status, serial, expires_at, cert_status in seeded:
                repository.add_request(
                    _request(
                        request_id,
                        status=request_status,
                        created_at=current - timedelta(days=10),
                    )
                )
                repository.add_issued_certificate(
                    _certificate(
                        serial,
                        request_id=request_id,
                        expires_at=expires_at,
                        status=cert_status,
                    )
                )

            repository.add_request(
                _request("req-pending-1", status=RequestStatus.PENDING, created_at=current)
            )
            repository.add_request(
                _request("req-pending-2", status=RequestStatus.PENDING, created_at=current)
            )
            repository.add_request(
                _request("req-rejected", status=RequestStatus.REJECTED, created_at=current)
            )

            repository.add_revocation(
                Revocation(
                    serial_number="cert-revoked-now",
                    reason=RevocationReason.SUPERSEDED,
                    revoked_at=current,
                )
            )
            old_month = (current.replace(day=1) - timedelta(days=1)).replace(hour=12)
            repository.add_revocation(
                Revocation(
                    serial_number="cert-revoked-old",
                    reason=RevocationReason.SUPERSEDED,
                    revoked_at=old_month,
                )
            )

            app.state.notifications.repository.add_log(
                NotificationLogEntry(
                    id="n-failed-recent",
                    event_type=NotificationEvent.EXPIRING.value,
                    template_name="t",
                    channel=NotificationChannel.EMAIL.value,
                    recipient="holder@example.test",
                    sent_at=current - timedelta(days=1),
                    success=False,
                )
            )
            app.state.notifications.repository.add_log(
                NotificationLogEntry(
                    id="n-success-recent",
                    event_type=NotificationEvent.EXPIRING.value,
                    template_name="t",
                    channel=NotificationChannel.EMAIL.value,
                    recipient="holder@example.test",
                    sent_at=current - timedelta(days=1),
                    success=True,
                )
            )
            app.state.notifications.repository.add_log(
                NotificationLogEntry(
                    id="n-failed-old",
                    event_type=NotificationEvent.EXPIRING.value,
                    template_name="t",
                    channel=NotificationChannel.EMAIL.value,
                    recipient="holder@example.test",
                    sent_at=current - timedelta(days=31),
                    success=False,
                )
            )

            with app.state.repository.database.connect() as connection:
                connection.execute(
                    """
                    INSERT INTO service_cert_errors(id, created_at, operation, target, message)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        "e-renew-recent",
                        (current - timedelta(days=2)).isoformat(),
                        "renew",
                        "svc",
                        "renew failed",
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO service_cert_errors(id, created_at, operation, target, message)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        "e-order-recent",
                        (current - timedelta(days=2)).isoformat(),
                        "order_create",
                        "svc",
                        "order failed",
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO service_cert_errors(id, created_at, operation, target, message)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        "e-renew-old",
                        (current - timedelta(days=31)).isoformat(),
                        "renew",
                        "svc",
                        "old renew failed",
                    ),
                )

            admin_token, admin_csrf = tokens["admin"]
            summary = route_endpoint(app, "/internal/admin/risk-summary", "GET")(
                request_with_session(admin_token, admin_csrf)
            )

            self.assertEqual(
                summary,
                {
                    "expired": 1,
                    "expiring_7_days": 1,
                    "expiring_30_days": 2,
                    "expiring_60_days": 3,
                    "pending_approval": 2,
                    "revoked_this_month": 1,
                    "failed_notifications_30_days": 1,
                    "failed_renewals_30_days": 1,
                },
            )

    def test_user_cannot_read_risk_summary(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, tokens = _app(tempdir)
            user_token, user_csrf = tokens["user"]
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/admin/risk-summary", "GET")(
                    request_with_session(user_token, user_csrf)
                )
            self.assertEqual(ctx.exception.status_code, 403)


if __name__ == "__main__":
    unittest.main()
