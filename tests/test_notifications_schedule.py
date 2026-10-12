from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from myownca.comms import DeliveryResult, NotificationChannel
from myownca.domain import CertificateStatus, IssuedCertificate, Person, Role
from myownca.notifications import (
    NotificationAudience,
    NotificationEvent,
    NotificationRepository,
    NotificationRule,
    NotificationService,
    NotificationTemplate,
)
from myownca.online.app import create_app
from tests.helpers import (
    TempPKI,
    add_login_ready_user,
    create_active_session,
    request_with_session,
    route_endpoint,
)

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=timezone.utc)


class FakeComms:
    def __init__(self) -> None:
        self.sent: list[tuple] = []

    def send(self, channel, recipient, message):
        self.sent.append((channel, recipient, message))
        return DeliveryResult(channel=channel, recipient=recipient, success=True, detail="ok")


def _cert(serial: str, *, expires: datetime, status=CertificateStatus.ACTIVE) -> IssuedCertificate:
    return IssuedCertificate(
        serial_number=serial,
        request_id=f"req-{serial}",
        template_id="host",
        certificate_pem="x",
        subject=f"CN={serial}.example.test",
        issued_at=NOW - timedelta(days=300),
        expires_at=expires,
        status=status,
        holder_person_id="p1",
    )


class RunScheduledTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pki = TempPKI()
        self.repo = NotificationRepository(self.pki.database)
        self.comms = FakeComms()
        self.pki.repository.add_person(
            Person(id="p1", name="Alice", surname="Ng", email="al@example.test", created_at=NOW)
        )
        self.repo.add_template(
            NotificationTemplate(
                name="notify-expiring", event_type=NotificationEvent.EXPIRING,
                subject="$serial expires in $days_until_expiry days", body="renew $serial",
            )
        )
        self.repo.add_template(
            NotificationTemplate(
                name="notify-expired", event_type=NotificationEvent.EXPIRED,
                subject="$serial has expired", body="replace $serial",
            )
        )
        self.service = NotificationService(self.repo, self.pki.repository, self.comms)

    def tearDown(self) -> None:
        self.pki.close()

    def _seed_request(self, serial: str) -> None:
        # IssuedCertificate.request_id has an FK to certificate_requests; create the anchor.
        from myownca.domain import CertificateProfile
        from tests.helpers import make_csr

        try:
            self.pki.repository.get_template("host")
        except Exception:  # noqa: BLE001 - create once
            self.pki.add_template("host", CertificateProfile.HOST_TLS)
        self.pki.service.submit_request(
            "host",
            make_csr(f"{serial}.example.test", dns_names=(f"{serial}.example.test",)),
            request_id=f"req-{serial}",
        )

    def _add_cert(self, serial: str, *, expires: datetime, status=CertificateStatus.ACTIVE) -> None:
        self._seed_request(serial)
        self.pki.repository.add_issued_certificate(_cert(serial, expires=expires, status=status))

    def _rule(self, rule_id: str, event: NotificationEvent, *, template: str, period=7, threshold=30, enabled=True) -> NotificationRule:
        rule = NotificationRule(
            id=rule_id, event_type=event, template_name=template,
            channel=NotificationChannel.EMAIL, audience=NotificationAudience.HOLDER,
            enabled=enabled, period_days=period, threshold_days=threshold,
        )
        self.repo.add_rule(rule)
        return rule

    def test_expiring_matches_threshold_window(self) -> None:
        self._add_cert("SOON", expires=NOW + timedelta(days=10))      # within 30d → match
        self._add_cert("LATER", expires=NOW + timedelta(days=90))     # beyond threshold → no
        self._add_cert("GONE", expires=NOW - timedelta(days=2))       # already expired → not "expiring"
        self._rule("r-exp", NotificationEvent.EXPIRING, template="notify-expiring")
        summary = self.service.run_scheduled(NOW)
        entry = summary["rules"][0]
        self.assertEqual(entry["matched"], 1)
        self.assertEqual(entry["sent"], 1)
        self.assertEqual(self.comms.sent[0][1], "al@example.test")
        self.assertIn("SOON expires in 10 days", self.comms.sent[0][2].subject)

    def test_expired_matches_past_certs_but_not_revoked(self) -> None:
        self._add_cert("DEAD", expires=NOW - timedelta(days=5))
        self._add_cert("REVOKED", expires=NOW - timedelta(days=5), status=CertificateStatus.REVOKED)
        self._add_cert("ALIVE", expires=NOW + timedelta(days=200))
        self._rule("r-dead", NotificationEvent.EXPIRED, template="notify-expired")
        summary = self.service.run_scheduled(NOW)
        entry = summary["rules"][0]
        self.assertEqual(entry["matched"], 1)
        self.assertEqual(entry["sent"], 1)
        self.assertIn("DEAD has expired", self.comms.sent[0][2].subject)

    def test_period_gate_and_force(self) -> None:
        self._add_cert("SOON", expires=NOW + timedelta(days=10))
        self._rule("r-exp", NotificationEvent.EXPIRING, template="notify-expiring", period=7)
        first = self.service.run_scheduled(NOW)
        self.assertTrue(first["rules"][0]["due"])
        # One day later: not due (period 7).
        second = self.service.run_scheduled(NOW + timedelta(days=1))
        self.assertFalse(second["rules"][0]["due"])
        self.assertEqual(second["rules"][0]["sent"], 0)
        # force overrides the gate but dedup still suppresses the resend.
        forced = self.service.run_scheduled(NOW + timedelta(days=1), force=True)
        self.assertTrue(forced["rules"][0]["due"])
        self.assertEqual(forced["rules"][0]["skipped"], 1)
        self.assertEqual(len(self.comms.sent), 1)
        # After the period has elapsed it is due again and the dedup window has moved on.
        third = self.service.run_scheduled(NOW + timedelta(days=8))
        self.assertTrue(third["rules"][0]["due"])
        self.assertEqual(third["rules"][0]["sent"], 1)
        self.assertEqual(len(self.comms.sent), 2)

    def test_dry_run_sends_and_stamps_nothing(self) -> None:
        self._add_cert("SOON", expires=NOW + timedelta(days=10))
        self._rule("r-exp", NotificationEvent.EXPIRING, template="notify-expiring")
        summary = self.service.run_scheduled(NOW, dry_run=True)
        entry = summary["rules"][0]
        self.assertEqual(entry["matched"], 1)
        self.assertEqual(entry["sent"], 0)
        self.assertEqual(self.comms.sent, [])
        self.assertIsNone(self.repo.get_rule("r-exp").last_run_at)

    def test_disabled_rules_and_event_filter(self) -> None:
        self._add_cert("SOON", expires=NOW + timedelta(days=10))
        self._add_cert("DEAD", expires=NOW - timedelta(days=5))
        self._rule("r-exp", NotificationEvent.EXPIRING, template="notify-expiring", enabled=False)
        self._rule("r-dead", NotificationEvent.EXPIRED, template="notify-expired")
        summary = self.service.run_scheduled(NOW, event=NotificationEvent.EXPIRED)
        self.assertEqual([entry["rule_id"] for entry in summary["rules"]], ["r-dead"])
        self.assertEqual(summary["rules"][0]["sent"], 1)


class RunEndpointTests(unittest.TestCase):
    def test_superuser_can_run_and_audit_is_recorded(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "n.sqlite3", lab_mode=True)
            su = add_login_ready_user(app, user_id="su-1", email="su1@example.test", role=Role.SUPERUSER)
            token, csrf = create_active_session(app, email="su1@example.test", totp_secret=su)
            summary = route_endpoint(app, "/internal/notifications/run", "POST")(
                request_with_session(token, csrf, method="POST")
            )
            self.assertIn("rules", summary)
            events = app.state.audit.repository.list_events(limit=10)
            self.assertTrue(any(event.action == "notifications_run" for event in events))


if __name__ == "__main__":
    unittest.main()
