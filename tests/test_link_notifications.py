from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from tempfile import TemporaryDirectory
from unittest import mock

from myownca.comms import CommsService, DeliveryResult, NotificationChannel
from myownca.domain import CertificateProfile, CertificateStatus, IssuedCertificate, Person, Role
from myownca.holder import LinkPurpose, SecureLinkRepository, SecureLinkService
from myownca.notifications import (
    NotificationAudience,
    NotificationEvent,
    NotificationRepository,
    NotificationRule,
    NotificationService,
    NotificationTemplate,
)
from myownca.domain import User
from tests.helpers import TempPKI, make_csr
from tests.test_claim_renewal import _app_with_renewal_link, _mtls_request, _renew

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=timezone.utc)


class FakeComms:
    def __init__(self) -> None:
        self.sent: list[tuple] = []

    def send(self, channel, recipient, message):
        self.sent.append((channel, recipient, message))
        return DeliveryResult(channel=channel, recipient=recipient, success=True, detail="ok")


class RenewalLinkNotificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pki = TempPKI()
        self.repo = NotificationRepository(self.pki.database)
        self.comms = FakeComms()
        self.links = SecureLinkService(SecureLinkRepository(self.pki.database), self.pki.repository)
        self.pki.repository.add_person(
            Person(id="p1", name="Alice", surname="Ng", email="al@example.test", created_at=NOW)
        )
        self.repo.add_template(
            NotificationTemplate(
                name="notify-expiring",
                event_type=NotificationEvent.EXPIRING,
                subject="$serial expires soon",
                body="Renew at $renewal_url before $link_expires (portal: $portal_url)",
            )
        )
        self.service = NotificationService(
            self.repo, self.pki.repository, self.comms, secure_links=self.links
        )
        self.pki.add_template("host", CertificateProfile.HOST_TLS)
        self.pki.service.submit_request(
            "host", make_csr("soon.example.test", dns_names=("soon.example.test",)),
            request_id="req-SOON",
        )
        self.pki.repository.add_issued_certificate(
            IssuedCertificate(
                serial_number="SOON",
                request_id="req-SOON",
                template_id="host",
                certificate_pem="x",
                subject="CN=soon.example.test",
                issued_at=NOW - timedelta(days=300),
                expires_at=NOW + timedelta(days=10),
                status=CertificateStatus.ACTIVE,
                holder_person_id="p1",
            )
        )

    def tearDown(self) -> None:
        self.pki.close()

    def _link_rule(self, *, include_link: bool = True) -> None:
        self.repo.add_rule(
            NotificationRule(
                id="r-exp",
                event_type=NotificationEvent.EXPIRING,
                template_name="notify-expiring",
                channel=NotificationChannel.EMAIL,
                audience=NotificationAudience.HOLDER,
                include_renewal_link=include_link,
            )
        )

    def test_scheduled_run_mints_link_and_renders_url(self) -> None:
        self.pki.repository.set_setting("portal_base_url", "https://ca.example.test")
        self._link_rule()
        summary = self.service.run_scheduled(NOW)
        self.assertEqual(summary["rules"][0]["sent"], 1)
        _channel, recipient, message = self.comms.sent[0]
        self.assertEqual(recipient, "al@example.test")
        self.assertIn("https://ca.example.test/claim/", message.body)
        self.assertIn("portal: https://ca.example.test", message.body)
        links = self.links.repository.list_links_for_serial("SOON", LinkPurpose.RENEWAL)
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0].created_by, "system:notify")

    def test_mtls_base_url_preferred_for_renewal_links(self) -> None:
        self.pki.repository.set_setting("portal_base_url", "https://ca.example.test")
        self.pki.repository.set_setting("mtls_base_url", "https://renew.example.test:8443")
        self._link_rule()
        self.service.run_scheduled(NOW)
        message = self.comms.sent[0][2]
        self.assertIn("https://renew.example.test:8443/claim/", message.body)

    def test_next_period_rerun_supersedes_previous_link(self) -> None:
        self.pki.repository.set_setting("portal_base_url", "https://ca.example.test")
        self._link_rule()
        self.service.run_scheduled(NOW)
        # Next period (outside the dedup window): a fresh link replaces the old.
        self.service.run_scheduled(NOW + timedelta(days=2))
        links = self.links.repository.list_links_for_serial("SOON", LinkPurpose.RENEWAL)
        self.assertEqual(len(links), 2)
        active = [link for link in links if link.revoked_at is None]
        self.assertEqual(len(active), 1)

    def test_without_base_url_no_link_and_placeholder_left(self) -> None:
        self._link_rule()
        self.service.run_scheduled(NOW)
        message = self.comms.sent[0][2]
        self.assertIn("$renewal_url", message.body)
        self.assertEqual(
            self.links.repository.list_links_for_serial("SOON", LinkPurpose.RENEWAL), []
        )

    def test_rule_without_flag_mints_nothing(self) -> None:
        self.pki.repository.set_setting("portal_base_url", "https://ca.example.test")
        self._link_rule(include_link=False)
        self.service.run_scheduled(NOW)
        self.assertEqual(
            self.links.repository.list_links_for_serial("SOON", LinkPurpose.RENEWAL), []
        )


class AccessRequestedEventTests(unittest.TestCase):
    def test_context_override_reaches_approvers_only(self) -> None:
        pki = TempPKI()
        try:
            repo = NotificationRepository(pki.database)
            comms = FakeComms()
            pki.repository.add_user(
                User(id="su-1", email="su1@example.test", role=Role.SUPERUSER)
            )
            repo.add_template(
                NotificationTemplate(
                    name="notify-access",
                    event_type=NotificationEvent.ACCESS_REQUESTED,
                    subject="Access request from $access_email",
                    body="$access_name ($access_kind): $access_message",
                )
            )
            for audience in (NotificationAudience.APPROVERS, NotificationAudience.HOLDER):
                repo.add_rule(
                    NotificationRule(
                        id=f"r-{audience.value}",
                        event_type=NotificationEvent.ACCESS_REQUESTED,
                        template_name="notify-access",
                        channel=NotificationChannel.EMAIL,
                        audience=audience,
                    )
                )
            service = NotificationService(repo, pki.repository, comms)
            entries = service.notify_event(
                NotificationEvent.ACCESS_REQUESTED,
                context_override={
                    "access_email": "new@example.test",
                    "access_name": "New Person",
                    "access_kind": "user",
                    "access_message": "please onboard me",
                },
                object_ref="acc-1",
            )
            self.assertEqual(len(entries), 1)  # holder-audience rule has no person → skipped
            _channel, recipient, message = comms.sent[0]
            self.assertEqual(recipient, "su1@example.test")
            self.assertIn("Access request from new@example.test", message.subject)
            self.assertIn("please onboard me", message.body)
            self.assertEqual(entries[0].object_ref, "acc-1")
        finally:
            pki.close()


class PruneTests(unittest.TestCase):
    def test_prune_removes_long_dead_links(self) -> None:
        pki = TempPKI()
        try:
            pki.repository.add_person(
                Person(id="p1", name="A", surname="B", email="a@example.test", created_at=NOW)
            )
            links = SecureLinkService(SecureLinkRepository(pki.database), pki.repository)
            old, _ = links.mint(
                LinkPurpose.ENROLLMENT, created_by="x", person_id="p1",
                expires_days=1, now=NOW - timedelta(days=60),
            )
            fresh, _ = links.mint(
                LinkPurpose.ENROLLMENT, created_by="x", person_id="p1", now=NOW
            )
            pruned = links.repository.prune(NOW)
            self.assertEqual(pruned, 1)
            remaining = links.repository.list_links()
            self.assertEqual([link.id for link in remaining], [fresh.id])
            self.assertNotEqual(remaining[0].id, old.id)
        finally:
            pki.close()


class AutoDeliveryLinkTests(unittest.TestCase):
    def test_link_originated_issuance_emails_delivery_link(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, _link, link_token, _su = _app_with_renewal_link(tempdir)
            app.state.repository.set_setting("portal_base_url", "https://ca.example.test")
            with mock.patch.object(
                CommsService,
                "send",
                side_effect=lambda channel, recipient, message: DeliveryResult(
                    channel=NotificationChannel.EMAIL,
                    recipient=recipient,
                    success=True,
                    detail="ok",
                ),
            ) as sent:
                result = _renew(app, link_token, _mtls_request(cert.certificate_pem))
            self.assertIsNotNone(result["issued_serial_number"])
            delivery_mail = next(
                call for call in sent.call_args_list
                if "https://ca.example.test/claim/" in call.args[2].body
            )
            self.assertEqual(delivery_mail.args[1], "holder@example.test")
            delivery_links = app.state.secure_links.repository.list_links_for_serial(
                result["issued_serial_number"], LinkPurpose.DELIVERY
            )
            self.assertEqual(len(delivery_links), 1)
            self.assertEqual(delivery_links[0].created_by, "system:issuance")


if __name__ == "__main__":
    unittest.main()
