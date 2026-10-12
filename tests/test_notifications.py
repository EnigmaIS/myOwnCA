from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from myownca.comms import CommsError, DeliveryResult, NotificationChannel
from myownca.domain import CertificateStatus, Device, IssuedCertificate, Person, Role, User
from myownca.notifications import (
    NotificationAudience,
    NotificationEvent,
    NotificationFormat,
    NotificationRepository,
    NotificationRule,
    NotificationService,
    NotificationTemplate,
    render,
)
from myownca.storage.repositories import RepositoryError
from tests.helpers import TempPKI

NOW = datetime(2026, 6, 10, tzinfo=timezone.utc)


class FakeComms:
    def __init__(self, *, fail: bool = False) -> None:
        self.sent: list[tuple] = []
        self.fail = fail

    def send(self, channel, recipient, message):
        if self.fail:
            raise CommsError("transport down")
        self.sent.append((channel, recipient, message))
        return DeliveryResult(channel=channel, recipient=recipient, success=True, detail="ok")


def _cert(*, serial="S1", person=None, device=None, expires=None) -> IssuedCertificate:
    return IssuedCertificate(
        serial_number=serial,
        request_id="r1",
        template_id="host",
        certificate_pem="-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----",
        subject="CN=api.example.test",
        issued_at=NOW,
        expires_at=expires or (NOW + timedelta(days=10)),
        status=CertificateStatus.ACTIVE,
        holder_person_id=person,
        holder_device_id=device,
    )


class RenderTests(unittest.TestCase):
    def test_substitutes_known_and_keeps_unknown(self) -> None:
        template = NotificationTemplate(
            name="t",
            event_type=NotificationEvent.EXPIRING,
            subject="$cert_name expires $expiry_date",
            body="Hi $person_name — $notification_text — $unknown_var",
        )
        subject, body = render(template, {
            "cert_name": "CN=api.example.test",
            "expiry_date": "2026-06-20",
            "person_name": "Alice Ng",
            "notification_text": "please renew",
        })
        self.assertEqual(subject, "CN=api.example.test expires 2026-06-20")
        self.assertIn("Hi Alice Ng — please renew —", body)
        self.assertIn("$unknown_var", body)  # unknown placeholder left intact


class NotificationRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pki = TempPKI()
        self.repo = NotificationRepository(self.pki.database)

    def tearDown(self) -> None:
        self.pki.close()

    def _template(self, name="notify-expiring") -> NotificationTemplate:
        return NotificationTemplate(
            name=name,
            event_type=NotificationEvent.EXPIRING,
            format=NotificationFormat.TEXT,
            subject="s",
            body="b",
        )

    def _rule(self, rule_id="rule-1", template="notify-expiring") -> NotificationRule:
        return NotificationRule(
            id=rule_id,
            event_type=NotificationEvent.EXPIRING,
            template_name=template,
            channel=NotificationChannel.EMAIL,
            audience=NotificationAudience.HOLDER,
            period_days=7,
            threshold_days=30,
        )

    def test_template_crud(self) -> None:
        self.repo.add_template(self._template())
        self.assertEqual(self.repo.get_template("notify-expiring").body, "b")
        self.repo.update_template(
            NotificationTemplate(name="notify-expiring", event_type=NotificationEvent.EXPIRING, body="b2")
        )
        self.assertEqual(self.repo.get_template("notify-expiring").body, "b2")
        self.assertEqual([t.name for t in self.repo.list_templates()], ["notify-expiring"])
        self.repo.delete_template("notify-expiring")
        with self.assertRaises(RepositoryError):
            self.repo.get_template("notify-expiring")

    def test_delete_template_referenced_blocked(self) -> None:
        self.repo.add_template(self._template())
        self.repo.add_rule(self._rule())
        with self.assertRaises(RepositoryError):
            self.repo.delete_template("notify-expiring")

    def test_rule_crud_and_last_run(self) -> None:
        self.repo.add_template(self._template())
        self.repo.add_rule(self._rule())
        self.assertEqual(self.repo.get_rule("rule-1").threshold_days, 30)
        self.assertEqual([r.id for r in self.repo.list_rules(event_type=NotificationEvent.EXPIRING)], ["rule-1"])
        self.repo.set_rule_last_run("rule-1", NOW)
        self.assertEqual(self.repo.get_rule("rule-1").last_run_at, NOW)
        self.repo.delete_rule("rule-1")
        with self.assertRaises(RepositoryError):
            self.repo.get_rule("rule-1")

    def test_rule_requires_existing_template(self) -> None:
        with self.assertRaises(RepositoryError):
            self.repo.add_rule(self._rule(template="ghost"))

    def test_log_and_dedup(self) -> None:
        from myownca.notifications.base import NotificationLogEntry

        self.repo.add_log(
            NotificationLogEntry(
                id="l1", rule_id="rule-1", event_type="expiring", template_name="t",
                channel="email", recipient="a@x.test", object_ref="S1", success=True, sent_at=NOW,
            )
        )
        self.assertTrue(self.repo.was_notified_since(rule_id="rule-1", object_ref="S1", since=NOW - timedelta(days=1)))
        self.assertFalse(self.repo.was_notified_since(rule_id="rule-1", object_ref="S1", since=NOW + timedelta(days=1)))
        self.assertEqual(len(self.repo.list_log()), 1)


class NotificationServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pki = TempPKI()
        self.repo = NotificationRepository(self.pki.database)
        self.pki.repository.add_person(
            Person(id="p1", name="Alice", surname="Ng", email="al@example.test",
                   created_at=NOW, phone="+48123123123", slack_handle="@al")
        )
        self.pki.repository.add_device(Device(id="d1", device_name="box", admin_id="p1", created_at=NOW))
        self.repo.add_template(
            NotificationTemplate(
                name="notify-expiring", event_type=NotificationEvent.EXPIRING,
                subject="$cert_name expires in $days_until_expiry days",
                body="Hi $person_name, cert $serial expires $expiry_date.",
            )
        )
        self.rule = NotificationRule(
            id="rule-1", event_type=NotificationEvent.EXPIRING, template_name="notify-expiring",
            channel=NotificationChannel.EMAIL, audience=NotificationAudience.HOLDER,
            notification_text="renew soon",
        )
        self.repo.add_rule(self.rule)

    def tearDown(self) -> None:
        self.pki.close()

    def _service(self, comms) -> NotificationService:
        return NotificationService(self.repo, self.pki.repository, comms, portal_url="https://ca.test")

    def test_notify_person_holder(self) -> None:
        comms = FakeComms()
        entries = self._service(comms).notify_certificate(self.rule, _cert(person="p1"), now=NOW)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].recipient, "al@example.test")
        self.assertTrue(entries[0].success)
        # rendered subject/body reached comms
        _channel, recipient, message = comms.sent[0]
        self.assertEqual(recipient, "al@example.test")
        self.assertIn("expires in 10 days", message.subject)
        self.assertIn("cert S1 expires 2026-06-20", message.body)
        # and it was logged for dedup
        self.assertTrue(self.repo.was_notified_since(rule_id="rule-1", object_ref="S1", since=NOW - timedelta(days=1)))

    def test_notify_device_holder_resolves_admin(self) -> None:
        comms = FakeComms()
        entries = self._service(comms).notify_certificate(self.rule, _cert(device="d1"), now=NOW)
        self.assertEqual([e.recipient for e in entries], ["al@example.test"])

    def test_failed_delivery_is_logged(self) -> None:
        comms = FakeComms(fail=True)
        entries = self._service(comms).notify_certificate(self.rule, _cert(person="p1"), now=NOW)
        self.assertEqual(len(entries), 1)
        self.assertFalse(entries[0].success)
        self.assertIn("transport down", entries[0].detail)
        self.assertFalse(self.repo.was_notified_since(rule_id="rule-1", object_ref="S1", since=NOW - timedelta(days=1)))

    def test_slack_channel_uses_handle(self) -> None:
        comms = FakeComms()
        rule = NotificationRule(
            id="rule-slack", event_type=NotificationEvent.EXPIRING, template_name="notify-expiring",
            channel=NotificationChannel.SLACK, audience=NotificationAudience.HOLDER,
        )
        self.repo.add_rule(rule)
        entries = self._service(comms).notify_certificate(rule, _cert(person="p1"), now=NOW)
        self.assertEqual(entries[0].recipient, "@al")

    def test_sms_channel_uses_phone(self) -> None:
        comms = FakeComms()
        rule = NotificationRule(
            id="rule-sms", event_type=NotificationEvent.EXPIRING,
            template_name="notify-expiring", channel=NotificationChannel.SMS,
            audience=NotificationAudience.HOLDER,
        )
        self.repo.add_rule(rule)
        entries = self._service(comms).notify_certificate(
            rule, _cert(person="p1"), now=NOW
        )
        self.assertEqual(entries[0].recipient, "+48123123123")

    def test_audience_approvers(self) -> None:
        self.pki.repository.add_user(User(id="su-1", email="su1@example.test", role=Role.SUPERUSER))
        self.pki.repository.add_user(User(id="su-2", email="su2@example.test", role=Role.SUPERUSER))
        self.pki.repository.add_user(User(id="u-1", email="user@example.test", role=Role.USER))
        rule = NotificationRule(
            id="rule-appr", event_type=NotificationEvent.REQUESTED, template_name="notify-expiring",
            channel=NotificationChannel.EMAIL, audience=NotificationAudience.APPROVERS,
        )
        recipients = self._service(FakeComms()).resolve_recipients(rule)
        self.assertEqual(sorted(recipients), ["su1@example.test", "su2@example.test"])

    def test_audience_requester(self) -> None:
        rule = NotificationRule(
            id="rule-req", event_type=NotificationEvent.REQUESTED, template_name="notify-expiring",
            channel=NotificationChannel.EMAIL, audience=NotificationAudience.REQUESTER,
        )
        recipients = self._service(FakeComms()).resolve_recipients(rule, requester_email="bob@example.test")
        self.assertEqual(recipients, ["bob@example.test"])

    def test_html_format_sets_content_type(self) -> None:
        self.repo.update_template(
            NotificationTemplate(
                name="notify-expiring", event_type=NotificationEvent.EXPIRING,
                format=NotificationFormat.HTML, subject="s", body="<b>$person_name</b>",
            )
        )
        comms = FakeComms()
        self._service(comms).notify_certificate(self.rule, _cert(person="p1"), now=NOW)
        _channel, _recipient, message = comms.sent[0]
        self.assertEqual(message.metadata.get("content_type"), "html")
        self.assertEqual(message.body, "<b>Alice Ng</b>")


if __name__ == "__main__":
    unittest.main()
