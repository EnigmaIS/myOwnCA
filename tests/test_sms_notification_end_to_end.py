"""A People phone number must reach the SMS broker's phone parameter.

The pieces are individually covered -- notifications resolve a person's phone,
and the SMS channel builds a request -- but nothing joined them. This walks the
whole path: a Person row, a notification rule on the SMS channel, the real
CommsService with a broker configuration, down to the bytes on the wire.
"""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock
from urllib.parse import parse_qs

from myownca.comms import CommsRepository, CommsService, NotificationChannel
from myownca.domain import CertificateStatus, Device, IssuedCertificate, Person
from myownca.notifications import (
    NotificationAudience,
    NotificationEvent,
    NotificationRepository,
    NotificationRule,
    NotificationService,
    NotificationTemplate,
)
from tests.helpers import TempPKI

NOW = datetime(2026, 6, 10, tzinfo=timezone.utc)
FORM = "application/x-www-form-urlencoded"
HTTP_SEND = "myownca.comms.sms.http_send"


def _certificate(person: str | None = None, device: str | None = None):
    return IssuedCertificate(
        serial_number="S1",
        request_id="r1",
        template_id="host",
        certificate_pem="-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----",
        subject="CN=api.example.test",
        issued_at=NOW,
        expires_at=NOW + timedelta(days=10),
        status=CertificateStatus.ACTIVE,
        holder_person_id=person,
        holder_device_id=device,
    )


class SmsNotificationReachesTheBrokerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pki = TempPKI()
        self.notifications = NotificationRepository(self.pki.database)
        self.pki.repository.add_person(
            Person(
                id="p1",
                name="Alice",
                surname="Ng",
                email="al@example.test",
                created_at=NOW,
                phone="+48123123123",
            )
        )
        self.notifications.add_template(
            NotificationTemplate(
                name="notify-expiring",
                event_type=NotificationEvent.EXPIRING,
                subject="expiring",
                body="Cert $serial expires $expiry_date.",
            )
        )
        self.rule = NotificationRule(
            id="rule-sms",
            event_type=NotificationEvent.EXPIRING,
            template_name="notify-expiring",
            channel=NotificationChannel.SMS,
            audience=NotificationAudience.HOLDER,
        )
        self.notifications.add_rule(self.rule)

        self.comms = CommsService(
            CommsRepository(self.pki.database), "unit-test-secret"
        )
        # A real broker shape: static account fields plus the two named parameters.
        self.comms.set_config(
            NotificationChannel.SMS,
            enabled=True,
            config={
                "url": "https://api.broker.test/sms.php",
                "method": "POST",
                "headers": {"Content-Type": FORM},
                "recipient_param": "number",
                "message_param": "text",
                "extra_params": {
                    "user": "acct",
                    "pass": "{password}",
                    "type": "sms",
                    "from": "SC2labs",
                },
            },
            secrets={"password": "broker-secret"},
        )

    def tearDown(self) -> None:
        self.pki.close()

    def _service(self) -> NotificationService:
        return NotificationService(
            self.notifications,
            self.pki.repository,
            self.comms,
            portal_url="https://ca.test",
        )

    def test_the_persons_phone_becomes_the_brokers_phone_parameter(self) -> None:
        with mock.patch(HTTP_SEND, return_value=(200, "OK")) as sent:
            entries = self._service().notify_certificate(
                self.rule, _certificate(person="p1"), now=NOW
            )

        self.assertEqual(len(entries), 1)
        self.assertTrue(entries[0].success)
        self.assertEqual(entries[0].recipient, "+48123123123")

        args, kwargs = sent.call_args
        self.assertEqual(args[0], "POST")
        fields = parse_qs(kwargs["data"].decode())
        # The whole point: the People phone landed in the configured parameter.
        self.assertEqual(fields["number"], ["+48123123123"])
        self.assertIn("Cert S1 expires", fields["text"][0])
        # …alongside the static broker fields, with the secret resolved.
        self.assertEqual(fields["user"], ["acct"])
        self.assertEqual(fields["pass"], ["broker-secret"])
        self.assertEqual(fields["from"], ["SC2labs"])

    def test_a_device_holder_uses_its_responsible_persons_phone(self) -> None:
        self.pki.repository.add_device(
            Device(id="d1", device_name="box", admin_id="p1", created_at=NOW)
        )

        with mock.patch(HTTP_SEND, return_value=(200, "OK")) as sent:
            entries = self._service().notify_certificate(
                self.rule, _certificate(device="d1"), now=NOW
            )

        self.assertEqual(entries[0].recipient, "+48123123123")
        self.assertEqual(
            parse_qs(sent.call_args.kwargs["data"].decode())["number"],
            ["+48123123123"],
        )

    def test_a_person_without_a_phone_is_recorded_as_skipped(self) -> None:
        """This used to vanish silently: SMS configured and healthy, the
        certificate expiring, and nothing sent because the People row had no
        phone -- no send, no log row, no error. The send is still impossible,
        but it is now visible in the notification log with the reason."""
        self.pki.repository.add_person(
            Person(
                id="p2",
                name="Bob",
                surname="No-Phone",
                email="bob@example.test",
                created_at=NOW,
            )
        )

        with mock.patch(HTTP_SEND, return_value=(200, "OK")) as sent:
            entries = self._service().notify_certificate(
                self.rule, _certificate(person="p2"), now=NOW
            )

        sent.assert_not_called()
        self.assertEqual(len(entries), 1)
        skipped = entries[0]
        self.assertFalse(skipped.success)
        self.assertEqual(skipped.recipient, "")
        self.assertIn("no phone number", skipped.detail.lower())
        # …and it is durable, so the operator can see it in the portal.
        logged = self.notifications.list_log(limit=10)
        self.assertEqual([row.id for row in logged], [skipped.id])

    def test_a_skipped_notification_does_not_suppress_the_next_attempt(self) -> None:
        """The row is unsuccessful, so dedup must not treat it as delivered:
        adding the phone later has to let the notification through."""
        self.pki.repository.add_person(
            Person(
                id="p4",
                name="Dan",
                surname="Late-Phone",
                email="dan@example.test",
                created_at=NOW,
            )
        )
        certificate = _certificate(person="p4")

        with mock.patch(HTTP_SEND, return_value=(200, "OK")):
            self._service().notify_certificate(self.rule, certificate, now=NOW)
        self.assertFalse(
            self.notifications.was_notified_since(
                rule_id="rule-sms", object_ref="S1", since=NOW - timedelta(days=1)
            )
        )

        self.pki.repository.update_person(
            Person(
                id="p4",
                name="Dan",
                surname="Late-Phone",
                email="dan@example.test",
                created_at=NOW,
                phone="+48999888777",
            )
        )
        with mock.patch(HTTP_SEND, return_value=(200, "OK")) as sent:
            entries = self._service().notify_certificate(self.rule, certificate, now=NOW)

        self.assertTrue(entries[0].success)
        self.assertEqual(
            parse_qs(sent.call_args.kwargs["data"].decode())["number"],
            ["+48999888777"],
        )

    def test_an_inapplicable_rule_is_not_reported_as_a_problem(self) -> None:
        """A holder-audience rule on an event with no holder is inapplicable,
        not misconfigured. Logging it would bury the cases worth acting on."""
        from myownca.notifications import NotificationEvent as Event

        self.notifications.add_template(
            NotificationTemplate(
                name="notify-access",
                event_type=Event.ACCESS_REQUESTED,
                subject="access",
                body="$access_email wants in.",
            )
        )
        self.notifications.add_rule(
            NotificationRule(
                id="rule-holder-access",
                event_type=Event.ACCESS_REQUESTED,
                template_name="notify-access",
                channel=NotificationChannel.SMS,
                audience=NotificationAudience.HOLDER,
            )
        )

        entries = self._service().notify_event(
            Event.ACCESS_REQUESTED,
            context_override={"access_email": "stranger@example.test"},
            object_ref="acc-1",
        )

        self.assertEqual(entries, [])
        self.assertEqual(self.notifications.list_log(limit=10), [])

    def test_an_email_rule_is_unaffected_by_the_missing_phone(self) -> None:
        """Proves the drop above is specific to SMS needing a phone."""
        email_rule = NotificationRule(
            id="rule-email",
            event_type=NotificationEvent.EXPIRING,
            template_name="notify-expiring",
            channel=NotificationChannel.EMAIL,
            audience=NotificationAudience.HOLDER,
        )
        self.notifications.add_rule(email_rule)
        self.pki.repository.add_person(
            Person(
                id="p3",
                name="Cara",
                surname="No-Phone",
                email="cara@example.test",
                created_at=NOW,
            )
        )

        recipients = self._service().resolve_recipients(
            email_rule, person=self.pki.repository.get_person("p3")
        )
        self.assertEqual(recipients, ["cara@example.test"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
