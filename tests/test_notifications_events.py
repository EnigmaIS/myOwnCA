from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from myownca.comms import DeliveryResult, NotificationChannel
from myownca.domain import CertificateProfile, CertificateTemplate, Role
from myownca.notifications import (
    NotificationAudience,
    NotificationEvent,
    NotificationRule,
    NotificationTemplate,
)
from myownca.online.app import create_app
from tests.helpers import (
    add_login_ready_user,
    create_active_session,
    make_csr,
    request_with_session,
    route_endpoint,
    seed_person,
)


def _issuance_app(tempdir: str):
    app = create_app(Path(tempdir) / "ev.sqlite3", lab_mode=True)
    su1 = add_login_ready_user(app, user_id="su-1", email="su1@example.test", role=Role.SUPERUSER)
    su2 = add_login_ready_user(app, user_id="su-2", email="su2@example.test", role=Role.SUPERUSER)
    add_login_ready_user(app, user_id="user-1", email="user@example.test", role=Role.USER)
    app.state.repository.add_template(
        CertificateTemplate(id="host", name="Host", profile=CertificateProfile.HOST_TLS)
    )
    tokens = {
        "su1": create_active_session(app, email="su1@example.test", totp_secret=su1),
        "su2": create_active_session(app, email="su2@example.test", totp_secret=su2),
        "user": create_active_session(app, email="user@example.test"),
    }
    return app, tokens


def _add_template(app, name: str, event: NotificationEvent) -> None:
    app.state.notifications.repository.add_template(
        NotificationTemplate(
            name=name, event_type=event,
            subject=f"[{event.value}] $cert_name$request_id",
            body="to $person_email / $requester_email — $notification_text",
        )
    )


def _add_rule(app, rule_id: str, event: NotificationEvent, template: str, audience: NotificationAudience) -> None:
    app.state.notifications.repository.add_rule(
        NotificationRule(
            id=rule_id, event_type=event, template_name=template,
            channel=NotificationChannel.WEBHOOK, audience=audience,
        )
    )


def _enable_webhook(app) -> None:
    app.state.comms.set_config(
        NotificationChannel.WEBHOOK, enabled=True, config={"url": "https://hook.test/x"}, secrets={}
    )


class IssuedEventHookTests(unittest.TestCase):
    def test_issuance_notifies_holder(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, tokens = _issuance_app(tempdir)
            _add_template(app, "notify-issued", NotificationEvent.ISSUED)
            _add_rule(app, "r-issued", NotificationEvent.ISSUED, "notify-issued", NotificationAudience.HOLDER)
            _enable_webhook(app)
            seed_person(app)  # holder@example.test

            req = app.state.service.submit_request(
                "host", make_csr("h.example.test", dns_names=("h.example.test",)), requested_by_user_id="user-1"
            )
            app.state.service.assign_request_holder(req.id, person_id="person-default")
            approve = route_endpoint(app, "/internal/certificate-requests/{request_id}/approvals", "POST")
            with mock.patch("myownca.comms.webhook.http_send", return_value=(200, "ok")):
                token, csrf = tokens["su1"]
                approve(req.id, request_with_session(token, csrf, method="POST"))
                token, csrf = tokens["su2"]
                result = approve(req.id, request_with_session(token, csrf, method="POST"))
            self.assertTrue(result["auto_issued"])
            log = app.state.notifications.repository.list_log()
            issued_rows = [row for row in log if row.event_type == "issued"]
            self.assertEqual(len(issued_rows), 1)
            self.assertEqual(issued_rows[0].recipient, "holder@example.test")
            self.assertTrue(issued_rows[0].success)

    def test_issuance_succeeds_even_when_comms_fails(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, tokens = _issuance_app(tempdir)
            _add_template(app, "notify-issued", NotificationEvent.ISSUED)
            _add_rule(app, "r-issued", NotificationEvent.ISSUED, "notify-issued", NotificationAudience.HOLDER)
            # webhook channel left UNCONFIGURED → comms raises on send
            seed_person(app)
            req = app.state.service.submit_request(
                "host", make_csr("h2.example.test", dns_names=("h2.example.test",)), requested_by_user_id="user-1"
            )
            app.state.service.assign_request_holder(req.id, person_id="person-default")
            approve = route_endpoint(app, "/internal/certificate-requests/{request_id}/approvals", "POST")
            token, csrf = tokens["su1"]
            approve(req.id, request_with_session(token, csrf, method="POST"))
            token, csrf = tokens["su2"]
            result = approve(req.id, request_with_session(token, csrf, method="POST"))
            # Issuance unaffected; the failed delivery is recorded, not raised.
            self.assertTrue(result["auto_issued"])
            log = app.state.notifications.repository.list_log()
            issued_rows = [row for row in log if row.event_type == "issued"]
            self.assertEqual(len(issued_rows), 1)
            self.assertFalse(issued_rows[0].success)


class RequestedEventHookTests(unittest.TestCase):
    def test_request_notifies_requester_and_approvers(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, tokens = _issuance_app(tempdir)
            _add_template(app, "notify-requested", NotificationEvent.REQUESTED)
            _add_rule(app, "r-req", NotificationEvent.REQUESTED, "notify-requested", NotificationAudience.REQUESTER)
            _add_rule(app, "r-appr", NotificationEvent.REQUESTED, "notify-requested", NotificationAudience.APPROVERS)
            _enable_webhook(app)

            from myownca.online.app import RequestCreate

            token, csrf = tokens["user"]
            with mock.patch("myownca.comms.webhook.http_send", return_value=(200, "ok")):
                route_endpoint(app, "/internal/certificate-requests", "POST")(
                    RequestCreate(template_id="host", csr_pem=make_csr("r.example.test", dns_names=("r.example.test",))),
                    request_with_session(token, csrf, method="POST"),
                )
            recipients = sorted(
                row.recipient
                for row in app.state.notifications.repository.list_log()
                if row.event_type == "requested"
            )
            self.assertEqual(
                recipients, ["su1@example.test", "su2@example.test", "user@example.test"]
            )


class OTPTemplateTests(unittest.TestCase):
    class _CaptureComms:
        def __init__(self) -> None:
            self.sent: list[tuple] = []

        def send(self, channel, recipient, message):
            self.sent.append((channel, recipient, message))
            return DeliveryResult(channel=channel, recipient=recipient, success=True)

    def test_otp_uses_template_when_present_and_falls_back_when_absent(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _tokens = _issuance_app(tempdir)
            capture = self._CaptureComms()
            app.state.auth_service.comms = capture
            user = app.state.auth_repository.get_user("user-1")

            # No otp template yet → default hardcoded text.
            app.state.auth_service._send_recovery_email(user, "483921")
            _channel, recipient, message = capture.sent[-1]
            self.assertEqual(recipient, "user@example.test")
            self.assertIn("Your myOwnCA account recovery code is: 483921", message.body)

            # With an otp template the rendered content is used instead —
            # but delivery still goes to the user's own email.
            app.state.notifications.repository.add_template(
                NotificationTemplate(
                    name="notify-otp", event_type=NotificationEvent.OTP,
                    subject="Code $otp_code", body="Use $otp_code within $otp_expires_minutes minutes.",
                )
            )
            app.state.auth_service._send_recovery_email(user, "112233")
            _channel, recipient, message = capture.sent[-1]
            self.assertEqual(recipient, "user@example.test")
            self.assertEqual(message.subject, "Code 112233")
            self.assertIn("Use 112233 within 15 minutes.", message.body)


if __name__ == "__main__":
    unittest.main()
