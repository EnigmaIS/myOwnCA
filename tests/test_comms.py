from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from myownca.comms import (
    Attachment,
    ChannelConfig,
    CommsConfigError,
    CommsError,
    CommsRepository,
    CommsService,
    Message,
    NotificationChannel,
)
from myownca.comms._http import http_send
from myownca.comms.email import send_email
from myownca.comms.httpreq import send_https
from myownca.comms.slack import send_slack
from myownca.comms.sms import send_sms
from myownca.comms.webhook import send_webhook
from myownca.storage.database import Database


def _service(tempdir: str) -> CommsService:
    db = Database(Path(tempdir) / "comms.sqlite3")
    db.migrate()
    return CommsService(CommsRepository(db), "unit-test-secret")


class CommsServiceConfigTests(unittest.TestCase):
    def test_secret_roundtrip_and_redaction(self) -> None:
        with TemporaryDirectory() as tempdir:
            service = _service(tempdir)
            redacted = service.set_config(
                NotificationChannel.EMAIL,
                enabled=True,
                config={"host": "smtp.example.test", "from_address": "ca@example.test"},
                secrets={"password": "hunter2"},
            )
            self.assertTrue(redacted["enabled"])
            self.assertEqual(redacted["secrets_set"], {"password": True})
            self.assertNotIn("hunter2", json.dumps(redacted))  # secret value never surfaced

            config = service.get_config(NotificationChannel.EMAIL)
            self.assertEqual(config.secrets["password"], "hunter2")
            self.assertEqual(config.config["host"], "smtp.example.test")

    def test_secret_is_encrypted_at_rest(self) -> None:
        with TemporaryDirectory() as tempdir:
            service = _service(tempdir)
            service.set_config(
                NotificationChannel.SLACK,
                enabled=True,
                config={},
                secrets={"bot_token": "xoxb-super-secret"},
            )
            stored = service.repository.get("slack")
            self.assertNotIn("xoxb-super-secret", stored.secret_ciphertext)
            self.assertTrue(stored.secret_ciphertext)

    def test_sms_bearer_token_is_encrypted_and_redacted(self) -> None:
        with TemporaryDirectory() as tempdir:
            service = _service(tempdir)
            redacted = service.set_config(
                NotificationChannel.SMS,
                enabled=True,
                config={"url": "https://sms.example.test/send"},
                secrets={"bearer_token": "sms-super-secret"},
            )
            # SMS also understands a 'password' secret, for brokers whose
            # credential is a request parameter rather than a bearer header.
            self.assertTrue(redacted["secrets_set"]["bearer_token"])
            self.assertFalse(redacted["secrets_set"]["password"])
            self.assertNotIn("sms-super-secret", json.dumps(redacted))
            stored = service.repository.get("sms")
            self.assertNotIn("sms-super-secret", stored.secret_ciphertext)

    def test_empty_secret_keeps_existing(self) -> None:
        with TemporaryDirectory() as tempdir:
            service = _service(tempdir)
            service.set_config(
                NotificationChannel.SLACK, enabled=True, config={}, secrets={"bot_token": "tok-1"}
            )
            # Re-save without re-entering the token.
            service.set_config(
                NotificationChannel.SLACK, enabled=False, config={"team": "x"}, secrets={"bot_token": ""}
            )
            config = service.get_config(NotificationChannel.SLACK)
            self.assertEqual(config.secrets["bot_token"], "tok-1")
            self.assertFalse(config.enabled)

    def test_send_requires_enabled_channel(self) -> None:
        with TemporaryDirectory() as tempdir:
            service = _service(tempdir)
            with self.assertRaises(CommsConfigError):
                service.send(NotificationChannel.EMAIL, "x@example.test", Message(body="hi"))
            service.set_config(
                NotificationChannel.EMAIL,
                enabled=False,
                config={"host": "h", "from_address": "f@x"},
                secrets={},
            )
            with self.assertRaises(CommsConfigError):
                service.send(NotificationChannel.EMAIL, "x@example.test", Message(body="hi"))


class EmailNotifierTests(unittest.TestCase):
    def _config(self, **over) -> ChannelConfig:
        config = {"host": "smtp.example.test", "from_address": "ca@example.test", "username": "u"}
        config.update(over)
        return ChannelConfig(
            channel=NotificationChannel.EMAIL,
            enabled=True,
            config=config,
            secrets={"password": "pw"},
        )

    def test_starttls_login_and_send(self) -> None:
        server = mock.MagicMock()
        with mock.patch("myownca.comms.email.smtplib.SMTP", return_value=server) as smtp:
            server.__enter__.return_value = server
            result = send_email(
                self._config(security="starttls", port=587),
                "alice@example.test",
                Message(body="Your cert is ready", subject="Cert"),
            )
        smtp.assert_called_once()
        server.starttls.assert_called_once()
        server.login.assert_called_once_with("u", "pw")
        server.send_message.assert_called_once()
        self.assertTrue(result.success)

    def test_ssl_mode_uses_smtp_ssl(self) -> None:
        server = mock.MagicMock()
        server.__enter__.return_value = server
        with mock.patch("myownca.comms.email.smtplib.SMTP_SSL", return_value=server) as smtp_ssl:
            send_email(self._config(security="ssl", port=465), "a@example.test", Message(body="b"))
        smtp_ssl.assert_called_once()
        server.starttls.assert_not_called()

    def test_smtp_failure_becomes_comms_error(self) -> None:
        import smtplib

        with mock.patch("myownca.comms.email.smtplib.SMTP", side_effect=smtplib.SMTPException("boom")):
            with self.assertRaises(CommsError):
                send_email(self._config(), "a@example.test", Message(body="b"))

    def test_html_content_type_sends_html_body(self) -> None:
        server = mock.MagicMock()
        server.__enter__.return_value = server
        with mock.patch("myownca.comms.email.smtplib.SMTP", return_value=server):
            send_email(
                self._config(),
                "alice@example.test",
                Message(body="<b>hi</b>", subject="s", metadata={"content_type": "html"}),
            )
        sent = server.send_message.call_args[0][0]
        self.assertEqual(sent.get_content_type(), "text/html")
        self.assertIn("<b>hi</b>", sent.get_content())

    def test_default_content_type_stays_plain_text(self) -> None:
        server = mock.MagicMock()
        server.__enter__.return_value = server
        with mock.patch("myownca.comms.email.smtplib.SMTP", return_value=server):
            send_email(self._config(), "alice@example.test", Message(body="plain"))
        sent = server.send_message.call_args[0][0]
        self.assertEqual(sent.get_content_type(), "text/plain")

    def test_binary_attachment_is_sent_with_declared_name_and_media_type(self) -> None:
        server = mock.MagicMock()
        server.__enter__.return_value = server
        with mock.patch("myownca.comms.email.smtplib.SMTP", return_value=server):
            send_email(
                self._config(),
                "alice@example.test",
                Message(
                    body="bundle attached",
                    attachments=(
                        Attachment(
                            content=b"pkcs12-bytes",
                            filename="alice.p12",
                            media_type="application/x-pkcs12",
                        ),
                    ),
                ),
            )
        sent = server.send_message.call_args.args[0]
        attachment = next(part for part in sent.iter_attachments())
        self.assertEqual(attachment.get_content_type(), "application/x-pkcs12")
        self.assertEqual(attachment.get_filename(), "alice.p12")
        self.assertEqual(attachment.get_payload(decode=True), b"pkcs12-bytes")


class SMSNotifierTests(unittest.TestCase):
    def _config(self, **over) -> ChannelConfig:
        config = {"url": "https://sms.example.test/send"}
        config.update(over)
        return ChannelConfig(
            channel=NotificationChannel.SMS,
            enabled=True,
            config=config,
            secrets={"bearer_token": "secret-token"},
        )

    def test_posts_default_json_with_bearer_token(self) -> None:
        with mock.patch(
            "myownca.comms.sms.http_send", return_value=(202, "accepted")
        ) as send:
            result = send_sms(
                self._config(),
                "+48123123123",
                Message(body="Code 12345678", subject="Recovery"),
            )
        method, url = send.call_args.args
        self.assertEqual((method, url), ("POST", "https://sms.example.test/send"))
        self.assertEqual(
            json.loads(send.call_args.kwargs["data"]),
            {"to": "+48123123123", "message": "Code 12345678"},
        )
        self.assertEqual(
            send.call_args.kwargs["headers"]["Authorization"],
            "Bearer secret-token",
        )
        self.assertTrue(result.success)
        self.assertEqual(result.status_code, 202)

    def test_custom_template_is_json_escaped_and_4xx_is_failure(self) -> None:
        template = '{"recipient":"{recipient}","subject":"{subject}","text":"{body}"}'
        with mock.patch(
            "myownca.comms.sms.http_send", return_value=(400, "bad request")
        ) as send:
            result = send_sms(
                self._config(body_template=template),
                "+48\"123",
                Message(body="line\nnext", subject="s"),
            )
        self.assertEqual(
            json.loads(send.call_args.kwargs["data"]),
            {"recipient": "+48\"123", "subject": "s", "text": "line\nnext"},
        )
        self.assertFalse(result.success)
        self.assertEqual(result.status_code, 400)

    def test_requires_https_and_recipient(self) -> None:
        with self.assertRaises(CommsError):
            send_sms(
                self._config(url="http://sms.example.test/send"),
                "+48123",
                Message(body="code"),
            )
        with self.assertRaises(CommsError):
            send_sms(self._config(), "", Message(body="code"))
        with self.assertRaises(CommsConfigError):
            send_sms(
                self._config(body_template="not-json {body}"),
                "+48123",
                Message(body="code"),
            )


class SlackNotifierTests(unittest.TestCase):
    def _config(self) -> ChannelConfig:
        return ChannelConfig(
            channel=NotificationChannel.SLACK,
            enabled=True,
            config={},
            secrets={"bot_token": "xoxb-1"},
        )

    def test_email_resolution_then_dm(self) -> None:
        calls = []

        def fake(method, url, *, headers=None, data=None, **kw):
            calls.append(url)
            if "users.lookupByEmail" in url:
                return 200, json.dumps({"ok": True, "user": {"id": "U1"}})
            if "conversations.open" in url:
                return 200, json.dumps({"ok": True, "channel": {"id": "D1"}})
            if "chat.postMessage" in url:
                return 200, json.dumps({"ok": True})
            raise AssertionError(url)

        with mock.patch("myownca.comms.slack.http_send", side_effect=fake):
            result = send_slack(self._config(), "alice@example.test", Message(body="hi", subject="s"))
        self.assertTrue(result.success)
        self.assertEqual(result.detail, "delivered to U1")
        self.assertTrue(any("users.lookupByEmail" in c for c in calls))

    def test_slack_api_error_raises(self) -> None:
        def fake(method, url, **kw):
            return 200, json.dumps({"ok": False, "error": "users_not_found"})

        with mock.patch("myownca.comms.slack.http_send", side_effect=fake):
            with self.assertRaises(CommsError):
                send_slack(self._config(), "ghost@example.test", Message(body="hi"))

    def test_missing_token_is_config_error(self) -> None:
        config = ChannelConfig(channel=NotificationChannel.SLACK, enabled=True, config={}, secrets={})
        with self.assertRaises(CommsConfigError):
            send_slack(config, "a@example.test", Message(body="b"))


class WebhookNotifierTests(unittest.TestCase):
    def test_posts_payload_with_signature(self) -> None:
        captured = {}

        def fake(method, url, *, headers=None, data=None, **kw):
            captured["url"] = url
            captured["headers"] = headers
            captured["data"] = data
            return 204, ""

        config = ChannelConfig(
            channel=NotificationChannel.WEBHOOK,
            enabled=True,
            config={"url": "https://hooks.example.test/x"},
            secrets={"signing_secret": "s3cr3t"},
        )
        with mock.patch("myownca.comms.webhook.http_send", side_effect=fake):
            result = send_webhook(config, "alice@example.test", Message(body="hi", subject="s"))
        self.assertTrue(result.success)
        self.assertEqual(result.status_code, 204)
        payload = json.loads(captured["data"])
        self.assertEqual(payload["recipient"], "alice@example.test")
        self.assertTrue(captured["headers"]["X-myOwnCA-Signature"].startswith("sha256="))

    def test_non_2xx_is_unsuccessful(self) -> None:
        config = ChannelConfig(
            channel=NotificationChannel.WEBHOOK,
            enabled=True,
            config={"url": "https://hooks.example.test/x"},
        )
        with mock.patch("myownca.comms.webhook.http_send", return_value=(500, "nope")):
            result = send_webhook(config, "a", Message(body="b"))
        self.assertFalse(result.success)
        self.assertEqual(result.status_code, 500)


class HttpsNotifierTests(unittest.TestCase):
    def test_renders_template_and_bearer(self) -> None:
        captured = {}

        def fake(method, url, *, headers=None, data=None, **kw):
            captured.update(method=method, url=url, headers=headers, data=data)
            return 200, "ok"

        config = ChannelConfig(
            channel=NotificationChannel.HTTPS,
            enabled=True,
            config={
                "url": "https://api.example.test/notify",
                "method": "POST",
                "body_template": '{"to": "{recipient}", "text": "{body}"}',
            },
            secrets={"bearer_token": "tok"},
        )
        with mock.patch("myownca.comms.httpreq.http_send", side_effect=fake):
            result = send_https(config, "alice@example.test", Message(body='he said "hi"'))
        self.assertTrue(result.success)
        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["headers"]["Authorization"], "Bearer tok")
        body = json.loads(captured["data"])  # valid JSON despite quotes in body
        self.assertEqual(body["to"], "alice@example.test")
        self.assertEqual(body["text"], 'he said "hi"')


class HttpTransportTests(unittest.TestCase):
    def test_rejects_non_https(self) -> None:
        with self.assertRaises(CommsError):
            http_send("POST", "http://insecure.example.test", require_https=True)


class CommsAPITests(unittest.TestCase):
    def _admin_app(self, tempdir: str):
        from myownca.domain import Role
        from myownca.online.app import create_app
        from tests.helpers import add_login_ready_user, create_active_session

        app = create_app(Path(tempdir) / "comms-api.sqlite3")
        admin_secret = add_login_ready_user(
            app, user_id="admin-1", email="admin1@example.test", role=Role.ADMIN
        )
        add_login_ready_user(app, user_id="user-1", email="user@example.test", role=Role.USER)
        admin = create_active_session(app, email="admin1@example.test", totp_secret=admin_secret)
        user = create_active_session(app, email="user@example.test")
        return app, admin, user

    def test_list_configure_and_send_flow(self) -> None:
        from myownca.online.app import (
            CommsChannelConfigUpdate,
            CommsSendRequest,
        )
        from tests.helpers import request_with_session, route_endpoint

        with TemporaryDirectory() as tempdir:
            app, (admin_token, admin_csrf), (user_token, user_csrf) = self._admin_app(tempdir)

            channels = route_endpoint(app, "/internal/comms/channels", "GET")(
                request_with_session(admin_token)
            )
            self.assertEqual(
                {c["channel"] for c in channels},
                {"email", "sms", "slack", "webhook", "https"},
            )

            route_endpoint(app, "/internal/comms/channels/{channel}", "PUT")(
                "webhook",
                CommsChannelConfigUpdate(
                    enabled=True,
                    config={"url": "https://hooks.example.test/x"},
                    secrets={"signing_secret": "s"},
                ),
                request_with_session(admin_token, admin_csrf, method="PUT"),
            )

            with mock.patch("myownca.comms.webhook.http_send", return_value=(200, "ok")):
                result = route_endpoint(app, "/internal/comms/send", "POST")(
                    CommsSendRequest(channel="webhook", recipient="alice@example.test", body="hi"),
                    request_with_session(admin_token, admin_csrf, method="POST"),
                )
            self.assertTrue(result["success"])
            self.assertEqual(result["channel"], "webhook")

    def test_role_gating_and_invalid_channel(self) -> None:
        from fastapi import HTTPException

        from myownca.online.app import CommsChannelConfigUpdate
        from tests.helpers import request_with_session, route_endpoint

        with TemporaryDirectory() as tempdir:
            app, (admin_token, admin_csrf), (user_token, user_csrf) = self._admin_app(tempdir)

            with self.assertRaises(HTTPException) as forbidden:
                route_endpoint(app, "/internal/comms/channels", "GET")(
                    request_with_session(user_token)
                )
            self.assertEqual(forbidden.exception.status_code, 403)

            with self.assertRaises(HTTPException) as not_found:
                route_endpoint(app, "/internal/comms/channels/{channel}", "PUT")(
                    "carrier-pigeon",
                    CommsChannelConfigUpdate(enabled=True),
                    request_with_session(admin_token, admin_csrf, method="PUT"),
                )
            self.assertEqual(not_found.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
