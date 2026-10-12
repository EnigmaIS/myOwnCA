from __future__ import annotations

import re
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from starlette.responses import Response

from myownca.ca_auth.service import AuthenticationError, ThrottledError
from myownca.comms import (
    ChannelConfig,
    DeliveryResult,
    NotificationChannel,
)
from myownca.domain import Person, Role, SessionStage
from myownca.online.app import (
    PasswordChangeCreate,
    PasswordRecoveryRequest,
    PasswordRecoveryVerify,
    create_app,
)
from tests.helpers import (
    add_login_ready_user,
    create_active_session,
    request_with_session,
    route_endpoint,
)

NOW = datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc)


class CaptureComms:
    def __init__(self, enabled: set[NotificationChannel] | None = None) -> None:
        self.enabled = enabled or set(NotificationChannel)
        self.sent: list[tuple[NotificationChannel, str, object]] = []

    def get_config(self, channel: NotificationChannel):
        if channel not in self.enabled:
            return None
        return ChannelConfig(channel=channel, enabled=True)

    def send(self, channel, recipient, message):
        self.sent.append((channel, recipient, message))
        return DeliveryResult(channel=channel, recipient=recipient, success=True)

    def last_code(self) -> str:
        match = re.search(r"recovery code is: (\d{8})", self.sent[-1][2].body)
        assert match is not None
        return match.group(1)


class PasswordRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = TemporaryDirectory()
        self.app = create_app(Path(self.tmp.name) / "recovery.sqlite3")
        self.auth = self.app.state.auth_service
        self.comms = CaptureComms()
        self.auth.comms = self.comms

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def add_person(
        self,
        email: str,
        *,
        phone: str = "+48123123123",
        slack_handle: str = "@alice",
    ) -> None:
        self.app.state.repository.add_person(
            Person(
                id=f"person-{len(self.app.state.repository.list_people()) + 1}",
                name="Alice",
                surname="Admin",
                email=email,
                phone=phone,
                slack_handle=slack_handle,
                created_at=NOW,
            )
        )

    def test_recovery_resets_required_totp_only_when_password_is_saved(self) -> None:
        secret = add_login_ready_user(
            self.app,
            user_id="admin-1",
            email="admin@example.test",
            role=Role.ADMIN,
        )
        old_token, _ = create_active_session(
            self.app,
            email="admin@example.test",
            totp_secret=secret,
        )

        self.auth.request_password_recovery(
            "admin@example.test", NotificationChannel.EMAIL, now=NOW
        )
        code = self.comms.last_code()
        recovered = self.auth.verify_password_recovery(
            "admin@example.test", NotificationChannel.EMAIL, code, now=NOW
        )
        self.assertEqual(
            recovered.session.stage,
            SessionStage.PASSWORD_RECOVERY_REQUIRED,
        )
        self.assertIsNotNone(self.app.state.auth_repository.get_totp_factor("admin-1"))
        self.assertEqual(
            self.auth.login("admin@example.test", "very-long-test-password", now=NOW).session.stage,
            SessionStage.TOTP_REQUIRED,
        )
        with self.assertRaises(AuthenticationError):
            self.auth.verify_password_recovery(
                "admin@example.test", NotificationChannel.EMAIL, code, now=NOW
            )

        completed = self.auth.change_password(
            recovered.token,
            "new-very-long-password",
            now=NOW + timedelta(seconds=1),
        )
        self.assertEqual(completed.session.stage, SessionStage.TOTP_ENROLLMENT_REQUIRED)
        self.assertIsNone(self.app.state.auth_repository.get_totp_factor("admin-1"))
        with self.assertRaises(AuthenticationError):
            self.auth.require_session(old_token, now=NOW + timedelta(seconds=1))
        with self.assertRaises(AuthenticationError):
            self.auth.login("admin@example.test", "very-long-test-password", now=NOW)
        self.assertEqual(
            self.auth.login("admin@example.test", "new-very-long-password", now=NOW).session.stage,
            SessionStage.TOTP_ENROLLMENT_REQUIRED,
        )

    def test_non_totp_role_becomes_active_and_sms_uses_person_phone(self) -> None:
        add_login_ready_user(
            self.app,
            user_id="user-1",
            email="user@example.test",
            role=Role.USER,
        )
        self.add_person("user@example.test")
        old_token, _ = create_active_session(self.app, email="user@example.test")

        self.auth.request_password_recovery(
            "user@example.test", NotificationChannel.SMS, now=NOW
        )
        channel, recipient, _message = self.comms.sent[-1]
        self.assertEqual(channel, NotificationChannel.SMS)
        self.assertEqual(recipient, "+48123123123")
        recovered = self.auth.verify_password_recovery(
            "user@example.test", NotificationChannel.SMS, self.comms.last_code(), now=NOW
        )
        completed = self.auth.change_password(
            recovered.token,
            "another-long-password",
            now=NOW + timedelta(seconds=1),
        )
        self.assertEqual(completed.session.stage, SessionStage.ACTIVE)
        with self.assertRaises(AuthenticationError):
            self.auth.require_session(old_token, now=NOW + timedelta(seconds=1))

    def test_certificate_operator_and_auditor_follow_their_totp_policy(self) -> None:
        cases = (
            (Role.SUPERUSER, SessionStage.TOTP_ENROLLMENT_REQUIRED),
            (Role.AUDITOR, SessionStage.ACTIVE),
        )
        for index, (role, expected_stage) in enumerate(cases, start=1):
            with self.subTest(role=role):
                email = f"role-{index}@example.test"
                add_login_ready_user(
                    self.app,
                    user_id=f"role-{index}",
                    email=email,
                    role=role,
                )
                self.auth.request_password_recovery(
                    email, NotificationChannel.EMAIL, now=NOW
                )
                recovered = self.auth.verify_password_recovery(
                    email,
                    NotificationChannel.EMAIL,
                    self.comms.last_code(),
                    now=NOW,
                )
                completed = self.auth.change_password(
                    recovered.token,
                    f"role-{index}-recovered-password",
                    now=NOW + timedelta(seconds=1),
                )
                self.assertEqual(completed.session.stage, expected_stage)

    def test_lost_totp_recovery_can_use_sms(self) -> None:
        add_login_ready_user(
            self.app,
            user_id="admin-1",
            email="admin@example.test",
            role=Role.ADMIN,
        )
        self.add_person("admin@example.test")
        login = self.auth.login("admin@example.test", "very-long-test-password", now=NOW)
        self.assertEqual(login.session.stage, SessionStage.TOTP_REQUIRED)
        self.auth.request_delivery_recovery(
            login.token,
            NotificationChannel.SMS,
            now=NOW,
        )
        recovered = self.auth.verify_delivery_recovery(
            login.token,
            NotificationChannel.SMS,
            self.comms.last_code(),
            now=NOW,
        )
        self.assertEqual(recovered.session.stage, SessionStage.TOTP_ENROLLMENT_REQUIRED)
        self.assertIsNone(self.app.state.auth_repository.get_totp_factor("admin-1"))

    def test_every_enabled_channel_resolves_the_expected_recipient(self) -> None:
        add_login_ready_user(
            self.app,
            user_id="user-1",
            email="alice@example.test",
            role=Role.USER,
        )
        self.add_person("alice@example.test")
        for channel in NotificationChannel:
            self.auth.request_password_recovery(
                "alice@example.test", channel, now=NOW
            )
        recipients = {channel: recipient for channel, recipient, _ in self.comms.sent}
        self.assertEqual(recipients[NotificationChannel.EMAIL], "alice@example.test")
        self.assertEqual(recipients[NotificationChannel.SMS], "+48123123123")
        self.assertEqual(recipients[NotificationChannel.SLACK], "@alice")
        self.assertEqual(recipients[NotificationChannel.WEBHOOK], "alice@example.test")
        self.assertEqual(recipients[NotificationChannel.HTTPS], "alice@example.test")
        self.assertEqual(
            self.auth.available_recovery_channels(),
            ["email", "sms", "slack", "webhook", "https"],
        )

    def test_unknown_account_missing_contact_and_disabled_channel_are_silent(self) -> None:
        add_login_ready_user(
            self.app,
            user_id="user-1",
            email="user@example.test",
            role=Role.USER,
        )
        self.auth.request_password_recovery(
            "missing@example.test", NotificationChannel.EMAIL, now=NOW
        )
        self.auth.request_password_recovery(
            "user@example.test", NotificationChannel.SMS, now=NOW
        )
        self.comms.enabled.remove(NotificationChannel.SLACK)
        self.auth.request_password_recovery(
            "user@example.test", NotificationChannel.SLACK, now=NOW
        )
        self.assertEqual(self.comms.sent, [])

    def test_code_expires_and_requests_are_rate_limited(self) -> None:
        add_login_ready_user(
            self.app,
            user_id="user-1",
            email="user@example.test",
            role=Role.USER,
        )
        self.auth.request_password_recovery(
            "user@example.test", NotificationChannel.EMAIL, now=NOW
        )
        expired_code = self.comms.last_code()
        with self.assertRaises(AuthenticationError):
            self.auth.verify_password_recovery(
                "user@example.test",
                NotificationChannel.EMAIL,
                expired_code,
                now=NOW + timedelta(minutes=16),
            )

        later = NOW + timedelta(hours=2)
        before = len(self.comms.sent)
        for _ in range(6):
            self.auth.request_password_recovery(
                "user@example.test", NotificationChannel.EMAIL, now=later
            )
        self.assertEqual(len(self.comms.sent) - before, 5)

    def test_wrong_codes_are_throttled(self) -> None:
        add_login_ready_user(
            self.app,
            user_id="user-1",
            email="user@example.test",
            role=Role.USER,
        )
        self.auth.request_password_recovery(
            "user@example.test", NotificationChannel.EMAIL, now=NOW
        )
        for _ in range(5):
            with self.assertRaises(AuthenticationError):
                self.auth.verify_password_recovery(
                    "user@example.test", NotificationChannel.EMAIL, "00000000", now=NOW
                )
        with self.assertRaises(ThrottledError):
            self.auth.verify_password_recovery(
                "user@example.test", NotificationChannel.EMAIL, "00000000", now=NOW
            )

    def test_public_api_is_generic_and_completes_recovery(self) -> None:
        add_login_ready_user(
            self.app,
            user_id="user-1",
            email="user@example.test",
            role=Role.USER,
        )
        request_endpoint = route_endpoint(
            self.app, "/internal/auth/password/recovery/request", "POST"
        )
        known = request_endpoint(
            PasswordRecoveryRequest(
                email="user@example.test", channel=NotificationChannel.EMAIL
            ),
            request_with_session(method="POST"),
        )
        unknown = request_endpoint(
            PasswordRecoveryRequest(
                email="missing@example.test", channel=NotificationChannel.EMAIL
            ),
            request_with_session(method="POST"),
        )
        self.assertEqual(known, unknown)

        response = Response()
        verified = route_endpoint(
            self.app, "/internal/auth/password/recovery/verify", "POST"
        )(
            PasswordRecoveryVerify(
                email="user@example.test",
                channel=NotificationChannel.EMAIL,
                code=self.comms.last_code(),
            ),
            request_with_session(method="POST"),
            response,
        )
        self.assertEqual(verified["stage"], "password_recovery_required")
        token = response.headers["set-cookie"].split("myownca_session=", 1)[1].split(";", 1)[0]
        completed = route_endpoint(
            self.app, "/internal/auth/password/change", "POST"
        )(
            PasswordChangeCreate(new_password="api-recovered-password"),
            request_with_session(token, verified["csrf_token"], method="POST"),
        )
        self.assertEqual(completed["stage"], "active")


if __name__ == "__main__":
    unittest.main()
