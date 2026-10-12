from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from myownca.ca_auth.service import MAX_FAILURES, AuthenticationError, AuthError, ThrottledError
from myownca.domain import Role, SessionStage
from myownca.online.app import create_app
from tests.helpers import add_login_ready_user, create_active_session


class _FakeComms:
    """Captures outbound messages so tests can read the emailed recovery code."""

    def __init__(self) -> None:
        self.sent: list[tuple] = []

    def send(self, channel, recipient, message):
        self.sent.append((channel, recipient, message))
        return None

    def last_code(self) -> str:
        body = self.sent[-1][2].body
        return body.split("recovery code is:")[1].split("\n")[0].strip()


class RecoveryTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        tempdir = self._tmp.name
        self.app = create_app(Path(tempdir) / "auth.sqlite3", online_key_dir=Path(tempdir) / "keys")
        self.auth = self.app.state.auth_service
        self.fake_comms = _FakeComms()
        self.auth.comms = self.fake_comms
        self.secret = add_login_ready_user(
            self.app, user_id="admin-1", email="admin1@example.test", role=Role.ADMIN
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _active_token(self) -> str:
        token, _ = create_active_session(
            self.app, email="admin1@example.test", totp_secret=self.secret
        )
        return token

    def _totp_required_token(self) -> str:
        created = self.auth.login("admin1@example.test", "very-long-test-password")
        self.assertEqual(created.session.stage, SessionStage.TOTP_REQUIRED)
        return created.token


class RecoveryCodeTests(RecoveryTestBase):
    def test_generate_and_use_recovery_code(self) -> None:
        codes = self.auth.regenerate_recovery_codes(self._active_token())
        self.assertEqual(len(codes), 10)

        token = self._totp_required_token()
        created = self.auth.verify_recovery_code(token, codes[0])
        self.assertEqual(created.session.stage, SessionStage.ACTIVE)

    def test_recovery_code_is_single_use(self) -> None:
        codes = self.auth.regenerate_recovery_codes(self._active_token())
        self.auth.verify_recovery_code(self._totp_required_token(), codes[0])
        with self.assertRaises(AuthenticationError):
            self.auth.verify_recovery_code(self._totp_required_token(), codes[0])

    def test_regenerate_invalidates_old_codes(self) -> None:
        active = self._active_token()  # one session; TOTP step can't be reused
        old = self.auth.regenerate_recovery_codes(active)
        self.auth.regenerate_recovery_codes(active)
        with self.assertRaises(AuthenticationError):
            self.auth.verify_recovery_code(self._totp_required_token(), old[0])

    def test_wrong_code_throttled_after_max_failures(self) -> None:
        self.auth.regenerate_recovery_codes(self._active_token())
        token = self._totp_required_token()
        for _ in range(MAX_FAILURES):
            with self.assertRaises(AuthenticationError):
                self.auth.verify_recovery_code(token, "ZZZZZ-ZZZZZ")
        with self.assertRaises(ThrottledError):
            self.auth.verify_recovery_code(token, "ZZZZZ-ZZZZZ")

    def test_codes_not_stored_in_plaintext(self) -> None:
        codes = self.auth.regenerate_recovery_codes(self._active_token())
        with self.app.state.auth_repository.database.connect() as connection:
            rows = connection.execute("SELECT code_hash FROM totp_recovery_codes").fetchall()
        stored = {row["code_hash"] for row in rows}
        normalized = self.auth._normalize_code(codes[0])
        self.assertNotIn(normalized, stored)
        self.assertIn(self.auth._hash_recovery(normalized), stored)


class EmailRecoveryTests(RecoveryTestBase):
    def test_email_recovery_forces_reenrollment(self) -> None:
        token = self._totp_required_token()
        self.auth.request_email_recovery(token)
        self.assertEqual(len(self.fake_comms.sent), 1)
        channel, recipient, _ = self.fake_comms.sent[0]
        self.assertEqual(recipient, "admin1@example.test")

        code = self.fake_comms.last_code()
        created = self.auth.verify_email_recovery(token, code)
        # Logged in but must set up a new authenticator; old factor is gone.
        self.assertEqual(created.session.stage, SessionStage.TOTP_ENROLLMENT_REQUIRED)
        self.assertIsNone(self.app.state.auth_repository.get_totp_factor("admin-1"))

    def test_email_recovery_code_is_single_use(self) -> None:
        token = self._totp_required_token()
        self.auth.request_email_recovery(token)
        code = self.fake_comms.last_code()
        self.auth.verify_email_recovery(token, code)
        # A fresh login is back at TOTP_ENROLLMENT_REQUIRED now (factor cleared),
        # so the consumed code cannot drive another recovery.
        with self.assertRaises(AuthError):
            self.auth.verify_email_recovery(self._enrollment_token(), code)

    def test_wrong_email_code_rejected(self) -> None:
        token = self._totp_required_token()
        self.auth.request_email_recovery(token)
        with self.assertRaises(AuthenticationError):
            self.auth.verify_email_recovery(token, "WRONGCODE")

    def test_email_recovery_requires_comms(self) -> None:
        self.auth.comms = None
        token = self._totp_required_token()
        with self.assertRaises(AuthError):
            self.auth.request_email_recovery(token)

    def test_request_throttled(self) -> None:
        token = self._totp_required_token()
        for _ in range(MAX_FAILURES):
            self.auth.request_email_recovery(token)
        with self.assertRaises(ThrottledError):
            self.auth.request_email_recovery(token)

    def _enrollment_token(self) -> str:
        created = self.auth.login("admin1@example.test", "very-long-test-password")
        return created.token


class RecoveryAPITests(RecoveryTestBase):
    def test_routes_end_to_end(self) -> None:
        from tests.helpers import request_with_session, route_endpoint
        from myownca.online.app import TOTPCodeCreate

        # Generate codes via the authenticated route.
        active_token, active_csrf = create_active_session(
            self.app, email="admin1@example.test", totp_secret=self.secret
        )
        result = route_endpoint(self.app, "/internal/auth/recovery/codes/regenerate", "POST")(
            request_with_session(active_token, active_csrf, method="POST")
        )
        self.assertEqual(len(result["recovery_codes"]), 10)

        # Use one at the TOTP challenge stage via the route.
        created = self.auth.login("admin1@example.test", "very-long-test-password")
        verify = route_endpoint(self.app, "/internal/auth/recovery/code", "POST")
        body = verify(
            TOTPCodeCreate(code=result["recovery_codes"][0]),
            request_with_session(created.token, created.session.csrf_token, method="POST"),
        )
        self.assertEqual(body["stage"], "active")


if __name__ == "__main__":
    unittest.main()
