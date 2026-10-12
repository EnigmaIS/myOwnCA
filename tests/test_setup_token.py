from __future__ import annotations

import unittest

from myownca.setup.token import SetupAuth


class SetupAuthTests(unittest.TestCase):
    def test_generated_token_is_high_entropy_and_verifies(self) -> None:
        auth = SetupAuth()
        self.assertGreater(len(auth.token), 20)  # token_urlsafe(32) -> 43 chars
        self.assertTrue(auth.verify_token(auth.token))

    def test_token_is_consumed_exactly_once(self) -> None:
        auth = SetupAuth()
        self.assertTrue(auth.consume_token(auth.token))
        self.assertFalse(auth.consume_token(auth.token))
        self.assertFalse(auth.verify_token(auth.token))

    def test_repr_does_not_leak_the_token(self) -> None:
        auth = SetupAuth(token="super-secret-token")
        self.assertNotIn("super-secret-token", repr(auth))

    def test_wrong_or_missing_token_rejected(self) -> None:
        auth = SetupAuth()
        self.assertFalse(auth.verify_token("nope"))
        self.assertFalse(auth.verify_token(""))
        self.assertFalse(auth.verify_token(None))

    def test_injected_token_is_used(self) -> None:
        auth = SetupAuth(token="injected-token")
        self.assertEqual(auth.token, "injected-token")
        self.assertTrue(auth.verify_token("injected-token"))

    def test_no_session_until_opened(self) -> None:
        auth = SetupAuth()
        self.assertFalse(auth.valid_session("anything"))
        self.assertFalse(auth.valid_csrf("anything"))

    def test_open_session_issues_valid_session_and_csrf(self) -> None:
        auth = SetupAuth()
        session_token, csrf_token = auth.open_session()
        self.assertTrue(session_token)
        self.assertTrue(csrf_token)
        self.assertTrue(auth.valid_session(session_token))
        self.assertTrue(auth.valid_csrf(csrf_token))

    def test_session_and_csrf_reject_wrong_values(self) -> None:
        auth = SetupAuth()
        auth.open_session()
        self.assertFalse(auth.valid_session("wrong"))
        self.assertFalse(auth.valid_session(None))
        self.assertFalse(auth.valid_csrf("wrong"))
        self.assertFalse(auth.valid_csrf(None))

    def test_open_session_rotates_previous_session(self) -> None:
        auth = SetupAuth()
        first_session, first_csrf = auth.open_session()
        second_session, second_csrf = auth.open_session()
        self.assertFalse(auth.valid_session(first_session))
        self.assertFalse(auth.valid_csrf(first_csrf))
        self.assertTrue(auth.valid_session(second_session))
        self.assertTrue(auth.valid_csrf(second_csrf))
