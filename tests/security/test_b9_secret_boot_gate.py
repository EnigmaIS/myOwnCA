"""B9 — a production install must not boot on the placeholder encryption secret.

`config.py` silently substitutes "change-me-for-local-testing" when
MYOWNCA_AUTH_ENCRYPTION_SECRET is unset. Everything held at rest hangs off that
value — the Fernet keys for TOTP seeds, notification credentials and ACME account
keys, plus the audit-chain and recovery-code peppers — so an install running on
the placeholder encrypts every secret with a published constant.

Lab installs stay exempt: local development and this suite must be unaffected.

The gate sits on the serving entry point (`myownca.online.app.run`, which both the
`myownca` launcher and `myownca-online` go through) rather than on `create_app`.
The factory is a library boundary used by tests and embedders that legitimately
run without a configured secret; refusing there would break them for no security
gain, since nothing is being served.
"""
from __future__ import annotations

import unittest
from unittest import mock

from myownca.online.app import (
    PLACEHOLDER_ENCRYPTION_SECRET,
    _require_configured_encryption_secret,
    run,
)


class EncryptionSecretBootGateTests(unittest.TestCase):
    def test_production_install_refuses_the_placeholder(self) -> None:
        with self.assertRaises(RuntimeError) as caught:
            _require_configured_encryption_secret(PLACEHOLDER_ENCRYPTION_SECRET, False)
        message = str(caught.exception)
        self.assertIn("MYOWNCA_AUTH_ENCRYPTION_SECRET", message)
        self.assertIn("MYOWNCA_LAB_MODE", message)  # tells the operator the way out

    def test_lab_install_is_exempt(self) -> None:
        _require_configured_encryption_secret(PLACEHOLDER_ENCRYPTION_SECRET, True)

    def test_production_install_with_a_real_secret_is_allowed(self) -> None:
        _require_configured_encryption_secret("a-real-high-entropy-secret", False)

    def test_gate_matches_the_value_config_actually_substitutes(self) -> None:
        """Guards against the default drifting out from under the gate."""
        from myownca.config import Settings

        settings = Settings.from_mapping({})
        self.assertEqual(settings.auth_encryption_secret, PLACEHOLDER_ENCRYPTION_SECRET)


class ServeEntryPointIsGatedTests(unittest.TestCase):
    """The gate must actually be wired into the path that serves traffic."""

    def test_run_refuses_to_serve_a_production_install_on_the_placeholder(self) -> None:
        from myownca.config import Settings

        production = Settings.from_mapping({"MYOWNCA_LAB_MODE": "false"})
        self.assertEqual(production.auth_encryption_secret, PLACEHOLDER_ENCRYPTION_SECRET)
        with mock.patch("myownca.online.app.Settings.from_env", return_value=production):
            with mock.patch("myownca.online.app.uvicorn.run") as served:
                with self.assertRaises(RuntimeError):
                    run()
        served.assert_not_called()  # refused before binding a port

    def test_run_serves_a_lab_install(self) -> None:
        from myownca.config import Settings

        lab = Settings.from_mapping({"MYOWNCA_LAB_MODE": "true"})
        with mock.patch("myownca.online.app.Settings.from_env", return_value=lab):
            with mock.patch("myownca.online.app.uvicorn.run") as served:
                run()
        served.assert_called_once()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
