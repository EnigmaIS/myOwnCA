from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr
from tempfile import TemporaryDirectory
from unittest import mock

from myownca import launcher
from myownca.config import Settings
from myownca.setup.config_writer import write_config, write_secrets
from myownca.setup.state import mark_setup_complete


class LauncherDispatchTests(unittest.TestCase):
    def test_auto_runs_setup_when_latch_absent(self) -> None:
        with TemporaryDirectory() as tempdir:
            with mock.patch.object(launcher, "run_setup", return_value=0) as setup, \
                 mock.patch.object(launcher, "run_service", return_value=0) as service:
                rc = launcher.main(["--state-dir", tempdir])
            self.assertEqual(rc, 0)
            setup.assert_called_once()
            service.assert_not_called()

    def test_auto_runs_service_when_latch_present(self) -> None:
        with TemporaryDirectory() as tempdir:
            mark_setup_complete(tempdir, None)
            with mock.patch.object(launcher, "run_setup", return_value=0) as setup, \
                 mock.patch.object(launcher, "run_service", return_value=0) as service, \
                 mock.patch.object(launcher, "_issuer_ready", return_value=True):
                rc = launcher.main(["--state-dir", tempdir])
            self.assertEqual(rc, 0)
            service.assert_called_once()
            setup.assert_not_called()

    def test_auto_keeps_service_boundary_when_latch_exists_without_issuer(self) -> None:
        with TemporaryDirectory() as tempdir:
            mark_setup_complete(tempdir, None)
            with mock.patch.object(launcher, "run_setup", return_value=0) as setup, \
                 mock.patch.object(launcher, "run_service", return_value=0) as service, \
                 mock.patch.object(launcher, "_issuer_ready", return_value=False):
                rc = launcher.main(["--state-dir", tempdir])
            self.assertEqual(rc, 0)
            service.assert_called_once()
            setup.assert_not_called()

    def test_explicit_serve_overrides_missing_latch(self) -> None:
        with TemporaryDirectory() as tempdir:
            with mock.patch.object(launcher, "run_service", return_value=0) as service:
                rc = launcher.main(["--state-dir", tempdir, "serve"])
            self.assertEqual(rc, 0)
            service.assert_called_once()

    def test_explicit_setup_refuses_present_latch(self) -> None:
        with TemporaryDirectory() as tempdir:
            mark_setup_complete(tempdir, None)
            with mock.patch("myownca.setup.token.SetupAuth") as auth, \
                 mock.patch.object(launcher, "_serve_setup_app") as serve, \
                 redirect_stderr(io.StringIO()) as output:
                self.assertEqual(launcher.main(["--state-dir", tempdir, "setup"]), 1)
                self.assertEqual(launcher.run_setup(tempdir), 1)
            auth.assert_not_called()
            serve.assert_not_called()
            self.assertIn("serve", output.getvalue())
            self.assertNotIn("Token:", output.getvalue())

    def test_main_propagates_delegate_exit_code(self) -> None:
        with TemporaryDirectory() as tempdir:
            with mock.patch.object(launcher, "run_setup", return_value=42):
                rc = launcher.main(["--state-dir", tempdir, "setup"])
            self.assertEqual(rc, 42)


class ConfigBridgeTests(unittest.TestCase):
    def test_file_config_injected_into_env_without_overriding_real_env(self) -> None:
        with TemporaryDirectory() as tempdir:
            write_secrets(tempdir, {"MYOWNCA_ONLINE_KEY_PASSPHRASE": "from-file"})
            environ: dict[str, str] = {"MYOWNCA_AUTH_ENCRYPTION_SECRET": "from-real-env"}
            launcher._apply_state_dir_config_to_env(tempdir, environ=environ)
            # File value is injected...
            self.assertEqual(environ["MYOWNCA_ONLINE_KEY_PASSPHRASE"], "from-file")
            # ...but a value already in the environment is left untouched.
            self.assertEqual(environ["MYOWNCA_AUTH_ENCRYPTION_SECRET"], "from-real-env")

    def test_real_env_wins_over_file_for_same_key(self) -> None:
        with TemporaryDirectory() as tempdir:
            write_secrets(tempdir, {"MYOWNCA_ONLINE_KEY_PASSPHRASE": "from-file"})
            environ = {"MYOWNCA_ONLINE_KEY_PASSPHRASE": "from-real-env"}
            launcher._apply_state_dir_config_to_env(tempdir, environ=environ)
            self.assertEqual(environ["MYOWNCA_ONLINE_KEY_PASSPHRASE"], "from-real-env")

    def test_bridge_precedence_matches_settings_load(self) -> None:
        # The launcher bridge (booting the existing service) and Settings.load
        # (used directly) must resolve identically: env > secrets > config.
        with TemporaryDirectory() as tempdir:
            # Same key in BOTH files (secrets must win) + a real-env override.
            write_config(tempdir, {"MYOWNCA_HSM_BACKEND": "from-config"})
            write_secrets(tempdir, {"MYOWNCA_HSM_BACKEND": "from-secrets"})
            real_env = {"MYOWNCA_LAB_MODE": "false"}

            bridged = dict(real_env)
            launcher._apply_state_dir_config_to_env(tempdir, environ=bridged)

            self.assertEqual(
                Settings.from_mapping(bridged),
                Settings.load(tempdir, environ=real_env),
            )
            # Secrets beat config for the colliding key.
            self.assertEqual(
                Settings.load(tempdir, environ=real_env).hsm_backend, "from-secrets"
            )


class FoundationRoundTripTests(unittest.TestCase):
    def test_wizard_output_drives_settings_and_mode(self) -> None:
        """Simulate what the finished wizard will do, then read it back."""
        with TemporaryDirectory() as tempdir:
            # Before setup: mode is 'setup'.
            self.assertFalse(launcher.is_setup_complete(tempdir))

            # Wizard writes config + secrets, then drops the latch last.
            write_config(tempdir, {"MYOWNCA_LAB_MODE": "false"})
            write_secrets(tempdir, {"MYOWNCA_AUTH_ENCRYPTION_SECRET": "generated"})
            mark_setup_complete(tempdir, {"version": "test"})

            # After setup: the launcher resolves the same dir, sees the latch, and
            # would select service mode; Settings then reflects the written files.
            resolved_dir = launcher.resolve_state_dir(tempdir)
            self.assertTrue(launcher.is_setup_complete(resolved_dir))
            settings = Settings.load(tempdir, environ={})
            self.assertFalse(settings.lab_mode)
            self.assertEqual(settings.auth_encryption_secret, "generated")


class SetupPortAndBannerTests(unittest.TestCase):
    def test_default_setup_port(self) -> None:
        self.assertEqual(launcher._resolve_setup_port(environ={}), 8765)

    def test_setup_port_from_env(self) -> None:
        self.assertEqual(
            launcher._resolve_setup_port(environ={"MYOWNCA_SETUP_PORT": "9001"}), 9001
        )

    def test_invalid_setup_port_falls_back_to_default(self) -> None:
        self.assertEqual(
            launcher._resolve_setup_port(environ={"MYOWNCA_SETUP_PORT": "not-a-port"}),
            8765,
        )

    def test_out_of_range_setup_port_falls_back_to_default(self) -> None:
        for bad in ("0", "-1", "99999"):
            self.assertEqual(
                launcher._resolve_setup_port(environ={"MYOWNCA_SETUP_PORT": bad}),
                8765,
                msg=bad,
            )

    def test_banner_contains_url_and_token(self) -> None:
        banner = launcher._setup_banner(8765, "tok-123")
        self.assertIn("http://127.0.0.1:8765/setup", banner)
        self.assertIn("tok-123", banner)

    def test_default_setup_host(self) -> None:
        self.assertEqual(launcher._resolve_setup_host(environ={}), "127.0.0.1")

    def test_setup_host_from_env(self) -> None:
        self.assertEqual(
            launcher._resolve_setup_host(environ={"MYOWNCA_SETUP_HOST": "0.0.0.0"}),
            "0.0.0.0",
        )

    def test_blank_setup_host_falls_back_to_localhost(self) -> None:
        self.assertEqual(
            launcher._resolve_setup_host(environ={"MYOWNCA_SETUP_HOST": "  "}),
            "127.0.0.1",
        )

    def test_banner_localhost_keeps_loopback_url(self) -> None:
        banner = launcher._setup_banner(8765, "tok-123", host="127.0.0.1")
        self.assertIn("http://127.0.0.1:8765/setup", banner)
        self.assertIn("tok-123", banner)

    def test_banner_nonlocal_host_does_not_claim_loopback(self) -> None:
        banner = launcher._setup_banner(8765, "tok-123", host="0.0.0.0")
        self.assertNotIn("127.0.0.1", banner)
        self.assertIn("8765", banner)
        # The bound host is named in the "(bound to ...)" parenthetical.
        self.assertIn("0.0.0.0", banner)
        self.assertIn("tok-123", banner)

    def test_banner_localhost_string_treated_as_loopback(self) -> None:
        # MYOWNCA_SETUP_HOST=localhost passes through _resolve_setup_host as-is;
        # the banner must treat it like loopback, not the published-port wording.
        banner = launcher._setup_banner(8765, "tok-123", host="localhost")
        self.assertIn("http://127.0.0.1:8765/setup", banner)
        self.assertNotIn("published setup port", banner)


class RunSetupHandoffTests(unittest.TestCase):
    def test_serves_then_boots_service_when_finalized(self) -> None:
        with TemporaryDirectory() as tempdir:
            # Fake serve: simulate the wizard finalizing (latch dropped) then the
            # server returning.
            def fake_serve(app, host, port):
                mark_setup_complete(tempdir, {"install_type": "lab"})

            with mock.patch.object(launcher, "_serve_setup_app", side_effect=fake_serve), \
                 mock.patch.object(launcher, "run_service", return_value=0) as service, \
                 mock.patch.object(launcher, "_issuer_ready", return_value=True):
                with redirect_stderr(io.StringIO()):
                    rc = launcher.run_setup(tempdir)
            self.assertEqual(rc, 0)
            service.assert_called_once()

    def test_returns_nonzero_when_not_finalized(self) -> None:
        with TemporaryDirectory() as tempdir:
            with mock.patch.object(launcher, "_serve_setup_app", return_value=None), \
                 mock.patch.object(launcher, "run_service", return_value=0) as service:
                with redirect_stderr(io.StringIO()):
                    rc = launcher.run_setup(tempdir)
            self.assertEqual(rc, 1)
            service.assert_not_called()

    def test_banner_is_printed(self) -> None:
        with TemporaryDirectory() as tempdir:
            with mock.patch.object(launcher, "_serve_setup_app", return_value=None), \
                 mock.patch.object(launcher, "run_service", return_value=0):
                buffer = io.StringIO()
                with redirect_stderr(buffer):
                    launcher.run_setup(tempdir)
        output = buffer.getvalue()
        self.assertIn("/setup", output)
        self.assertIn("Token:", output)  # the one-time token is surfaced to the operator

    def test_serve_uses_resolved_setup_host(self) -> None:
        with TemporaryDirectory() as tempdir:
            captured = {}

            def fake_serve(app, host, port):
                captured["host"] = host

            with mock.patch.dict("os.environ", {"MYOWNCA_SETUP_HOST": "0.0.0.0"}), \
                 mock.patch.object(launcher, "_serve_setup_app", side_effect=fake_serve), \
                 mock.patch.object(launcher, "run_service", return_value=0):
                with redirect_stderr(io.StringIO()):
                    launcher.run_setup(tempdir)
            self.assertEqual(captured["host"], "0.0.0.0")
