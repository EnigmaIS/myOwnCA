from __future__ import annotations

import subprocess
import unittest
from unittest import mock

from myownca.ca_hsm.scctl import DKEKStatus, ScHsmCtl, ScHsmError, _redact, _parse_dkek_status


def _completed(stdout: str = "", returncode: int = 0, stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class ScHsmCtlArgsTests(unittest.TestCase):
    def test_initialize_builds_expected_args_with_dkek(self) -> None:
        ctl = ScHsmCtl("sc-hsm-tool")
        with mock.patch("subprocess.run", return_value=_completed()) as run:
            ctl.initialize(so_pin="3537363231383830", pin="648219", label="myOwnCA", dkek_shares=3)
        cmd = run.call_args.args[0]
        self.assertEqual(cmd[0], "sc-hsm-tool")
        self.assertIn("--initialize", cmd)
        self.assertIn("--dkek-shares", cmd)
        self.assertEqual(cmd[cmd.index("--dkek-shares") + 1], "3")
        self.assertEqual(cmd[cmd.index("--label") + 1], "myOwnCA")

    def test_initialize_omits_dkek_when_zero(self) -> None:
        ctl = ScHsmCtl()
        with mock.patch("subprocess.run", return_value=_completed()) as run:
            ctl.initialize(so_pin="x", pin="y", label="L", dkek_shares=0)
        self.assertNotIn("--dkek-shares", run.call_args.args[0])

    def test_initialize_rejects_negative_dkek(self) -> None:
        with self.assertRaises(ValueError):
            ScHsmCtl().initialize(so_pin="x", pin="y", label="L", dkek_shares=-1)

    def test_create_dkek_share_uses_one_password_without_threshold_fields(self) -> None:
        with mock.patch("subprocess.run", return_value=_completed()) as run:
            ScHsmCtl(reader="Nitrokey HSM").create_dkek_share(
                "/tmp/s.pbe",
                password="pw",
            )
        cmd = run.call_args.args[0]
        self.assertNotIn("--pwd-shares-threshold", cmd)
        self.assertNotIn("--pwd-shares-total", cmd)
        self.assertEqual(cmd[cmd.index("--reader") + 1], "Nitrokey HSM")

    def test_run_raises_on_nonzero_exit_and_redacts_secrets(self) -> None:
        ctl = ScHsmCtl()
        with mock.patch(
            "subprocess.run",
            return_value=_completed(
                returncode=1,
                stderr="Using reader with a card",
                stdout="actual failure",
            ),
        ):
            with self.assertRaises(ScHsmError) as ctx:
                ctl.initialize(so_pin="TOPSECRET", pin="USERPIN", label="L")
        message = str(ctx.exception)
        self.assertNotIn("TOPSECRET", message)
        self.assertNotIn("USERPIN", message)
        self.assertIn("***", message)
        self.assertIn("Using reader with a card", message)
        self.assertIn("actual failure", message)

    def test_missing_binary_raises_schsmerror(self) -> None:
        with mock.patch("subprocess.run", side_effect=FileNotFoundError()):
            with self.assertRaises(ScHsmError):
                ScHsmCtl("/nonexistent").dkek_status()

    def test_timeout_raises_schsmerror(self) -> None:
        with mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired("sc-hsm-tool", 60)):
            with self.assertRaises(ScHsmError):
                ScHsmCtl().dkek_status()


class RedactTests(unittest.TestCase):
    def test_redacts_each_secret_flag_value(self) -> None:
        cmd = ["sc-hsm-tool", "--so-pin", "s", "--pin", "p", "--password", "w", "--label", "L"]
        redacted = _redact(cmd)
        self.assertEqual(
            redacted,
            "sc-hsm-tool --so-pin *** --pin *** --password *** --label L",
        )


class ParseDkekStatusTests(unittest.TestCase):
    def test_pending_import(self) -> None:
        status = _parse_dkek_status("DKEK shares          : 3\nDKEK import pending, 1 of 3 shares missing")
        self.assertEqual(status, DKEKStatus(shares_total=3, shares_imported=2, complete=False, kcv=None))

    def test_current_opensc_pending_import(self) -> None:
        status = _parse_dkek_status(
            "DKEK shares          : 3\n"
            "DKEK import pending, 2 shares still missing\n"
            "DKEK key check value : A1B2C3"
        )
        self.assertEqual(
            status,
            DKEKStatus(
                shares_total=3,
                shares_imported=1,
                complete=False,
                kcv="A1B2C3",
            ),
        )

    def test_complete_with_kcv(self) -> None:
        status = _parse_dkek_status("DKEK shares          : 2\nDKEK key check value : A1B2C3")
        self.assertEqual(status.shares_total, 2)
        self.assertTrue(status.complete)
        self.assertEqual(status.kcv, "A1B2C3")

    def test_no_dkek(self) -> None:
        status = _parse_dkek_status("Version              : 3.4")
        self.assertEqual(status, DKEKStatus(shares_total=0, shares_imported=0, complete=False, kcv=None))


if __name__ == "__main__":
    unittest.main()
