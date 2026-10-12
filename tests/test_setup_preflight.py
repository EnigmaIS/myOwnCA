from __future__ import annotations

import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from myownca.setup.preflight import preflight


class PreflightTests(unittest.TestCase):
    def test_reports_python_version_and_ok_flag(self) -> None:
        with TemporaryDirectory() as tempdir:
            report = preflight(tempdir)
        self.assertEqual(
            report["python_version"], ".".join(str(p) for p in sys.version_info[:3])
        )
        # The test runner is >=3.12 by definition (requires-python).
        self.assertTrue(report["python_ok"])

    def test_existing_dir_is_writable(self) -> None:
        with TemporaryDirectory() as tempdir:
            report = preflight(tempdir)
        self.assertEqual(report["state_dir"], str(Path(tempdir)))
        self.assertTrue(report["state_dir_writable"])

    def test_nonexistent_dir_under_writable_parent_is_writable(self) -> None:
        with TemporaryDirectory() as tempdir:
            target = Path(tempdir) / "does" / "not" / "exist"
            report = preflight(target)
        self.assertTrue(report["state_dir_writable"])

    def test_path_under_a_file_ancestor_is_not_writable(self) -> None:
        # The first existing ancestor is a file, so mkdir under it would fail.
        with TemporaryDirectory() as tempdir:
            a_file = Path(tempdir) / "afile"
            a_file.write_text("x")
            report = preflight(a_file / "sub")
        self.assertFalse(report["state_dir_writable"])

    def test_reports_hsm_and_mariadb_keys(self) -> None:
        with TemporaryDirectory() as tempdir:
            report = preflight(tempdir)
        # Keys are always present; values depend on the host.
        self.assertIn("hsm_available", report)
        self.assertIsInstance(report["hsm_available"], bool)
        self.assertIn("pkcs11_lib", report)
        self.assertIn("mariadb_driver", report)
        self.assertIsInstance(report["mariadb_driver"], bool)
        self.assertIsInstance(report["python_ok"], bool)
        self.assertEqual(
            set(report),
            {
                "python_version",
                "python_ok",
                "pkcs11_lib",
                "hsm_available",
                "state_dir",
                "state_dir_writable",
                "mariadb_driver",
            },
        )
