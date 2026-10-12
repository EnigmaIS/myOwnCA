from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from myownca.ca_hsm import SoftwareHSM
from myownca.ca_main.crypto import certificate_to_pem, create_lab_ca_chain
from myownca.online.app import create_app


def _root_pem() -> str:
    return certificate_to_pem(create_lab_ca_chain(SoftwareHSM()).root.certificate)


def _set_required_admins(orchestrator) -> None:
    orchestrator.set_admins(
        {"id": "admin-1", "email": "a1@example.test", "password": "p" * 16},
        {"id": "admin-2", "email": "a2@example.test", "password": "q" * 16},
    )


class PendingRootApplyTests(unittest.TestCase):
    def test_pending_root_is_imported_on_boot(self) -> None:
        with TemporaryDirectory() as tempdir:
            pending = Path(tempdir) / "setup" / "root-ca.pem"
            pending.parent.mkdir(parents=True)
            pem = _root_pem()
            pending.write_text(pem)
            with mock.patch.dict(
                "os.environ", {"MYOWNCA_STATE_DIR": tempdir}, clear=True
            ):
                app = create_app(Path(tempdir) / "api.sqlite3")
            self.assertEqual(app.state.repository.get_root_certificate_pem(), pem)

    def test_no_pending_file_is_a_noop(self) -> None:
        with TemporaryDirectory() as tempdir:
            with mock.patch.dict(
                "os.environ", {"MYOWNCA_STATE_DIR": tempdir}, clear=True
            ):
                app = create_app(Path(tempdir) / "api.sqlite3")
            self.assertIsNone(app.state.repository.get_root_certificate_pem())

    def test_existing_root_is_not_overwritten(self) -> None:
        with TemporaryDirectory() as tempdir:
            pending = Path(tempdir) / "setup" / "root-ca.pem"
            pending.parent.mkdir(parents=True)
            pending.write_text(_root_pem())
            with mock.patch.dict(
                "os.environ", {"MYOWNCA_STATE_DIR": tempdir}, clear=True
            ):
                app = create_app(Path(tempdir) / "api.sqlite3")
                app.state.repository.set_root_certificate_pem("ALREADY-SET\n")
                # Re-create: the pending file must not clobber the existing root.
                app2 = create_app(Path(tempdir) / "api.sqlite3")
            self.assertEqual(
                app2.state.repository.get_root_certificate_pem(), "ALREADY-SET\n"
            )


class RootCaptureToBootTests(unittest.TestCase):
    def test_wizard_captured_root_is_applied_on_service_boot(self) -> None:
        from myownca.setup.orchestrator import SetupOrchestrator

        with TemporaryDirectory() as tempdir:
            pem = _root_pem()
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_install_type("production")
            orchestrator.set_governance_mode("dual_control")
            _set_required_admins(orchestrator)
            orchestrator.set_root_certificate(pem)
            orchestrator.prepare_runtime()  # writes <tempdir>/setup/root-ca.pem

            with mock.patch.dict(
                "os.environ", {"MYOWNCA_STATE_DIR": tempdir}, clear=True
            ):
                app = create_app(Path(tempdir) / "api.sqlite3")
            self.assertEqual(app.state.repository.get_root_certificate_pem(), pem)
