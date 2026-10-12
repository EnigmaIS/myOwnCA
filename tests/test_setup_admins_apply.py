from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from myownca.online.app import create_app
from myownca.setup.orchestrator import SetupOrchestrator
from myownca.setup.state import load_setup_state, save_setup_state
from myownca.storage.repositories import RepositoryError

_ADMINS = [
    {"id": "admin-1", "email": "a1@example.test", "password": "p" * 16},
    {"id": "admin-2", "email": "a2@example.test", "password": "q" * 16},
]


def _finalize_with_admins(tempdir: str) -> None:
    o = SetupOrchestrator(tempdir)
    o.set_install_type("lab")
    o.set_governance_mode("dual_control")
    o.set_listener(topology="proxy")
    o.set_admins(_ADMINS[0], _ADMINS[1])
    o.finalize()


class PendingAdminsApplyTests(unittest.TestCase):
    def test_lab_single_admin_artifact_bootstraps_one_account(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_install_type("lab")
            orchestrator.set_listener(topology="proxy")
            orchestrator.set_admins(_ADMINS[0])
            orchestrator.finalize()
            with mock.patch.dict(
                "os.environ",
                {
                    "MYOWNCA_STATE_DIR": tempdir,
                    "MYOWNCA_GOVERNANCE_MODE": "single_admin",
                    "MYOWNCA_LAB_MODE": "true",
                },
                clear=True,
            ):
                app = create_app()  # Use the database provisioned before completion.
            self.assertEqual(
                app.state.auth_service.governance_mode().value,
                "single_admin",
            )
            self.assertIsNotNone(app.state.auth_repository.get_user("admin-1"))
            with self.assertRaises(RepositoryError):
                app.state.auth_repository.get_user("admin-2")

    def test_pending_admins_bootstrapped_on_boot(self) -> None:
        with TemporaryDirectory() as tempdir:
            _finalize_with_admins(tempdir)
            with mock.patch.dict(
                "os.environ", {"MYOWNCA_STATE_DIR": tempdir}, clear=True
            ):
                app = create_app()
            self.assertTrue(app.state.auth_repository.has_any_users())
            self.assertIsNotNone(app.state.auth_repository.get_user("admin-1"))
            # The temp-password artifact is removed once applied.
            self.assertFalse((Path(tempdir) / "secrets" / "pending-admins.json").exists())
            state = load_setup_state(tempdir)
            self.assertTrue(all("password" not in admin for admin in state.data["admins"]))

    def test_upgrade_scrubs_old_state_without_pending_admin_artifact(self) -> None:
        with TemporaryDirectory() as tempdir:
            _finalize_with_admins(tempdir)
            with mock.patch.dict("os.environ", {"MYOWNCA_STATE_DIR": tempdir}, clear=True):
                database = Path(tempdir) / "myownca.sqlite3"
                create_app(database)
                state = load_setup_state(tempdir)
                state.data["admins"] = [dict(admin) for admin in _ADMINS]
                save_setup_state(tempdir, state)
                self.assertFalse((Path(tempdir) / "secrets/pending-admins.json").exists())
                app = create_app(database)
                self.assertTrue(app.state.auth_service.login(
                    "a1@example.test", "p" * 16
                ).session)
            self.assertTrue(all(
                "password" not in admin for admin in load_setup_state(tempdir).data["admins"]
            ))

    def test_no_pending_admins_is_a_noop(self) -> None:
        with TemporaryDirectory() as tempdir:
            with mock.patch.dict(
                "os.environ", {"MYOWNCA_STATE_DIR": tempdir}, clear=True
            ):
                app = create_app(Path(tempdir) / "api.sqlite3")
            self.assertFalse(app.state.auth_repository.has_any_users())

    def test_failed_bootstrap_preserves_both_copies_for_retry(self) -> None:
        with TemporaryDirectory() as tempdir:
            _finalize_with_admins(tempdir)
            state_path = Path(tempdir) / "setup/state.json"
            pending = Path(tempdir) / "secrets/pending-admins.json"
            before_state, before_pending = state_path.read_bytes(), pending.read_bytes()
            with mock.patch.dict("os.environ", {"MYOWNCA_STATE_DIR": tempdir}, clear=True):
                database = Path(tempdir) / "myownca.sqlite3"
                with mock.patch(
                    "myownca.ca_auth.service.AuthService.bootstrap_initial_admins",
                    side_effect=RepositoryError("database unavailable"),
                ):
                    with self.assertRaises(RepositoryError):
                        create_app(database)
                self.assertEqual(state_path.read_bytes(), before_state)
                self.assertEqual(pending.read_bytes(), before_pending)
                app = create_app(database)
                self.assertTrue(app.state.auth_repository.has_any_users())
            self.assertFalse(pending.exists())
            self.assertTrue(all(
                "password" not in admin for admin in load_setup_state(tempdir).data["admins"]
            ))

    def test_existing_users_are_not_re_bootstrapped(self) -> None:
        with TemporaryDirectory() as tempdir:
            _finalize_with_admins(tempdir)
            with mock.patch.dict(
                "os.environ", {"MYOWNCA_STATE_DIR": tempdir}, clear=True
            ):
                create_app()  # first boot bootstraps + deletes
                # Re-write the artifact and re-boot: users already exist -> no-op.
                rewritten = Path(tempdir) / "secrets" / "pending-admins.json"
                rewritten.parent.mkdir(parents=True, exist_ok=True)
                rewritten.write_text('[{"id":"x","email":"x@x.test","password":"z"}]')
                app2 = create_app()
            self.assertIsNotNone(app2.state.auth_repository.get_user("admin-1"))
            with self.assertRaises(RepositoryError):
                app2.state.auth_repository.get_user("x")
            # The skip path drops the stale temp-password artifact too.
            self.assertFalse(rewritten.exists())

    def test_corrupt_artifact_does_not_crash_boot(self) -> None:
        with TemporaryDirectory() as tempdir:
            pending = Path(tempdir) / "secrets" / "pending-admins.json"
            pending.parent.mkdir(parents=True)
            pending.write_text("{ not valid json")  # corrupt / hand-edited
            with mock.patch.dict(
                "os.environ", {"MYOWNCA_STATE_DIR": tempdir}, clear=True
            ):
                app = create_app(Path(tempdir) / "api.sqlite3")  # must NOT raise
            # No admins created, and the unusable artifact is left for a fix + retry.
            self.assertFalse(app.state.auth_repository.has_any_users())
            self.assertTrue(pending.exists())


class AdminsLoginReadyTests(unittest.TestCase):
    def test_bootstrapped_admin_must_change_password(self) -> None:
        with TemporaryDirectory() as tempdir:
            _finalize_with_admins(tempdir)
            with mock.patch.dict(
                "os.environ", {"MYOWNCA_STATE_DIR": tempdir}, clear=True
            ):
                app = create_app()
            auth_service = app.state.auth_service
            # Logging in with the temp password lands in the forced password-change stage.
            created = auth_service.login("a1@example.test", "p" * 16)
            self.assertEqual(created.session.stage.value, "password_change_required")
