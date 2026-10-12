from __future__ import annotations

import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi import HTTPException

from myownca.ca_auth.service import AuthError, AuthenticationError, AuthorizationError
from myownca.config import Settings
from myownca.domain import AdminChangeStatus, Role, SessionStage
from myownca.online.app import (
    DestructiveActionConfirmation,
    PasswordReauthenticate,
    RoleTOTPPolicyChange,
    create_app,
)
from myownca.setup.config_writer import read_config_env
from myownca.setup.orchestrator import SetupError, SetupOrchestrator
from myownca.storage.database import Database
from myownca_core.storage.database import Database as CoreDatabase
from tests.helpers import (
    add_login_ready_user,
    create_active_session,
    request_with_session,
    route_endpoint,
)


_REASON = "Changing the installation TOTP role policy"


class RoleTOTPPolicyTests(unittest.TestCase):
    def _app(self, tempdir: str, *, roles: str | None = None, single: bool = False):
        env = {}
        if roles is not None:
            env["MYOWNCA_TOTP_REQUIRED_ROLES"] = roles
        if single:
            env["MYOWNCA_GOVERNANCE_MODE"] = "single_admin"
        with mock.patch.dict("os.environ", env, clear=False):
            return create_app(Path(tempdir) / "policy.sqlite3")

    def test_default_policy_preserves_admin_and_operator_requirement(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = self._app(tempdir)
            self.assertEqual(
                app.state.auth_service.totp_policy(),
                {
                    Role.ADMIN: True,
                    Role.SUPERUSER: True,
                    Role.AUDITOR: False,
                    Role.USER: False,
                },
            )

    def test_every_role_can_be_required_and_is_challenged(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = self._app(tempdir, roles="admin,superuser,auditor,user")
            for role in Role:
                secret = add_login_ready_user(
                    app,
                    user_id=f"account-{role.value}",
                    email=f"{role.value}@example.test",
                    role=role,
                )
                self.assertIsNotNone(secret)
                created = app.state.auth_service.login(
                    f"{role.value}@example.test", "very-long-test-password"
                )
                self.assertEqual(created.session.stage, SessionStage.TOTP_REQUIRED)

    def test_explicit_empty_policy_makes_admin_password_only(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = self._app(tempdir, roles="", single=True)
            secret = add_login_ready_user(
                app, user_id="admin-1", email="admin@example.test", role=Role.ADMIN
            )
            self.assertIsNone(secret)
            created = app.state.auth_service.login(
                "admin@example.test", "very-long-test-password"
            )
            self.assertEqual(created.session.stage, SessionStage.ACTIVE)

    def test_settings_distinguish_absent_empty_and_explicit_role_policy(self) -> None:
        self.assertIsNone(Settings.from_mapping({}).totp_required_roles)
        self.assertEqual(
            Settings.from_mapping(
                {"MYOWNCA_TOTP_REQUIRED_ROLES": ""}
            ).totp_required_roles,
            (),
        )
        self.assertEqual(
            Settings.from_mapping(
                {"MYOWNCA_TOTP_REQUIRED_ROLES": "admin, auditor,admin"}
            ).totp_required_roles,
            ("admin", "auditor"),
        )
        with self.assertRaises(ValueError):
            Settings.from_mapping({"MYOWNCA_TOTP_REQUIRED_ROLES": "admin,unknown"})

    def test_disabling_role_revokes_sessions_and_deletes_totp_recovery_data(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = self._app(tempdir, roles="admin,user", single=True)
            admin_secret = add_login_ready_user(
                app, user_id="admin-1", email="admin@example.test", role=Role.ADMIN
            )
            user_secret = add_login_ready_user(
                app, user_id="user-1", email="user@example.test", role=Role.USER
            )
            admin_token, _ = create_active_session(
                app, email="admin@example.test", totp_secret=admin_secret
            )
            user_token, _ = create_active_session(
                app, email="user@example.test", totp_secret=user_secret
            )
            app.state.auth_service.regenerate_recovery_codes(user_token)

            proposal = app.state.auth_service.create_totp_policy_change(
                app.state.auth_repository.get_user("admin-1"),
                required_roles={Role.ADMIN},
                reason=_REASON,
            )

            self.assertEqual(proposal.status, AdminChangeStatus.APPROVED)
            self.assertIsNone(app.state.auth_repository.get_totp_factor("user-1"))
            self.assertEqual(
                app.state.auth_repository.count_unused_recovery_codes("user-1"), 0
            )
            with self.assertRaises(AuthenticationError):
                app.state.auth_service.require_session(user_token)
            # Administrator policy did not change, so its session stays live.
            app.state.auth_service.require_session(admin_token)

    def test_dual_control_requires_a_different_admin(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = self._app(tempdir)
            add_login_ready_user(
                app, user_id="admin-1", email="a1@example.test", role=Role.ADMIN
            )
            add_login_ready_user(
                app, user_id="admin-2", email="a2@example.test", role=Role.ADMIN
            )
            admin1 = app.state.auth_repository.get_user("admin-1")
            admin2 = app.state.auth_repository.get_user("admin-2")
            proposal = app.state.auth_service.create_totp_policy_change(
                admin1,
                required_roles={Role.ADMIN, Role.SUPERUSER, Role.AUDITOR},
                reason=_REASON,
            )
            self.assertEqual(proposal.status, AdminChangeStatus.PENDING)
            with self.assertRaises(AuthorizationError):
                app.state.auth_service.approve_proposal(proposal.id, admin1)
            approved = app.state.auth_service.approve_proposal(proposal.id, admin2)
            self.assertEqual(approved.status, AdminChangeStatus.APPROVED)
            self.assertTrue(app.state.auth_service.totp_required(Role.AUDITOR))

    def test_second_admin_approves_policy_without_password_step_up(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = self._app(tempdir, roles="")
            add_login_ready_user(
                app, user_id="admin-1", email="a1@example.test", role=Role.ADMIN
            )
            add_login_ready_user(
                app, user_id="admin-2", email="a2@example.test", role=Role.ADMIN
            )
            token1, csrf1 = create_active_session(app, email="a1@example.test")
            token2, csrf2 = create_active_session(app, email="a2@example.test")

            created = route_endpoint(
                app, "/internal/admin/auth-policy/changes", "POST"
            )(
                RoleTOTPPolicyChange(
                    required_roles=[Role.AUDITOR],
                    reason=_REASON,
                    confirmation="CHANGE TOTP POLICY",
                ),
                request_with_session(token1, csrf1, method="POST"),
            )
            proposal_id = created["proposal"]["id"]
            self.assertEqual(created["proposal"]["status"], "pending")

            approved = route_endpoint(
                app,
                "/internal/admin/auth-policy/proposals/{proposal_id}/approve",
                "POST",
            )(
                proposal_id,
                DestructiveActionConfirmation(
                    reason="Second administrator approves this TOTP policy",
                    confirmation="APPROVE TOTP POLICY",
                ),
                request_with_session(token2, csrf2, method="POST"),
            )
            self.assertEqual(approved["proposal"]["status"], "approved")
            self.assertTrue(app.state.auth_service.totp_required(Role.AUDITOR))

    def test_stale_policy_proposal_is_rejected_without_applying(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = self._app(tempdir)
            add_login_ready_user(
                app, user_id="admin-1", email="a1@example.test", role=Role.ADMIN
            )
            add_login_ready_user(
                app, user_id="admin-2", email="a2@example.test", role=Role.ADMIN
            )
            repository = app.state.auth_repository
            proposal = app.state.auth_service.create_totp_policy_change(
                repository.get_user("admin-1"),
                required_roles={Role.ADMIN, Role.SUPERUSER, Role.AUDITOR},
                reason=_REASON,
            )
            with repository.database.connect() as connection:
                connection.execute(
                    "UPDATE role_totp_policies SET totp_required = 1 WHERE role = ?",
                    (Role.USER.value,),
                )
            with self.assertRaises(AuthError) as stale:
                app.state.auth_service.approve_proposal(
                    proposal.id, repository.get_user("admin-2")
                )
            self.assertIn("proposal was rejected", str(stale.exception))
            self.assertEqual(
                repository.get_proposal(proposal.id).status,
                AdminChangeStatus.REJECTED,
            )
            self.assertFalse(app.state.auth_service.totp_required(Role.AUDITOR))

    def test_enabling_totp_does_not_require_password_step_up(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = self._app(tempdir, roles="", single=True)
            add_login_ready_user(
                app, user_id="admin-1", email="admin@example.test", role=Role.ADMIN
            )
            token, csrf = create_active_session(app, email="admin@example.test")
            change = RoleTOTPPolicyChange(
                required_roles=[Role.ADMIN],
                reason=_REASON,
                confirmation="CHANGE TOTP POLICY",
            )
            result = route_endpoint(app, "/internal/admin/auth-policy/changes", "POST")(
                change, request_with_session(token, csrf, method="POST")
            )
            self.assertEqual(result["proposal"]["status"], "approved")
            self.assertTrue(app.state.auth_service.totp_required(Role.ADMIN))
            with self.assertRaises(AuthenticationError):
                app.state.auth_service.require_session(token)

    def test_password_step_up_still_protects_disabling_totp(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = self._app(tempdir, roles="user", single=True)
            add_login_ready_user(
                app, user_id="admin-1", email="admin@example.test", role=Role.ADMIN
            )
            token, csrf = create_active_session(app, email="admin@example.test")
            change = RoleTOTPPolicyChange(
                required_roles=[],
                reason=_REASON,
                confirmation="CHANGE TOTP POLICY",
            )
            with self.assertRaises(HTTPException) as missing:
                route_endpoint(app, "/internal/admin/auth-policy/changes", "POST")(
                    change, request_with_session(token, csrf, method="POST")
                )
            self.assertEqual(missing.exception.status_code, 403)

            with self.assertRaises(HTTPException) as wrong:
                route_endpoint(app, "/internal/auth/password/reauthenticate", "POST")(
                    PasswordReauthenticate(password="wrong-password"),
                    request_with_session(token, csrf, method="POST"),
                )
            self.assertEqual(wrong.exception.status_code, 401)
            reauthenticated = route_endpoint(
                app, "/internal/auth/password/reauthenticate", "POST"
            )(
                PasswordReauthenticate(password="very-long-test-password"),
                request_with_session(token, csrf, method="POST"),
            )
            self.assertTrue(reauthenticated["sensitive_auth"]["recent"])
            self.assertEqual(reauthenticated["sensitive_auth"]["method"], "password")

            result = route_endpoint(app, "/internal/admin/auth-policy/changes", "POST")(
                change, request_with_session(token, csrf, method="POST")
            )
            self.assertEqual(result["proposal"]["status"], "approved")
            self.assertFalse(app.state.auth_service.totp_required(Role.USER))
            self.assertEqual(app.state.auth_service.require_session(token)[0].stage, SessionStage.ACTIVE)


class TOTPPolicyMigrationAndSetupTests(unittest.TestCase):
    def test_migration_preserves_historical_policy_for_existing_users(self) -> None:
        with TemporaryDirectory() as tempdir:
            partial = Path(tempdir) / "partial"
            partial.mkdir()
            migrations = Path(__file__).parents[1] / "src/myownca/storage/migrations"
            for source in sorted(migrations.glob("*.sql")):
                if source.name < "0026_role_totp_policy.sql":
                    shutil.copy(source, partial / source.name)
            path = Path(tempdir) / "legacy.sqlite3"
            legacy = CoreDatabase(path)
            legacy.migrate(partial)
            with legacy.connect() as connection:
                connection.execute(
                    "INSERT INTO users(id, email, role, is_active) VALUES (?, ?, ?, ?)",
                    ("legacy-user", "legacy@example.test", "user", 1),
                )

            database = Database(path)
            database.migrate()
            from myownca.ca_auth.repository import AuthRepository

            repository = AuthRepository(database)
            self.assertTrue(repository.is_totp_required(Role.ADMIN))
            self.assertTrue(repository.is_totp_required(Role.SUPERUSER))
            self.assertFalse(repository.is_totp_required(Role.AUDITOR))
            self.assertFalse(repository.is_totp_required(Role.USER))

    def test_setup_persists_custom_policy_and_rejects_unknown_roles(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_install_type("lab")
            self.assertEqual(
                orchestrator.snapshot()["totp_required_roles"],
                ["admin", "superuser"],
            )
            orchestrator.set_totp_policy(["admin", "auditor"])
            self.assertEqual(
                orchestrator.snapshot()["totp_required_roles"],
                ["admin", "auditor"],
            )
            with self.assertRaises(SetupError):
                orchestrator.set_totp_policy(["admin", "unknown"])

            orchestrator.set_listener(topology="proxy")
            orchestrator.set_admins(
                {
                    "id": "admin-1",
                    "email": "admin@example.test",
                    "password": "temporary-password-1",
                }
            )
            orchestrator.finalize()
            self.assertEqual(
                read_config_env(tempdir)["MYOWNCA_TOTP_REQUIRED_ROLES"],
                "admin,auditor",
            )


if __name__ == "__main__":
    unittest.main()
