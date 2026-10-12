from __future__ import annotations

import json
import shutil
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier
from unittest import mock

from fastapi import HTTPException

from myownca.ca_auth.repository import decode_payload
from myownca.ca_auth.service import AuthError, AuthenticationError, AuthorizationError
from myownca.config import Settings
from myownca.domain import AdminChangeStatus, GovernanceMode, Role
from myownca.online.app import (
    DestructiveActionConfirmation,
    PrivilegedRoleGrantCreate,
    create_app,
)
from myownca.setup.orchestrator import SetupError, SetupOrchestrator
from myownca.storage.repositories import RepositoryError
from myownca_core.storage.database import Database as CoreDatabase
from tests.helpers import (
    add_login_ready_user,
    create_active_session,
    request_with_session,
    route_endpoint,
)


_REASON = "Approved governance policy change for this installation"
_ADMIN_1 = {
    "id": "admin-1",
    "email": "admin1@example.test",
    "password": "temporary-password-1",
}
_ADMIN_2 = {
    "id": "admin-2",
    "email": "admin2@example.test",
    "password": "temporary-password-2",
}


class GovernanceModeTests(unittest.TestCase):
    def _app(
        self,
        tempdir: str,
        *,
        mode: GovernanceMode | None = None,
        lab_mode: bool = False,
        admin_count: int = 2,
        totp_roles: str | None = None,
    ):
        env = {
            "MYOWNCA_GOVERNANCE_MODE": "" if mode is None else mode.value,
        }
        if totp_roles is not None:
            env["MYOWNCA_TOTP_REQUIRED_ROLES"] = totp_roles
        with mock.patch.dict("os.environ", env, clear=False):
            app = create_app(
                Path(tempdir) / "governance.sqlite3",
                lab_mode=lab_mode,
                online_key_dir=Path(tempdir) / "keys",
            )
        sessions = []
        for number in range(1, admin_count + 1):
            secret = add_login_ready_user(
                app,
                user_id=f"admin-{number}",
                email=f"admin{number}@example.test",
                role=Role.ADMIN,
            )
            sessions.append(
                create_active_session(
                    app,
                    email=f"admin{number}@example.test",
                    totp_secret=secret,
                )
            )
        return app, sessions

    def test_single_admin_privileged_changes_apply_immediately(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _ = self._app(
                tempdir,
                mode=GovernanceMode.SINGLE_ADMIN,
                admin_count=1,
            )
            admin = app.state.auth_repository.get_user("admin-1")
            proposal = app.state.auth_service.create_privileged_role_grant_proposal(
                admin,
                user_id="operator-1",
                email="operator1@example.test",
                role=Role.SUPERUSER,
                temporary_password="temporary-password-3",
            )
            self.assertEqual(proposal.status, AdminChangeStatus.APPROVED)
            self.assertTrue(app.state.auth_repository.get_user("operator-1").is_active)
            captured = decode_payload(proposal.payload_json)
            self.assertEqual(captured["governance_mode_at_creation"], "single_admin")
            self.assertEqual(captured["required_approvals"], 0)
            self.assertEqual(app.state.auth_repository.list_pending_proposals(), [])

    def test_pending_dual_proposal_keeps_its_requirement_after_downgrade(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _ = self._app(tempdir)
            service = app.state.auth_service
            repository = app.state.auth_repository
            admin1 = repository.get_user("admin-1")
            admin2 = repository.get_user("admin-2")

            privileged = service.create_privileged_role_grant_proposal(
                admin1,
                user_id="operator-1",
                email="operator1@example.test",
                role=Role.SUPERUSER,
                temporary_password="temporary-password-3",
            )
            downgrade = service.create_governance_downgrade_proposal(
                admin1,
                reason=_REASON,
            )
            service.approve_proposal(downgrade.id, admin2)
            self.assertEqual(service.governance_mode(), GovernanceMode.SINGLE_ADMIN)
            self.assertFalse(repository.get_user("operator-1").is_active)

            with self.assertRaises(AuthorizationError):
                service.approve_proposal(privileged.id, admin1)
            approved = service.approve_proposal(privileged.id, admin2)
            self.assertEqual(approved.status, AdminChangeStatus.APPROVED)
            self.assertTrue(repository.get_user("operator-1").is_active)
            self.assertEqual(
                decode_payload(privileged.payload_json)["governance_mode_at_creation"],
                "dual_control",
            )

    def test_pending_role_grant_cannot_be_activated_or_reset_directly(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _ = self._app(tempdir)
            service = app.state.auth_service
            repository = app.state.auth_repository
            admin1 = repository.get_user("admin-1")
            admin2 = repository.get_user("admin-2")
            proposal = service.create_privileged_role_grant_proposal(
                admin1,
                user_id="future-admin",
                email="future-admin@example.test",
                role=Role.ADMIN,
                temporary_password="temporary-password-3",
            )

            placeholder = repository.get_user("future-admin")
            self.assertEqual(placeholder.role, Role.USER)
            self.assertFalse(placeholder.is_active)
            self.assertIsNone(repository.get_password_credential("future-admin"))
            with self.assertRaises(AuthError):
                service.set_user_active(
                    admin1,
                    target_user_id="future-admin",
                    active=True,
                )
            with self.assertRaises(AuthError):
                service.reset_ordinary_password(
                    admin1,
                    target_user_id="future-admin",
                    temporary_password="replacement-password-1",
                )
            self.assertFalse(repository.get_user("future-admin").is_active)

            approved = service.approve_proposal(proposal.id, admin2)
            self.assertEqual(approved.status, AdminChangeStatus.APPROVED)
            activated = repository.get_user("future-admin")
            self.assertEqual(activated.role, Role.ADMIN)
            self.assertTrue(activated.is_active)
            self.assertIsNotNone(repository.get_password_credential("future-admin"))

    def test_role_grant_rejection_cleanup_keeps_auth_event_evidence(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _ = self._app(tempdir)
            service = app.state.auth_service
            repository = app.state.auth_repository
            proposal = service.create_privileged_role_grant_proposal(
                repository.get_user("admin-1"),
                user_id="operator-1",
                email="operator1@example.test",
                role=Role.SUPERUSER,
                temporary_password="temporary-password-3",
            )
            with self.assertRaises(AuthenticationError):
                service.login(
                    "operator1@example.test",
                    "temporary-password-3",
                )
            service.reject_proposal(proposal.id, repository.get_user("admin-2"))

            with repository.database.connect() as connection:
                events = connection.execute(
                    """
                    SELECT event_type, user_id, email, details_json FROM auth_events
                    WHERE email = ?
                    ORDER BY occurred_at
                    """,
                    ("operator1@example.test",),
                ).fetchall()
            login_failure = next(
                event for event in events if event["event_type"] == "login_failure"
            )
            event = next(
                event
                for event in events
                if event["event_type"] == "role_grant_placeholder_discarded"
            )
            self.assertIsNone(login_failure["user_id"])
            self.assertIsNone(event["user_id"])
            self.assertEqual(event["email"], "operator1@example.test")
            details = json.loads(event["details_json"])
            self.assertEqual(details["proposal_id"], proposal.id)
            self.assertEqual(details["resolution_status"], "rejected")

    def test_runtime_transitions_are_guarded_audited_and_cannot_be_bypassed(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, sessions = self._app(
                tempdir,
                mode=GovernanceMode.SINGLE_ADMIN,
                admin_count=2,
            )
            token1, csrf1 = sessions[0]
            token2, csrf2 = sessions[1]

            status = route_endpoint(app, "/internal/admin/governance", "GET")(
                request_with_session(token1)
            )
            self.assertEqual(status["mode"], "single_admin")
            self.assertEqual(status["install_type"], "production")
            self.assertEqual(status["recommended_mode"], "dual_control")

            upgraded = route_endpoint(
                app,
                "/internal/admin/governance/enable-dual-control",
                "POST",
            )(
                DestructiveActionConfirmation(
                    reason=_REASON,
                    confirmation="ENABLE DUAL CONTROL",
                ),
                request_with_session(token1, csrf1, method="POST"),
            )
            self.assertEqual(upgraded["mode"], "dual_control")

            proposal = route_endpoint(
                app,
                "/internal/admin/governance/single-admin-proposals",
                "POST",
            )(
                DestructiveActionConfirmation(
                    reason=_REASON,
                    confirmation="REQUEST SINGLE ADMIN",
                ),
                request_with_session(token1, csrf1, method="POST"),
            )
            self.assertEqual(proposal["status"], "pending")
            self.assertEqual(proposal["required_approvals"], 1)
            self.assertTrue(proposal["requires_different_admin"])
            self.assertEqual(app.state.auth_service.governance_mode(), GovernanceMode.DUAL_CONTROL)

            with self.assertRaises(HTTPException) as bypass:
                route_endpoint(
                    app,
                    "/internal/admin/proposals/{proposal_id}/approve",
                    "POST",
                )(
                    proposal["id"],
                    request_with_session(token2, csrf2, method="POST"),
                )
            self.assertEqual(bypass.exception.status_code, 400)
            self.assertEqual(app.state.auth_service.governance_mode(), GovernanceMode.DUAL_CONTROL)

            approved = route_endpoint(
                app,
                "/internal/admin/governance/single-admin-proposals/{proposal_id}/approve",
                "POST",
            )(
                proposal["id"],
                DestructiveActionConfirmation(
                    reason="Second administrator approved this governance change",
                    confirmation="APPROVE SINGLE ADMIN",
                ),
                request_with_session(token2, csrf2, method="POST"),
            )
            self.assertEqual(approved["status"], "approved")
            self.assertEqual(app.state.auth_service.governance_mode(), GovernanceMode.SINGLE_ADMIN)
            events = app.state.audit.list_events(limit=50)
            changed = [
                event
                for event in events
                if event.action == "governance_mode_downgrade_approved"
            ]
            self.assertEqual(len(changed), 1)
            self.assertEqual(changed[0].details["proposal_reason"], _REASON)
            serialized = json.dumps(changed[0].details)
            self.assertNotIn("password", serialized.lower())

    def test_enabling_dual_control_does_not_require_password_step_up(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, sessions = self._app(
                tempdir,
                mode=GovernanceMode.SINGLE_ADMIN,
                admin_count=2,
                totp_roles="",
            )
            token, csrf = sessions[0]
            upgraded = route_endpoint(
                app,
                "/internal/admin/governance/enable-dual-control",
                "POST",
            )(
                DestructiveActionConfirmation(
                    reason=_REASON,
                    confirmation="ENABLE DUAL CONTROL",
                ),
                request_with_session(token, csrf, method="POST"),
            )
            self.assertEqual(upgraded["mode"], GovernanceMode.DUAL_CONTROL.value)

    def test_dual_upgrade_requires_two_active_admins_and_preserves_minimum(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, sessions = self._app(
                tempdir,
                mode=GovernanceMode.SINGLE_ADMIN,
                admin_count=1,
            )
            token, csrf = sessions[0]
            with self.assertRaises(HTTPException) as insufficient:
                route_endpoint(
                    app,
                    "/internal/admin/governance/enable-dual-control",
                    "POST",
                )(
                    DestructiveActionConfirmation(
                        reason=_REASON,
                        confirmation="ENABLE DUAL CONTROL",
                    ),
                    request_with_session(token, csrf, method="POST"),
                )
            self.assertEqual(insufficient.exception.status_code, 400)
            self.assertEqual(app.state.auth_service.governance_mode(), GovernanceMode.SINGLE_ADMIN)

            add_login_ready_user(
                app,
                user_id="admin-2",
                email="admin2@example.test",
                role=Role.ADMIN,
            )
            actor = app.state.auth_repository.get_user("admin-1")
            app.state.auth_service.enable_dual_control(actor)
            with self.assertRaises(AuthError) as deactivation:
                app.state.auth_service.set_user_active(
                    actor,
                    target_user_id="admin-2",
                    active=False,
                )
            self.assertIn("two active administrators", str(deactivation.exception))

    def test_setup_lab_defaults_single_and_production_requires_explicit_choice(self) -> None:
        with TemporaryDirectory() as tempdir:
            lab = SetupOrchestrator(tempdir)
            lab.set_install_type("lab")
            self.assertEqual(lab.snapshot()["governance_mode"], "single_admin")
            lab.set_listener(topology="proxy")
            lab.set_admins(dict(_ADMIN_1))
            lab.finalize()
            self.assertEqual(Settings.load(tempdir, environ={}).governance_mode, "single_admin")
            pending = json.loads(
                (Path(tempdir) / "secrets" / "pending-admins.json").read_text()
            )
            self.assertEqual(len(pending), 1)

        with TemporaryDirectory() as tempdir:
            production = SetupOrchestrator(tempdir)
            production.set_install_type("production")
            with self.assertRaises(SetupError) as missing_mode:
                production.set_admins(dict(_ADMIN_1), dict(_ADMIN_2))
            self.assertIn("governance mode", str(missing_mode.exception))
            production.set_governance_mode("dual_control")
            production.set_admins(dict(_ADMIN_1), dict(_ADMIN_2))
            self.assertEqual(
                production.snapshot()["governance_mode"],
                "dual_control",
            )

        with TemporaryDirectory() as tempdir:
            production_single = SetupOrchestrator(tempdir)
            production_single.set_install_type("production")
            production_single.set_governance_mode("single_admin")
            production_single.set_admins(dict(_ADMIN_1))
            from myownca.ca_hsm import SoftwareHSM
            from myownca.ca_main.crypto import certificate_to_pem, create_lab_ca_chain

            production_single.set_root_certificate(
                certificate_to_pem(
                    create_lab_ca_chain(SoftwareHSM()).root.certificate
                )
            )
            production_single.prepare_runtime()
            settings = Settings.load(tempdir, environ={})
            self.assertFalse(settings.lab_mode)
            self.assertEqual(settings.governance_mode, "single_admin")

    def test_existing_install_migration_remains_dual_even_with_single_config(self) -> None:
        with TemporaryDirectory() as tempdir:
            database_path = Path(tempdir) / "legacy.sqlite3"
            partial_migrations = Path(tempdir) / "legacy-migrations"
            partial_migrations.mkdir()
            source_migrations = (
                Path(__file__).parents[1] / "src" / "myownca" / "storage" / "migrations"
            )
            for source in sorted(source_migrations.glob("*.sql")):
                if source.name < "0024_install_governance.sql":
                    shutil.copy(source, partial_migrations / source.name)
            legacy_database = CoreDatabase(database_path)
            legacy_database.migrate(partial_migrations)
            with legacy_database.connect() as connection:
                connection.execute(
                    "INSERT INTO users(id, email, role, is_active) VALUES (?, ?, ?, ?)",
                    ("legacy-admin", "legacy@example.test", "admin", 1),
                )

            with mock.patch.dict(
                "os.environ",
                {"MYOWNCA_GOVERNANCE_MODE": "single_admin"},
                clear=False,
            ):
                app = create_app(
                    database_path,
                    lab_mode=True,
                    online_key_dir=Path(tempdir) / "keys",
                )
            self.assertEqual(app.state.auth_service.governance_mode(), GovernanceMode.DUAL_CONTROL)
            with app.state.auth_repository.database.connect() as connection:
                row = connection.execute(
                    "SELECT source FROM install_governance WHERE singleton_id = 1"
                ).fetchone()
            self.assertEqual(row["source"], "legacy_preserved")

    def test_bootstrap_validation_failure_leaves_users_table_empty(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _ = self._app(
                tempdir,
                mode=GovernanceMode.DUAL_CONTROL,
                admin_count=0,
            )
            with self.assertRaises(AuthError):
                app.state.auth_service.bootstrap_initial_admins(
                    ("admin-1", "admin1@example.test", "temporary-password-1"),
                    ("admin-2", "admin2@example.test", "short"),
                )
            self.assertFalse(app.state.auth_repository.has_any_users())

            created = app.state.auth_service.bootstrap_initial_admins(
                ("admin-1", "admin1@example.test", "temporary-password-1"),
                ("admin-2", "admin2@example.test", "temporary-password-2"),
            )
            self.assertEqual(len(created), 2)

    def test_concurrent_dual_deactivations_cannot_cross_admin_floor(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _ = self._app(
                tempdir,
                mode=GovernanceMode.DUAL_CONTROL,
                admin_count=3,
            )
            service = app.state.auth_service
            repository = app.state.auth_repository
            actor = repository.get_user("admin-1")
            barrier = Barrier(3)

            def deactivate(target_user_id: str) -> str:
                barrier.wait()
                try:
                    service.set_user_active(
                        actor,
                        target_user_id=target_user_id,
                        active=False,
                    )
                except AuthError:
                    return "blocked"
                return "deactivated"

            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [
                    executor.submit(deactivate, "admin-2"),
                    executor.submit(deactivate, "admin-3"),
                ]
                barrier.wait()
                outcomes = [future.result() for future in futures]

            self.assertEqual(sorted(outcomes), ["blocked", "deactivated"])
            self.assertEqual(repository.count_active_users_with_role(Role.ADMIN), 2)

    def test_concurrent_upgrade_and_deactivation_remain_consistent(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _ = self._app(
                tempdir,
                mode=GovernanceMode.SINGLE_ADMIN,
                admin_count=2,
            )
            service = app.state.auth_service
            repository = app.state.auth_repository
            actor = repository.get_user("admin-1")
            barrier = Barrier(3)

            def upgrade() -> None:
                barrier.wait()
                try:
                    service.enable_dual_control(actor)
                except AuthError:
                    pass

            def deactivate() -> None:
                barrier.wait()
                try:
                    service.set_user_active(
                        actor,
                        target_user_id="admin-2",
                        active=False,
                    )
                except AuthError:
                    pass

            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(upgrade), executor.submit(deactivate)]
                barrier.wait()
                for future in futures:
                    future.result()

            mode = service.governance_mode()
            active_admins = repository.count_active_users_with_role(Role.ADMIN)
            self.assertFalse(
                mode is GovernanceMode.DUAL_CONTROL and active_admins < 2
            )

    def test_proposal_creation_is_linearized_with_dual_upgrade(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _ = self._app(
                tempdir,
                mode=GovernanceMode.SINGLE_ADMIN,
                admin_count=2,
            )
            service = app.state.auth_service
            repository = app.state.auth_repository
            actor = repository.get_user("admin-1")
            barrier = Barrier(3)

            def create_change():
                barrier.wait()
                return service.create_privileged_role_grant_proposal(
                    actor,
                    user_id="operator-1",
                    email="operator1@example.test",
                    role=Role.SUPERUSER,
                    temporary_password="temporary-password-3",
                )

            def upgrade() -> None:
                barrier.wait()
                service.enable_dual_control(actor)

            with ThreadPoolExecutor(max_workers=2) as executor:
                proposal_future = executor.submit(create_change)
                upgrade_future = executor.submit(upgrade)
                barrier.wait()
                proposal = proposal_future.result()
                upgrade_future.result()

            captured = decode_payload(proposal.payload_json)
            self.assertEqual(service.governance_mode(), GovernanceMode.DUAL_CONTROL)
            if captured["governance_mode_at_creation"] == "single_admin":
                self.assertEqual(proposal.status, AdminChangeStatus.APPROVED)
                self.assertTrue(repository.get_user("operator-1").is_active)
            else:
                self.assertEqual(captured["governance_mode_at_creation"], "dual_control")
                self.assertEqual(proposal.status, AdminChangeStatus.PENDING)
                self.assertFalse(repository.get_user("operator-1").is_active)

    def test_concurrent_governance_approval_and_rejection_have_one_winner(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _ = self._app(tempdir, admin_count=3)
            service = app.state.auth_service
            repository = app.state.auth_repository
            proposal = service.create_governance_downgrade_proposal(
                repository.get_user("admin-1"),
                reason=_REASON,
            )
            barrier = Barrier(3)

            def approve() -> str:
                barrier.wait()
                try:
                    service.approve_proposal(
                        proposal.id,
                        repository.get_user("admin-2"),
                    )
                except (AuthError, RepositoryError):
                    return "lost"
                return "approved"

            def reject() -> str:
                barrier.wait()
                try:
                    service.reject_proposal(
                        proposal.id,
                        repository.get_user("admin-3"),
                    )
                except AuthError:
                    return "lost"
                return "rejected"

            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(approve), executor.submit(reject)]
                barrier.wait()
                outcomes = [future.result() for future in futures]

            self.assertEqual(outcomes.count("lost"), 1)
            resolved = repository.get_proposal(proposal.id)
            if resolved.status is AdminChangeStatus.APPROVED:
                self.assertEqual(service.governance_mode(), GovernanceMode.SINGLE_ADMIN)
            else:
                self.assertEqual(resolved.status, AdminChangeStatus.REJECTED)
                self.assertEqual(service.governance_mode(), GovernanceMode.DUAL_CONTROL)

    def test_concurrent_privileged_approval_and_rejection_have_one_winner(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _ = self._app(tempdir, admin_count=3)
            add_login_ready_user(
                app,
                user_id="operator-1",
                email="operator1@example.test",
                role=Role.SUPERUSER,
            )
            service = app.state.auth_service
            repository = app.state.auth_repository
            original_hash = repository.get_password_credential(
                "operator-1"
            ).password_hash
            proposal = service.create_privileged_password_reset_proposal(
                repository.get_user("admin-1"),
                target_user_id="operator-1",
                temporary_password="replacement-password-1",
            )
            barrier = Barrier(3)

            def approve() -> str:
                barrier.wait()
                try:
                    service.approve_proposal(
                        proposal.id,
                        repository.get_user("admin-2"),
                    )
                except (AuthError, RepositoryError):
                    return "lost"
                return "approved"

            def reject() -> str:
                barrier.wait()
                try:
                    service.reject_proposal(
                        proposal.id,
                        repository.get_user("admin-3"),
                    )
                except AuthError:
                    return "lost"
                return "rejected"

            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(approve), executor.submit(reject)]
                barrier.wait()
                outcomes = [future.result() for future in futures]

            self.assertEqual(outcomes.count("lost"), 1)
            resolved = repository.get_proposal(proposal.id)
            final_hash = repository.get_password_credential("operator-1").password_hash
            if resolved.status is AdminChangeStatus.APPROVED:
                self.assertNotEqual(final_hash, original_hash)
            else:
                self.assertEqual(resolved.status, AdminChangeStatus.REJECTED)
                self.assertEqual(final_hash, original_hash)

    def test_expired_downgrade_does_not_block_a_replacement(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _ = self._app(tempdir)
            service = app.state.auth_service
            repository = app.state.auth_repository
            actor = repository.get_user("admin-1")
            created_at = datetime.now(timezone.utc)
            expired = service.create_governance_downgrade_proposal(
                actor,
                reason=_REASON,
                now=created_at,
            )
            replacement = service.create_governance_downgrade_proposal(
                actor,
                reason="Replacement governance request after the earlier one expired",
                now=created_at + timedelta(hours=25),
            )
            self.assertEqual(
                repository.get_proposal(expired.id).status,
                AdminChangeStatus.EXPIRED,
            )
            self.assertEqual(replacement.status, AdminChangeStatus.PENDING)

    def test_pending_list_sweeps_expired_role_grant_placeholder(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _ = self._app(tempdir)
            service = app.state.auth_service
            repository = app.state.auth_repository
            created_at = datetime.now(timezone.utc)
            proposal = service.create_privileged_role_grant_proposal(
                repository.get_user("admin-1"),
                user_id="operator-1",
                email="operator1@example.test",
                role=Role.SUPERUSER,
                temporary_password="temporary-password-3",
                now=created_at,
            )
            self.assertEqual(proposal.status, AdminChangeStatus.PENDING)
            with self.assertRaises(AuthenticationError):
                service.login(
                    "operator1@example.test",
                    "temporary-password-3",
                    now=created_at + timedelta(minutes=1),
                )

            pending = repository.list_pending_proposals(
                now=created_at + timedelta(hours=25)
            )
            self.assertEqual(pending, [])
            self.assertIsNone(repository.get_user_by_email("operator1@example.test"))
            with self.assertRaises(RepositoryError):
                repository.get_proposal(proposal.id)
            with repository.database.connect() as connection:
                event = connection.execute(
                    """
                    SELECT details_json FROM auth_events
                    WHERE event_type = ?
                    """,
                    ("role_grant_placeholder_discarded",),
                ).fetchone()
            details = json.loads(event["details_json"])
            self.assertEqual(details["proposal_id"], proposal.id)
            self.assertEqual(details["resolution_status"], "expired")
            retry = service.create_privileged_role_grant_proposal(
                repository.get_user("admin-1"),
                user_id="operator-1",
                email="operator1@example.test",
                role=Role.SUPERUSER,
                temporary_password="temporary-password-4",
                now=created_at + timedelta(hours=25, minutes=1),
            )
            self.assertEqual(retry.status, AdminChangeStatus.PENDING)

    def test_single_admin_role_grant_route_updates_people_mirror(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, sessions = self._app(
                tempdir,
                mode=GovernanceMode.SINGLE_ADMIN,
                admin_count=1,
            )
            token, csrf = sessions[0]
            proposal = route_endpoint(
                app,
                "/internal/admin/proposals/privileged-role-grants",
                "POST",
            )(
                PrivilegedRoleGrantCreate(
                    id="operator-1",
                    email="operator1@example.test",
                    role=Role.SUPERUSER,
                    temporary_password="temporary-password-3",
                ),
                request_with_session(token, csrf, method="POST"),
            )
            self.assertEqual(proposal["status"], "approved")
            self.assertIn(
                "operator1@example.test",
                {person.email for person in app.state.repository.list_people()},
            )

    def test_operations_governance_copy_is_install_context_aware(self) -> None:
        for lab_mode, expected_status, phrase in (
            (True, "pass", "Test/Lab default"),
            (False, "warn", "Production is using single-admin"),
        ):
            with self.subTest(lab_mode=lab_mode), TemporaryDirectory() as tempdir:
                app, sessions = self._app(
                    tempdir,
                    mode=GovernanceMode.SINGLE_ADMIN,
                    lab_mode=lab_mode,
                    admin_count=1,
                )
                readiness = route_endpoint(app, "/internal/admin/readiness", "GET")(
                    request_with_session(sessions[0][0])
                )
                governance = next(
                    item
                    for item in readiness["items"]
                    if item["id"] == "governance.pending_changes"
                )
                self.assertEqual(governance["status"], expected_status)
                self.assertIn(phrase, governance["summary"])

    def test_understaffed_dual_control_is_reported_as_needing_attention(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, sessions = self._app(
                tempdir,
                mode=GovernanceMode.DUAL_CONTROL,
                admin_count=1,
            )
            status = route_endpoint(app, "/internal/admin/governance", "GET")(
                request_with_session(sessions[0][0])
            )
            self.assertFalse(status["dual_control_operational"])
            self.assertIn("two active administrators", status["warning"])

            readiness = route_endpoint(app, "/internal/admin/readiness", "GET")(
                request_with_session(sessions[0][0])
            )
            governance = next(
                item
                for item in readiness["items"]
                if item["id"] == "governance.pending_changes"
            )
            self.assertEqual(governance["status"], "warn")
            self.assertIn("fewer than two active administrators", governance["summary"])

    def test_understaffed_dual_control_rejects_new_governed_proposals(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _ = self._app(
                tempdir,
                mode=GovernanceMode.DUAL_CONTROL,
                admin_count=1,
            )
            service = app.state.auth_service
            repository = app.state.auth_repository
            actor = repository.get_user("admin-1")
            with self.assertRaises(AuthError) as role_grant:
                service.create_privileged_role_grant_proposal(
                    actor,
                    user_id="operator-1",
                    email="operator1@example.test",
                    role=Role.SUPERUSER,
                    temporary_password="temporary-password-3",
                )
            self.assertIn("two active administrators", str(role_grant.exception))
            self.assertIsNone(repository.get_user_by_email("operator1@example.test"))

            with self.assertRaises(AuthError) as downgrade:
                service.create_governance_downgrade_proposal(
                    actor,
                    reason=_REASON,
                )
            self.assertIn("two active administrators", str(downgrade.exception))


if __name__ == "__main__":
    unittest.main()
