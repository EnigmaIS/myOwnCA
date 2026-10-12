from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import HTTPException, Response

from myownca.ca_auth.service import AuthError, AuthenticationError, ThrottledError
from myownca.ca_auth.totp import code_for_step, current_step
from myownca.domain import AdminChangeStatus, GovernanceMode, Role, SessionStage
from myownca.online.app import (
    LoginCreate,
    PasswordChangeCreate,
    TOTPCodeCreate,
    TemplateCreate,
    create_app,
)
from tests.helpers import (
    add_login_ready_user,
    create_active_session,
    request_with_session,
    route_endpoint,
)


class AuthFoundationTests(unittest.TestCase):
    def test_bootstrap_password_change_and_totp_enrollment_flow(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "api.sqlite3")
            admins = app.state.auth_service.bootstrap_initial_admins(
                ("admin-1", "admin1@example.test", "temporary-password-1"),
                ("admin-2", "admin2@example.test", "temporary-password-2"),
            )
            self.assertEqual([admin.role for admin in admins], [Role.ADMIN, Role.ADMIN])
            with self.assertRaises(AuthError):
                app.state.auth_service.bootstrap_initial_admins(
                    ("again-1", "again1@example.test", "temporary-password-3"),
                    ("again-2", "again2@example.test", "temporary-password-4"),
                )

            response = Response()
            logged_in = route_endpoint(app, "/internal/auth/login", "POST")(
                LoginCreate(
                    email="admin1@example.test",
                    password="temporary-password-1",
                ),
                response,
            )
            token = self._session_token(response)
            self.assertEqual(logged_in["stage"], "password_change_required")

            changed = route_endpoint(app, "/internal/auth/password/change", "POST")(
                PasswordChangeCreate(new_password="replacement-password-1"),
                request_with_session(
                    token,
                    logged_in["csrf_token"],
                    method="POST",
                ),
            )
            self.assertEqual(changed["stage"], "totp_enrollment_required")

            enrollment = route_endpoint(app, "/internal/auth/totp/enroll", "POST")(
                request_with_session(token, changed["csrf_token"], method="POST")
            )
            active = route_endpoint(app, "/internal/auth/totp/enroll/confirm", "POST")(
                TOTPCodeCreate(code=code_for_step(enrollment["secret"], current_step())),
                request_with_session(token, changed["csrf_token"], method="POST"),
            )
            self.assertEqual(active["stage"], "active")

    def test_ordinary_users_are_password_only_and_cannot_use_admin_routes(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "api.sqlite3")
            add_login_ready_user(
                app, user_id="user-1", email="user@example.test", role=Role.USER
            )
            token, csrf = create_active_session(app, email="user@example.test")

            with self.assertRaises(HTTPException) as denied:
                route_endpoint(app, "/internal/templates", "POST")(
                    TemplateCreate(id="host", name="Host TLS", profile="host_tls"),
                    request_with_session(token, csrf, method="POST"),
                )
            self.assertEqual(denied.exception.status_code, 403)

    def test_privileged_login_requires_totp_route_challenge(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "api.sqlite3")
            secret = add_login_ready_user(
                app,
                user_id="admin-1",
                email="admin1@example.test",
                role=Role.ADMIN,
            )

            response = Response()
            challenged = route_endpoint(app, "/internal/auth/login", "POST")(
                LoginCreate(
                    email="admin1@example.test",
                    password="very-long-test-password",
                ),
                response,
            )
            token = self._session_token(response)
            self.assertEqual(challenged["stage"], "totp_required")

            active = route_endpoint(app, "/internal/auth/totp/challenge", "POST")(
                TOTPCodeCreate(code=code_for_step(secret, current_step())),
                request_with_session(token, challenged["csrf_token"], method="POST"),
            )
            self.assertEqual(active["stage"], "active")

    def test_csrf_logout_and_session_revocation_are_enforced(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "api.sqlite3")
            add_login_ready_user(
                app, user_id="admin-1", email="admin1@example.test", role=Role.ADMIN
            )
            token, csrf = create_active_session(
                app,
                email="admin1@example.test",
                totp_secret="JBSWY3DPEHPK3PXP",
            )

            with self.assertRaises(HTTPException) as denied:
                route_endpoint(app, "/internal/templates", "POST")(
                    TemplateCreate(id="host", name="Host TLS", profile="host_tls"),
                    request_with_session(token, method="POST"),
                )
            self.assertEqual(denied.exception.status_code, 403)

            route_endpoint(app, "/internal/auth/logout", "POST")(
                request_with_session(token, csrf, method="POST"),
                Response(),
            )
            with self.assertRaises(AuthenticationError):
                app.state.auth_service.require_session(token)

    def test_sessions_expire_and_totp_replay_and_throttling_are_rejected(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "api.sqlite3")
            secret = add_login_ready_user(
                app,
                user_id="admin-1",
                email="admin1@example.test",
                role=Role.ADMIN,
            )
            now = datetime(2026, 5, 16, tzinfo=timezone.utc)
            created = app.state.auth_service.login(
                "admin1@example.test",
                "very-long-test-password",
                now=now,
            )
            code = code_for_step(secret, current_step(now))
            active = app.state.auth_service.verify_totp_challenge(created.token, code, now=now)
            self.assertEqual(active.session.stage, SessionStage.ACTIVE)

            second = app.state.auth_service.login(
                "admin1@example.test",
                "very-long-test-password",
                now=now + timedelta(seconds=1),
            )
            with self.assertRaises(AuthenticationError):
                app.state.auth_service.verify_totp_challenge(
                    second.token,
                    code,
                    now=now + timedelta(seconds=1),
                )
            for offset in range(2, 6):
                with self.assertRaises(AuthenticationError):
                    app.state.auth_service.verify_totp_challenge(
                        second.token,
                        "000000",
                        now=now + timedelta(seconds=offset),
                    )
            with self.assertRaises(ThrottledError):
                app.state.auth_service.verify_totp_challenge(
                    second.token,
                    "000000",
                    now=now + timedelta(seconds=6),
                )
            with self.assertRaises(AuthenticationError):
                app.state.auth_service.require_session(
                    active.token,
                    now=now + timedelta(hours=9),
                )

    def test_dual_control_for_privileged_changes_rejection_and_expiry(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "api.sqlite3")
            add_login_ready_user(
                app, user_id="admin-1", email="admin1@example.test", role=Role.ADMIN
            )
            add_login_ready_user(
                app, user_id="admin-2", email="admin2@example.test", role=Role.ADMIN
            )
            admin1 = app.state.auth_repository.get_user("admin-1")
            admin2 = app.state.auth_repository.get_user("admin-2")

            proposal = app.state.auth_service.create_privileged_role_grant_proposal(
                admin1,
                user_id="su-1",
                email="su1@example.test",
                role=Role.SUPERUSER,
                temporary_password="temporary-password-1",
            )
            self.assertFalse(app.state.auth_repository.get_user("su-1").is_active)
            # re-proposing the same id/email is a clean AuthError, not a 500
            with self.assertRaises(AuthError) as duplicate:
                app.state.auth_service.create_privileged_role_grant_proposal(
                    admin1,
                    user_id="su-1",
                    email="su1@example.test",
                    role=Role.SUPERUSER,
                    temporary_password="temporary-password-1",
                )
            self.assertIn("already exists", str(duplicate.exception))
            with self.assertRaises(AuthError):
                app.state.auth_service.approve_proposal(proposal.id, admin1)
            approved = app.state.auth_service.approve_proposal(proposal.id, admin2)
            self.assertEqual(approved.status, AdminChangeStatus.APPROVED)
            self.assertTrue(app.state.auth_repository.get_user("su-1").is_active)

            reset = app.state.auth_service.create_privileged_totp_reset_proposal(
                admin1,
                target_user_id="su-1",
            )
            app.state.auth_service.approve_proposal(reset.id, admin2)
            self.assertIsNone(app.state.auth_repository.get_totp_factor("su-1"))

            rejected = app.state.auth_service.create_privileged_password_reset_proposal(
                admin1,
                target_user_id="su-1",
                temporary_password="replacement-password-1",
            )
            resolved = app.state.auth_service.reject_proposal(rejected.id, admin2)
            self.assertEqual(resolved.status, AdminChangeStatus.REJECTED)

            expired = app.state.auth_service.create_privileged_password_reset_proposal(
                admin1,
                target_user_id="su-1",
                temporary_password="replacement-password-2",
                now=datetime(2026, 5, 15, tzinfo=timezone.utc),
            )
            with self.assertRaises(AuthError):
                app.state.auth_service.approve_proposal(
                    expired.id,
                    admin2,
                    now=datetime(2026, 5, 16, 0, 0, 1, tzinfo=timezone.utc),
                )
            self.assertEqual(
                app.state.auth_repository.get_proposal(expired.id).status,
                AdminChangeStatus.EXPIRED,
            )

    def test_hsm_backup_export_requires_a_different_admin_in_single_mode(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "api.sqlite3")
            app.state.auth_repository.initialize_governance_mode(
                GovernanceMode.SINGLE_ADMIN,
                datetime.now(timezone.utc),
            )
            add_login_ready_user(
                app, user_id="admin-1", email="admin1@example.test", role=Role.ADMIN
            )
            add_login_ready_user(
                app, user_id="admin-2", email="admin2@example.test", role=Role.ADMIN
            )
            admin1 = app.state.auth_repository.get_user("admin-1")
            admin2 = app.state.auth_repository.get_user("admin-2")

            proposal = app.state.auth_service.create_hsm_backup_proposal(
                admin1,
                reason="Export native HSM backups for the recovery ceremony",
            )
            self.assertEqual(proposal.status, AdminChangeStatus.PENDING)
            with self.assertRaises(AuthError):
                app.state.auth_service.approve_proposal(proposal.id, admin1)
            approved = app.state.auth_service.approve_proposal(proposal.id, admin2)
            self.assertEqual(approved.status, AdminChangeStatus.APPROVED)

    def test_dead_role_grant_proposals_release_their_placeholder_user(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "api.sqlite3")
            add_login_ready_user(
                app, user_id="admin-1", email="admin1@example.test", role=Role.ADMIN
            )
            add_login_ready_user(
                app, user_id="admin-2", email="admin2@example.test", role=Role.ADMIN
            )
            admin1 = app.state.auth_repository.get_user("admin-1")
            admin2 = app.state.auth_repository.get_user("admin-2")
            service = app.state.auth_service
            repo = app.state.auth_repository

            # rejection releases the placeholder account and its credential
            proposal = service.create_privileged_role_grant_proposal(
                admin1,
                user_id="su-9",
                email="su9@example.test",
                role=Role.SUPERUSER,
                temporary_password="temporary-password-1",
            )
            service.reject_proposal(proposal.id, admin2)
            self.assertIsNone(repo.get_user_by_email("su9@example.test"))
            self.assertIsNone(repo.get_password_credential("su-9"))

            # the identity is re-proposable; expiry releases it just the same
            created_at = datetime(2026, 5, 15, tzinfo=timezone.utc)
            retry = service.create_privileged_role_grant_proposal(
                admin1,
                user_id="su-9",
                email="su9@example.test",
                role=Role.SUPERUSER,
                temporary_password="temporary-password-1",
                now=created_at,
            )
            with self.assertRaises(AuthError):
                service.approve_proposal(
                    retry.id, admin2, now=created_at + timedelta(hours=25)
                )
            self.assertIsNone(repo.get_user_by_email("su9@example.test"))

            # third attempt completes the normal dual-control flow
            final = service.create_privileged_role_grant_proposal(
                admin1,
                user_id="su-9",
                email="su9@example.test",
                role=Role.SUPERUSER,
                temporary_password="temporary-password-1",
            )
            service.approve_proposal(final.id, admin2)
            self.assertTrue(repo.get_user("su-9").is_active)

            # an account activated through any other path survives rejection
            survivor = service.create_privileged_role_grant_proposal(
                admin1,
                user_id="su-10",
                email="su10@example.test",
                role=Role.SUPERUSER,
                temporary_password="temporary-password-1",
            )
            with repo.database.connect() as connection:
                connection.execute(
                    "UPDATE users SET role = ?, is_active = 1 WHERE id = ?",
                    (Role.SUPERUSER.value, "su-10"),
                )
            service.reject_proposal(survivor.id, admin2)
            self.assertTrue(repo.get_user("su-10").is_active)

    @staticmethod
    def _session_token(response: Response) -> str:
        cookie = SimpleCookie()
        cookie.load(response.headers["set-cookie"])
        return cookie["myownca_session"].value
