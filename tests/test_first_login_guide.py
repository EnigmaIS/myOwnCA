from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import HTTPException

from myownca.comms import NotificationChannel
from myownca.domain import CertificateProfile, CertificateTemplate, Role, User
from myownca.online.app import FirstLoginGuideDismiss, create_app
from tests.helpers import (
    add_login_ready_user,
    create_active_session,
    request_with_session,
    route_endpoint,
)


class FirstLoginGuideApiTests(unittest.TestCase):
    def test_guide_is_per_account_skippable_and_reports_live_prerequisites(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "api.sqlite3")
            admin_secret = add_login_ready_user(
                app,
                user_id="admin-1",
                email="admin@example.test",
                role=Role.ADMIN,
            )
            add_login_ready_user(
                app,
                user_id="user-1",
                email="user@example.test",
                role=Role.USER,
            )
            admin_token, admin_csrf = create_active_session(
                app,
                email="admin@example.test",
                totp_secret=admin_secret,
            )
            user_token, user_csrf = create_active_session(
                app,
                email="user@example.test",
            )
            status_endpoint = route_endpoint(
                app,
                "/internal/auth/first-login-guide",
                "GET",
            )
            dismiss_endpoint = route_endpoint(
                app,
                "/internal/auth/first-login-guide/dismiss",
                "POST",
            )

            initial = status_endpoint(
                request_with_session(admin_token, admin_csrf)
            )
            self.assertTrue(initial["eligible"])
            self.assertTrue(initial["show"])
            self.assertTrue(initial["action_needed"])
            self.assertEqual(initial["role"], "admin")
            self.assertFalse(
                initial["prerequisites"]["certificate_templates"]["ready"]
            )
            self.assertFalse(initial["prerequisites"]["password_recovery"]["ready"])
            self.assertEqual(
                initial["prerequisites"]["certificate_operator"],
                {"ready": False, "count": 0},
            )

            app.state.repository.add_user(
                User(
                    id="operator-inactive",
                    email="inactive-operator@example.test",
                    role=Role.SUPERUSER,
                    is_active=False,
                )
            )
            inactive_operator = status_endpoint(
                request_with_session(admin_token, admin_csrf)
            )
            self.assertEqual(
                inactive_operator["prerequisites"]["certificate_operator"],
                {"ready": False, "count": 0},
            )

            operator_secret = add_login_ready_user(
                app,
                user_id="operator-1",
                email="operator@example.test",
                role=Role.SUPERUSER,
            )
            operator_token, operator_csrf = create_active_session(
                app,
                email="operator@example.test",
                totp_secret=operator_secret,
            )

            app.state.repository.add_template(
                CertificateTemplate(
                    id="host",
                    name="Host TLS",
                    profile=CertificateProfile.HOST_TLS,
                )
            )
            app.state.comms.set_config(
                NotificationChannel.EMAIL,
                enabled=True,
                config={"host": "smtp.example.test", "from_address": "ca@example.test"},
                secrets={},
            )
            ready = status_endpoint(
                request_with_session(admin_token, admin_csrf)
            )
            self.assertEqual(
                ready["prerequisites"]["certificate_templates"],
                {"ready": True, "count": 1},
            )
            self.assertEqual(
                ready["prerequisites"]["password_recovery"],
                {"ready": True, "channels": ["email"]},
            )
            self.assertEqual(
                ready["prerequisites"]["certificate_operator"],
                {"ready": True, "count": 1},
            )
            self.assertFalse(ready["action_needed"])

            skipped = dismiss_endpoint(
                FirstLoginGuideDismiss(outcome="skipped"),
                request_with_session(admin_token, admin_csrf, method="POST"),
            )
            self.assertFalse(skipped["show"])
            self.assertEqual(skipped["outcome"], "skipped")

            operator_initial = status_endpoint(
                request_with_session(operator_token, operator_csrf)
            )
            self.assertTrue(operator_initial["show"])
            self.assertEqual(operator_initial["role"], "superuser")
            completed = dismiss_endpoint(
                FirstLoginGuideDismiss(outcome="completed"),
                request_with_session(operator_token, operator_csrf, method="POST"),
            )
            self.assertFalse(completed["show"])
            self.assertEqual(completed["outcome"], "completed")

            ordinary_user = status_endpoint(
                request_with_session(user_token, user_csrf)
            )
            self.assertFalse(ordinary_user["eligible"])
            self.assertFalse(ordinary_user["show"])
            with self.assertRaises(HTTPException) as denied:
                dismiss_endpoint(
                    FirstLoginGuideDismiss(outcome="skipped"),
                    request_with_session(user_token, user_csrf, method="POST"),
                )
            self.assertEqual(denied.exception.status_code, 403)

    def test_dismiss_requires_csrf(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "api.sqlite3")
            secret = add_login_ready_user(
                app,
                user_id="admin-1",
                email="admin@example.test",
                role=Role.ADMIN,
            )
            token, _ = create_active_session(
                app,
                email="admin@example.test",
                totp_secret=secret,
            )
            with self.assertRaises(HTTPException) as denied:
                route_endpoint(
                    app,
                    "/internal/auth/first-login-guide/dismiss",
                    "POST",
                )(
                    FirstLoginGuideDismiss(outcome="skipped"),
                    request_with_session(token, method="POST"),
                )
            self.assertEqual(denied.exception.status_code, 403)


class FirstLoginGuideUiTests(unittest.TestCase):
    def test_admin_and_operator_portals_mount_the_reopenable_guide(self) -> None:
        static = Path(__file__).parents[1] / "src/myownca/online/static"
        admin_html = (static / "admin.html").read_text()
        operator_html = (static / "superuser.html").read_text()
        shared_js = (static / "app_shared.js").read_text()
        css = (static / "app.css").read_text()

        self.assertIn('id="getting-started"', admin_html)
        self.assertIn('id="getting-started"', operator_html)
        self.assertIn('id="getting-started" class="has-pending-action hidden" hidden', admin_html)
        self.assertIn('id="getting-started" class="has-pending-action hidden" hidden', operator_html)
        self.assertLess(
            admin_html.index('id="getting-started"'),
            admin_html.index('data-view="dashboard"'),
        )
        self.assertLess(
            operator_html.index('id="getting-started"'),
            operator_html.index('data-view="dashboard"'),
        )
        self.assertIn("/internal/auth/first-login-guide", shared_js)
        self.assertIn('sideNav.addEventListener("click"', shared_js)
        self.assertIn("refreshGettingStartedNavigation().catch(showError)", shared_js)
        self.assertIn('cache: "no-store"', shared_js)
        self.assertIn("Skip wizard", shared_js)
        self.assertIn("updateGettingStartedNavigation(status)", shared_js)
        self.assertIn("status.action_needed", shared_js)
        self.assertIn('classList.toggle("hidden", !actionNeeded)', shared_js)
        self.assertIn('indicator.textContent = "!"', shared_js)
        self.assertIn('indicator.setAttribute("aria-label", "Action needed")', shared_js)
        self.assertIn('#getting-started.has-pending-action:not([hidden]):not(.hidden)', css)
        self.assertIn('@keyframes getting-started-pulse', css)
        self.assertIn('@media (prefers-reduced-motion: reduce)', css)
        self.assertIn('badge ${ready ? "ok" : "danger"}', shared_js)
        self.assertIn('classList.toggle("is-action-needed", !ready)', shared_js)
        self.assertIn("dismissible: false", shared_js)
        self.assertNotIn("Continue later", shared_js)
        self.assertIn("page = Math.max(0, page - 1)", shared_js)
        self.assertIn("Certificate Operator access is ready", shared_js)
        self.assertNotIn("No Certificate Operators have been added yet.", shared_js)
        self.assertIn("Open Privileged users", shared_js)
        self.assertIn("Create or manage Certificate Operator accounts in Privileged users.", shared_js)
        self.assertLess(
            shared_js.index("Create and activate a Certificate Operator account"),
            shared_js.index("Create or manage Certificate Operator accounts in Privileged users."),
        )
        self.assertLess(
            shared_js.index("Create or manage Certificate Operator accounts in Privileged users."),
            shared_js.index("Open Privileged users"),
        )
        self.assertLess(
            shared_js.index("Create and activate a Certificate Operator account"),
            shared_js.index("available to issue and manage certificates."),
        )
        self.assertLess(
            shared_js.index("available to issue and manage certificates."),
            shared_js.index("Open Privileged users"),
        )
        self.assertNotIn(
            'if (!hasOperator) {\n          step.append(continueLaterAction("Open Privileged users"',
            shared_js,
        )
        self.assertIn("Define certificate templates before creating certificates", shared_js)
        self.assertIn("Create or review certificate templates in Templates.", shared_js)
        self.assertIn("Open Templates", shared_js)
        self.assertIn("Self-service password recovery needs at least one enabled notification channel", shared_js)
        self.assertIn("under Dual control, fewer than two Administrators", shared_js)
        self.assertIn("Open Notifications & integrations", shared_js)
        self.assertNotIn('"Next steps"', shared_js)
        self.assertNotIn("Your next steps", shared_js)
        self.assertIn('["admin", "superuser"].includes(currentUser.role)', shared_js)
        self.assertIn(".first-login-guide-progress", css)
        self.assertIn(".first-login-guide-check.is-action-needed", css)


if __name__ == "__main__":
    unittest.main()
