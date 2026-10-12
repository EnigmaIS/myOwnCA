from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import HTTPException
from fastapi.responses import FileResponse, RedirectResponse

from myownca import __version__
from myownca.domain import Role
from myownca.offline.cli import build_parser
from myownca.online.app import create_app
from tests.helpers import (
    add_login_ready_user,
    create_active_session,
    request_with_session,
    route_endpoint,
)


class SmokeTests(unittest.TestCase):
    def test_online_api_starts_and_reports_health(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "api.sqlite3")
        routes = {route.path: route for route in app.routes}
        self.assertIn("/health", routes)
        self.assertEqual(routes["/health"].endpoint(), {"status": "ok"})
        self.assertEqual(app.version, __version__)

    def test_setup_finalize_status_follows_form_section_order(self) -> None:
        setup_html = (
            Path(__file__).parents[1] / "src/myownca/setup/static/setup.html"
        ).read_text()
        checks = [
            setup_html.index("else if (!rootReady)"),
            setup_html.index("else if (!databaseReady)"),
            setup_html.index("else if (!cloudReady)"),
            setup_html.index("else if (!pkcs11Ready)"),
            setup_html.index("else if (!issuerConfigured)"),
            setup_html.index("else if (!governanceMode)"),
            setup_html.index("else if (!adminsReady)"),
            setup_html.index("else if (!finalPinReady)"),
        ]

        self.assertEqual(checks, sorted(checks))
        self.assertIn(
            '"Import and verify the Root CA certificate before continuing."',
            setup_html,
        )
        self.assertIn(
            '"Complete the database configuration before continuing."',
            setup_html,
        )

    def test_role_portal_routes_and_static_assets_are_registered(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "api.sqlite3")
            admin_secret = add_login_ready_user(
                app,
                user_id="admin-1",
                email="admin1@example.test",
                role=Role.ADMIN,
            )
            su_secret = add_login_ready_user(
                app,
                user_id="su-1",
                email="su1@example.test",
                role=Role.SUPERUSER,
            )
            add_login_ready_user(
                app,
                user_id="user-1",
                email="user@example.test",
                role=Role.USER,
            )
            add_login_ready_user(
                app,
                user_id="auditor-1",
                email="auditor@example.test",
                role=Role.AUDITOR,
            )

            unauthenticated = route_endpoint(app, "/app/user", "GET")(request_with_session())
            console_redirect = route_endpoint(app, "/console", "GET")()
            admin_token, admin_csrf = create_active_session(
                app,
                email="admin1@example.test",
                totp_secret=admin_secret,
            )
            su_token, su_csrf = create_active_session(
                app,
                email="su1@example.test",
                totp_secret=su_secret,
            )
            user_token, user_csrf = create_active_session(app, email="user@example.test")
            auditor_token, auditor_csrf = create_active_session(app, email="auditor@example.test")

            admin_home = route_endpoint(app, "/app", "GET")(
                request_with_session(admin_token, admin_csrf)
            )
            active_login = route_endpoint(app, "/login", "GET")(
                request_with_session(admin_token, admin_csrf)
            )
            anonymous_login = route_endpoint(app, "/login", "GET")(request_with_session())
            admin_page = route_endpoint(app, "/app/admin", "GET")(
                request_with_session(admin_token, admin_csrf)
            )
            admin_identity = route_endpoint(app, "/internal/auth/me", "GET")(
                request_with_session(admin_token, admin_csrf)
            )
            su_page = route_endpoint(app, "/app/superuser", "GET")(
                request_with_session(su_token, su_csrf)
            )
            user_page = route_endpoint(app, "/app/user", "GET")(
                request_with_session(user_token, user_csrf)
            )
            auditor_page = route_endpoint(app, "/app/auditor", "GET")(
                request_with_session(auditor_token, auditor_csrf)
            )
            with self.assertRaises(HTTPException) as denied:
                route_endpoint(app, "/app/admin", "GET")(
                    request_with_session(user_token, user_csrf)
                )
        routes = {route.path: route for route in app.routes}
        static_dir = Path(__file__).parents[1] / "src/myownca/online/static"
        theme_css = Path(__file__).parents[1] / "src/myownca/ui_theme.css"
        admin_html = (static_dir / "admin.html").read_text()
        user_html = (static_dir / "user.html").read_text()
        auditor_html = (static_dir / "auditor.html").read_text()
        user_js = (static_dir / "user.js").read_text()
        superuser_html = (static_dir / "superuser.html").read_text()
        login_html = (static_dir / "login.html").read_text()
        shared_js = (static_dir / "app_shared.js").read_text()
        superuser_js = (static_dir / "superuser.js").read_text()
        admin_js = (static_dir / "admin.js").read_text()
        admin_dashboard_js = (static_dir / "admin-dashboard.js").read_text()
        admin_backup_js = (static_dir / "admin-backup.js").read_text()
        auth_js = (static_dir / "auth.js").read_text()
        app_css = (static_dir / "app.css").read_text()
        setup_html = (
            Path(__file__).parents[1] / "src/myownca/setup/static/setup.html"
        ).read_text()

        self.assertIsInstance(unauthenticated, RedirectResponse)
        self.assertEqual(unauthenticated.status_code, 303)
        self.assertEqual(unauthenticated.headers["location"], "/login")
        self.assertIsInstance(console_redirect, RedirectResponse)
        self.assertEqual(console_redirect.headers["location"], "/app")
        self.assertIsInstance(admin_home, RedirectResponse)
        self.assertEqual(admin_home.headers["location"], "/app/admin")
        self.assertIsInstance(active_login, RedirectResponse)
        self.assertEqual(active_login.headers["location"], "/app")
        self.assertIsInstance(anonymous_login, FileResponse)
        self.assertEqual(anonymous_login.headers["cache-control"], "no-store")
        self.assertIsInstance(admin_page, FileResponse)
        self.assertEqual(admin_page.headers["cache-control"], "no-cache")
        self.assertEqual(admin_identity["app_version"], __version__)
        self.assertIsInstance(su_page, FileResponse)
        self.assertIsInstance(user_page, FileResponse)
        self.assertIsInstance(auditor_page, FileResponse)
        self.assertEqual(denied.exception.status_code, 403)
        self.assertTrue((static_dir / "login.html").exists())
        self.assertTrue((static_dir / "app.css").exists())
        self.assertTrue(theme_css.exists())
        self.assertIn('"myownca" = ["ui_theme.css"]', (Path(__file__).parents[1] / "pyproject.toml").read_text())
        self.assertTrue((static_dir / "app_shared.js").exists())
        self.assertTrue((static_dir / "user.js").exists())
        self.assertTrue((static_dir / "superuser.js").exists())
        self.assertTrue((static_dir / "admin.js").exists())
        self.assertTrue((static_dir / "admin-dashboard.js").exists())
        self.assertTrue((static_dir / "auth.js").exists())
        self.assertFalse((static_dir / "console.html").exists())
        self.assertFalse((static_dir / "console.js").exists())
        self.assertIn("myOwnCA · Admin", admin_html)
        self.assertIn('href="/app/assets/app.css?v=21"', admin_html)
        self.assertNotIn('href="/app/assets/app.css?v=12"', admin_html)
        self.assertIn('data-view="dashboard"', admin_html)
        self.assertIn('data-view="privileged"', admin_html)
        self.assertIn("proposal-badge", admin_html)
        self.assertIn("details-drawer", admin_html)
        self.assertNotIn("subca-request-form", admin_html)
        self.assertIn("privileged-role-form", admin_html)
        self.assertIn('id="governance-mode-panel"', admin_html)
        self.assertIn('id="governance-mode-badge"', admin_html)
        self.assertIn("<strong>Governed scope:</strong>", admin_html)
        self.assertIn('name="governance-mode" value="single_admin"', setup_html)
        self.assertIn('name="governance-mode" value="dual_control"', setup_html)
        self.assertIn("Recommended for production", setup_html)
        self.assertIn("Test/Lab default", setup_html)
        self.assertIn("Production requires an explicit choice", setup_html)
        self.assertIn("/setup/governance-mode", setup_html)
        self.assertIn('governanceMode === "dual_control"', setup_html)
        self.assertIn('id="include-admin2" type="checkbox"', setup_html)
        self.assertIn('aria-controls="admin2-fields"', setup_html)
        self.assertIn("admins.second =", setup_html)
        self.assertIn('status: "/internal/admin/governance"', admin_js)
        self.assertIn("/internal/admin/governance/enable-dual-control", admin_js)
        self.assertIn("/internal/admin/governance/single-admin-proposals", admin_js)
        self.assertIn('/app/assets/admin.js?v=29', admin_html)
        self.assertNotIn('/app/assets/admin.js?v=13', admin_html)
        self.assertIn('confirmation: "ENABLE DUAL CONTROL"', admin_js)
        self.assertIn('confirmation: "REQUEST SINGLE ADMIN"', admin_js)
        self.assertIn('confirmation: "APPROVE SINGLE ADMIN"', admin_js)
        self.assertIn("A different administrator must approve", admin_js)
        self.assertIn("A downgrade request does not change the current mode", admin_js)
        self.assertIn('governanceState?.install_type === "lab"', admin_js)
        self.assertIn('button.textContent = dualControl ? "Create proposal" : "Apply change"', admin_js)
        self.assertIn("entropy-form", admin_html)
        self.assertIn('href="#/entropy" data-view="entropy">Random number source</a>', admin_html)
        self.assertIn('id="view-entropy"', admin_html)
        self.assertIn('entropy: { title: "Random number source", section: "#view-entropy"', admin_js)
        self.assertNotIn("Key material &amp; entropy", admin_html)
        self.assertNotIn("and entropy sources", admin_html)
        self.assertNotIn("root-cert-form", admin_html)
        self.assertIn("Immutable trust chain", admin_html)
        self.assertNotIn("Trust-chain protection", admin_html)
        self.assertNotIn("Authenticated session active, but recent", admin_html)
        self.assertIn("User portal", user_html)
        self.assertIn("renewal-certificate-select", user_html)
        self.assertIn("Request, withdraw, and receive certificates", user_html)
        self.assertIn("key-source", user_html)
        self.assertIn("server-key-fields", user_html)
        self.assertIn('actionButton("Withdraw"', user_js)
        self.assertIn("/reject", user_js)
        self.assertIn("openExportModal", shared_js)
        self.assertIn("/export", shared_js)
        holder_html = (static_dir / "holder.html").read_text()
        holder_js = (static_dir / "holder.js").read_text()
        self.assertIn("panel-otp", holder_html)
        self.assertIn("bundle-password", holder_html)
        self.assertTrue((static_dir / "holder.js").exists())
        self.assertIn("holder-portal-form", admin_html)
        self.assertIn("theme-panel", admin_html)
        self.assertIn('id="theme-color"', admin_html)
        self.assertIn("color-control-row", admin_html)
        self.assertIn("color-control", admin_html)
        self.assertIn("#theme-color::-webkit-color-swatch", app_css)
        self.assertIn("/internal/branding/theme", admin_js)
        self.assertIn("tpl-cert-link-form", superuser_html)
        self.assertIn("include_renewal_link", superuser_html)
        self.assertIn("access_requested", superuser_html)
        self.assertIn("access-requests-table", superuser_html)
        request_access_html = (static_dir / "request-access.html").read_text()
        self.assertIn("access-form", request_access_html)
        self.assertIn('name="website"', request_access_html)  # honeypot
        self.assertTrue((static_dir / "request-access.js").exists())
        self.assertIn("/request-access", login_html)
        self.assertIn("panel-enroll", holder_html)
        self.assertIn("links-table", superuser_html)
        self.assertIn("server_key_purge_days", admin_html)
        self.assertIn('data-view="license"', admin_html)
        self.assertIn("license-form", admin_html)
        self.assertIn("certs-usage", superuser_html)
        self.assertIn("myOwnCA Certificate Operator Portal", superuser_html)
        self.assertIn('data-view="requests"', superuser_html)
        self.assertIn("Approval automatically attempts issuance", superuser_html)
        self.assertIn("rejectRequest", superuser_js)
        self.assertIn("/reject", superuser_js)
        self.assertIn("auto_issue_error", superuser_js)
        self.assertIn('name="email_addresses"', user_html)
        self.assertIn('name="email_addresses"', admin_html)
        self.assertIn('name="email_addresses"', superuser_html)
        self.assertIn('name="email_addresses"', holder_html)
        self.assertIn("syncProfileSanFields", shared_js)
        self.assertIn("profileSanPayload", user_js)
        self.assertIn("profileSanPayload", superuser_js)
        self.assertIn("profileSanPayload", holder_js)
        # Feature C: "Use as portal TLS" action + status panel on the External Certs view.
        self.assertIn("portal-tls-panel", superuser_html)
        self.assertIn("Portal TLS certificate", superuser_html)
        self.assertIn("use-as-portal-tls", superuser_js)
        self.assertIn('s.key_backend === "software"', superuser_js)
        self.assertIn("renderPortalTls", superuser_js)
        # ACME phase 2: DNS-01 provider fields on the account form; manual "Complete DNS-01" removed.
        self.assertIn('name="dns_provider"', superuser_html)
        self.assertNotIn("tpl-acme-complete-form", superuser_html)
        self.assertNotIn("openAcmeCompleteModal", superuser_js)
        # Corrections batch 2: People→holder-only; login-account management moved to admin.
        self.assertNotIn("/internal/users", superuser_js)
        self.assertIn("login-accounts-table", admin_html)
        self.assertIn("/internal/users", admin_js)
        self.assertIn("/internal/admin/risk-summary", admin_dashboard_js)
        self.assertIn("/internal/admin/operations", admin_dashboard_js)
        self.assertIn("/internal/admin/readiness", admin_dashboard_js)
        self.assertNotIn("/internal/admin/recovery-attestations", admin_dashboard_js)
        self.assertIn("/internal/admin/backups", admin_backup_js)
        self.assertIn("/internal/audit/events?limit=40", admin_dashboard_js)
        self.assertIn("Promise.allSettled", admin_dashboard_js)
        self.assertIn('BB.licenseTierDisplay({ status: "none" })', admin_dashboard_js)
        self.assertIn("All lifecycle and automation features are available", admin_dashboard_js)
        self.assertIn("Embedded licensing key error", admin_dashboard_js)
        self.assertIn("License public-key configuration error", admin_js)
        self.assertIn("This development build has no embedded licensing public keys", admin_dashboard_js)
        self.assertNotIn("MYOWNCA_LICENSE_PUBLIC_KEYS", admin_js)
        self.assertIn("producer-signed release", admin_js)
        self.assertIn("active of ${limit} certificate identities", admin_dashboard_js)
        self.assertNotIn("active + ${reserved} reserved", admin_dashboard_js)
        self.assertIn("capacity-meter-pending", admin_dashboard_js)
        self.assertIn("pending approval", admin_dashboard_js)
        self.assertIn("const risk = lifecycle.risk_summary || {};", admin_dashboard_js)
        self.assertIn('BB.api("/internal/admin/risk-summary").catch(() => null)', admin_dashboard_js)
        self.assertIn(
            'risk.status === "fulfilled" ? { risk_summary: risk.value } : {}',
            admin_dashboard_js,
        )
        self.assertIn(".capacity-meter-pending", app_css)
        self.assertIn("radial-gradient(circle, var(--warn)", app_css)
        self.assertNotIn("reserved / ${summary.lineage_limit}", admin_js)
        self.assertNotIn("reserved / ${license.lineage_limit}", superuser_js)
        self.assertNotIn("reserved of ${license.lineage_limit}", superuser_js)
        self.assertNotIn("lifecycleCapacityNotice", admin_dashboard_js)
        self.assertIn("AdminDashboard.mount", admin_js)
        self.assertIn("load: AdminDashboard.refreshActivity", admin_js)
        self.assertIn('src="/app/assets/admin-dashboard.js?v=14"', admin_html)
        self.assertIn('src="/app/assets/admin-backup.js?v=1"', admin_html)
        self.assertNotIn('src="/app/assets/admin-dashboard.js?v=12"', admin_html)
        self.assertIn('src="/app/assets/app_shared.js?v=22"', admin_html)
        self.assertIn('src="/app/assets/app_shared.js?v=22"', user_html)
        self.assertIn('src="/app/assets/app_shared.js?v=22"', auditor_html)
        self.assertIn('href="/app/assets/app.css?v=21"', superuser_html)
        self.assertIn('src="/app/assets/app_shared.js?v=22"', superuser_html)
        self.assertIn('src="/app/assets/superuser.js?v=15"', superuser_html)
        self.assertIn('id="dashboard-license-summary"', superuser_html)
        self.assertIn("data-license-tier", admin_html)
        self.assertIn("data-license-tier", superuser_html)
        self.assertIn("data-app-version", admin_html)
        self.assertIn("data-app-version", superuser_html)
        self.assertLess(
            admin_html.index("data-license-tier"),
            admin_html.index("data-app-version"),
        )
        self.assertLess(
            superuser_html.index("data-license-tier"),
            superuser_html.index("data-app-version"),
        )
        self.assertIn("currentUser.app_version", shared_js)
        self.assertIn("Personal Licence – NOT for commercial use", shared_js)
        self.assertIn("Commercial Licence", shared_js)
        self.assertIn('summary.status === "valid"', shared_js)
        self.assertIn(".status-pill.license-tier", app_css)
        self.assertIn("overflow-wrap: anywhere", app_css)
        self.assertIn(".status-pill.sidebar-license-tier", app_css)
        self.assertIn(".sidebar-app-version", app_css)
        self.assertIn(".side-nav a.has-pending-action", app_css)
        self.assertIn(".pending-action-cta", app_css)
        self.assertIn(".muted-action-cta", app_css)
        self.assertIn("setNavPending", shared_js)
        self.assertIn("setDashboardAlertMuted", shared_js)
        self.assertIn("updatePendingNavigation", admin_dashboard_js)
        self.assertIn("toggleAdminAlertMute", admin_dashboard_js)
        self.assertIn("toggleOperatorDashboardAlert", superuser_js)
        self.assertIn('id="dashboard-attention-region"', admin_html)
        self.assertIn('id="dashboard-readiness-region"', admin_html)
        self.assertIn('id="dashboard-lifecycle-region"', admin_html)
        self.assertIn('id="dashboard-capacity-region"', admin_html)
        self.assertNotIn('id="dashboard-security-region"', admin_html)
        self.assertIn('id="activity-changes-region"', admin_html)
        dashboard_view = admin_html[
            admin_html.index('id="view-dashboard"') : admin_html.index("<!-- Appearance -->")
        ]
        self.assertLess(
            dashboard_view.index('id="dashboard-lifecycle-region"'),
            dashboard_view.index('id="dashboard-readiness-region"'),
        )
        self.assertLess(
            dashboard_view.index('id="dashboard-capacity-region"'),
            dashboard_view.index('id="dashboard-readiness-region"'),
        )
        self.assertLess(
            dashboard_view.index('id="dashboard-readiness-region"'),
            dashboard_view.index('id="dashboard-attention-region"'),
        )
        activity_view = admin_html[admin_html.index('id="view-logs"') :]
        self.assertNotIn("Security posture", dashboard_view)
        self.assertNotIn("Recent changes", dashboard_view)
        self.assertIn("Accountability", activity_view)
        self.assertIn("Recent changes", activity_view)
        self.assertIn('document.createElement("details")', admin_dashboard_js)
        self.assertIn("Other completed checks", admin_dashboard_js)
        self.assertIn(
            'item.status === "pass" && item.id !== BACKUP_CHECK_ID', admin_dashboard_js
        )
        self.assertIn("REGION_KEYS.length - unavailable", admin_dashboard_js)
        self.assertIn(
            'id="activity-changes-freshness" class="freshness" role="status" aria-live="polite"',
            admin_html,
        )
        activity_changes_tag = admin_html.split('id="activity-changes"', 1)[1].split(">", 1)[0]
        self.assertNotIn("aria-live", activity_changes_tag)
        self.assertIn('.filter((item) => item.status !== "pass")', admin_dashboard_js)
        dashboard_refresh = admin_dashboard_js.split("async function refresh() {", 1)[1].split(
            "function mount()", 1
        )[0]
        self.assertNotIn("/internal/audit/events", dashboard_refresh)
        self.assertNotIn("Human attestation", admin_dashboard_js)
        self.assertIn("Application backup", admin_dashboard_js)
        self.assertIn("hand off to a Certificate Operator", admin_dashboard_js)
        # Communication channels moved superuser Settings -> admin Channels.
        self.assertNotIn("comms-table", superuser_html)
        self.assertNotIn("/internal/comms", superuser_js)
        self.assertIn('data-view="channels"', admin_html)
        self.assertIn("comms-table", admin_html)
        self.assertIn("/internal/comms", admin_js)
        self.assertIn('/internal/comms/test', admin_js)
        self.assertIn("if (!result.success)", admin_js)
        self.assertIn("Notification test failed", admin_js)
        self.assertIn("Notifications &amp; integrations", admin_html)
        self.assertIn("Activity &amp; diagnostics", admin_html)
        # Holder self-service panel: own row + inline checkbox.
        self.assertIn("panel grid-full", admin_html)
        self.assertIn('class="checkbox"><input id="access-request-enabled"', admin_html)
        # mTLS setup moved into a popup opened from a link; holder grid is two columns.
        self.assertIn("tpl-mtls-proxy-help", admin_html)
        self.assertIn('id="mtls-help-link"', admin_html)
        self.assertIn("grid grid-2", admin_html)
        self.assertIn("openMtlsHelp", admin_js)
        self.assertNotIn('id="mtls-proxy-panel"', admin_html)
        self.assertNotIn("/issue", superuser_js)
        self.assertNotIn('actionButton("Issue"', superuser_js)
        self.assertIn("/internal/auth/me", shared_js)
        self.assertIn("password-change-form", login_html)
        self.assertIn("totp-enroll-panel", login_html)
        self.assertNotIn("Last response", login_html)
        self.assertNotIn('id="auth-output"', login_html)
        self.assertNotIn("authOutput", auth_js)
        self.assertIn('id="auth-error"', login_html)
        self.assertIn("function showAuthError", auth_js)
        self.assertIn("function runAuthAction", auth_js)
        self.assertIn("body?.detail ?? body?.error ?? body?.message", auth_js)
        self.assertIn('/app/assets/auth.js?v=4', login_html)
        self.assertLess(
            auth_js.index('body.stage === "active"'),
            auth_js.index('passwordRecoveryRequestForm?.classList.add("hidden")'),
        )
        self.assertIn('window.location.replace("/app")', auth_js)
        self.assertIn("/internal/auth/totp/challenge", auth_js)
        self.assertIn("/app/assets", routes)
        self.assertIn("/theme.css", routes)
        self.assertIn("function apiErrorMessage", shared_js)
        self.assertIn("body?.detail ?? body?.error ?? body?.message", shared_js)
        self.assertIn("value.success === false || value.ok === false", shared_js)
        self.assertIn("const TOAST_DURATION_MS = 10_000", shared_js)
        self.assertIn("window.setTimeout(close, TOAST_DURATION_MS)", shared_js)
        self.assertIn('progress.className = "result-toast-progress"', shared_js)
        self.assertIn("@keyframes result-toast-countdown", app_css)
        self.assertIn("var(--toast-duration, 10s)", app_css)
        self.assertIn("key listing error", admin_js)
        self.assertIn("DKEK status error", admin_js)
        self.assertNotIn('id="hsm-init-form"', admin_html)
        self.assertNotIn("Initialize smartcard", admin_html)
        self.assertNotIn("SmartCard-HSM requires exactly 16 hexadecimal characters", admin_html)
        self.assertIn("SmartCard-HSM User PINs are numeric", admin_html)
        self.assertIn('pattern="[0-9]{6,15}"', admin_html)
        self.assertIn("DKEK shares are created only during Setup", admin_html)
        self.assertIn('id="hsm-dkek-disabled-notice"', admin_html)
        self.assertIn('id="hsm-dkek-controls"', admin_html)
        self.assertNotIn('id="hsm-dkek-form"', admin_html)
        self.assertNotIn("Create DKEK share", admin_html)
        self.assertNotIn('BB.api("/internal/hsm/dkek/shares", {', admin_js)
        self.assertIn('id="hsm-raw-backup-controls"', admin_html)
        self.assertIn("initializedWithoutDkek", admin_js)
        self.assertIn("hsmDkekRecoveryAvailable", admin_js)
        self.assertIn('admin.js?v=29', admin_html)
        self.assertNotIn('id="hsm-advanced"', admin_html)
        self.assertNotIn("Advanced HSM administration", admin_html)
        self.assertNotIn("MYOWNCA_HSM_BACKEND", admin_html)
        self.assertNotIn('id="hsm-switch-software"', admin_html)
        self.assertNotIn('id="hsm-switch-pkcs11"', admin_html)
        self.assertNotIn("/internal/hsm/backend/switch", admin_js)
        self.assertNotIn("Sensitive-action protection", admin_html)
        self.assertNotIn("Trust-chain change protection", admin_html)
        self.assertIn("confirmSensitiveAction", admin_js)
        self.assertIn("/internal/auth/totp/reauthenticate", admin_js)
        self.assertIn("mfa_recent", admin_js)
        self.assertIn("SENSITIVE_REASON_MIN_LENGTH = 10", admin_js)
        self.assertNotIn('confirmation: "SWITCH HSM BACKEND"', admin_js)
        self.assertNotIn('confirmation: "INITIALIZE HSM"', admin_js)
        self.assertNotIn("/internal/hsm/initialize", admin_js)
        self.assertIn("`DELETE KEY ${label}`", admin_js)
        self.assertIn("`IMPORT DKEK ${filename}`", admin_js)
        self.assertIn("`DELETE DKEK ${filename}`", admin_js)
        self.assertNotIn('confirmation: "IMPORT ISSUER"', admin_js)
        self.assertNotIn('confirmation: "SET ROOT CERTIFICATE"', admin_js)
        self.assertNotIn("Type <code>CREATE LAB CA</code>", setup_html)
        self.assertNotIn("Type <code>IMPORT EXISTING SUBCA</code>", setup_html)
        self.assertIn(".sensitive-action-form", app_css)
        self.assertIn(".sensitive-impact", app_css)
        self.assertIn('value="superuser">Certificate Operator</option>', admin_html)
        self.assertNotIn("Admin or superuser", admin_html)
        self.assertNotIn("mandatory superuser approval", admin_html)
        self.assertIn('id="hsm-key-generate"', admin_html)
        self.assertIn('id="hsm-key-status"', admin_html)
        self.assertIn("#hsm-key-form > label", app_css)
        self.assertIn("hsmKeyGenerationInFlight", admin_js)
        self.assertIn("Generating key on the token", admin_js)
        self.assertIn('id="issuer-new-mode"', setup_html)
        self.assertIn('id="issuer-lab-mode"', setup_html)
        self.assertIn("/setup/issuer/request", setup_html)
        self.assertFalse((static_dir / "admin-issuer-wizard.js").exists())
        self.assertIn(".info-tip", app_css)
        self.assertIn(".tip-bubble", app_css)
        self.assertIn(".info-tip:hover .tip-bubble", app_css)
        self.assertIn(".table-scroll", app_css)
        self.assertIn('th[aria-sort="ascending"]', app_css)
        self.assertIn('card.setAttribute("aria-labelledby", heading.id)', shared_js)
        self.assertNotIn("closeButton.focus();", shared_js)
        self.assertIn('id="service-urls-copy-crl"', admin_html)
        self.assertIn('id="service-urls-form-state"', admin_html)
        self.assertIn('id="syslog-form-state"', admin_html)
        self.assertIn('id="ocsp-form-state"', admin_html)
        self.assertIn("Install-time environment values seed missing settings once", admin_js)

    def test_admin_has_service_urls_panel(self) -> None:
        from pathlib import Path

        static_dir = Path(__file__).parents[1] / "src/myownca/online/static"
        admin_html = (static_dir / "admin.html").read_text()
        admin_js = (static_dir / "admin.js").read_text()
        self.assertIn('id="service-urls-form"', admin_html)
        self.assertIn('name="crl_base_url"', admin_html)
        self.assertIn('name="aia_base_url"', admin_html)
        self.assertIn('name="ocsp_url"', admin_html)
        self.assertIn('name="admin_base_url"', admin_html)
        self.assertIn('name="superuser_base_url"', admin_html)
        self.assertIn("/internal/admin/service-urls", admin_js)

    def test_admin_has_ocsp_panel(self) -> None:
        from pathlib import Path

        static_dir = Path(__file__).parents[1] / "src/myownca/online/static"
        admin_html = (static_dir / "admin.html").read_text()
        admin_js = (static_dir / "admin.js").read_text()
        self.assertIn('id="ocsp-form"', admin_html)
        self.assertIn('name="responder_validity_days"', admin_html)
        self.assertIn('id="ocsp-enabled"', admin_html)
        self.assertIn("/internal/admin/ocsp", admin_js)
        self.assertIn("/internal/ocsp", admin_js)

    def test_offline_cli_exposes_expected_commands(self) -> None:
        parser = build_parser()
        with io.StringIO() as buffer, redirect_stdout(buffer):
            with self.assertRaises(SystemExit):
                parser.parse_args(["--help"])
            help_text = buffer.getvalue()
        self.assertIn("root-create", help_text)
        self.assertIn("subca-sign-csr", help_text)
        self.assertIn("root-crl-sign", help_text)
        self.assertNotIn("request-key-import", help_text)
        self.assertNotIn("bundle", help_text.lower())
