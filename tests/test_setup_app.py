from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi import HTTPException, Response
from fastapi.responses import FileResponse
from starlette.requests import Request

from myownca.config import Settings
from myownca.setup.app import (
    AdminPayload,
    AdminsPayload,
    DatabasePayload,
    GovernanceModePayload,
    HSMPayload,
    InstallTypePayload,
    IssuanceEndpointsPayload,
    ListenerPayload,
    RootCertificatePayload,
    ServiceUrlsPayload,
    TOTPPolicyPayload,
    UnlockPayload,
    create_setup_app,
)
from myownca.setup.state import is_setup_complete
from myownca.setup.token import SetupAuth
from tests.helpers import route_endpoint


# Local builder (not tests.helpers.request_with_session): the setup app uses its
# own cookie name `myownca_setup`, distinct from the main app's `myownca_session`.
def _request(*, session: str | None = None, csrf: str | None = None, method: str = "GET") -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if session is not None:
        headers.append((b"cookie", f"myownca_setup={session}".encode()))
    if csrf is not None:
        headers.append((b"x-csrf-token", csrf.encode()))
    return Request({"type": "http", "method": method, "path": "/", "headers": headers})


def _admins_payload() -> AdminsPayload:
    return AdminsPayload(
        first=AdminPayload(id="admin-1", email="a1@example.test", password="p" * 16),
        second=AdminPayload(id="admin-2", email="a2@example.test", password="q" * 16),
    )


class SetupPageAndUnlockTests(unittest.TestCase):
    def test_setup_page_served(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_setup_app(tempdir, SetupAuth())
            page = route_endpoint(app, "/setup", "GET")()
        self.assertIsInstance(page, FileResponse)
        self.assertEqual(page.headers["X-Robots-Tag"], "noindex")

    def test_theme_css_served(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_setup_app(tempdir, SetupAuth())
            resp = route_endpoint(app, "/theme.css", "GET")()
        self.assertIsInstance(resp, FileResponse)
        self.assertEqual(resp.media_type, "text/css")

    def test_root_redirects_to_setup(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_setup_app(tempdir, SetupAuth())
            resp = route_endpoint(app, "/", "GET")()
        self.assertIn(resp.status_code, (302, 303, 307))
        self.assertEqual(resp.headers["location"], "/setup")

    def test_branding_logo_served(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_setup_app(tempdir, SetupAuth())
            resp = route_endpoint(app, "/branding/logo", "GET")()
        self.assertIsInstance(resp, FileResponse)
        self.assertEqual(resp.media_type, "image/svg+xml")

    def test_openapi_docs_are_disabled(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_setup_app(tempdir, SetupAuth())
        paths = {route.path for route in app.routes}
        self.assertNotIn("/docs", paths)
        self.assertNotIn("/redoc", paths)
        self.assertNotIn("/openapi.json", paths)

    def test_unlock_with_good_token_opens_session(self) -> None:
        with TemporaryDirectory() as tempdir:
            auth = SetupAuth()
            app = create_setup_app(tempdir, auth)
            response = Response()
            result = route_endpoint(app, "/setup/unlock", "POST")(
                UnlockPayload(token=auth.token), response
            )
        self.assertIn("csrf_token", result)
        self.assertTrue(auth.valid_csrf(result["csrf_token"]))
        cookie_header = response.headers.get("set-cookie", "")
        self.assertIn("myownca_setup", cookie_header)
        self.assertIn("HttpOnly", cookie_header)
        self.assertIn("SameSite=strict", cookie_header)
        with self.assertRaises(HTTPException) as replay:
            route_endpoint(app, "/setup/unlock", "POST")(
                UnlockPayload(token=auth.token), Response()
            )
        self.assertEqual(replay.exception.status_code, 401)

    def test_unlock_with_bad_token_rejected(self) -> None:
        with TemporaryDirectory() as tempdir:
            auth = SetupAuth()
            app = create_setup_app(tempdir, auth)
            with self.assertRaises(HTTPException) as caught:
                route_endpoint(app, "/setup/unlock", "POST")(
                    UnlockPayload(token="wrong"), Response()
                )
        self.assertEqual(caught.exception.status_code, 401)

    def test_state_requires_session(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_setup_app(tempdir, SetupAuth())
            with self.assertRaises(HTTPException) as caught:
                route_endpoint(app, "/setup/state", "GET")(_request())
        self.assertEqual(caught.exception.status_code, 401)

    def test_state_with_session_returns_snapshot(self) -> None:
        with TemporaryDirectory() as tempdir:
            auth = SetupAuth()
            app = create_setup_app(tempdir, auth)
            session_token, _ = auth.open_session()
            snapshot = route_endpoint(app, "/setup/state", "GET")(
                _request(session=session_token)
            )
        self.assertFalse(snapshot["complete"])
        self.assertEqual(snapshot["app_version"], app.version)


class SetupStepEndpointTests(unittest.TestCase):
    def _app_with_session(self, tempdir: str):
        auth = SetupAuth()
        app = create_setup_app(tempdir, auth)
        session_token, csrf_token = auth.open_session()
        return app, session_token, csrf_token

    def test_preflight_endpoint_requires_session_then_returns_report(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, session_token, _ = self._app_with_session(tempdir)
            with self.assertRaises(HTTPException):
                route_endpoint(app, "/setup/preflight", "GET")(_request())
            report = route_endpoint(app, "/setup/preflight", "GET")(
                _request(session=session_token)
            )
        self.assertIn("python_ok", report)

    def test_install_type_endpoint_sets_value(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, session_token, csrf_token = self._app_with_session(tempdir)
            result = route_endpoint(app, "/setup/install-type", "POST")(
                InstallTypePayload(value="lab"),
                _request(session=session_token, csrf=csrf_token, method="POST"),
            )
        self.assertEqual(result["install_type"], "lab")

    def test_install_type_requires_session(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _, csrf_token = self._app_with_session(tempdir)
            with self.assertRaises(HTTPException) as caught:
                route_endpoint(app, "/setup/install-type", "POST")(
                    InstallTypePayload(value="lab"),
                    _request(method="POST"),  # no session, no csrf
                )
        self.assertEqual(caught.exception.status_code, 401)

    def test_install_type_requires_csrf(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, session_token, _ = self._app_with_session(tempdir)
            with self.assertRaises(HTTPException) as caught:
                route_endpoint(app, "/setup/install-type", "POST")(
                    InstallTypePayload(value="lab"),
                    _request(session=session_token, method="POST"),  # no csrf
                )
        self.assertEqual(caught.exception.status_code, 403)

    def test_install_type_rejects_unknown_value(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, session_token, csrf_token = self._app_with_session(tempdir)
            with self.assertRaises(HTTPException) as caught:
                route_endpoint(app, "/setup/install-type", "POST")(
                    InstallTypePayload(value="banana"),
                    _request(session=session_token, csrf=csrf_token, method="POST"),
                )
        self.assertEqual(caught.exception.status_code, 400)

    def test_totp_policy_endpoint_persists_role_selection(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, session_token, csrf_token = self._app_with_session(tempdir)
            result = route_endpoint(app, "/setup/totp-policy", "POST")(
                TOTPPolicyPayload(required_roles=["admin", "auditor"]),
                _request(session=session_token, csrf=csrf_token, method="POST"),
            )
        self.assertEqual(result["totp_required_roles"], ["admin", "auditor"])


class SetupFinalizeEndpointTests(unittest.TestCase):
    def _app_with_session(self, tempdir: str):
        auth = SetupAuth()
        app = create_setup_app(tempdir, auth)
        session_token, csrf_token = auth.open_session()
        return app, session_token, csrf_token

    def test_finalize_writes_latch_and_calls_shutdown_hook(self) -> None:
        calls: list[int] = []
        with TemporaryDirectory() as tempdir:
            app, session_token, csrf_token = self._app_with_session(tempdir)
            app.state.request_shutdown = lambda: calls.append(1)

            route_endpoint(app, "/setup/install-type", "POST")(
                InstallTypePayload(value="lab"),
                _request(session=session_token, csrf=csrf_token, method="POST"),
            )
            route_endpoint(app, "/setup/listener", "POST")(
                ListenerPayload(topology="proxy"),
                _request(session=session_token, csrf=csrf_token, method="POST"),
            )
            route_endpoint(app, "/setup/admins", "POST")(
                _admins_payload(),
                _request(session=session_token, csrf=csrf_token, method="POST"),
            )
            result = route_endpoint(app, "/setup/finalize", "POST")(
                _request(session=session_token, csrf=csrf_token, method="POST")
            )
            self.assertTrue(is_setup_complete(tempdir))

        self.assertTrue(result["complete"])
        self.assertEqual(calls, [1])  # shutdown hook fired exactly once

    def test_finalize_requires_csrf(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, session_token, _ = self._app_with_session(tempdir)
            with self.assertRaises(HTTPException) as caught:
                route_endpoint(app, "/setup/finalize", "POST")(
                    _request(session=session_token, method="POST")  # no csrf
                )
        self.assertEqual(caught.exception.status_code, 403)

    def test_finalize_requires_session(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _, csrf_token = self._app_with_session(tempdir)
            with self.assertRaises(HTTPException) as caught:
                route_endpoint(app, "/setup/finalize", "POST")(
                    _request(method="POST")  # no session
                )
        self.assertEqual(caught.exception.status_code, 401)

    def test_finalize_without_install_type_is_400_and_no_shutdown(self) -> None:
        calls: list[int] = []
        with TemporaryDirectory() as tempdir:
            app, session_token, csrf_token = self._app_with_session(tempdir)
            app.state.request_shutdown = lambda: calls.append(1)
            with self.assertRaises(HTTPException) as caught:
                route_endpoint(app, "/setup/finalize", "POST")(
                    _request(session=session_token, csrf=csrf_token, method="POST")
                )
        self.assertEqual(caught.exception.status_code, 400)
        self.assertEqual(calls, [])  # shutdown must not fire on the error path

    def test_finalize_without_admins_is_400_and_no_shutdown(self) -> None:
        calls: list[int] = []
        with TemporaryDirectory() as tempdir:
            app, session_token, csrf_token = self._app_with_session(tempdir)
            app.state.request_shutdown = lambda: calls.append(1)
            route_endpoint(app, "/setup/install-type", "POST")(
                InstallTypePayload(value="lab"),
                _request(session=session_token, csrf=csrf_token, method="POST"),
            )
            with self.assertRaises(HTTPException) as caught:
                route_endpoint(app, "/setup/finalize", "POST")(
                    _request(session=session_token, csrf=csrf_token, method="POST")
                )
        self.assertEqual(caught.exception.status_code, 400)
        self.assertEqual(calls, [])

    def test_hsm_endpoint_saves_pkcs11_choice(self) -> None:
        with TemporaryDirectory() as tempdir:
            module = Path(tempdir) / "opensc-pkcs11.dll"
            module.write_text("fake")
            app, session_token, csrf_token = self._app_with_session(tempdir)
            snapshot = route_endpoint(app, "/setup/hsm", "POST")(
                HSMPayload(backend="pkcs11", pkcs11_lib=str(module), token_label="Token A"),
                _request(session=session_token, csrf=csrf_token, method="POST"),
            )
        self.assertEqual(snapshot["hsm"]["backend"], "pkcs11")
        self.assertEqual(snapshot["hsm"]["pkcs11_lib"], str(module))
        self.assertEqual(snapshot["hsm"]["token_label"], "Token A")


class SetupVerticalSliceTests(unittest.TestCase):
    def test_unlock_install_type_finalize_drives_settings(self) -> None:
        """The full shell path: open session -> pick lab -> finalize -> Settings reflect it."""
        with TemporaryDirectory() as tempdir:
            auth = SetupAuth()
            app = create_setup_app(tempdir, auth)
            session_token, csrf_token = auth.open_session()

            # Choose the lab install type.
            route_endpoint(app, "/setup/install-type", "POST")(
                InstallTypePayload(value="lab"),
                _request(session=session_token, csrf=csrf_token, method="POST"),
            )
            route_endpoint(app, "/setup/listener", "POST")(
                ListenerPayload(topology="proxy"),
                _request(session=session_token, csrf=csrf_token, method="POST"),
            )
            route_endpoint(app, "/setup/admins", "POST")(
                _admins_payload(),
                _request(session=session_token, csrf=csrf_token, method="POST"),
            )

            # Finalize.
            shutdown_calls: list[int] = []
            app.state.request_shutdown = lambda: shutdown_calls.append(1)
            result = route_endpoint(app, "/setup/finalize", "POST")(
                _request(session=session_token, csrf=csrf_token, method="POST")
            )

            # The read path also reports completion through the HTTP layer.
            snapshot = route_endpoint(app, "/setup/state", "GET")(
                _request(session=session_token)
            )
            self.assertTrue(snapshot["complete"])

            # The wizard output drives a real Settings.
            settings = Settings.load(tempdir, environ={})
            self.assertTrue(settings.lab_mode)
            self.assertNotEqual(
                settings.auth_encryption_secret, "change-me-for-local-testing"
            )

        # Checked after tempdir teardown (matches SetupFinalizeEndpointTests).
        self.assertTrue(result["complete"])
        self.assertEqual(shutdown_calls, [1])


class SetupDatabaseEndpointTests(unittest.TestCase):
    def _app_with_session(self, tempdir: str):
        auth = SetupAuth()
        app = create_setup_app(tempdir, auth)
        session_token, csrf_token = auth.open_session()
        return app, session_token, csrf_token

    def test_set_database_sqlite(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, session_token, csrf_token = self._app_with_session(tempdir)
            result = route_endpoint(app, "/setup/database", "POST")(
                DatabasePayload(kind="sqlite"),
                _request(session=session_token, csrf=csrf_token, method="POST"),
            )
        self.assertEqual(result["database"], {"kind": "sqlite"})

    def test_set_database_requires_csrf(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, session_token, _ = self._app_with_session(tempdir)
            with self.assertRaises(HTTPException) as caught:
                route_endpoint(app, "/setup/database", "POST")(
                    DatabasePayload(kind="sqlite"),
                    _request(session=session_token, method="POST"),  # no csrf
                )
        self.assertEqual(caught.exception.status_code, 403)

    def test_set_database_bad_kind_is_400(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, session_token, csrf_token = self._app_with_session(tempdir)
            with self.assertRaises(HTTPException) as caught:
                route_endpoint(app, "/setup/database", "POST")(
                    DatabasePayload(kind="postgres"),
                    _request(session=session_token, csrf=csrf_token, method="POST"),
                )
        self.assertEqual(caught.exception.status_code, 400)

    def test_database_test_endpoint_ok_for_sqlite(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, session_token, csrf_token = self._app_with_session(tempdir)
            route_endpoint(app, "/setup/database", "POST")(
                DatabasePayload(kind="sqlite"),
                _request(session=session_token, csrf=csrf_token, method="POST"),
            )
            result = route_endpoint(app, "/setup/database/test", "POST")(
                _request(session=session_token, csrf=csrf_token, method="POST")
            )
        self.assertTrue(result["ok"])


class SetupUrlEndpointTests(unittest.TestCase):
    def _app_with_session(self, tempdir: str):
        auth = SetupAuth()
        app = create_setup_app(tempdir, auth)
        session_token, csrf_token = auth.open_session()
        return app, session_token, csrf_token

    def test_set_service_urls(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, session_token, csrf_token = self._app_with_session(tempdir)
            result = route_endpoint(app, "/setup/service-urls", "POST")(
                ServiceUrlsPayload(
                    admin="https://a.example.test",
                    superuser="https://s.example.test",
                    frontend="https://f.example.test",
                ),
                _request(session=session_token, csrf=csrf_token, method="POST"),
            )
        self.assertEqual(result["service_urls"]["admin"], "https://a.example.test")

    def test_set_direct_listener_persists_validated_values(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, session_token, csrf_token = self._app_with_session(tempdir)
            result = route_endpoint(app, "/setup/listener", "POST")(
                ListenerPayload(
                    topology="direct",
                    bind_host="172.21.220.42",
                    bind_port=8443,
                ),
                _request(session=session_token, csrf=csrf_token, method="POST"),
            )
        self.assertEqual(
            result["listener"],
            {"topology": "direct", "bind_host": "172.21.220.42", "bind_port": 8443},
        )

    def test_listener_requires_session_and_csrf(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, session_token, csrf_token = self._app_with_session(tempdir)
            with self.assertRaises(HTTPException) as no_session:
                route_endpoint(app, "/setup/listener", "POST")(
                    ListenerPayload(topology="proxy"),
                    _request(csrf=csrf_token, method="POST"),
                )
            with self.assertRaises(HTTPException) as no_csrf:
                route_endpoint(app, "/setup/listener", "POST")(
                    ListenerPayload(topology="proxy"),
                    _request(session=session_token, method="POST"),
                )
        self.assertEqual(no_session.exception.status_code, 401)
        self.assertEqual(no_csrf.exception.status_code, 403)

    def test_listener_rejects_non_address_bind_host(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, session_token, csrf_token = self._app_with_session(tempdir)
            with self.assertRaises(HTTPException) as caught:
                route_endpoint(app, "/setup/listener", "POST")(
                    ListenerPayload(
                        topology="direct", bind_host="not an address", bind_port=8000
                    ),
                    _request(session=session_token, csrf=csrf_token, method="POST"),
                )
        self.assertEqual(caught.exception.status_code, 400)

    def test_set_issuance_endpoints(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, session_token, csrf_token = self._app_with_session(tempdir)
            result = route_endpoint(app, "/setup/issuance-endpoints", "POST")(
                IssuanceEndpointsPayload(
                    crl="https://f.example.test/crl",
                    aia="https://f.example.test/aia",
                    ocsp="https://f.example.test/ocsp",
                ),
                _request(session=session_token, csrf=csrf_token, method="POST"),
            )
        self.assertEqual(result["issuance_endpoints"]["crl"], "https://f.example.test/crl")

    def test_service_urls_requires_session(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _, csrf_token = self._app_with_session(tempdir)
            with self.assertRaises(HTTPException) as caught:
                route_endpoint(app, "/setup/service-urls", "POST")(
                    ServiceUrlsPayload(admin="a", superuser="s", frontend="f"),
                    _request(csrf=csrf_token, method="POST"),  # no session
                )
        self.assertEqual(caught.exception.status_code, 401)


class SetupPageMarkupTests(unittest.TestCase):
    def test_page_contains_config_step_controls(self) -> None:
        from pathlib import Path as _Path

        html = (
            _Path(__file__).parents[1]
            / "src/myownca/setup/static/setup.html"
        ).read_text()
        for marker in (
            "database-fieldset",
            "service-urls-fieldset",
            "issuer-fieldset",
        ):
            self.assertIn(marker, html)

    def test_page_links_deployment_type_to_listener_settings(self) -> None:
        html = (Path(__file__).parents[1] / "src/myownca/setup/static/setup.html").read_text()
        for marker in (
            'id="listener-fieldset"',
            'id="deployment-type-fieldset"',
            'name="deployment-type" value="bare-metal" required',
            'name="deployment-type" value="docker-bundle"',
            "Docker + Reverse Proxy Bundle",
            'id="listener-bind-host" value="127.0.0.1"',
            'id="listener-bind-port" type="number" min="1" max="65535" value="8000"',
            'id="listener-tls-enabled" type="checkbox"',
            'id="listener-tls-cert"',
            'id="listener-tls-key"',
            'id="listener-tls-guidance"',
            "Serve direct HTTPS",
            "change portal URLs to https",
            'id="listener-direct-guidance"',
            'id="listener-exposure-warning"',
            'id="listener-proxy-guidance"',
            "function listenerPayload()",
            "function saveDeploymentType()",
            "function applyDeploymentState(state, hasSavedUrls = false)",
            "tls_enabled: tlsEnabled",
            "function setPublicUrlProtocol(protocol)",
            'api("/setup/listener"',
            "listenerReady",
            "public URLs below remain editable and do not change that listener choice",
        ):
            self.assertIn(marker, html)
        self.assertNotIn('name="listener-topology"', html)
        self.assertLess(html.index('id="listener-tls-toggle"'), html.index('id="url-admin"'))
        self.assertLess(html.index('id="listener-tls-toggle"'), html.index('id="listener-fieldset"'))

    def test_page_contains_admin_account_controls(self) -> None:
        from pathlib import Path as _Path

        html = (
            _Path(__file__).parents[1] / "src/myownca/setup/static/setup.html"
        ).read_text()
        for marker in ("admins-fieldset", "admin1-id", "admin1-password", "admin2-email"):
            self.assertIn(marker, html)
        for marker in (
            'id="admin1-id" required',
            'id="admin2-id" required disabled',
            'id="admin1-email" type="email" required autocomplete="email"',
            'id="admin2-email" type="email" required disabled autocomplete="email"',
            'pattern="[^\\s@]+@[^\\s@]+\\.[^\\s@]+"',
            'title="Use an email address like admin@example.com"',
            "const includesSecondAdmin = requiresSecondAdmin || optionalSecondAdmin;",
            "input.disabled = !includesSecondAdmin;",
            "Provide the first admin ID, a valid email, and a temporary password",
        ):
            self.assertIn(marker, html)

    def test_page_contains_root_certificate_control(self) -> None:
        from pathlib import Path as _Path

        html = (
            _Path(__file__).parents[1] / "src/myownca/setup/static/setup.html"
        ).read_text()
        self.assertIn("root-certificate-fieldset", html)
        self.assertIn("root-cert-input", html)
        self.assertIn('data-app-version>Version…</span>', html)
        self.assertIn('target.textContent = `Version ${state.app_version}`;', html)
        self.assertIn("function clearRootCertificateInput()", html)
        self.assertIn('if (radio.value === "lab") clearRootCertificateInput();', html)
        self.assertIn('id="root-cert-verify"', html)
        self.assertIn('/setup/root-certificate/verify', html)

    def test_page_contains_linked_deployment_url_defaults(self) -> None:
        from pathlib import Path as _Path

        html = (
            _Path(__file__).parents[1] / "src/myownca/setup/static/setup.html"
        ).read_text()
        for marker in (
            'id="deployment-type-fieldset"',
            'name="deployment-type" value="bare-metal"',
            'name="deployment-type" value="docker-bundle"',
            '"bare-metal": { topology: "direct", defaultUrl: "http://127.0.0.1:8000/" }',
            '"docker-bundle": { topology: "proxy", defaultUrl: "https://localhost/" }',
            "function applyDeploymentUrlDefaults(deploymentType)",
            "if (defaultUrl) setPublicUrls(defaultUrl);",
            'setPublicUrlProtocol($("listener-tls-enabled").checked ? "https:" : "http:");',
            '$("listener-tls-enabled").addEventListener("change", async () => {',
            "if (!listenerConfigurationReady()) return;",
            "function saveDeploymentType()",
        ):
            self.assertIn(marker, html)
        self.assertNotIn('name="url-preset"', html)
        self.assertNotIn('name="listener-topology"', html)
        self.assertNotIn("deploymentTypeChosen", html)
        self.assertNotIn("publicUrlsEdited", html)

    def test_page_completion_link_uses_admin_url(self) -> None:
        from pathlib import Path as _Path

        html = (
            _Path(__file__).parents[1] / "src/myownca/setup/static/setup.html"
        ).read_text()
        self.assertIn('const base = ($("url-admin").value || fallback)', html)
        self.assertIn('const loginUrl = base + "/login";', html)


class SetupConfigVerticalSliceTests(unittest.TestCase):
    def test_config_steps_through_the_app_drive_config_toml(self) -> None:
        from myownca.setup.config_writer import read_config_env

        with TemporaryDirectory() as tempdir:
            auth = SetupAuth()
            app = create_setup_app(tempdir, auth)
            session_token, csrf_token = auth.open_session()

            def post(path, payload):
                return route_endpoint(app, path, "POST")(
                    payload, _request(session=session_token, csrf=csrf_token, method="POST")
                )

            post("/setup/install-type", InstallTypePayload(value="production"))
            post(
                "/setup/governance-mode",
                GovernanceModePayload(value="dual_control"),
            )
            post("/setup/database", DatabasePayload(kind="sqlite"))
            post(
                "/setup/listener",
                ListenerPayload(
                    topology="direct", bind_host="172.21.220.42", bind_port=8443
                ),
            )
            post("/setup/service-urls", ServiceUrlsPayload(
                admin="https://a.example.test",
                superuser="https://s.example.test",
                frontend="https://f.example.test",
            ))
            post("/setup/issuance-endpoints", IssuanceEndpointsPayload(
                crl="https://f.example.test/crl", aia="", ocsp="https://f.example.test/ocsp",
            ))
            from myownca.ca_hsm import SoftwareHSM
            from myownca.ca_main.crypto import certificate_to_pem, create_lab_ca_chain

            post(
                "/setup/root-certificate",
                RootCertificatePayload(
                    pem=certificate_to_pem(
                        create_lab_ca_chain(SoftwareHSM()).root.certificate
                    )
                ),
            )
            post("/setup/admins", _admins_payload())
            app.state.request_shutdown = lambda: None
            with mock.patch(
                "myownca.setup.provisioning.SetupProvisioningService"
            ) as provisioning_type:
                provisioning = provisioning_type.return_value
                provisioning.status.return_value = {
                    "configured": True,
                    "pending": [],
                }
                provisioning.repository.list_sub_cas.return_value = [object()]
                provisioning.assert_finalizable = mock.Mock(
                    return_value={"configured": True, "pending": []}
                )
                route_endpoint(app, "/setup/finalize", "POST")(
                    _request(session=session_token, csrf=csrf_token, method="POST")
                )
            config = read_config_env(tempdir)

        self.assertEqual(config["MYOWNCA_LAB_MODE"], "false")
        self.assertEqual(config["MYOWNCA_GOVERNANCE_MODE"], "dual_control")
        self.assertEqual(config["MYOWNCA_ADMIN_BASE_URL"], "https://a.example.test")
        self.assertEqual(config["MYOWNCA_CRL_URL"], "https://f.example.test/crl")
        self.assertEqual(config["MYOWNCA_OCSP_URL"], "https://f.example.test/ocsp")
        self.assertEqual(config["MYOWNCA_BIND_HOST"], "172.21.220.42")
        self.assertEqual(config["MYOWNCA_BIND_PORT"], "8443")
        # Empty AIA was not written.
        self.assertNotIn("MYOWNCA_AIA_URL", config)


class SetupRootCertificateEndpointTests(unittest.TestCase):
    def _app_with_session(self, tempdir: str):
        auth = SetupAuth()
        app = create_setup_app(tempdir, auth)
        session_token, csrf_token = auth.open_session()
        return app, session_token, csrf_token

    def _root_pem(self) -> str:
        from myownca.ca_hsm import SoftwareHSM
        from myownca.ca_main.crypto import certificate_to_pem, create_lab_ca_chain

        return certificate_to_pem(create_lab_ca_chain(SoftwareHSM()).root.certificate)

    def test_set_root_certificate(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, session_token, csrf_token = self._app_with_session(tempdir)
            result = route_endpoint(app, "/setup/root-certificate", "POST")(
                RootCertificatePayload(pem=self._root_pem()),
                _request(session=session_token, csrf=csrf_token, method="POST"),
            )
        self.assertTrue(result["root_captured"])

    def test_verify_root_certificate_does_not_change_state(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, session_token, csrf_token = self._app_with_session(tempdir)
            before = route_endpoint(app, "/setup/state", "GET")(
                _request(session=session_token, csrf=csrf_token)
            )
            result = route_endpoint(app, "/setup/root-certificate/verify", "POST")(
                RootCertificatePayload(pem=self._root_pem()),
                _request(session=session_token, csrf=csrf_token, method="POST"),
            )
            after = route_endpoint(app, "/setup/state", "GET")(
                _request(session=session_token, csrf=csrf_token)
            )
        self.assertTrue(result["verified"])
        self.assertEqual(before, after)

    def test_set_root_certificate_bad_pem_is_400(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, session_token, csrf_token = self._app_with_session(tempdir)
            with self.assertRaises(HTTPException) as caught:
                route_endpoint(app, "/setup/root-certificate", "POST")(
                    RootCertificatePayload(pem="garbage"),
                    _request(session=session_token, csrf=csrf_token, method="POST"),
                )
        self.assertEqual(caught.exception.status_code, 400)

    def test_set_root_certificate_requires_session(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _, csrf_token = self._app_with_session(tempdir)
            with self.assertRaises(HTTPException) as caught:
                route_endpoint(app, "/setup/root-certificate", "POST")(
                    RootCertificatePayload(pem=self._root_pem()),
                    _request(csrf=csrf_token, method="POST"),  # no session
                )
        self.assertEqual(caught.exception.status_code, 401)


class SetupAdminsEndpointTests(unittest.TestCase):
    def _app_with_session(self, tempdir: str):
        auth = SetupAuth()
        app = create_setup_app(tempdir, auth)
        session_token, csrf_token = auth.open_session()
        route_endpoint(app, "/setup/install-type", "POST")(
            InstallTypePayload(value="lab"),
            _request(session=session_token, csrf=csrf_token, method="POST"),
        )
        return app, session_token, csrf_token

    def _payload(self) -> AdminsPayload:
        return _admins_payload()

    def test_set_admins(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, session_token, csrf_token = self._app_with_session(tempdir)
            result = route_endpoint(app, "/setup/admins", "POST")(
                self._payload(),
                _request(session=session_token, csrf=csrf_token, method="POST"),
            )
        emails = [a["email"] for a in result["admins"]]
        self.assertEqual(emails, ["a1@example.test", "a2@example.test"])
        self.assertNotIn("password", result["admins"][0])

    def test_set_admins_short_password_is_400(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, session_token, csrf_token = self._app_with_session(tempdir)
            with self.assertRaises(HTTPException) as caught:
                route_endpoint(app, "/setup/admins", "POST")(
                    AdminsPayload(
                        first=AdminPayload(id="a", email="a@x.test", password="short"),
                        second=AdminPayload(id="b", email="b@x.test", password="q" * 16),
                    ),
                    _request(session=session_token, csrf=csrf_token, method="POST"),
                )
        self.assertEqual(caught.exception.status_code, 400)

    def test_set_admins_invalid_email_is_400(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, session_token, csrf_token = self._app_with_session(tempdir)
            with self.assertRaises(HTTPException) as caught:
                route_endpoint(app, "/setup/admins", "POST")(
                    AdminsPayload(
                        first=AdminPayload(id="a", email="not-an-email", password="p" * 16),
                        second=AdminPayload(id="b", email="b@example.test", password="q" * 16),
                    ),
                    _request(session=session_token, csrf=csrf_token, method="POST"),
                )
        self.assertEqual(caught.exception.status_code, 400)

    def test_set_admins_requires_session(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _, csrf_token = self._app_with_session(tempdir)
            with self.assertRaises(HTTPException) as caught:
                route_endpoint(app, "/setup/admins", "POST")(
                    self._payload(), _request(csrf=csrf_token, method="POST")
                )
        self.assertEqual(caught.exception.status_code, 401)


class SetupCrlLabelTests(unittest.TestCase):
    def test_wizard_requires_crl_migration_state_for_existing_issuer(self) -> None:
        from pathlib import Path

        setup_html = (
            Path(__file__).parents[1] / "src/myownca/setup/static/setup.html"
        ).read_text()
        self.assertIn("CRL migration", setup_html)
        self.assertIn("never issued a CRL", setup_html)
        self.assertNotIn("CRL distribution URL", setup_html)
