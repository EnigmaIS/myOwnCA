from __future__ import annotations

import datetime
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import HTTPException

from myownca.domain import Role
from myownca.online.app import create_app
from myownca.online.portal_tls import portal_paths
from tests.helpers import (
    add_login_ready_user,
    create_active_session,
    request_with_session,
    route_endpoint,
)


def _key_pem(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def _cert_pem(key, common_name: str) -> str:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


class PortalTlsApiTests(unittest.TestCase):
    def _app(self, tempdir: str):
        app = create_app(Path(tempdir) / "api.sqlite3", online_key_dir=Path(tempdir) / "keys")
        su_secret = add_login_ready_user(
            app, user_id="su-1", email="su@example.test", role=Role.SUPERUSER
        )
        ad_secret = add_login_ready_user(
            app, user_id="ad-1", email="ad@example.test", role=Role.ADMIN
        )
        au_secret = add_login_ready_user(
            app, user_id="au-1", email="au@example.test", role=Role.AUDITOR
        )
        su = create_active_session(app, email="su@example.test", totp_secret=su_secret)
        ad = create_active_session(app, email="ad@example.test", totp_secret=ad_secret)
        au = create_active_session(app, email="au@example.test", totp_secret=au_secret)
        return app, su, ad, au

    def _import_software_cert(self, app, name="portal"):
        key = ec.generate_private_key(ec.SECP256R1())
        leaf = _cert_pem(key, f"{name}.example.test")
        return app.state.service_certs.import_pem(
            name, certificate_pem=leaf, private_key_pem=_key_pem(key)
        )

    def test_set_status_and_clear_roundtrip(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, su, _ad, au = self._app(tempdir)
            su_token, su_csrf = su
            au_token, _ = au
            cert = self._import_software_cert(app)
            with mock.patch.dict(os.environ, {"MYOWNCA_STATE_DIR": tempdir}):
                status = route_endpoint(
                    app, "/internal/service-certs/{cert_id}/use-as-portal-tls", "POST"
                )(cert.id, request_with_session(su_token, su_csrf, method="POST"))
                self.assertEqual(status["service_cert_id"], cert.id)
                crt_path, key_path = portal_paths(tempdir)
                self.assertTrue(crt_path.exists())
                self.assertTrue(key_path.exists())
                self.assertEqual(
                    app.state.repository.get_setting("portal_tls_service_cert_id"), cert.id
                )
                got = route_endpoint(app, "/internal/portal-tls", "GET")(
                    request_with_session(au_token)
                )
                self.assertEqual(got["service_cert_id"], cert.id)
                self.assertTrue(got["files_present"])
                cleared = route_endpoint(app, "/internal/portal-tls", "DELETE")(
                    request_with_session(su_token, su_csrf, method="DELETE")
                )
                self.assertTrue(cleared["cleared"])
                self.assertFalse(crt_path.exists())
                self.assertFalse(key_path.exists())
                empty = route_endpoint(app, "/internal/portal-tls", "GET")(
                    request_with_session(au_token)
                )
                self.assertIsNone(empty["service_cert_id"])

    def test_set_on_pending_csr_is_400(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, su, _ad, _au = self._app(tempdir)
            su_token, su_csrf = su
            cert, _csr = app.state.service_certs.generate_csr(
                "pending", common_name="pending.example.test"
            )
            with mock.patch.dict(os.environ, {"MYOWNCA_STATE_DIR": tempdir}):
                with self.assertRaises(HTTPException) as ctx:
                    route_endpoint(
                        app, "/internal/service-certs/{cert_id}/use-as-portal-tls", "POST"
                    )(cert.id, request_with_session(su_token, su_csrf, method="POST"))
                self.assertEqual(ctx.exception.status_code, 400)

    def test_set_on_unknown_cert_is_404(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, su, _ad, _au = self._app(tempdir)
            su_token, su_csrf = su
            with mock.patch.dict(os.environ, {"MYOWNCA_STATE_DIR": tempdir}):
                with self.assertRaises(HTTPException) as ctx:
                    route_endpoint(
                        app, "/internal/service-certs/{cert_id}/use-as-portal-tls", "POST"
                    )("does-not-exist", request_with_session(su_token, su_csrf, method="POST"))
                self.assertEqual(ctx.exception.status_code, 404)

    def test_non_superuser_cannot_set_or_clear(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _su, ad, _au = self._app(tempdir)
            ad_token, ad_csrf = ad
            cert = self._import_software_cert(app)
            with self.assertRaises(HTTPException) as set_ctx:
                route_endpoint(
                    app, "/internal/service-certs/{cert_id}/use-as-portal-tls", "POST"
                )(cert.id, request_with_session(ad_token, ad_csrf, method="POST"))
            self.assertEqual(set_ctx.exception.status_code, 403)
            with self.assertRaises(HTTPException) as del_ctx:
                route_endpoint(app, "/internal/portal-tls", "DELETE")(
                    request_with_session(ad_token, ad_csrf, method="DELETE")
                )
            self.assertEqual(del_ctx.exception.status_code, 403)

    def test_renew_rematerializes_selected_cert(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, su, _ad, _au = self._app(tempdir)
            su_token, su_csrf = su
            cert = self._import_software_cert(app)
            with mock.patch.dict(os.environ, {"MYOWNCA_STATE_DIR": tempdir}):
                route_endpoint(
                    app, "/internal/service-certs/{cert_id}/use-as-portal-tls", "POST"
                )(cert.id, request_with_session(su_token, su_csrf, method="POST"))
                crt_path, key_path = portal_paths(tempdir)
                crt_path.unlink()
                key_path.unlink()
                app.state.service_certs.renew = lambda _cid: {"renewed": _cid}
                route_endpoint(app, "/internal/service-certs/{cert_id}/renew", "POST")(
                    cert.id, request_with_session(su_token, su_csrf, method="POST")
                )
                self.assertTrue(crt_path.exists())
                self.assertTrue(key_path.exists())

    def test_boot_rematerializes_persisted_selection(self) -> None:
        with TemporaryDirectory() as tempdir:
            with mock.patch.dict(os.environ, {"MYOWNCA_STATE_DIR": tempdir}):
                db = Path(tempdir) / "api.sqlite3"
                keys = Path(tempdir) / "keys"
                app1 = create_app(db, online_key_dir=keys)
                cert = self._import_software_cert(app1)
                app1.state.repository.set_setting("portal_tls_service_cert_id", cert.id)
                crt_path, key_path = portal_paths(tempdir)
                crt_path.unlink(missing_ok=True)
                key_path.unlink(missing_ok=True)
                create_app(db, online_key_dir=keys)
                self.assertTrue(crt_path.exists())
                self.assertTrue(key_path.exists())

    def test_set_on_hsm_keyed_cert_is_400(self) -> None:
        from dataclasses import replace

        from myownca.service_certs import KeyBackend

        with TemporaryDirectory() as tempdir:
            app, su, _ad, _au = self._app(tempdir)
            su_token, su_csrf = su
            cert = self._import_software_cert(app)
            # Force the server-side software-only gate: an HSM-keyed cert must 400
            # at the endpoint even though the UI would never offer the action.
            hsm_cert = replace(cert, key_backend=KeyBackend.PKCS11)
            app.state.service_certs.get_cert = lambda _cid: hsm_cert  # type: ignore[method-assign]
            with mock.patch.dict(os.environ, {"MYOWNCA_STATE_DIR": tempdir}):
                with self.assertRaises(HTTPException) as ctx:
                    route_endpoint(
                        app, "/internal/service-certs/{cert_id}/use-as-portal-tls", "POST"
                    )(cert.id, request_with_session(su_token, su_csrf, method="POST"))
                self.assertEqual(ctx.exception.status_code, 400)

    def test_status_reports_missing_when_selected_cert_gone(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _su, _ad, au = self._app(tempdir)
            au_token, _ = au
            # A persisted selection pointing at a cert that no longer exists.
            app.state.repository.set_setting("portal_tls_service_cert_id", "ghost-cert")
            with mock.patch.dict(os.environ, {"MYOWNCA_STATE_DIR": tempdir}):
                status = route_endpoint(app, "/internal/portal-tls", "GET")(
                    request_with_session(au_token)
                )
            self.assertEqual(status["service_cert_id"], "ghost-cert")
            self.assertTrue(status["missing"])
            self.assertFalse(status["files_present"])


if __name__ == "__main__":
    unittest.main()


class PortalTlsSetupHelpTests(unittest.TestCase):
    """Selecting a certificate writes the files but serves nothing.

    How to actually serve them -- config.toml keys, the bind address, and the
    ordering and cookie traps -- was absent from the documentation, so the
    operator portal carries it next to the control that writes the files.
    """

    def _asset(self, name: str) -> str:
        import myownca.online.app as app_module

        return (Path(app_module.__file__).parent / "static" / name).read_text()

    def _help_block(self) -> str:
        page = self._asset("superuser.html")
        return page.split('<template id="tpl-portal-tls-help">', 1)[1].split("</template>", 1)[0]

    def test_the_portal_tls_panel_offers_the_setup_help(self) -> None:
        page = self._asset("superuser.html")
        self.assertIn('id="portal-tls-help-link"', page)
        self.assertIn('<template id="tpl-portal-tls-help">', page)
        self.assertIn("openPortalTlsHelp", self._asset("superuser.js"))

    def test_the_help_gives_the_config_toml_keys_the_listener_reads(self) -> None:
        from myownca.config import Settings

        block = self._help_block()
        self.assertIn("[env]", block)
        for key in (
            "MYOWNCA_BIND_HOST",
            "MYOWNCA_TLS_CERT",
            "MYOWNCA_TLS_KEY",
            "MYOWNCA_SESSION_COOKIE_SECURE",
        ):
            self.assertIn(key, block)
        # The keys must be the ones the settings loader actually consumes.
        settings = Settings.from_mapping({"MYOWNCA_BIND_HOST": "10.0.0.5"})
        self.assertEqual(settings.bind_host, "10.0.0.5")

    def test_the_help_states_the_quoted_string_rule(self) -> None:
        """config.toml rejects bare numbers and booleans; an unquoted port is
        the first thing an operator gets wrong."""
        self.assertIn("quoted string", self._help_block())

    def test_the_help_warns_about_the_traps_that_have_no_visible_symptom(self) -> None:
        block = self._help_block()
        # Secure cookie before TLS: login simply stops working, with no error.
        self.assertIn("Cookie flag before TLS", block)
        # A renewed certificate is not served until the process restarts.
        self.assertIn("Renewal needs a restart", block)
        # Files must exist before a listener points at them.
        self.assertIn("Order of operations", block)

    def test_the_help_covers_both_a_direct_listener_and_a_proxy(self) -> None:
        block = self._help_block()
        self.assertIn("ssl_certificate_key", block)
        self.assertIn("127.0.0.1", block)

    def test_the_configuration_reference_documents_the_real_filenames(self) -> None:
        """Prose drifts silently. Tie the documented paths to portal_paths, so
        renaming the materialized files fails rather than leaving a doc that
        sends operators to a path that no longer exists."""
        reference = (Path(__file__).resolve().parents[1] / "docs" / "configuration-reference.md").read_text()
        crt, key = portal_paths("<state>")
        self.assertIn(crt.as_posix(), reference)
        self.assertIn(key.as_posix(), reference)

    def test_the_configuration_reference_covers_the_same_traps_as_the_help(self) -> None:
        reference = (Path(__file__).resolve().parents[1] / "docs" / "configuration-reference.md").read_text()
        section = reference.split("### Serving the portal TLS certificate", 1)[1].split("\n## ", 1)[0]
        for key in (
            "MYOWNCA_BIND_HOST",
            "MYOWNCA_TLS_CERT",
            "MYOWNCA_TLS_KEY",
            "MYOWNCA_SESSION_COOKIE_SECURE",
        ):
            self.assertIn(key, section)
        self.assertIn("restart the service or reload the proxy", section)
        self.assertIn("SAN", section)
        self.assertIn("in the clear", section)

    def test_the_help_shows_this_installations_real_paths(self) -> None:
        """A placeholder the operator has to translate is where mistakes start."""
        script = self._asset("superuser.js")
        body = script.split("function openPortalTlsHelp()", 1)[1].split("\n}", 1)[0]
        self.assertIn("portalTlsPaths", body)
        # The substitution must actually walk the code blocks. Asserting only
        # that the strings appear let a mutation replacing the selector with an
        # empty list pass, which would leave the placeholders on screen.
        self.assertIn('content.querySelectorAll("pre")', body)
        self.assertIn("<crt path>", body)
        self.assertIn("<key path>", body)
        # textContent, not innerHTML: a path is rendered as text, never markup.
        self.assertIn("block.textContent", body)
        self.assertNotIn("innerHTML", body)
