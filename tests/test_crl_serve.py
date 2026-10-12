from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography import x509
from fastapi import HTTPException

from myownca.domain import Role
from myownca.online.app import create_app
from tests.helpers import add_login_ready_user, create_active_session, request_with_session, route_endpoint


class CrlServeTests(unittest.TestCase):
    def _lab_app(self, tempdir: str):
        app = create_app(Path(tempdir) / "c.sqlite3", lab_mode=True)
        su = add_login_ready_user(app, user_id="su-1", email="su1@example.test", role=Role.SUPERUSER)
        token, csrf = create_active_session(app, email="su1@example.test", totp_secret=su)
        return app, token, csrf

    def test_serves_der_after_generate(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, token, csrf = self._lab_app(tempdir)
            route_endpoint(app, "/internal/crls", "POST")(request_with_session(token, csrf, method="POST"))
            app.state.crl_worker.run_once()
            resp = route_endpoint(app, "/crl/{issuer_id}.crl", "GET")("myOwnCA_Lab_CA")
            self.assertEqual(resp.media_type, "application/pkix-crl")
            crl = x509.load_der_x509_crl(resp.body)
            self.assertIsNotNone(crl.issuer)

    def test_unknown_id_404(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _t, _c = self._lab_app(tempdir)
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/crl/{issuer_id}.crl", "GET")("does-not-exist")
            self.assertEqual(ctx.exception.status_code, 404)

    def test_no_crl_yet_404(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _t, _c = self._lab_app(tempdir)
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/crl/{issuer_id}.crl", "GET")("myOwnCA_Lab_CA")
            self.assertEqual(ctx.exception.status_code, 404)

    def test_invalid_charset_id_404(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _t, _c = self._lab_app(tempdir)
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/crl/{issuer_id}.crl", "GET")("../etc/passwd")
            self.assertEqual(ctx.exception.status_code, 404)

    def test_create_crl_returns_distribution_url_when_base_set(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, token, csrf = self._lab_app(tempdir)
            app.state.repository.set_setting("crl_base_url", "http://ca.test/")
            created = route_endpoint(app, "/internal/crls", "POST")(
                request_with_session(token, csrf, method="POST")
            )
            self.assertEqual(created["distribution_url"], "http://ca.test/crl/myOwnCA_Lab_CA.crl")

    def test_create_crl_distribution_url_null_when_base_unset(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, token, csrf = self._lab_app(tempdir)
            created = route_endpoint(app, "/internal/crls", "POST")(
                request_with_session(token, csrf, method="POST")
            )
            self.assertIsNone(created["distribution_url"])
