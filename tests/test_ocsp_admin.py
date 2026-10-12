from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import HTTPException

from myownca.domain import Role
from myownca.online.app import OcspSettingsUpdate, create_app
from tests.helpers import add_login_ready_user, create_active_session, request_with_session, route_endpoint


def _admin_app(tempdir):
    app = create_app(Path(tempdir) / "c.sqlite3", lab_mode=True)
    secret = add_login_ready_user(app, user_id="a-1", email="a1@example.test", role=Role.ADMIN)
    token, csrf = create_active_session(app, email="a1@example.test", totp_secret=secret)
    return app, token, csrf


class OcspAdminTests(unittest.TestCase):
    def test_defaults_disabled_and_validity_30(self) -> None:
        with TemporaryDirectory() as t:
            app, token, csrf = _admin_app(t)
            status = route_endpoint(app, "/internal/admin/ocsp", "GET")(request_with_session(token, csrf))
            self.assertFalse(status["enabled"])
            self.assertEqual(status["responder_validity_days"], 30)

    def test_enable_sets_flag_and_validity(self) -> None:
        with TemporaryDirectory() as t:
            app, token, csrf = _admin_app(t)
            updated = route_endpoint(app, "/internal/admin/ocsp", "PUT")(
                OcspSettingsUpdate(enabled=True, responder_validity_days=7),
                request_with_session(token, csrf, method="PUT"))
            self.assertTrue(updated["enabled"])
            self.assertEqual(updated["responder_validity_days"], 7)
            self.assertEqual(app.state.repository.get_setting("ocsp_enabled"), "true")

    def test_validity_rejects_non_positive(self) -> None:
        with TemporaryDirectory() as t:
            app, token, csrf = _admin_app(t)
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/admin/ocsp", "PUT")(
                    OcspSettingsUpdate(responder_validity_days=0),
                    request_with_session(token, csrf, method="PUT"))
            self.assertEqual(ctx.exception.status_code, 400)

    def test_non_admin_rejected(self) -> None:
        with TemporaryDirectory() as t:
            app = create_app(Path(t) / "c.sqlite3", lab_mode=True)
            secret = add_login_ready_user(app, user_id="su-1", email="su1@example.test", role=Role.SUPERUSER)
            token, csrf = create_active_session(app, email="su1@example.test", totp_secret=secret)
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/admin/ocsp", "GET")(request_with_session(token, csrf))
            self.assertEqual(ctx.exception.status_code, 403)
