from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import HTTPException

from myownca.domain import Role
from myownca.online.app import ServiceUrlsUpdate, create_app
from tests.helpers import add_login_ready_user, create_active_session, request_with_session, route_endpoint


def _admin_app(tempdir: str):
    app = create_app(Path(tempdir) / "c.sqlite3", lab_mode=True)
    secret = add_login_ready_user(app, user_id="a-1", email="a1@example.test", role=Role.ADMIN)
    token, csrf = create_active_session(app, email="a1@example.test", totp_secret=secret)
    return app, token, csrf


class ServiceUrlsEndpointTests(unittest.TestCase):
    def test_get_put_round_trip_and_trailing_slash_strip(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, token, csrf = _admin_app(tempdir)
            initial = route_endpoint(app, "/internal/admin/service-urls", "GET")(
                request_with_session(token, csrf)
            )
            self.assertEqual(
                set(initial) - {"suggested"},
                {"admin_base_url", "superuser_base_url", "crl_base_url", "aia_base_url", "ocsp_url"},
            )
            self.assertIsNone(initial["crl_base_url"])

            updated = route_endpoint(app, "/internal/admin/service-urls", "PUT")(
                ServiceUrlsUpdate(crl_base_url="http://ca.test/", aia_base_url="http://ca.test/"),
                request_with_session(token, csrf, method="PUT"),
            )
            self.assertEqual(updated["crl_base_url"], "http://ca.test")  # base URL stripped
            self.assertEqual(updated["aia_base_url"], "http://ca.test")  # base URL stripped

    def test_put_rejects_non_http(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, token, csrf = _admin_app(tempdir)
            # Pre-seed a known value so the assertion proves the rejected write was
            # suppressed (not merely that the key started absent).
            app.state.repository.set_setting("crl_base_url", "http://old.test")
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/admin/service-urls", "PUT")(
                    ServiceUrlsUpdate(crl_base_url="ftp://ca.test"),
                    request_with_session(token, csrf, method="PUT"),
                )
            self.assertEqual(ctx.exception.status_code, 400)
            self.assertEqual(app.state.repository.get_setting("crl_base_url"), "http://old.test")

    def test_put_empty_clears_key(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, token, csrf = _admin_app(tempdir)
            app.state.repository.set_setting("crl_base_url", "http://old.test")
            cleared = route_endpoint(app, "/internal/admin/service-urls", "PUT")(
                ServiceUrlsUpdate(crl_base_url=""),
                request_with_session(token, csrf, method="PUT"),
            )
            self.assertIsNone(cleared["crl_base_url"])
            self.assertEqual(app.state.repository.get_setting("crl_base_url"), "")

    def test_non_admin_rejected(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "c.sqlite3", lab_mode=True)
            secret = add_login_ready_user(app, user_id="su-1", email="su1@example.test", role=Role.SUPERUSER)
            token, csrf = create_active_session(app, email="su1@example.test", totp_secret=secret)
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/admin/service-urls", "GET")(request_with_session(token, csrf))
            self.assertEqual(ctx.exception.status_code, 403)


class ServiceUrlSuggestionTests(unittest.TestCase):
    def test_suggested_derived_from_portal_host_as_http(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, token, csrf = _admin_app(tempdir)
            app.state.repository.set_setting("portal_base_url", "https://ca.example.com")
            data = route_endpoint(app, "/internal/admin/service-urls", "GET")(
                request_with_session(token, csrf)
            )
            self.assertEqual(data["suggested"], {
                "crl_base_url": "http://ca.example.com",
                "aia_base_url": "http://ca.example.com",
                "ocsp_url": "http://ca.example.com/ocsp",
            })

    def test_no_suggestions_when_portal_unset(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, token, csrf = _admin_app(tempdir)
            data = route_endpoint(app, "/internal/admin/service-urls", "GET")(
                request_with_session(token, csrf)
            )
            self.assertEqual(data["suggested"], {})
