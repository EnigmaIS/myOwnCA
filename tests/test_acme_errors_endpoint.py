from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi import HTTPException

from myownca.domain import Role
from myownca.online.app import AcmeOrderCreate, create_app
from myownca.service_certs.base import ServiceCertError
from tests.helpers import add_login_ready_user, create_active_session, request_with_session, route_endpoint


def _admin_app(tempdir: str):
    app = create_app(Path(tempdir) / "c.sqlite3", lab_mode=True)
    secret = add_login_ready_user(app, user_id="a-1", email="a1@example.test", role=Role.ADMIN)
    token, csrf = create_active_session(app, email="a1@example.test", totp_secret=secret)
    return app, token, csrf


class AcmeOrderFailureTests(unittest.TestCase):
    def test_known_failure_returns_400_and_records(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, token, csrf = _admin_app(tempdir)
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/service-certs/acme/orders", "POST")(
                    AcmeOrderCreate(name="svc-x", account_id="nope", domains=["x.test"]),
                    request_with_session(token, csrf, method="POST"),
                )
            self.assertEqual(ctx.exception.status_code, 400)
            self.assertTrue(ctx.exception.detail)  # not empty / not a bare 500
            errors = app.state.service_certs.repository.list_recent_errors()
            self.assertEqual(len(errors), 1)
            self.assertEqual(errors[0]["operation"], "order_create")
            self.assertIn("svc-x", errors[0]["target"])

    def test_unexpected_failure_returns_502_and_records(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, token, csrf = _admin_app(tempdir)
            with mock.patch.object(
                app.state.service_certs, "request_certificate", side_effect=KeyError("boom")
            ):
                with self.assertRaises(HTTPException) as ctx:
                    route_endpoint(app, "/internal/service-certs/acme/orders", "POST")(
                        AcmeOrderCreate(name="svc-y", account_id="a", domains=["y.test"]),
                        request_with_session(token, csrf, method="POST"),
                    )
            self.assertEqual(ctx.exception.status_code, 502)
            self.assertIn("boom", ctx.exception.detail)
            self.assertEqual(app.state.service_certs.repository.list_recent_errors()[0]["operation"], "order_create")

    def test_account_create_failure_records(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, token, csrf = _admin_app(tempdir)
            from myownca.online.app import AcmeAccountCreate
            with mock.patch.object(
                app.state.service_certs, "create_account", side_effect=ServiceCertError("nope")
            ):
                with self.assertRaises(HTTPException) as ctx:
                    route_endpoint(app, "/internal/service-certs/acme/accounts", "POST")(
                        AcmeAccountCreate(directory_url="https://acme.test/dir", contact=""),
                        request_with_session(token, csrf, method="POST"),
                    )
            self.assertEqual(ctx.exception.status_code, 400)
            errors = app.state.service_certs.repository.list_recent_errors()
            self.assertEqual(errors[0]["operation"], "account_create")
            self.assertEqual(errors[0]["target"], "https://acme.test/dir")


class AcmeErrorEndpointTests(unittest.TestCase):
    def test_list_and_clear(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, token, csrf = _admin_app(tempdir)
            app.state.service_certs.repository.record_error("order_create", "svc-z (z.test)", "kaboom")
            listed = route_endpoint(app, "/internal/service-certs/acme/errors", "GET")(
                request_with_session(token, csrf)
            )
            self.assertEqual(len(listed), 1)
            self.assertEqual(listed[0]["message"], "kaboom")

            route_endpoint(app, "/internal/service-certs/acme/errors", "DELETE")(
                request_with_session(token, csrf, method="DELETE")
            )
            self.assertEqual(
                route_endpoint(app, "/internal/service-certs/acme/errors", "GET")(
                    request_with_session(token, csrf)
                ),
                [],
            )

    def test_non_privileged_rejected(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "c.sqlite3", lab_mode=True)
            add_login_ready_user(app, user_id="u-1", email="u1@example.test", role=Role.USER)
            token, csrf = create_active_session(app, email="u1@example.test")
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/service-certs/acme/errors", "GET")(
                    request_with_session(token, csrf)
                )
            self.assertEqual(ctx.exception.status_code, 403)


if __name__ == "__main__":
    unittest.main()
