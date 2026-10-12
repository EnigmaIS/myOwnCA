from __future__ import annotations

import datetime
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi import HTTPException

from myownca.domain import Role
from myownca.online.app import create_app
from myownca.service_certs.base import AcmeAccount, AcmeAccountInUseError
from tests.helpers import add_login_ready_user, create_active_session, request_with_session, route_endpoint


def _admin_app(tempdir: str):
    app = create_app(Path(tempdir) / "c.sqlite3", lab_mode=True)
    secret = add_login_ready_user(app, user_id="a-1", email="a1@example.test", role=Role.ADMIN)
    token, csrf = create_active_session(app, email="a1@example.test", totp_secret=secret)
    return app, token, csrf


def _seed_account(app, account_id="acc-1") -> str:
    app.state.service_certs.repository.add_account(
        AcmeAccount(
            id=account_id,
            directory_url="https://acme.test/dir",
            account_url="https://acme.test/acct/1",
            account_key_ciphertext="ct",
            contact="",
            created_at=datetime.datetime.now(datetime.timezone.utc),
        )
    )
    return account_id


class AcmeAccountDeleteEndpointTests(unittest.TestCase):
    def test_list_includes_certificates_field(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, token, csrf = _admin_app(tempdir)
            _seed_account(app)
            listed = route_endpoint(app, "/internal/service-certs/acme/accounts", "GET")(
                request_with_session(token, csrf)
            )
            self.assertEqual(listed[0]["certificates"], [])

    def test_delete_unused_returns_204(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, token, csrf = _admin_app(tempdir)
            _seed_account(app)
            resp = route_endpoint(app, "/internal/service-certs/acme/accounts/{account_id}", "DELETE")(
                "acc-1", request_with_session(token, csrf, method="DELETE"), False
            )
            self.assertEqual(resp.status_code, 204)
            self.assertEqual(app.state.service_certs.list_accounts(), [])

    def test_delete_in_use_returns_409(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, token, csrf = _admin_app(tempdir)
            _seed_account(app)

            class _Cert:
                name = "web"
            with mock.patch.object(
                app.state.service_certs, "delete_account", side_effect=AcmeAccountInUseError([_Cert()])
            ):
                with self.assertRaises(HTTPException) as ctx:
                    route_endpoint(app, "/internal/service-certs/acme/accounts/{account_id}", "DELETE")(
                        "acc-1", request_with_session(token, csrf, method="DELETE"), False
                    )
            self.assertEqual(ctx.exception.status_code, 409)
            self.assertIn("web", ctx.exception.detail)

    def test_delete_unknown_returns_404(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, token, csrf = _admin_app(tempdir)
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/service-certs/acme/accounts/{account_id}", "DELETE")(
                    "nope", request_with_session(token, csrf, method="DELETE"), False
                )
            self.assertEqual(ctx.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
