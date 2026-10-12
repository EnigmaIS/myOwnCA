from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import HTTPException

from myownca.domain import Role
from myownca.online.app import DashboardAlertMuteUpdate, create_app
from tests.helpers import (
    add_login_ready_user,
    create_active_session,
    request_with_session,
    route_endpoint,
)


class DashboardAlertMuteApiTests(unittest.TestCase):
    def _add_session(self, app, *, user_id: str, email: str, role: Role):
        secret = add_login_ready_user(
            app,
            user_id=user_id,
            email=email,
            role=role,
        )
        return create_active_session(app, email=email, totp_secret=secret)

    def test_mute_is_persistent_and_scoped_to_user_and_portal(self) -> None:
        with TemporaryDirectory() as tempdir:
            database_path = Path(tempdir) / "alerts.sqlite3"
            app = create_app(
                database_path,
                lab_mode=True,
                online_key_dir=Path(tempdir) / "keys",
            )
            admin_token, admin_csrf = self._add_session(
                app,
                user_id="admin-1",
                email="admin@example.test",
                role=Role.ADMIN,
            )
            operator_token, operator_csrf = self._add_session(
                app,
                user_id="operator-1",
                email="operator@example.test",
                role=Role.SUPERUSER,
            )
            list_mutes = route_endpoint(
                app, "/internal/dashboard-alert-mutes", "GET"
            )
            update_mute = route_endpoint(
                app, "/internal/dashboard-alert-mutes/{alert_id}", "PUT"
            )

            self.assertEqual(
                list_mutes(request_with_session(admin_token)),
                {"muted_alert_ids": []},
            )
            muted = update_mute(
                "issuer.configured",
                DashboardAlertMuteUpdate(muted=True),
                request_with_session(admin_token, admin_csrf, method="PUT"),
            )
            self.assertEqual(muted["muted_alert_ids"], ["issuer.configured"])
            self.assertEqual(
                list_mutes(request_with_session(operator_token)),
                {"muted_alert_ids": []},
            )

            update_mute(
                "certificate-requests",
                DashboardAlertMuteUpdate(muted=True),
                request_with_session(operator_token, operator_csrf, method="PUT"),
            )
            self.assertEqual(
                list_mutes(request_with_session(operator_token)),
                {"muted_alert_ids": ["certificate-requests"]},
            )
            self.assertEqual(
                list_mutes(request_with_session(admin_token)),
                {"muted_alert_ids": ["issuer.configured"]},
            )

            app2 = create_app(
                database_path,
                lab_mode=True,
                online_key_dir=Path(tempdir) / "keys-2",
            )
            persisted = route_endpoint(
                app2, "/internal/dashboard-alert-mutes", "GET"
            )(request_with_session(admin_token))
            self.assertEqual(persisted, {"muted_alert_ids": ["issuer.configured"]})

            unmuted = route_endpoint(
                app2, "/internal/dashboard-alert-mutes/{alert_id}", "PUT"
            )(
                "issuer.configured",
                DashboardAlertMuteUpdate(muted=False),
                request_with_session(admin_token, admin_csrf, method="PUT"),
            )
            self.assertEqual(unmuted["muted_alert_ids"], [])

    def test_update_requires_csrf_and_rejects_invalid_alert_ids(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(
                Path(tempdir) / "alerts.sqlite3",
                lab_mode=True,
                online_key_dir=Path(tempdir) / "keys",
            )
            token, csrf = self._add_session(
                app,
                user_id="admin-1",
                email="admin@example.test",
                role=Role.ADMIN,
            )
            update_mute = route_endpoint(
                app, "/internal/dashboard-alert-mutes/{alert_id}", "PUT"
            )

            with self.assertRaises(HTTPException) as missing_csrf:
                update_mute(
                    "issuer.configured",
                    DashboardAlertMuteUpdate(muted=True),
                    request_with_session(token, method="PUT"),
                )
            self.assertEqual(missing_csrf.exception.status_code, 403)

            with self.assertRaises(HTTPException) as invalid_id:
                update_mute(
                    "../../not-an-alert",
                    DashboardAlertMuteUpdate(muted=True),
                    request_with_session(token, csrf, method="PUT"),
                )
            self.assertEqual(invalid_id.exception.status_code, 400)


if __name__ == "__main__":
    unittest.main()
