from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from myownca.domain import Role, User
from myownca.online.app import UserCreate, create_app
from tests.helpers import add_login_ready_user, create_active_session, request_with_session, route_endpoint


def _app(tempdir: str):
    app = create_app(Path(tempdir) / "api.sqlite3", online_key_dir=Path(tempdir) / "keys")
    secret = add_login_ready_user(app, user_id="ad-1", email="ad@example.test", role=Role.ADMIN)
    admin = create_active_session(app, email="ad@example.test", totp_secret=secret)
    return app, admin


class PeopleSyncApiTests(unittest.TestCase):
    def test_creating_ordinary_user_mirrors_a_person(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, (token, csrf) = _app(tempdir)
            route_endpoint(app, "/internal/users", "POST")(
                UserCreate(id="u-new", email="newuser@example.test", role=Role.USER,
                           temporary_password="x" * 16),
                request_with_session(token, csrf, method="POST"),
            )
            emails = {p.email for p in app.state.repository.list_people()}
            self.assertIn("newuser@example.test", emails)

    def test_boot_backfills_people_for_existing_users(self) -> None:
        with TemporaryDirectory() as tempdir:
            db = Path(tempdir) / "api.sqlite3"
            keys = Path(tempdir) / "keys"
            app1 = create_app(db, online_key_dir=keys)
            app1.state.repository.add_user(User(id="legacy", email="legacy@example.test", role=Role.AUDITOR))
            self.assertNotIn("legacy@example.test", {p.email for p in app1.state.repository.list_people()})
            app2 = create_app(db, online_key_dir=keys)
            self.assertIn("legacy@example.test", {p.email for p in app2.state.repository.list_people()})


if __name__ == "__main__":
    unittest.main()
