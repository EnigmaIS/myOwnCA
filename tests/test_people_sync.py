from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from myownca.domain import Role, User
from myownca.people_sync import (
    ensure_people_for_all_users,
    ensure_person_for_user,
    person_fields_from_user,
)
from myownca.storage.database import Database
from myownca.storage.repositories import PKIRepository


def _repo(tempdir: str) -> PKIRepository:
    db = Database(Path(tempdir) / "p.sqlite3")
    db.migrate()
    return PKIRepository(db)


class PeopleSyncTests(unittest.TestCase):
    def test_person_fields_from_user_derives_name_from_local_part(self) -> None:
        user = User(id="u1", email="Jane.Doe@example.test", role=Role.ADMIN)
        fields = person_fields_from_user(user)
        self.assertEqual(fields["name"], "Jane.Doe")
        self.assertEqual(fields["surname"], "")
        self.assertEqual(fields["email"], "Jane.Doe@example.test")

    def test_ensure_person_creates_when_absent(self) -> None:
        with TemporaryDirectory() as tempdir:
            repo = _repo(tempdir)
            created = ensure_person_for_user(repo, User(id="u1", email="op@example.test", role=Role.SUPERUSER))
            self.assertTrue(created)
            people = repo.list_people()
            self.assertEqual([p.email for p in people], ["op@example.test"])
            self.assertEqual(people[0].name, "op")

    def test_ensure_person_is_idempotent_case_insensitive(self) -> None:
        with TemporaryDirectory() as tempdir:
            repo = _repo(tempdir)
            ensure_person_for_user(repo, User(id="u1", email="op@example.test", role=Role.ADMIN))
            again = ensure_person_for_user(repo, User(id="u1", email="OP@EXAMPLE.TEST", role=Role.ADMIN))
            self.assertFalse(again)
            self.assertEqual(len(repo.list_people()), 1)

    def test_ensure_all_backfills_only_missing(self) -> None:
        with TemporaryDirectory() as tempdir:
            repo = _repo(tempdir)
            repo.add_user(User(id="u1", email="a@example.test", role=Role.ADMIN))
            repo.add_user(User(id="u2", email="b@example.test", role=Role.AUDITOR))
            ensure_person_for_user(repo, User(id="u1", email="a@example.test", role=Role.ADMIN))
            created = ensure_people_for_all_users(repo)
            self.assertEqual(created, 1)  # only b@ was missing
            self.assertEqual({p.email for p in repo.list_people()}, {"a@example.test", "b@example.test"})


if __name__ == "__main__":
    unittest.main()
