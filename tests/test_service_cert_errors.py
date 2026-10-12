from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from myownca.service_certs.repository import _MAX_ERRORS, ServiceCertRepository
from myownca.storage.database import Database


def _repo(tempdir: str) -> ServiceCertRepository:
    db = Database(Path(tempdir) / "svc.sqlite3")
    db.migrate()
    return ServiceCertRepository(db)


class ServiceCertErrorLogTests(unittest.TestCase):
    def test_record_then_list_newest_first(self) -> None:
        with TemporaryDirectory() as tempdir:
            repo = _repo(tempdir)
            repo.record_error("account_create", "https://acme.test/dir", "boom-1")
            repo.record_error("order_create", "svc-a (a.test)", "boom-2")
            rows = repo.list_recent_errors()
            self.assertEqual([r["operation"] for r in rows], ["order_create", "account_create"])
            self.assertEqual(rows[0]["target"], "svc-a (a.test)")
            self.assertEqual(rows[0]["message"], "boom-2")
            self.assertIn("created_at", rows[0])
            self.assertIn("id", rows[0])

    def test_limit_is_respected(self) -> None:
        with TemporaryDirectory() as tempdir:
            repo = _repo(tempdir)
            for i in range(5):
                repo.record_error("order_create", f"svc-{i}", f"m{i}")
            self.assertEqual(len(repo.list_recent_errors(limit=3)), 3)

    def test_pruned_to_max(self) -> None:
        with TemporaryDirectory() as tempdir:
            repo = _repo(tempdir)
            for i in range(_MAX_ERRORS + 5):
                repo.record_error("order_create", f"svc-{i}", f"m{i}")
            self.assertEqual(len(repo.list_recent_errors(limit=10_000)), _MAX_ERRORS)

    def test_clear_empties_the_log(self) -> None:
        with TemporaryDirectory() as tempdir:
            repo = _repo(tempdir)
            repo.record_error("dns_provider", "account x", "boom")
            repo.clear_errors()
            self.assertEqual(repo.list_recent_errors(), [])


if __name__ == "__main__":
    unittest.main()
