from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from myownca.config import Settings
from myownca.online.app import _seed_service_urls
from myownca.storage.database import Database
from myownca.storage.repositories import PKIRepository


def _repo(tempdir: str) -> PKIRepository:
    db = Database(Path(tempdir) / "s.sqlite3")
    db.migrate()
    return PKIRepository(db)


class SeedServiceUrlsTests(unittest.TestCase):
    def test_seeds_unset_keys_from_config(self) -> None:
        with TemporaryDirectory() as tempdir:
            repo = _repo(tempdir)
            settings = Settings.from_mapping(
                {
                    "MYOWNCA_ADMIN_BASE_URL": "https://admin.example/",
                    "MYOWNCA_FRONTEND_BASE_URL": "https://app.example",
                    "MYOWNCA_CRL_URL": "http://ca.example/",
                }
            )
            _seed_service_urls(settings, repo)
            self.assertEqual(repo.get_setting("admin_base_url"), "https://admin.example")
            self.assertEqual(repo.get_setting("portal_base_url"), "https://app.example")
            self.assertEqual(repo.get_setting("crl_base_url"), "http://ca.example")
            self.assertIsNone(repo.get_setting("ocsp_url"))

    def test_does_not_overwrite_existing_setting(self) -> None:
        with TemporaryDirectory() as tempdir:
            repo = _repo(tempdir)
            repo.set_setting("crl_base_url", "http://admin-chosen.example")
            repo.set_setting("admin_base_url", "")  # explicitly cleared
            settings = Settings.from_mapping(
                {"MYOWNCA_CRL_URL": "http://from-config.example", "MYOWNCA_ADMIN_BASE_URL": "http://x.example"}
            )
            _seed_service_urls(settings, repo)
            self.assertEqual(repo.get_setting("crl_base_url"), "http://admin-chosen.example")
            self.assertEqual(repo.get_setting("admin_base_url"), "")
