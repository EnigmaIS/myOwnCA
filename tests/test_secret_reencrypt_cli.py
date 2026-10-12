from __future__ import annotations

import json
import unittest
from dataclasses import replace
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography.fernet import Fernet

from myownca.config import Settings
from myownca.secret_keys import COMMS_DOMAIN, derive_fernet_key, legacy_fernet_key
from myownca.storage.database import Database
from myownca.storage.reencrypt_cli import run

SECRET = "an-operator-encryption-secret"


def _settings(database: Path) -> Settings:
    base = Settings.from_mapping({"MYOWNCA_AUTH_ENCRYPTION_SECRET": SECRET})
    return replace(base, database_path=database, auth_encryption_secret=SECRET)


def _seed_legacy(database: Database) -> None:
    blob = (
        Fernet(legacy_fernet_key(SECRET))
        .encrypt(json.dumps({"password": "pw"}).encode())
        .decode()
    )
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO comms_channel_configs(channel, enabled, config_json,"
            " secret_ciphertext, updated_at) VALUES(?,?,?,?,?)",
            ("email", 1, "{}", blob, "2026-01-01T00:00:00+00:00"),
        )


def _stored(database: Database) -> str:
    with database.connect() as connection:
        row = connection.execute(
            "SELECT secret_ciphertext AS v FROM comms_channel_configs WHERE channel='email'"
        ).fetchone()
    return row["v"]


class ReencryptCliTests(unittest.TestCase):
    def test_dry_run_reports_and_writes_nothing(self) -> None:
        with TemporaryDirectory() as tempdir:
            path = Path(tempdir) / "cli.sqlite3"
            database = Database(path)
            database.migrate()
            _seed_legacy(database)
            before = _stored(database)
            out = StringIO()

            code = run([], settings=_settings(path), stdout=out, stderr=StringIO())

            self.assertEqual(code, 0)
            self.assertIn("Would convert 1", out.getvalue())
            self.assertIn("comms_channel_configs.secret_ciphertext", out.getvalue())
            self.assertIn("--execute", out.getvalue())
            self.assertEqual(_stored(database), before)  # untouched

    def test_execute_converts(self) -> None:
        with TemporaryDirectory() as tempdir:
            path = Path(tempdir) / "cli.sqlite3"
            database = Database(path)
            database.migrate()
            _seed_legacy(database)
            out = StringIO()

            code = run(["--execute"], settings=_settings(path), stdout=out, stderr=StringIO())

            self.assertEqual(code, 0)
            self.assertIn("Converted 1", out.getvalue())
            stored = _stored(database)
            self.assertEqual(
                json.loads(
                    Fernet(derive_fernet_key(SECRET, COMMS_DOMAIN))
                    .decrypt(stored.encode())
                    .decode()
                ),
                {"password": "pw"},
            )

    def test_to_legacy_reverses(self) -> None:
        with TemporaryDirectory() as tempdir:
            path = Path(tempdir) / "cli.sqlite3"
            database = Database(path)
            database.migrate()
            _seed_legacy(database)
            run(["--execute"], settings=_settings(path), stdout=StringIO(), stderr=StringIO())

            code = run(
                ["--execute", "--to-legacy"],
                settings=_settings(path),
                stdout=StringIO(),
                stderr=StringIO(),
            )

            self.assertEqual(code, 0)
            stored = _stored(database)
            self.assertEqual(
                json.loads(Fernet(legacy_fernet_key(SECRET)).decrypt(stored.encode()).decode()),
                {"password": "pw"},
            )

    def test_wrong_secret_refuses_with_exit_code_2(self) -> None:
        with TemporaryDirectory() as tempdir:
            path = Path(tempdir) / "cli.sqlite3"
            database = Database(path)
            database.migrate()
            _seed_legacy(database)
            before = _stored(database)
            err = StringIO()
            wrong = replace(_settings(path), auth_encryption_secret="a-different-secret")

            code = run(["--execute"], settings=wrong, stdout=StringIO(), stderr=err)

            self.assertEqual(code, 2)
            self.assertIn("MYOWNCA_AUTH_ENCRYPTION_SECRET", err.getvalue())
            self.assertEqual(_stored(database), before)  # nothing written

    def test_second_execute_is_a_no_op(self) -> None:
        with TemporaryDirectory() as tempdir:
            path = Path(tempdir) / "cli.sqlite3"
            database = Database(path)
            database.migrate()
            _seed_legacy(database)
            run(["--execute"], settings=_settings(path), stdout=StringIO(), stderr=StringIO())
            after_first = _stored(database)
            out = StringIO()

            run(["--execute"], settings=_settings(path), stdout=out, stderr=StringIO())

            self.assertIn("Converted 0", out.getvalue())
            self.assertIn("Already current: 1", out.getvalue())
            self.assertEqual(_stored(database), after_first)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
