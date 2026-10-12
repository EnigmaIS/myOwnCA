from __future__ import annotations

import re
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from myownca.storage.database import Database, IntegrityError
from myownca.storage.dialect import key_columns_for_scripts, prepare_ddl, translate_dml

_MIGRATIONS = Path(__file__).resolve().parents[1] / "src/myownca/storage/migrations"


class DmlTranslationTests(unittest.TestCase):
    def test_sqlite_passthrough(self) -> None:
        sql = "INSERT INTO users(id) VALUES (?)"
        self.assertEqual(translate_dml(sql, "sqlite"), sql)

    def test_mysql_placeholders_and_upsert(self) -> None:
        sql = (
            "INSERT INTO online_settings(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value"
        )
        out = translate_dml(sql, "mysql")
        self.assertIn("VALUES (%s, %s)", out)
        self.assertIn("ON DUPLICATE KEY UPDATE value = VALUES(value)", out)
        self.assertNotIn("ON CONFLICT", out)
        self.assertIn("`key`", out)
        self.assertNotIn(" key,", out)  # bare reserved word was quoted

    def test_mysql_multi_column_upsert(self) -> None:
        sql = (
            "INSERT INTO comms_channel_configs(channel, enabled) VALUES (?, ?) "
            "ON CONFLICT(channel) DO UPDATE SET enabled = excluded.enabled"
        )
        out = translate_dml(sql, "mysql")
        self.assertIn("ON DUPLICATE KEY UPDATE enabled = VALUES(enabled)", out)


class DdlTranslationTests(unittest.TestCase):
    def test_text_key_and_content_columns(self) -> None:
        ddl = (
            "CREATE TABLE devices ("
            "id TEXT PRIMARY KEY, "
            "device_name TEXT NOT NULL, "
            "admin_id TEXT NOT NULL REFERENCES people(id), "
            "comments TEXT NOT NULL DEFAULT '', "
            "created_at TEXT NOT NULL)"
        )
        out = prepare_ddl(ddl, "mysql")[0]
        self.assertIn("id VARCHAR(191) PRIMARY KEY", out)
        self.assertIn("admin_id VARCHAR(191)", out)            # FK column -> keyed
        self.assertIn("device_name LONGTEXT", out)             # plain content
        self.assertIn("FOREIGN KEY (`admin_id`) REFERENCES people(`id`)", out)
        self.assertNotIn("REFERENCES people(id),", out)        # inline ref was lifted out

    def test_alter_add_column_with_reference_is_split(self) -> None:
        ddl = "ALTER TABLE certificate_requests ADD COLUMN requested_by_user_id TEXT REFERENCES users(id)"
        out = prepare_ddl(ddl, "mysql")
        self.assertEqual(len(out), 2)
        self.assertEqual(
            out[0], "ALTER TABLE certificate_requests ADD COLUMN requested_by_user_id VARCHAR(191)"
        )
        self.assertIn("ADD FOREIGN KEY (`requested_by_user_id`) REFERENCES users(`id`)", out[1])
        self.assertNotIn("REFERENCES", out[0])  # inline ref removed from the column

    def test_create_index_if_not_exists_stripped_for_mysql(self) -> None:
        out = prepare_ddl("CREATE INDEX IF NOT EXISTS idx_x ON t(category)", "mysql")[0]
        self.assertNotIn("IF NOT EXISTS", out)

    def test_on_delete_cascade_preserved(self) -> None:
        ddl = (
            "CREATE TABLE acme_cert_configs ("
            "service_certificate_id TEXT PRIMARY KEY REFERENCES service_certificates(id) ON DELETE CASCADE, "
            "account_id TEXT NOT NULL REFERENCES acme_accounts(id))"
        )
        out = prepare_ddl(ddl, "mysql")[0]
        self.assertIn("FOREIGN KEY (`service_certificate_id`) REFERENCES service_certificates(`id`) ON DELETE CASCADE", out)

    def test_all_real_migrations_translate_for_mysql(self) -> None:
        for path in sorted(_MIGRATIONS.glob("*.sql")):
            statements = prepare_ddl(path.read_text(), "mysql")
            out = "\n".join(statements)
            with self.subTest(migration=path.name):
                # No raw TEXT used as a key (MySQL can't index TEXT without a length).
                self.assertIsNone(
                    re.search(r"\bTEXT\b\s+PRIMARY\s+KEY", out),
                    f"{path.name}: bare TEXT primary key remains",
                )
                self.assertIsNone(
                    re.search(r"\bTEXT\b\s+NOT\s+NULL\s+UNIQUE", out),
                    f"{path.name}: bare TEXT unique remains",
                )

    def test_future_indexes_make_earlier_text_columns_indexable(self) -> None:
        migration_texts = [path.read_text() for path in sorted(_MIGRATIONS.glob("*.sql"))]
        key_columns = key_columns_for_scripts(migration_texts)
        initial_schema = "\n".join(
            prepare_ddl(
                (_MIGRATIONS / "0001_initial.sql").read_text(),
                "mysql",
                key_columns=key_columns,
            )
        )
        self.assertIn("status VARCHAR(191) NOT NULL", initial_schema)
        self.assertIn("expires_at VARCHAR(191) NOT NULL", initial_schema)

    def test_indexed_alter_column_uses_varchar(self) -> None:
        out = prepare_ddl(
            "ALTER TABLE issued_certificates ADD COLUMN source TEXT NOT NULL DEFAULT 'issued'",
            "mysql",
            key_columns={"issued_certificates": {"source"}},
        )
        self.assertEqual(
            out,
            [
                (
                    "ALTER TABLE issued_certificates ADD COLUMN source VARCHAR(191) "
                    "NOT NULL DEFAULT 'issued'"
                )
            ],
        )

    def test_content_columns_become_longtext(self) -> None:
        out = "\n".join(prepare_ddl((_MIGRATIONS / "0010_service_certs.sql").read_text(), "mysql"))
        self.assertIn("certificate_pem LONGTEXT", out)
        self.assertIn("csr_pem LONGTEXT", out)

    def test_cloud_key_ref_is_not_truncated_by_mysql_indexes(self) -> None:
        out = "\n".join(
            prepare_ddl(
                (_MIGRATIONS / "0029_cloud_signing.sql").read_text(), "mysql"
            )
        )
        self.assertIn("key_ref LONGTEXT", out)
        self.assertIn("key_ref_digest VARCHAR(191)", out)
        self.assertIn("UNIQUE (provider, key_ref_digest)", out)

    def test_sqlite_ddl_is_untouched(self) -> None:
        ddl = "CREATE TABLE t (id TEXT PRIMARY KEY, body TEXT NOT NULL)"
        self.assertEqual(prepare_ddl(ddl, "sqlite"), [ddl])

    def test_translated_mysql_schema_is_structurally_valid(self) -> None:
        # SQLite accepts backticks, VARCHAR(n), LONGTEXT and table-level FKs, so
        # replaying the MySQL-translated DDL here proves it is well-formed SQL
        # (structure/parens/FK syntax) even without a MySQL server available.
        import sqlite3

        conn = sqlite3.connect(":memory:")
        conn.execute("PRAGMA foreign_keys = OFF")
        try:
            for path in sorted(_MIGRATIONS.glob("*.sql")):
                for statement in prepare_ddl(path.read_text(), "mysql"):
                    # SQLite's ALTER TABLE can't ADD FOREIGN KEY; those statements
                    # are validated against real MariaDB, not here. ADD COLUMN and
                    # everything else still replays to prove well-formedness.
                    if "ADD FOREIGN KEY" in statement.upper():
                        continue
                    conn.execute(statement)
        finally:
            conn.close()


class DatabaseShimTests(unittest.TestCase):
    def _db(self, tempdir: str) -> Database:
        db = Database(Path(tempdir) / "shim.sqlite3")
        db.migrate()
        return db

    def test_dict_rows_and_rowcount(self) -> None:
        with TemporaryDirectory() as tempdir:
            db = self._db(tempdir)
            with db.connect() as c:
                c.execute(
                    "INSERT INTO users(id, email, role, is_active) VALUES (?, ?, ?, ?)",
                    ("u1", "u1@example.test", "admin", 1),
                )
            with db.connect() as c:
                row = c.execute("SELECT * FROM users WHERE id = ?", ("u1",)).fetchone()
            self.assertEqual(row["email"], "u1@example.test")
            with db.connect() as c:
                cur = c.execute(
                    "UPDATE users SET role = ? WHERE id = ?",
                    ("auditor", "u1"),
                )
                self.assertEqual(cur.rowcount, 1)

    def test_transfer_column_is_removed_without_losing_pending_csr(self) -> None:
        with TemporaryDirectory() as tempdir:
            db = Database(Path(tempdir) / "legacy-pending.sqlite3")
            with db.connect() as connection:
                connection.executescript(
                    "CREATE TABLE schema_migrations (version TEXT PRIMARY KEY)"
                )
                for migration in sorted(_MIGRATIONS.glob("*.sql")):
                    if migration.name >= "0039_remove_subca_transfer_bundle.sql":
                        break
                    connection.executescript(migration.read_text())
                    connection.execute(
                        "INSERT INTO schema_migrations(version) VALUES (?)",
                        (migration.name,),
                    )
                connection.execute(
                    """
                    INSERT INTO pending_sub_cas(
                        id, bundle_id, key_ref, csr_pem, subject, created_at,
                        allowed_profiles_json, key_backend, token_label
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "pending-1",
                        "obsolete-transfer-id",
                        "issuer-key",
                        "CSR PEM",
                        "CN=Pending",
                        "2026-07-23T00:00:00+00:00",
                        '["host_tls"]',
                        "pkcs11",
                        "myOwnCA",
                    ),
                )

            db.migrate()

            with db.connect() as connection:
                columns = {
                    row["name"]
                    for row in connection.execute(
                        "PRAGMA table_info(pending_sub_cas)"
                    ).fetchall()
                }
                pending = connection.execute(
                    "SELECT * FROM pending_sub_cas WHERE id = ?",
                    ("pending-1",),
                ).fetchone()
            self.assertNotIn("bundle_id", columns)
            self.assertEqual(pending["csr_pem"], "CSR PEM")
            self.assertEqual(pending["key_ref"], "issuer-key")

    def test_unique_violation_raises_integrity_error(self) -> None:
        with TemporaryDirectory() as tempdir:
            db = self._db(tempdir)
            row = ("u1", "dup@example.test", "admin", 1)
            with db.connect() as c:
                c.execute("INSERT INTO users(id, email, role, is_active) VALUES (?, ?, ?, ?)", row)
            with self.assertRaises(IntegrityError):
                with db.connect() as c:
                    c.execute(
                        "INSERT INTO users(id, email, role, is_active) VALUES (?, ?, ?, ?)",
                        ("u2", "dup@example.test", "admin", 1),
                    )

    def test_foreign_key_enforced_on_sqlite(self) -> None:
        with TemporaryDirectory() as tempdir:
            db = self._db(tempdir)
            with self.assertRaises(IntegrityError):
                with db.connect() as c:
                    c.execute(
                        "INSERT INTO devices(id, device_name, fqdn, admin_id, comments, created_at) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        ("d1", "dev", "", "ghost-person", "", "2026-01-01T00:00:00+00:00"),
                    )

    def test_executemany(self) -> None:
        with TemporaryDirectory() as tempdir:
            db = self._db(tempdir)
            with db.connect() as c:
                c.executemany(
                    "INSERT INTO users(id, email, role, is_active) VALUES (?, ?, ?, ?)",
                    [("a", "a@x", "user", 1), ("b", "b@x", "user", 1)],
                )
            with db.connect() as c:
                count = c.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
                self.assertEqual(count, 2)


class DialectDetectionTests(unittest.TestCase):
    def test_sqlite_path_and_mysql_url(self) -> None:
        with TemporaryDirectory() as tempdir:
            self.assertEqual(Database(Path(tempdir) / "x.sqlite3").dialect, "sqlite")
        # Building the engine for a URL does not open a connection.
        self.assertEqual(Database("mysql+pymysql://u:p@198.51.100.10/db").dialect, "mysql")


if __name__ == "__main__":
    unittest.main()
