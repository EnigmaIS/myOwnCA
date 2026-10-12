from __future__ import annotations

import base64
import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography.fernet import Fernet, InvalidToken

from myownca.secret_keys import (
    CA_AUTH_DOMAIN,
    COMMS_DOMAIN,
    SERVICE_CERTS_DOMAIN,
    derive_fernet_key,
    legacy_fernet_key,
)
from myownca.storage.database import Database
from myownca.storage.reencrypt import reencrypt_secrets

SECRET = "an-operator-encryption-secret"


def _db(tempdir: str) -> Database:
    database = Database(Path(tempdir) / "sweep.sqlite3")
    database.migrate()
    return database


def _legacy(value: bytes) -> str:
    return Fernet(legacy_fernet_key(SECRET)).encrypt(value).decode()


def _domain_key(domain: str) -> Fernet:
    return Fernet(derive_fernet_key(SECRET, domain))


def _seed(database: Database, **rows: str) -> None:
    """Insert one legacy-encrypted row into each target table."""
    with database.connect() as connection:
        if "totp" in rows:
            connection.execute(
                "INSERT INTO users(id, email, role) VALUES(?,?,?)",
                ("u-1", "u1@example.test", "admin"),
            )
            connection.execute(
                "INSERT INTO totp_factors(user_id, secret_ciphertext) VALUES(?,?)",
                ("u-1", rows["totp"]),
            )
        if "comms" in rows:
            connection.execute(
                "INSERT INTO comms_channel_configs(channel, enabled, config_json,"
                " secret_ciphertext, updated_at) VALUES(?,?,?,?,?)",
                ("email", 1, "{}", rows["comms"], "2026-01-01T00:00:00+00:00"),
            )
        if "acme_key" in rows:
            connection.execute(
                "INSERT INTO acme_accounts(id, directory_url, account_url,"
                " account_key_ciphertext, contact, created_at,"
                " dns_credentials_ciphertext) VALUES(?,?,?,?,?,?,?)",
                ("a-1", "https://acme.test/dir", "https://acme.test/acct/1",
                 rows["acme_key"], "ca@test", "2026-01-01T00:00:00+00:00",
                 rows.get("acme_dns")),
            )


def _column(database: Database, table: str, column: str, pk_col: str, pk: str) -> str | None:
    with database.connect() as connection:
        row = connection.execute(
            f"SELECT {column} AS v FROM {table} WHERE {pk_col} = ?", (pk,)
        ).fetchone()
    return None if row is None else row["v"]


class ReencryptSweepTests(unittest.TestCase):
    def test_converts_every_legacy_column(self) -> None:
        with TemporaryDirectory() as tempdir:
            database = _db(tempdir)
            _seed(
                database,
                totp=_legacy(b"JBSWY3DPEHPK3PXP"),
                comms=_legacy(json.dumps({"password": "pw"}).encode()),
                acme_key=_legacy(b"-----BEGIN PRIVATE KEY-----"),
                acme_dns=_legacy(json.dumps({"auth_token": "t"}).encode()),
            )

            result = reencrypt_secrets(database, SECRET)

            self.assertEqual(result.converted, 4)
            self.assertEqual(result.failed, 0)
            # every value now opens under its own domain key, and not the legacy one
            checks = [
                ("totp_factors", "secret_ciphertext", "user_id", "u-1", CA_AUTH_DOMAIN,
                 b"JBSWY3DPEHPK3PXP"),
                ("comms_channel_configs", "secret_ciphertext", "channel", "email", COMMS_DOMAIN,
                 json.dumps({"password": "pw"}).encode()),
                ("acme_accounts", "account_key_ciphertext", "id", "a-1", SERVICE_CERTS_DOMAIN,
                 b"-----BEGIN PRIVATE KEY-----"),
                ("acme_accounts", "dns_credentials_ciphertext", "id", "a-1", SERVICE_CERTS_DOMAIN,
                 json.dumps({"auth_token": "t"}).encode()),
            ]
            for table, column, pk_col, pk, domain, plaintext in checks:
                stored = _column(database, table, column, pk_col, pk)
                self.assertEqual(_domain_key(domain).decrypt(stored.encode()), plaintext)
                with self.assertRaises(InvalidToken):
                    Fernet(legacy_fernet_key(SECRET)).decrypt(stored.encode())

    def test_is_idempotent_and_does_not_rewrite_converted_rows(self) -> None:
        with TemporaryDirectory() as tempdir:
            database = _db(tempdir)
            _seed(database, totp=_legacy(b"SEED"))
            reencrypt_secrets(database, SECRET)
            first = _column(database, "totp_factors", "secret_ciphertext", "user_id", "u-1")

            second_run = reencrypt_secrets(database, SECRET)

            self.assertEqual(second_run.converted, 0)
            self.assertEqual(second_run.already_current, 1)
            # byte-identical: an already-converted row is left completely alone
            self.assertEqual(
                _column(database, "totp_factors", "secret_ciphertext", "user_id", "u-1"), first
            )

    def test_resumes_from_a_half_converted_corpus(self) -> None:
        with TemporaryDirectory() as tempdir:
            database = _db(tempdir)
            _seed(
                database,
                totp=_domain_key(CA_AUTH_DOMAIN).encrypt(b"already").decode(),
                comms=_legacy(json.dumps({"password": "pw"}).encode()),
            )
            result = reencrypt_secrets(database, SECRET)
            self.assertEqual(result.converted, 1)
            self.assertEqual(result.already_current, 1)

    def test_empty_and_null_values_are_skipped_not_fatal(self) -> None:
        with TemporaryDirectory() as tempdir:
            database = _db(tempdir)
            # '' is the legitimate "no secrets" value; NULL means "no DNS provider".
            _seed(database, comms="", acme_key=_legacy(b"k"), acme_dns=None)
            result = reencrypt_secrets(database, SECRET)
            self.assertEqual(result.converted, 1)
            self.assertEqual(result.failed, 0)
            self.assertEqual(result.skipped_empty, 2)

    def test_junk_rows_are_reported_not_fatal(self) -> None:
        with TemporaryDirectory() as tempdir:
            database = _db(tempdir)
            _seed(database, totp="not-a-fernet-token", comms=_legacy(b"{}"))
            result = reencrypt_secrets(database, SECRET)
            self.assertEqual(result.converted, 1)
            self.assertEqual(result.failed, 1)
            self.assertTrue(any("totp_factors" in note for note in result.failures))

    def test_wrong_secret_refuses_to_write_anything(self) -> None:
        """All rows failing means a wrong secret, not a corpus of junk."""
        with TemporaryDirectory() as tempdir:
            database = _db(tempdir)
            _seed(database, totp=_legacy(b"SEED"), comms=_legacy(b"{}"))
            before = _column(database, "totp_factors", "secret_ciphertext", "user_id", "u-1")

            with self.assertRaises(ValueError):
                reencrypt_secrets(database, "a-completely-different-secret")

            self.assertEqual(
                _column(database, "totp_factors", "secret_ciphertext", "user_id", "u-1"), before
            )

    def test_dry_run_reports_without_writing(self) -> None:
        with TemporaryDirectory() as tempdir:
            database = _db(tempdir)
            _seed(database, totp=_legacy(b"SEED"))
            before = _column(database, "totp_factors", "secret_ciphertext", "user_id", "u-1")

            result = reencrypt_secrets(database, SECRET, dry_run=True)

            self.assertEqual(result.converted, 1)  # would convert
            self.assertEqual(
                _column(database, "totp_factors", "secret_ciphertext", "user_id", "u-1"), before
            )

    def test_reverse_sweep_restores_legacy_ciphertext(self) -> None:
        with TemporaryDirectory() as tempdir:
            database = _db(tempdir)
            _seed(database, totp=_legacy(b"SEED"))
            reencrypt_secrets(database, SECRET)

            result = reencrypt_secrets(database, SECRET, to_legacy=True)

            self.assertEqual(result.converted, 1)
            stored = _column(database, "totp_factors", "secret_ciphertext", "user_id", "u-1")
            self.assertEqual(Fernet(legacy_fernet_key(SECRET)).decrypt(stored.encode()), b"SEED")

    def test_unknown_comms_channel_row_is_still_swept(self) -> None:
        """Sweep the table, not the NotificationChannel enum."""
        with TemporaryDirectory() as tempdir:
            database = _db(tempdir)
            with database.connect() as connection:
                connection.execute(
                    "INSERT INTO comms_channel_configs(channel, enabled, config_json,"
                    " secret_ciphertext, updated_at) VALUES(?,?,?,?,?)",
                    ("some-future-channel", 1, "{}", _legacy(b"{}"),
                     "2026-01-01T00:00:00+00:00"),
                )
            result = reencrypt_secrets(database, SECRET)
            self.assertEqual(result.converted, 1)

    def test_preserves_the_exact_plaintext_including_unknown_keys(self) -> None:
        with TemporaryDirectory() as tempdir:
            database = _db(tempdir)
            payload = json.dumps({"password": "pw", "custom_extra": "keep-me"})
            _seed(database, comms=_legacy(payload.encode()))
            reencrypt_secrets(database, SECRET)
            stored = _column(database, "comms_channel_configs", "secret_ciphertext",
                             "channel", "email")
            self.assertEqual(
                json.loads(_domain_key(COMMS_DOMAIN).decrypt(stored.encode()).decode()),
                {"password": "pw", "custom_extra": "keep-me"},
            )


class LegacyKeyHelperTests(unittest.TestCase):
    def test_legacy_helper_matches_the_pre_f1_formula(self) -> None:
        self.assertEqual(
            legacy_fernet_key(SECRET),
            base64.urlsafe_b64encode(hashlib.sha256(SECRET.encode()).digest()),
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
