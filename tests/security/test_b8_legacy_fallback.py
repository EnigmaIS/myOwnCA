"""B8 — an install upgrading across F-1 must keep reading its existing secrets.

Every row written before the domain-separation change is encrypted under the old
undifferentiated key. The service ciphers are MultiFernet([domain, legacy]), so:

  * legacy ciphertext still decrypts (no lockout, no data loss, and a database
    restored from a backup taken either side of the upgrade still works);
  * anything written afterwards is domain-separated and is NOT readable with the
    legacy key.

Each subsystem is exercised through its real service, not the cipher in isolation.
"""
from __future__ import annotations

import base64
import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography.fernet import Fernet

from myownca.ca_auth.repository import AuthRepository
from myownca.ca_auth.service import AuthService
from myownca.comms import NotificationChannel
from myownca.comms.repository import CommsRepository
from myownca.comms.service import CommsService
from myownca.secret_keys import SecretDecryptionError
from myownca.storage.database import Database

SECRET = "an-operator-encryption-secret"


def _legacy_cipher(secret: str = SECRET) -> Fernet:
    """The pre-F-1 undifferentiated key."""
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest()))


def _database(tempdir: str, name: str) -> Database:
    database = Database(Path(tempdir) / name)
    database.migrate()
    return database


class CommsLegacyFallbackTests(unittest.TestCase):
    def _seed_legacy(self, repository: CommsRepository) -> None:
        blob = _legacy_cipher().encrypt(json.dumps({"password": "smtp-pw"}).encode()).decode()
        repository.upsert(
            channel=NotificationChannel.EMAIL.value,
            enabled=True,
            config_json=json.dumps({"host": "smtp.test", "from_address": "ca@test"}),
            secret_ciphertext=blob,
        )

    def test_reads_pre_upgrade_ciphertext(self) -> None:
        with TemporaryDirectory() as tempdir:
            repository = CommsRepository(_database(tempdir, "comms.sqlite3"))
            self._seed_legacy(repository)
            service = CommsService(repository, SECRET)
            config = service.get_config(NotificationChannel.EMAIL)
            self.assertEqual(config.secrets, {"password": "smtp-pw"})

    def test_rewrite_is_domain_separated(self) -> None:
        with TemporaryDirectory() as tempdir:
            repository = CommsRepository(_database(tempdir, "comms.sqlite3"))
            self._seed_legacy(repository)
            service = CommsService(repository, SECRET)
            service.set_config(
                NotificationChannel.EMAIL,
                enabled=True,
                config={"host": "smtp.test", "from_address": "ca@test"},
                secrets={"password": "rotated"},
            )
            stored = repository.get(NotificationChannel.EMAIL.value)
            with self.assertRaises(Exception):
                _legacy_cipher().decrypt(stored.secret_ciphertext.encode())
            self.assertEqual(
                service.get_config(NotificationChannel.EMAIL).secrets, {"password": "rotated"}
            )

    def test_wrong_secret_raises_a_clear_value_error(self) -> None:
        with TemporaryDirectory() as tempdir:
            repository = CommsRepository(_database(tempdir, "comms.sqlite3"))
            self._seed_legacy(repository)
            with self.assertRaises(SecretDecryptionError) as caught:
                CommsService(repository, "a-different-secret").get_config(NotificationChannel.EMAIL)
            self.assertIsInstance(caught.exception, ValueError)
            self.assertIn("MYOWNCA_AUTH_ENCRYPTION_SECRET", str(caught.exception))

    def test_empty_secret_blob_is_not_an_error(self) -> None:
        """'' is the normal 'channel has no secrets' value, not corruption."""
        with TemporaryDirectory() as tempdir:
            repository = CommsRepository(_database(tempdir, "comms.sqlite3"))
            repository.upsert(
                channel=NotificationChannel.SLACK.value,
                enabled=False,
                config_json=json.dumps({}),
                secret_ciphertext="",
            )
            service = CommsService(repository, SECRET)
            self.assertEqual(service.get_config(NotificationChannel.SLACK).secrets, {})


class AuthLegacyFallbackTests(unittest.TestCase):
    def test_totp_secret_written_pre_upgrade_still_decrypts(self) -> None:
        with TemporaryDirectory() as tempdir:
            database = _database(tempdir, "auth.sqlite3")
            service = AuthService(AuthRepository(database), SECRET)
            legacy_blob = _legacy_cipher().encrypt(b"JBSWY3DPEHPK3PXP").decode()
            self.assertEqual(service._decrypt(legacy_blob), "JBSWY3DPEHPK3PXP")

    def test_new_totp_secret_is_domain_separated(self) -> None:
        with TemporaryDirectory() as tempdir:
            database = _database(tempdir, "auth.sqlite3")
            service = AuthService(AuthRepository(database), SECRET)
            token = service._encrypt("JBSWY3DPEHPK3PXP")
            with self.assertRaises(Exception):
                _legacy_cipher().decrypt(token.encode())
            self.assertEqual(service._decrypt(token), "JBSWY3DPEHPK3PXP")

    def test_wrong_secret_gives_a_clear_error(self) -> None:
        with TemporaryDirectory() as tempdir:
            database = _database(tempdir, "auth.sqlite3")
            token = AuthService(AuthRepository(database), SECRET)._encrypt("SEED")
            other = AuthService(AuthRepository(database), "a-different-secret")
            with self.assertRaises(SecretDecryptionError):
                other._decrypt(token)


class CrossDomainIsolationTests(unittest.TestCase):
    def test_new_comms_ciphertext_is_not_readable_by_auth(self) -> None:
        """The actual F-1 fix: separate subsystems no longer share a key.

        Uses the domain keys directly. The service ciphers still carry the legacy
        fallback, so asserting against them would pass vacuously.
        """
        from myownca.secret_keys import (
            CA_AUTH_DOMAIN,
            COMMS_DOMAIN,
            SERVICE_CERTS_DOMAIN,
            derive_fernet_key,
        )

        domains = (CA_AUTH_DOMAIN, COMMS_DOMAIN, SERVICE_CERTS_DOMAIN)
        for writer in domains:
            token = Fernet(derive_fernet_key(SECRET, writer)).encrypt(b"secret")
            for reader in domains:
                if reader == writer:
                    continue
                with self.assertRaises(Exception):
                    Fernet(derive_fernet_key(SECRET, reader)).decrypt(token)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
