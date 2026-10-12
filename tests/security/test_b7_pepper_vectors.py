"""B7 — frozen known-answer vectors for the non-Fernet secret derivations.

The audit-chain pepper and the recovery-code pepper are HMAC keys derived from the
operator secret. Nothing can re-encrypt them: if either derivation string changes,
every stored hash silently stops matching.

  * a changed audit pepper voids the whole forensic log (verify_chain fails at
    sequence 1) with no crash and no log line;
  * a changed recovery pepper makes every printed recovery code unredeemable, and
    the user sees only "Invalid recovery code".

The existing tests for both re-derive the pepper on *both* sides of their
assertions, so they cannot detect a changed prefix. These vectors are frozen
constants read back from the live services, so they fail loudly if a derivation
is ever altered — which is what makes the neighbouring F-1 Fernet work safe.

DO NOT "fix" a failure here by recomputing a constant. A failure means stored
data in the field has just been invalidated.
"""
from __future__ import annotations

import hashlib
import hmac
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography.fernet import Fernet

from myownca.audit.repository import AuditRepository
from myownca.audit.service import AuditService
from myownca.ca_auth.repository import AuthRepository
from myownca.ca_auth.service import AuthService
from myownca.ca_main.server_keys import RequestKeyVault
from myownca.storage.database import Database
from myownca.storage.repositories import PKIRepository

SECRET = "f1-known-answer-vector-secret"

# sha256(f"{label}:{SECRET}") — captured 2026-08-04, before the F-1 Fernet change.
RECOVERY_PEPPER = "a4adec9d296a69ce5b3e387b1fe1539e8ac5a4a6a3e73d24f7dd887457d36bd7"
AUDIT_PEPPER = "471c3d3c795f4763b9271d91388c9914dd7c6060308711bced688d2d3bd81608"
SERVER_KEYS_DIGEST = "d862d099e248a70cc48180ad7ce5ee8df3a398a09cf337403d2763f0b9f0d5f2"

# HMAC outputs, i.e. what is actually stored in the database.
RECOVERY_CODE_HASH = "efd3b1578b4aba7c59b811e86c066c3607b837c78d2f35030036ace367ffd4c0"
AUDIT_PAYLOAD_HASH = "b9fa7722d6b3b09b02c4b2cc69d1b0216da47d3138d11c06bdf647d53137e34d"


def _database(tempdir: str, name: str) -> Database:
    database = Database(Path(tempdir) / name)
    database.migrate()
    return database


class PepperDerivationVectorTests(unittest.TestCase):
    """The derivation strings themselves are frozen."""

    def test_recovery_pepper_derivation_is_frozen(self) -> None:
        self.assertEqual(
            hashlib.sha256(f"recovery:{SECRET}".encode()).hexdigest(), RECOVERY_PEPPER
        )

    def test_audit_pepper_derivation_is_frozen(self) -> None:
        self.assertEqual(
            hashlib.sha256(f"audit:{SECRET}".encode()).hexdigest(), AUDIT_PEPPER
        )

    def test_server_keys_derivation_is_frozen(self) -> None:
        self.assertEqual(
            hashlib.sha256(f"server-keys:{SECRET}".encode()).hexdigest(), SERVER_KEYS_DIGEST
        )

    def test_stored_recovery_code_hash_is_stable(self) -> None:
        self.assertEqual(
            hmac.new(bytes.fromhex(RECOVERY_PEPPER), b"ABCDE-FGHIJ", hashlib.sha256).hexdigest(),
            RECOVERY_CODE_HASH,
        )

    def test_stored_audit_hash_is_stable(self) -> None:
        self.assertEqual(
            hmac.new(bytes.fromhex(AUDIT_PEPPER), b"payload", hashlib.sha256).hexdigest(),
            AUDIT_PAYLOAD_HASH,
        )


class LivePepperMatchesVectorTests(unittest.TestCase):
    """The running services must derive exactly these peppers.

    These read what the real constructors computed, so they detect a changed
    derivation string in the source — which the re-deriving tests cannot.
    """

    def test_auth_service_recovery_pepper_matches_vector(self) -> None:
        with TemporaryDirectory() as tempdir:
            service = AuthService(AuthRepository(_database(tempdir, "auth.sqlite3")), SECRET)
            self.assertEqual(service._recovery_pepper.hex(), RECOVERY_PEPPER)

    def test_auth_service_recovery_hash_matches_vector(self) -> None:
        with TemporaryDirectory() as tempdir:
            service = AuthService(AuthRepository(_database(tempdir, "auth.sqlite3")), SECRET)
            self.assertEqual(service._hash_recovery("ABCDE-FGHIJ"), RECOVERY_CODE_HASH)

    def test_audit_service_pepper_matches_vector(self) -> None:
        with TemporaryDirectory() as tempdir:
            service = AuditService(AuditRepository(_database(tempdir, "audit.sqlite3")), SECRET)
            self.assertEqual(service._pepper.hex(), AUDIT_PEPPER)

    def test_audit_service_hash_matches_vector(self) -> None:
        with TemporaryDirectory() as tempdir:
            service = AuditService(AuditRepository(_database(tempdir, "audit.sqlite3")), SECRET)
            self.assertEqual(service._hash("payload"), AUDIT_PAYLOAD_HASH)

    def test_server_key_vault_uses_the_frozen_derivation(self) -> None:
        """Ciphertext the live vault writes must open under the frozen digest."""
        import base64

        with TemporaryDirectory() as tempdir:
            database = _database(tempdir, "vault.sqlite3")
            vault = RequestKeyVault(PKIRepository(database), SECRET)
            token = vault.cipher.encrypt(b"vaulted-key-material")
            frozen = Fernet(base64.urlsafe_b64encode(bytes.fromhex(SERVER_KEYS_DIGEST)))
            self.assertEqual(frozen.decrypt(token), b"vaulted-key-material")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
