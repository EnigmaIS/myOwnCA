from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from myownca.key_lifecycle import (
    ORPHAN_GRACE_PERIOD,
    CleanupClaimLostError,
    DuplicateKeyReferenceError,
    InvalidKeyStateError,
    KeyCleanupError,
    KeyLifecycleRepository,
    KeyLifecycleService,
    KeyOwnership,
    KeyStatus,
    UnknownKeyError,
)
from myownca.storage.database import Database


NOW = datetime(2026, 7, 22, 12, 0, tzinfo=timezone.utc)


class KeyLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = TemporaryDirectory()
        self.database = Database(Path(self.tempdir.name) / "keys.sqlite3")
        self.database.migrate()
        self.repository = KeyLifecycleRepository(self.database)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def register(
        self,
        key_id: str = "key-1",
        *,
        backend: str = "software",
        ownership: KeyOwnership = KeyOwnership.MANAGED,
    ):
        return self.repository.register(
            key_id=key_id,
            backend=backend,
            key_ref=f"key-ref-{key_id}",
            purpose="leaf_certificate",
            ownership=ownership,
            now=NOW,
        )

    def make_due(self, key_id: str = "key-1", **kwargs):
        key = self.register(key_id, **kwargs)
        self.repository.mark_orphaned(key.id, now=NOW)
        return self.repository.get(key.id)

    def test_registration_is_explicit_and_round_trips_without_key_material(self) -> None:
        self.assertIsNone(
            self.repository.find(backend="pkcs11", key_ref="unregistered-token-key")
        )
        with self.assertRaises(UnknownKeyError):
            self.repository.bind(
                "unregistered",
                resource_type="certificate",
                resource_id="cert-1",
                now=NOW,
            )

        key = self.repository.register(
            key_id="registered",
            backend="pkcs11",
            key_ref="slot/01/key/a1",
            purpose="sub_ca",
            ownership=KeyOwnership.ATTACHED,
            now=NOW,
        )

        self.assertEqual(self.repository.get(key.id), key)
        self.assertEqual(
            self.repository.find(backend="pkcs11", key_ref="slot/01/key/a1"), key
        )
        self.assertEqual(key.status, KeyStatus.ACTIVE)
        self.assertIsNone(key.delete_after)
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM key_lifecycle_keys WHERE id = ?", (key.id,)
            ).fetchone()
        self.assertNotIn("private", row)
        self.assertEqual(len(row["key_ref_digest"]), 64)

    def test_key_id_and_backend_reference_are_unique(self) -> None:
        self.register()
        with self.assertRaises(DuplicateKeyReferenceError):
            self.repository.register(
                key_id="key-2",
                backend="software",
                key_ref="key-ref-key-1",
                purpose="other",
                ownership=KeyOwnership.MANAGED,
                now=NOW,
            )
        with self.assertRaises(DuplicateKeyReferenceError):
            self.repository.register(
                key_id="key-1",
                backend="pkcs11",
                key_ref="another",
                purpose="other",
                ownership=KeyOwnership.MANAGED,
                now=NOW,
            )

    def test_public_key_fingerprint_is_backfilled_once_and_cannot_change(self) -> None:
        key = self.register(backend="pkcs11")
        fingerprint = "ab" * 32

        updated = self.repository.set_public_key_fingerprint(
            key.id,
            fingerprint.upper(),
            now=NOW + timedelta(minutes=1),
        )
        repeated = self.repository.set_public_key_fingerprint(
            key.id,
            fingerprint,
            now=NOW + timedelta(minutes=2),
        )

        self.assertEqual(updated.public_key_sha256, fingerprint)
        self.assertEqual(repeated.public_key_sha256, fingerprint)
        with self.assertRaises(InvalidKeyStateError):
            self.repository.set_public_key_fingerprint(
                key.id,
                "cd" * 32,
                now=NOW + timedelta(minutes=3),
            )

    def test_only_last_unbind_starts_fixed_grace_and_duplicate_is_idempotent(self) -> None:
        key = self.register()
        self.repository.bind(
            key.id, resource_type="certificate", resource_id="cert-1", now=NOW
        )
        self.repository.bind(
            key.id, resource_type="certificate", resource_id="cert-2", now=NOW
        )
        # Binding the same resource twice does not create duplicate consumers.
        self.repository.bind(
            key.id, resource_type="certificate", resource_id="cert-2", now=NOW
        )
        self.assertEqual(len(self.repository.list_bindings(key.id)), 2)

        one_left = self.repository.unbind(
            key.id,
            resource_type="certificate",
            resource_id="cert-1",
            now=NOW + timedelta(hours=1),
        )
        self.assertEqual(one_left.status, KeyStatus.ACTIVE)
        self.assertIsNone(one_left.delete_after)

        orphaned_at = NOW + timedelta(hours=2)
        orphaned = self.repository.unbind(
            key.id,
            resource_type="certificate",
            resource_id="cert-2",
            now=orphaned_at,
        )
        self.assertEqual(orphaned.status, KeyStatus.ORPHANED)
        self.assertEqual(orphaned.orphaned_at, orphaned_at)
        self.assertEqual(orphaned.delete_after, orphaned_at + ORPHAN_GRACE_PERIOD)

        unchanged = self.repository.unbind(
            key.id,
            resource_type="certificate",
            resource_id="cert-2",
            now=orphaned_at + timedelta(days=1),
        )
        self.assertEqual(unchanged.delete_after, orphaned.delete_after)

    def test_binding_during_grace_cancels_cleanup(self) -> None:
        key = self.make_due()
        due_at = key.delete_after
        self.assertEqual(self.repository.list_due(now=due_at - timedelta(microseconds=1)), [])
        self.assertEqual(self.repository.list_due(now=due_at), [key])

        rebound = self.repository.bind(
            key.id,
            resource_type="certificate",
            resource_id="replacement",
            now=due_at,
        )
        self.assertEqual(rebound.status, KeyStatus.ACTIVE)
        self.assertIsNone(rebound.orphaned_at)
        self.assertIsNone(rebound.delete_after)
        self.assertEqual(self.repository.list_due(now=due_at), [])

    def test_explicit_orphaning_refuses_a_bound_key(self) -> None:
        key = self.register()
        self.repository.bind(
            key.id, resource_type="workflow", resource_id="pending-1", now=NOW
        )
        with self.assertRaises(InvalidKeyStateError):
            self.repository.mark_orphaned(key.id, now=NOW)

    def test_managed_keys_are_deleted_and_attached_keys_are_detached_once(self) -> None:
        managed = self.make_due("managed", backend="software")
        attached = self.make_due(
            "attached", backend="aws_kms", ownership=KeyOwnership.ATTACHED
        )
        calls: list[tuple[str, str]] = []
        service = KeyLifecycleService(
            self.repository,
            deleters={"software": lambda key: calls.append(("delete", key.id))},
            detachers={"aws_kms": lambda key: calls.append(("detach", key.id))},
        )

        outcomes = service.cleanup_due(now=NOW + ORPHAN_GRACE_PERIOD)

        self.assertEqual(
            {(result.key_id, result.status) for result in outcomes},
            {
                (managed.id, KeyStatus.DELETED),
                (attached.id, KeyStatus.DETACHED),
            },
        )
        self.assertEqual(set(calls), {("delete", managed.id), ("detach", attached.id)})
        self.assertEqual(
            service.cleanup_due(now=NOW + ORPHAN_GRACE_PERIOD), []
        )
        self.assertEqual(len(calls), 2)

    def test_safe_failure_is_retryable_and_unexpected_detail_is_not_persisted(self) -> None:
        key = self.make_due()

        def fail_unexpected(_key) -> None:
            raise RuntimeError("provider credential=super-secret")

        failed = KeyLifecycleService(
            self.repository, deleters={"software": fail_unexpected}
        ).cleanup_due(now=NOW + ORPHAN_GRACE_PERIOD)
        self.assertEqual(failed[0].status, KeyStatus.ERROR)
        self.assertNotIn("super-secret", failed[0].error)
        self.assertEqual(self.repository.get(key.id).cleanup_attempts, 1)

        calls: list[str] = []
        retried = KeyLifecycleService(
            self.repository,
            deleters={"software": lambda item: calls.append(item.id)},
        ).cleanup_due(now=NOW + ORPHAN_GRACE_PERIOD + timedelta(minutes=1))
        self.assertEqual(retried[0].status, KeyStatus.DELETED)
        self.assertEqual(calls, [key.id])
        self.assertEqual(self.repository.get(key.id).cleanup_attempts, 2)

    def test_declared_safe_backend_error_and_missing_handler_are_visible(self) -> None:
        safe = self.make_due("safe")
        missing = self.make_due("missing", backend="pkcs11")

        def fail_safely(_key) -> None:
            raise KeyCleanupError("Token is offline.")

        outcomes = KeyLifecycleService(
            self.repository, deleters={"software": fail_safely}
        ).cleanup_due(now=NOW + ORPHAN_GRACE_PERIOD)
        by_id = {outcome.key_id: outcome for outcome in outcomes}
        self.assertEqual(by_id[safe.id].error, "Token is offline.")
        self.assertIn("pkcs11", by_id[missing.id].error)
        self.assertTrue(all(outcome.status is KeyStatus.ERROR for outcome in outcomes))

    def test_claim_token_guards_completion_and_stale_claim_can_be_retried(self) -> None:
        key = self.make_due()
        due_at = NOW + ORPHAN_GRACE_PERIOD
        claim = self.repository.claim_cleanup(key.id, now=due_at, token="worker-1")
        self.assertEqual(claim.key.status, KeyStatus.DELETING)
        self.assertIsNone(
            self.repository.claim_cleanup(key.id, now=due_at, token="worker-2")
        )
        with self.assertRaises(CleanupClaimLostError):
            self.repository.complete_cleanup(key.id, token="wrong", now=due_at)

        self.assertEqual(
            self.repository.recover_stale_cleanups(
                stale_before=due_at - timedelta(seconds=1), now=due_at
            ),
            0,
        )
        self.assertEqual(
            self.repository.recover_stale_cleanups(
                stale_before=due_at, now=due_at + timedelta(minutes=15)
            ),
            1,
        )
        with self.assertRaises(CleanupClaimLostError):
            self.repository.complete_cleanup(key.id, token="worker-1", now=due_at)

        retry = self.repository.claim_cleanup(
            key.id, now=due_at + timedelta(minutes=15), token="worker-2"
        )
        completed = self.repository.complete_cleanup(
            key.id, token=retry.token, now=due_at + timedelta(minutes=15)
        )
        self.assertEqual(completed.status, KeyStatus.DELETED)

    def test_deleting_and_terminal_keys_cannot_be_rebound(self) -> None:
        key = self.make_due()
        due_at = NOW + ORPHAN_GRACE_PERIOD
        claim = self.repository.claim_cleanup(key.id, now=due_at)
        with self.assertRaises(InvalidKeyStateError):
            self.repository.bind(
                key.id, resource_type="certificate", resource_id="too-late", now=due_at
            )
        self.repository.complete_cleanup(key.id, token=claim.token, now=due_at)
        with self.assertRaises(InvalidKeyStateError):
            self.repository.bind(
                key.id, resource_type="certificate", resource_id="terminal", now=due_at
            )

    def test_timestamps_must_be_timezone_aware(self) -> None:
        with self.assertRaises(ValueError):
            self.repository.register(
                backend="software",
                key_ref="naive",
                purpose="leaf",
                ownership=KeyOwnership.MANAGED,
                now=datetime(2026, 7, 22, 12, 0),
            )


if __name__ == "__main__":
    unittest.main()
