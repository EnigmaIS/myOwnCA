from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event, Thread

from myownca.cloud import (
    CloudKeyOwnership,
    CloudKeyRepository,
    CloudKeyStatus,
    CloudRepositoryError,
    CloudSigningWorker,
    DuplicateActiveSigningJob,
    InvalidSigningJobTransition,
    PermanentSigningError,
    SigningJobLeaseLost,
    SigningJobRepository,
    SigningJobStatus,
    TransientSigningError,
    UnknownCloudKeyError,
)
from myownca.cloud.repository import retry_delay
from myownca.storage.database import Database


NOW = datetime(2026, 7, 22, 12, 0, tzinfo=timezone.utc)


class _ObservedHeartbeatRepository(SigningJobRepository):
    """Gate the first heartbeat so worker concurrency tests need no sleeps."""

    def __init__(self, database: Database) -> None:
        super().__init__(database)
        self.heartbeat_entered = Event()
        self.allow_heartbeat = Event()
        self.heartbeat_completed = Event()
        self.acknowledgement_started = Event()
        self.first_heartbeat = None
        self.heartbeat_after_ack = False

    def heartbeat(self, *args, **kwargs):
        if self.acknowledgement_started.is_set():
            self.heartbeat_after_ack = True
        self.heartbeat_entered.set()
        if not self.allow_heartbeat.wait(timeout=2):
            raise AssertionError("Test did not release the heartbeat")
        result = super().heartbeat(*args, **kwargs)
        if self.first_heartbeat is None:
            self.first_heartbeat = result
            self.heartbeat_completed.set()
        return result

    def succeed(self, *args, **kwargs):
        self.acknowledgement_started.set()
        return super().succeed(*args, **kwargs)


class CloudSigningRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = TemporaryDirectory()
        self.database = Database(Path(self.tempdir.name) / "cloud.sqlite3")
        self.database.migrate()
        self.keys = CloudKeyRepository(self.database)
        self.jobs = SigningJobRepository(self.database)
        self.key = self.keys.register(
            key_id="key-1",
            provider="test-provider",
            key_ref="test://vault/keys/sub-ca/version-1",
            label="Sub CA",
            algorithm="EC-P384",
            protection="hsm",
            purpose="sub_ca",
            ownership=CloudKeyOwnership.MANAGED,
            now=NOW,
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def enqueue(self, *, dedup: str = "request-1", resource_id: str = "request-1"):
        return self.jobs.enqueue(
            cloud_key_id=self.key.id,
            operation="sign_certificate",
            resource_type="certificate_request",
            resource_id=resource_id,
            payload={"tbs_der": "AAEC", "context": {"profile": "user"}},
            deduplication_key=dedup,
            now=NOW,
        )

    def test_cloud_key_registry_round_trip_filters_and_status(self) -> None:
        loaded = self.keys.get(self.key.id)
        self.assertEqual(loaded, self.key)
        self.assertEqual(
            self.keys.find(provider=self.key.provider, key_ref=self.key.key_ref), self.key
        )
        self.assertEqual(self.keys.list_all(provider="test-provider"), [self.key])
        self.assertEqual(self.keys.list_all(purpose="other"), [])

        disabled = self.keys.set_status(
            self.key.id, CloudKeyStatus.DISABLED, now=NOW + timedelta(minutes=1)
        )
        self.assertEqual(disabled.status, CloudKeyStatus.DISABLED)
        self.assertEqual(
            self.keys.list_all(status=CloudKeyStatus.DISABLED), [disabled]
        )

    def test_cloud_key_reference_is_unique_per_provider(self) -> None:
        with self.assertRaises(CloudRepositoryError):
            self.keys.register(
                provider=self.key.provider,
                key_ref=self.key.key_ref,
                algorithm="EC-P384",
                purpose="service_certificate",
                ownership=CloudKeyOwnership.ATTACHED,
                now=NOW,
            )

    def test_long_cloud_key_reference_is_stored_without_truncation(self) -> None:
        key_ref = (
            "https://very-long-vault-name.vault.azure.net/keys/"
            + "k" * 127
            + "/"
            + "a" * 64
        )
        self.assertGreater(len(key_ref), 191)

        key = self.keys.register(
            provider="azure_key_vault",
            key_ref=key_ref,
            algorithm="ecdsa-p384",
            purpose="subca",
            ownership=CloudKeyOwnership.ATTACHED,
            now=NOW,
        )

        self.assertEqual(key.key_ref, key_ref)
        self.assertEqual(
            self.keys.find(provider="azure_key_vault", key_ref=key_ref), key
        )

    def test_enqueue_rejects_unknown_cloud_key(self) -> None:
        with self.assertRaises(UnknownCloudKeyError):
            self.jobs.enqueue(
                cloud_key_id="missing",
                operation="sign",
                resource_type="request",
                resource_id="r1",
                payload={},
                deduplication_key="r1",
                now=NOW,
            )

    def test_inactive_cloud_key_cannot_enqueue_or_be_claimed(self) -> None:
        queued = self.enqueue().job
        self.keys.set_status(self.key.id, CloudKeyStatus.DISABLED, now=NOW)

        with self.assertRaises(CloudRepositoryError):
            self.enqueue(dedup="disabled", resource_id="disabled")
        self.assertIsNone(self.jobs.claim_next(worker_id="worker-1", now=NOW))
        self.assertEqual(
            self.jobs.get(queued.id).status,
            SigningJobStatus.QUEUED,
        )

    def test_active_job_is_deduplicated_but_terminal_job_is_not(self) -> None:
        first = self.enqueue()
        duplicate = self.enqueue()
        self.assertTrue(first.created)
        self.assertFalse(duplicate.created)
        self.assertEqual(duplicate.job.id, first.job.id)
        self.assertEqual(len(first.job.deduplication_key), 64)

        claimed = self.jobs.claim_next(worker_id="worker-1", now=NOW)
        completed = self.jobs.succeed(
            claimed.id,
            worker_id="worker-1",
            result={"signature": "AQID"},
            now=NOW + timedelta(seconds=1),
        )
        self.assertEqual(completed.status, SigningJobStatus.SUCCEEDED)
        self.assertEqual(completed.result, {"signature": "AQID"})

        replacement = self.enqueue()
        self.assertTrue(replacement.created)
        self.assertNotEqual(replacement.job.id, first.job.id)

    def test_workers_can_claim_disjoint_operation_classes(self) -> None:
        short = self.enqueue(dedup="short", resource_id="short").job
        acme = self.jobs.enqueue(
            cloud_key_id=self.key.id,
            operation="acme_order",
            resource_type="service_certificate",
            resource_id="cert-1",
            payload={"certificate_id": "cert-1"},
            deduplication_key="acme-order:cert-1",
            now=NOW,
        ).job

        claimed_acme = self.jobs.claim_next(
            worker_id="acme-worker", now=NOW, operations=("acme_order", "acme_renew")
        )
        claimed_short = self.jobs.claim_next(
            worker_id="signing-worker",
            now=NOW,
            operations=("sign_certificate",),
        )

        self.assertEqual(claimed_acme.id, acme.id)
        self.assertEqual(claimed_short.id, short.id)

    def test_claim_is_guarded_and_expired_lease_can_be_recovered(self) -> None:
        job = self.enqueue().job
        first = self.jobs.claim_next(
            worker_id="worker-1", now=NOW, lease_for=timedelta(minutes=5)
        )
        self.assertEqual(first.id, job.id)
        self.assertEqual(first.attempt_count, 1)
        self.assertIsNone(
            self.jobs.claim_next(
                worker_id="worker-2",
                now=NOW + timedelta(minutes=4),
                lease_for=timedelta(minutes=5),
            )
        )

        recovered = self.jobs.claim_next(
            worker_id="worker-2",
            now=NOW + timedelta(minutes=5),
            lease_for=timedelta(minutes=5),
        )
        self.assertEqual(recovered.id, job.id)
        self.assertEqual(recovered.attempt_count, 2)
        with self.assertRaises(SigningJobLeaseLost):
            self.jobs.succeed(
                job.id,
                worker_id="worker-1",
                now=NOW + timedelta(minutes=5, seconds=1),
            )
        completed = self.jobs.succeed(
            job.id,
            worker_id="worker-2",
            now=NOW + timedelta(minutes=5, seconds=1),
        )
        self.assertEqual(completed.status, SigningJobStatus.SUCCEEDED)

    def test_heartbeat_extends_only_an_active_owned_lease(self) -> None:
        job = self.enqueue().job
        self.jobs.claim_next(
            worker_id="worker-1", now=NOW, lease_for=timedelta(minutes=2)
        )
        extended = self.jobs.heartbeat(
            job.id,
            worker_id="worker-1",
            now=NOW + timedelta(minutes=1),
            lease_for=timedelta(minutes=5),
        )
        self.assertEqual(extended.lease_expires_at, NOW + timedelta(minutes=6))
        with self.assertRaises(SigningJobLeaseLost):
            self.jobs.heartbeat(
                job.id,
                worker_id="other",
                now=NOW + timedelta(minutes=1),
            )

    def test_retry_schedule_is_30s_2m_5m_then_15m(self) -> None:
        job = self.enqueue().job
        current = NOW
        expected_delays = [
            timedelta(seconds=30),
            timedelta(minutes=2),
            timedelta(minutes=5),
            timedelta(minutes=15),
            timedelta(minutes=15),
        ]
        for attempt, expected_delay in enumerate(expected_delays, start=1):
            claimed = self.jobs.claim_next(
                worker_id="worker-1",
                now=current,
                lease_for=timedelta(hours=1),
            )
            self.assertEqual(claimed.id, job.id)
            self.assertEqual(claimed.attempt_count, attempt)
            queued = self.jobs.retry_transient(
                job.id,
                worker_id="worker-1",
                error_code="provider_busy",
                error_message="Provider is busy.",
                now=current,
            )
            self.assertEqual(queued.status, SigningJobStatus.QUEUED)
            self.assertEqual(queued.next_attempt_at, current + expected_delay)
            current = queued.next_attempt_at

        self.assertEqual(retry_delay(99), timedelta(minutes=15))

    def test_job_fails_at_24_hour_retry_deadline(self) -> None:
        job = self.enqueue().job
        almost_deadline = NOW + timedelta(hours=23, minutes=59, seconds=45)
        self.jobs.claim_next(
            worker_id="worker-1",
            now=almost_deadline,
            lease_for=timedelta(minutes=5),
        )
        queued = self.jobs.retry_transient(
            job.id,
            worker_id="worker-1",
            error_code="timeout",
            error_message="Provider timed out.",
            now=almost_deadline,
        )
        self.assertEqual(queued.next_attempt_at, NOW + timedelta(hours=24))

        self.assertIsNone(
            self.jobs.claim_next(
                worker_id="worker-2", now=NOW + timedelta(hours=24)
            )
        )
        failed = self.jobs.get(job.id)
        self.assertEqual(failed.status, SigningJobStatus.FAILED)
        self.assertEqual(failed.last_error_code, "retry_window_expired")
        self.assertEqual(failed.completed_at, NOW + timedelta(hours=24))

    def test_manual_retry_starts_a_new_window_and_detects_active_duplicate(self) -> None:
        job = self.enqueue().job
        self.jobs.claim_next(worker_id="worker-1", now=NOW)
        self.jobs.fail_permanent(
            job.id,
            worker_id="worker-1",
            error_code="invalid_key",
            error_message="Key cannot sign.",
            now=NOW + timedelta(seconds=1),
        )
        retry_time = NOW + timedelta(hours=1)
        retried = self.jobs.retry_failed(job.id, now=retry_time)
        self.assertEqual(retried.status, SigningJobStatus.QUEUED)
        self.assertEqual(retried.attempt_count, 0)
        self.assertEqual(retried.retry_window_started_at, retry_time)
        self.assertIsNone(retried.last_error_code)

        self.jobs.claim_next(worker_id="worker-1", now=retry_time)
        self.jobs.fail_permanent(
            job.id,
            worker_id="worker-1",
            error_code="still_invalid",
            error_message="Still invalid.",
            now=retry_time + timedelta(seconds=1),
        )
        active = self.jobs.enqueue(
            cloud_key_id=self.key.id,
            operation="sign_certificate",
            resource_type="certificate_request",
            resource_id="request-1",
            payload={},
            deduplication_key="request-1",
            now=retry_time + timedelta(seconds=2),
        ).job
        with self.assertRaises(DuplicateActiveSigningJob) as raised:
            self.jobs.retry_failed(job.id, now=retry_time + timedelta(seconds=3))
        self.assertEqual(raised.exception.existing_job_id, active.id)

    def test_cancel_is_immediate_when_queued_and_cooperative_when_running(self) -> None:
        queued = self.enqueue(dedup="queued").job
        canceled = self.jobs.cancel(queued.id, now=NOW + timedelta(seconds=1))
        self.assertEqual(canceled.status, SigningJobStatus.CANCELED)
        self.assertTrue(canceled.terminal)

        running = self.enqueue(dedup="running", resource_id="request-2").job
        self.jobs.claim_next(
            worker_id="worker-1", now=NOW, lease_for=timedelta(minutes=1)
        )
        requested = self.jobs.cancel(running.id, now=NOW + timedelta(seconds=1))
        self.assertEqual(requested.status, SigningJobStatus.RUNNING)
        self.assertTrue(requested.cancel_requested)
        acknowledged = self.jobs.succeed(
            running.id,
            worker_id="worker-1",
            result={"must": "be discarded"},
            now=NOW + timedelta(seconds=2),
        )
        self.assertEqual(acknowledged.status, SigningJobStatus.CANCELED)
        self.assertIsNone(acknowledged.result)

    def test_maintenance_cancels_abandoned_running_job_after_lease(self) -> None:
        job = self.enqueue().job
        self.jobs.claim_next(
            worker_id="dead-worker", now=NOW, lease_for=timedelta(minutes=1)
        )
        self.jobs.cancel(job.id, now=NOW + timedelta(seconds=1))
        changed = self.jobs.maintain(now=NOW + timedelta(minutes=1))
        self.assertEqual(changed, 1)
        self.assertEqual(self.jobs.get(job.id).status, SigningJobStatus.CANCELED)

    def test_terminal_jobs_reject_invalid_manual_transitions(self) -> None:
        job = self.enqueue().job
        self.jobs.claim_next(worker_id="worker-1", now=NOW)
        self.jobs.succeed(job.id, worker_id="worker-1", now=NOW + timedelta(seconds=1))
        with self.assertRaises(InvalidSigningJobTransition):
            self.jobs.cancel(job.id, now=NOW + timedelta(seconds=2))
        with self.assertRaises(InvalidSigningJobTransition):
            self.jobs.retry_failed(job.id, now=NOW + timedelta(seconds=2))

    def test_list_filters_by_status_key_and_resource(self) -> None:
        first = self.enqueue(dedup="one", resource_id="r1").job
        self.enqueue(dedup="two", resource_id="r2")
        self.jobs.cancel(first.id, now=NOW)
        queued = self.jobs.list_all(
            status=SigningJobStatus.QUEUED,
            cloud_key_id=self.key.id,
            resource_type="certificate_request",
            resource_id="r2",
        )
        self.assertEqual(len(queued), 1)
        self.assertEqual(queued[0].resource_id, "r2")


class CloudSigningWorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = TemporaryDirectory()
        self.database = Database(Path(self.tempdir.name) / "worker.sqlite3")
        self.database.migrate()
        keys = CloudKeyRepository(self.database)
        self.key = keys.register(
            key_id="key-1",
            provider="test-provider",
            key_ref="test://key/version",
            algorithm="RSA-3072",
            purpose="service_certificate",
            ownership=CloudKeyOwnership.ATTACHED,
            now=NOW,
        )
        self.jobs = SigningJobRepository(self.database)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def enqueue(self, dedup: str = "one"):
        return self.jobs.enqueue(
            cloud_key_id=self.key.id,
            operation="sign_csr",
            resource_type="service_certificate",
            resource_id=dedup,
            payload={"csr": "PEM"},
            deduplication_key=dedup,
            now=NOW,
        ).job

    def test_worker_persists_success_result(self) -> None:
        job = self.enqueue()
        worker = CloudSigningWorker(
            self.jobs,
            lambda claimed: {"signature": claimed.id},
            worker_id="worker-1",
        )
        completed = worker.run_once(now=NOW)
        self.assertEqual(completed.id, job.id)
        self.assertEqual(completed.status, SigningJobStatus.SUCCEEDED)
        self.assertEqual(completed.result, {"signature": job.id})

    def test_worker_classifies_declared_transient_and_permanent_errors(self) -> None:
        transient_job = self.enqueue("transient")

        def transient(_job):
            raise TransientSigningError("throttled", "Provider throttled the request.")

        transient_result = CloudSigningWorker(
            self.jobs, transient, worker_id="worker-transient"
        ).run_once(now=NOW)
        self.assertEqual(transient_result.id, transient_job.id)
        self.assertEqual(transient_result.status, SigningJobStatus.QUEUED)
        self.assertEqual(transient_result.next_attempt_at, NOW + timedelta(seconds=30))

        permanent_job = self.enqueue("permanent")

        def permanent(_job):
            raise PermanentSigningError("key_disabled", "The key is disabled.")

        permanent_result = CloudSigningWorker(
            self.jobs, permanent, worker_id="worker-permanent"
        ).run_once(now=NOW)
        self.assertEqual(permanent_result.id, permanent_job.id)
        self.assertEqual(permanent_result.status, SigningJobStatus.FAILED)
        self.assertEqual(permanent_result.last_error_code, "key_disabled")

    def test_unknown_handler_exception_is_retryable_and_redacted(self) -> None:
        job = self.enqueue()

        def broken(_job):
            raise RuntimeError("secret-token-which-must-not-be-stored")

        result = CloudSigningWorker(
            self.jobs, broken, worker_id="worker-1"
        ).run_once(now=NOW)
        self.assertEqual(result.id, job.id)
        self.assertEqual(result.status, SigningJobStatus.QUEUED)
        self.assertEqual(result.last_error_code, "unexpected_handler_error")
        self.assertNotIn("secret-token", result.last_error_message)

    def test_run_available_stops_when_no_ready_jobs_remain(self) -> None:
        self.enqueue("one")
        self.enqueue("two")
        worker = CloudSigningWorker(
            self.jobs, lambda job: {"resource": job.resource_id}, worker_id="worker-1"
        )
        completed = worker.run_available(now=NOW)
        self.assertEqual(len(completed), 2)
        self.assertTrue(all(job.status is SigningJobStatus.SUCCEEDED for job in completed))

    def test_worker_heartbeats_long_handler_and_stops_before_ack(self) -> None:
        jobs = _ObservedHeartbeatRepository(self.database)
        job = jobs.enqueue(
            cloud_key_id=self.key.id,
            operation="sign_csr",
            resource_type="service_certificate",
            resource_id="long-running",
            payload={"csr": "PEM"},
            deduplication_key="long-running",
            now=NOW,
        ).job
        handler_started = Event()
        release_handler = Event()

        def long_handler(_job):
            handler_started.set()
            if not release_handler.wait(timeout=2):
                raise AssertionError("Test did not release the signing handler")
            return {"signed": True}

        worker = CloudSigningWorker(
            jobs,
            long_handler,
            worker_id="worker-long",
            lease_for=timedelta(minutes=1),
            heartbeat_interval=timedelta(milliseconds=1),
            clock=lambda: NOW + timedelta(seconds=50),
        )
        results = []
        errors = []

        def run_worker() -> None:
            try:
                results.append(worker.run_once(now=NOW))
            except Exception as exc:  # noqa: BLE001 - surfaced in the test thread
                errors.append(exc)

        worker_thread = Thread(target=run_worker, daemon=True)
        worker_thread.start()
        self.assertTrue(handler_started.wait(timeout=2))
        self.assertTrue(jobs.heartbeat_entered.wait(timeout=2))
        jobs.allow_heartbeat.set()
        self.assertTrue(jobs.heartbeat_completed.wait(timeout=2))
        self.assertEqual(
            jobs.first_heartbeat.lease_expires_at,
            NOW + timedelta(minutes=1, seconds=50),
        )

        # The original one-minute lease has elapsed, but a competing worker
        # still cannot reclaim the operation while its handler is active.
        self.assertIsNone(
            jobs.claim_next(
                worker_id="worker-competing",
                now=NOW + timedelta(minutes=1, seconds=1),
                lease_for=timedelta(minutes=1),
            )
        )
        release_handler.set()
        worker_thread.join(timeout=2)

        self.assertFalse(worker_thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(results[0].id, job.id)
        self.assertEqual(results[0].status, SigningJobStatus.SUCCEEDED)
        self.assertTrue(jobs.acknowledgement_started.is_set())
        self.assertFalse(jobs.heartbeat_after_ack)

    def test_worker_keeps_lease_after_cooperative_cancel_until_handler_returns(
        self,
    ) -> None:
        jobs = _ObservedHeartbeatRepository(self.database)
        job = jobs.enqueue(
            cloud_key_id=self.key.id,
            operation="sign_csr",
            resource_type="service_certificate",
            resource_id="cancel-running",
            payload={"csr": "PEM"},
            deduplication_key="cancel-running",
            now=NOW,
        ).job
        handler_started = Event()
        release_handler = Event()

        def long_handler(_job):
            handler_started.set()
            if not release_handler.wait(timeout=2):
                raise AssertionError("Test did not release the signing handler")
            return {"must": "be discarded"}

        worker = CloudSigningWorker(
            jobs,
            long_handler,
            worker_id="worker-cancel",
            lease_for=timedelta(minutes=1),
            heartbeat_interval=timedelta(milliseconds=1),
            clock=lambda: NOW + timedelta(seconds=50),
        )
        results = []
        errors = []

        def run_worker() -> None:
            try:
                results.append(worker.run_once(now=NOW))
            except Exception as exc:  # noqa: BLE001 - surfaced in the test thread
                errors.append(exc)

        worker_thread = Thread(target=run_worker, daemon=True)
        worker_thread.start()
        self.assertTrue(handler_started.wait(timeout=2))
        self.assertTrue(jobs.heartbeat_entered.wait(timeout=2))

        requested = jobs.cancel(job.id, now=NOW + timedelta(seconds=10))
        self.assertTrue(requested.cancel_requested)
        jobs.allow_heartbeat.set()
        self.assertTrue(jobs.heartbeat_completed.wait(timeout=2))
        self.assertTrue(jobs.first_heartbeat.cancel_requested)
        self.assertEqual(
            jobs.first_heartbeat.lease_expires_at,
            NOW + timedelta(minutes=1, seconds=50),
        )

        release_handler.set()
        worker_thread.join(timeout=2)

        self.assertFalse(worker_thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(results[0].status, SigningJobStatus.CANCELED)
        self.assertIsNone(results[0].result)
        self.assertFalse(jobs.heartbeat_after_ack)


if __name__ == "__main__":
    unittest.main()
