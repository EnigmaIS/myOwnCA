from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping
from uuid import uuid4

from myownca.cloud.base import (
    CloudKey,
    CloudKeyOwnership,
    CloudKeyStatus,
    CloudRepositoryError,
    DuplicateActiveSigningJob,
    EnqueueResult,
    InvalidSigningJobTransition,
    SigningJob,
    SigningJobLeaseLost,
    SigningJobStatus,
    UnknownCloudKeyError,
    UnknownSigningJobError,
)
from myownca.storage.database import Database, IntegrityError


DEFAULT_LEASE_DURATION = timedelta(minutes=5)
RETRY_WINDOW = timedelta(hours=24)
RETRY_DELAYS = (
    timedelta(seconds=30),
    timedelta(minutes=2),
    timedelta(minutes=5),
    timedelta(minutes=15),
)
_CLAIM_SCAN_LIMIT = 32
_MAX_ERROR_MESSAGE_LENGTH = 2_000


class CloudKeyRepository:
    """Persistence for non-secret cloud key metadata."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def add(self, key: CloudKey) -> None:
        _required(key.id, "key id")
        _required(key.provider, "provider")
        _required(key.key_ref, "key reference")
        _required(key.algorithm, "algorithm")
        _required(key.purpose, "purpose")
        try:
            with self.database.connect() as connection:
                connection.execute(
                    """
                    INSERT INTO cloud_keys(
                        id, provider, key_ref, key_ref_digest, label, algorithm, protection,
                        purpose, ownership, status, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        key.id,
                        key.provider,
                        key.key_ref,
                        _key_ref_digest(key.key_ref),
                        key.label,
                        key.algorithm,
                        key.protection,
                        key.purpose,
                        key.ownership.value,
                        key.status.value,
                        _dump_dt(key.created_at),
                        _dump_dt(key.updated_at),
                    ),
                )
        except IntegrityError as exc:
            raise CloudRepositoryError(
                f"Cloud key id or provider reference already exists: {key.id}"
            ) from exc

    def register(
        self,
        *,
        provider: str,
        key_ref: str,
        algorithm: str,
        purpose: str,
        ownership: CloudKeyOwnership,
        label: str = "",
        protection: str | None = None,
        status: CloudKeyStatus = CloudKeyStatus.ACTIVE,
        now: datetime | None = None,
        key_id: str | None = None,
    ) -> CloudKey:
        current = _as_utc(now or datetime.now(timezone.utc))
        key = CloudKey(
            id=key_id or str(uuid4()),
            provider=provider,
            key_ref=key_ref,
            label=label,
            algorithm=algorithm,
            protection=protection,
            purpose=purpose,
            ownership=ownership,
            status=status,
            created_at=current,
            updated_at=current,
        )
        self.add(key)
        return key

    def get(self, key_id: str) -> CloudKey:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM cloud_keys WHERE id = ?", (key_id,)
            ).fetchone()
        if row is None:
            raise UnknownCloudKeyError(f"Unknown cloud key: {key_id}")
        return _cloud_key_from_row(row)

    def find(self, *, provider: str, key_ref: str) -> CloudKey | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM cloud_keys "
                "WHERE provider = ? AND key_ref_digest = ? AND key_ref = ?",
                (provider, _key_ref_digest(key_ref), key_ref),
            ).fetchone()
        return None if row is None else _cloud_key_from_row(row)

    def list_all(
        self,
        *,
        provider: str | None = None,
        purpose: str | None = None,
        status: CloudKeyStatus | None = None,
    ) -> list[CloudKey]:
        clauses: list[str] = []
        params: list[str] = []
        if provider is not None:
            clauses.append("provider = ?")
            params.append(provider)
        if purpose is not None:
            clauses.append("purpose = ?")
            params.append(purpose)
        if status is not None:
            clauses.append("status = ?")
            params.append(status.value)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self.database.connect() as connection:
            rows = connection.execute(
                f"SELECT * FROM cloud_keys{where} ORDER BY provider, label, id",  # noqa: S608
                params,
            ).fetchall()
        return [_cloud_key_from_row(row) for row in rows]

    def set_status(
        self,
        key_id: str,
        status: CloudKeyStatus,
        *,
        now: datetime | None = None,
    ) -> CloudKey:
        current = _as_utc(now or datetime.now(timezone.utc))
        with self.database.connect() as connection:
            cursor = connection.execute(
                "UPDATE cloud_keys SET status = ?, updated_at = ? WHERE id = ?",
                (status.value, _dump_dt(current), key_id),
            )
            if cursor.rowcount == 0:
                raise UnknownCloudKeyError(f"Unknown cloud key: {key_id}")
        return self.get(key_id)


class SigningJobRepository:
    """Durable, provider-neutral queue for cloud signing work.

    Claims use a compare-and-set update after selecting a small candidate set.
    The guarded update is the source of truth, so competing workers cannot both
    own a job even when their initial SELECT sees the same row.
    """

    def __init__(self, database: Database) -> None:
        self.database = database

    def enqueue(
        self,
        *,
        cloud_key_id: str,
        operation: str,
        resource_type: str,
        resource_id: str,
        payload: Mapping[str, Any],
        deduplication_key: str,
        now: datetime | None = None,
        job_id: str | None = None,
    ) -> EnqueueResult:
        _required(cloud_key_id, "cloud key id")
        _required(operation, "operation")
        _required(resource_type, "resource type")
        _required(resource_id, "resource id")
        _required(deduplication_key, "deduplication key")
        current = _as_utc(now or datetime.now(timezone.utc))
        dedup_digest = _dedup_digest(cloud_key_id, operation, deduplication_key)
        identifier = job_id or str(uuid4())
        payload_json = _dump_object(payload, "job payload")
        try:
            with self.database.connect() as connection:
                key_row = connection.execute(
                    "SELECT status FROM cloud_keys WHERE id = ?", (cloud_key_id,)
                ).fetchone()
                if key_row is None:
                    raise UnknownCloudKeyError(f"Unknown cloud key: {cloud_key_id}")
                if CloudKeyStatus(key_row["status"]) is not CloudKeyStatus.ACTIVE:
                    raise CloudRepositoryError(
                        f"Cloud key is not active: {cloud_key_id}"
                    )
                connection.execute(
                    """
                    INSERT INTO signing_jobs(
                        id, cloud_key_id, operation, resource_type, resource_id,
                        payload_json, status, deduplication_key,
                        active_deduplication_key, attempt_count,
                        retry_window_started_at, next_attempt_at,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        identifier,
                        cloud_key_id,
                        operation,
                        resource_type,
                        resource_id,
                        payload_json,
                        SigningJobStatus.QUEUED.value,
                        dedup_digest,
                        dedup_digest,
                        0,
                        _dump_dt(current),
                        _dump_dt(current),
                        _dump_dt(current),
                        _dump_dt(current),
                    ),
                )
        except IntegrityError as exc:
            active = self._find_active_by_digest(dedup_digest)
            if active is not None:
                return EnqueueResult(job=active, created=False)
            if not self._cloud_key_exists(cloud_key_id):
                raise UnknownCloudKeyError(f"Unknown cloud key: {cloud_key_id}") from exc
            raise CloudRepositoryError(f"Could not enqueue signing job: {identifier}") from exc
        return EnqueueResult(job=self.get(identifier), created=True)

    def get(self, job_id: str) -> SigningJob:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM signing_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        if row is None:
            raise UnknownSigningJobError(f"Unknown signing job: {job_id}")
        return _signing_job_from_row(row)

    def list_all(
        self,
        *,
        status: SigningJobStatus | None = None,
        cloud_key_id: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        limit: int = 100,
    ) -> list[SigningJob]:
        if limit < 1 or limit > 1_000:
            raise ValueError("limit must be between 1 and 1000")
        clauses: list[str] = []
        params: list[Any] = []
        if status is not None:
            clauses.append("status = ?")
            params.append(status.value)
        if cloud_key_id is not None:
            clauses.append("cloud_key_id = ?")
            params.append(cloud_key_id)
        if resource_type is not None:
            clauses.append("resource_type = ?")
            params.append(resource_type)
        if resource_id is not None:
            clauses.append("resource_id = ?")
            params.append(resource_id)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(limit)
        with self.database.connect() as connection:
            rows = connection.execute(
                f"SELECT * FROM signing_jobs{where} "  # noqa: S608
                "ORDER BY created_at DESC, id DESC LIMIT ?",
                params,
            ).fetchall()
        return [_signing_job_from_row(row) for row in rows]

    def has_active_for_key(self, cloud_key_id: str) -> bool:
        """Return whether any queued/running job still depends on a key.

        This intentionally does not use ``list_all(limit=...)``: key deletion
        safety must account for every active row, regardless of queue history.
        """

        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM signing_jobs "
                "WHERE cloud_key_id = ? AND status IN (?, ?) LIMIT 1",
                (
                    cloud_key_id,
                    SigningJobStatus.QUEUED.value,
                    SigningJobStatus.RUNNING.value,
                ),
            ).fetchone()
        return row is not None

    def list_alerting(
        self,
        *,
        now: datetime | None = None,
        alert_after: timedelta = timedelta(minutes=15),
        limit: int = 1_000,
    ) -> list[SigningJob]:
        """Failed jobs plus active jobs whose current retry window is overdue."""

        _positive_duration(alert_after, "alert threshold")
        if limit < 1 or limit > 10_000:
            raise ValueError("limit must be between 1 and 10000")
        cutoff = _as_utc(now or datetime.now(timezone.utc)) - alert_after
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM signing_jobs "
                "WHERE status = ? OR (status IN (?, ?) AND retry_window_started_at <= ?) "
                "ORDER BY retry_window_started_at ASC, id ASC LIMIT ?",
                (
                    SigningJobStatus.FAILED.value,
                    SigningJobStatus.QUEUED.value,
                    SigningJobStatus.RUNNING.value,
                    _dump_dt(cutoff),
                    limit,
                ),
            ).fetchall()
        return [_signing_job_from_row(row) for row in rows]

    def status_counts(self) -> dict[SigningJobStatus, int]:
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT status, COUNT(*) AS total FROM signing_jobs GROUP BY status"
            ).fetchall()
        counts = {status: 0 for status in SigningJobStatus}
        for row in rows:
            counts[SigningJobStatus(row["status"])] = int(row["total"])
        return counts

    def claim_next(
        self,
        *,
        worker_id: str,
        now: datetime | None = None,
        lease_for: timedelta = DEFAULT_LEASE_DURATION,
        operations: tuple[str, ...] | None = None,
    ) -> SigningJob | None:
        _required(worker_id, "worker id")
        _positive_duration(lease_for, "lease duration")
        operation_filter: tuple[str, ...] = ()
        if operations is not None:
            operation_filter = tuple(
                dict.fromkeys(_required(value, "operation") for value in operations)
            )
            if not operation_filter:
                raise ValueError("operations filter must not be empty")
        operation_clause = (
            " AND operation IN ("
            + ", ".join("?" for _ in operation_filter)
            + ")"
            if operation_filter
            else ""
        )
        current = _as_utc(now or datetime.now(timezone.utc))
        lease_expires = current + lease_for
        cutoff = current - RETRY_WINDOW
        claimed_row = None
        with self.database.connect() as connection:
            self._finish_expired_cancellations(connection, current)
            self._expire_retry_windows(connection, current)
            candidates = connection.execute(
                f"""
                SELECT id FROM signing_jobs
                WHERE cancel_requested_at IS NULL
                  AND EXISTS (
                    SELECT 1 FROM cloud_keys
                    WHERE cloud_keys.id = signing_jobs.cloud_key_id
                      AND cloud_keys.status = ?
                  )
                  AND retry_window_started_at > ?
                  {operation_clause}
                  AND (
                    (status = ? AND next_attempt_at <= ?)
                    OR (status = ? AND lease_expires_at <= ?)
                  )
                ORDER BY next_attempt_at, created_at, id
                LIMIT ?
                """,  # noqa: S608 - only generated placeholders are interpolated
                (
                    CloudKeyStatus.ACTIVE.value,
                    _dump_dt(cutoff),
                    *operation_filter,
                    SigningJobStatus.QUEUED.value,
                    _dump_dt(current),
                    SigningJobStatus.RUNNING.value,
                    _dump_dt(current),
                    _CLAIM_SCAN_LIMIT,
                ),
            ).fetchall()
            for candidate in candidates:
                cursor = connection.execute(
                    """
                    UPDATE signing_jobs
                    SET status = ?, lease_owner = ?, lease_expires_at = ?,
                        attempt_count = attempt_count + 1, updated_at = ?
                    WHERE id = ?
                      AND cancel_requested_at IS NULL
                      AND EXISTS (
                        SELECT 1 FROM cloud_keys
                        WHERE cloud_keys.id = signing_jobs.cloud_key_id
                          AND cloud_keys.status = ?
                      )
                      AND retry_window_started_at > ?
                      AND (
                        (status = ? AND next_attempt_at <= ?)
                        OR (status = ? AND lease_expires_at <= ?)
                      )
                    """,
                    (
                        SigningJobStatus.RUNNING.value,
                        worker_id,
                        _dump_dt(lease_expires),
                        _dump_dt(current),
                        candidate["id"],
                        CloudKeyStatus.ACTIVE.value,
                        _dump_dt(cutoff),
                        SigningJobStatus.QUEUED.value,
                        _dump_dt(current),
                        SigningJobStatus.RUNNING.value,
                        _dump_dt(current),
                    ),
                )
                if cursor.rowcount == 1:
                    claimed_row = connection.execute(
                        "SELECT * FROM signing_jobs WHERE id = ?", (candidate["id"],)
                    ).fetchone()
                    break
        return None if claimed_row is None else _signing_job_from_row(claimed_row)

    def heartbeat(
        self,
        job_id: str,
        *,
        worker_id: str,
        now: datetime | None = None,
        lease_for: timedelta = DEFAULT_LEASE_DURATION,
    ) -> SigningJob:
        """Extend an owned lease while its provider operation is still running.

        A cancellation request is deliberately *not* a reason to stop extending
        the lease.  Provider calls generally cannot be interrupted after they
        have started, so the current worker must retain exclusive ownership
        until the call returns and it can discard the result cooperatively.
        """

        _positive_duration(lease_for, "lease duration")
        current = _as_utc(now or datetime.now(timezone.utc))
        with self.database.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE signing_jobs
                SET lease_expires_at = ?, updated_at = ?
                WHERE id = ? AND status = ? AND lease_owner = ?
                  AND lease_expires_at > ?
                """,
                (
                    _dump_dt(current + lease_for),
                    _dump_dt(current),
                    job_id,
                    SigningJobStatus.RUNNING.value,
                    worker_id,
                    _dump_dt(current),
                ),
            )
            if cursor.rowcount == 0:
                self._raise_lease_or_unknown(connection, job_id, worker_id, current)
        return self.get(job_id)

    def succeed(
        self,
        job_id: str,
        *,
        worker_id: str,
        result: Mapping[str, Any] | None = None,
        now: datetime | None = None,
    ) -> SigningJob:
        current = _as_utc(now or datetime.now(timezone.utc))
        result_json = None if result is None else _dump_object(result, "job result")
        with self.database.connect() as connection:
            row = self._require_lease(connection, job_id, worker_id, current)
            if row["cancel_requested_at"] is not None:
                self._finish_canceled(connection, job_id, worker_id, current)
            else:
                cursor = connection.execute(
                    """
                    UPDATE signing_jobs
                    SET status = ?, active_deduplication_key = NULL,
                        lease_owner = NULL, lease_expires_at = NULL,
                        result_json = ?, completed_at = ?, updated_at = ?
                    WHERE id = ? AND status = ? AND lease_owner = ?
                      AND lease_expires_at > ? AND cancel_requested_at IS NULL
                    """,
                    (
                        SigningJobStatus.SUCCEEDED.value,
                        result_json,
                        _dump_dt(current),
                        _dump_dt(current),
                        job_id,
                        SigningJobStatus.RUNNING.value,
                        worker_id,
                        _dump_dt(current),
                    ),
                )
                if cursor.rowcount == 0:
                    self._raise_lease_or_unknown(connection, job_id, worker_id, current)
        return self.get(job_id)

    def retry_transient(
        self,
        job_id: str,
        *,
        worker_id: str,
        error_code: str,
        error_message: str,
        now: datetime | None = None,
    ) -> SigningJob:
        current = _as_utc(now or datetime.now(timezone.utc))
        safe_code, safe_message = _safe_error(error_code, error_message)
        with self.database.connect() as connection:
            row = self._require_lease(connection, job_id, worker_id, current)
            if row["cancel_requested_at"] is not None:
                self._finish_canceled(connection, job_id, worker_id, current)
            else:
                deadline = _load_dt(row["retry_window_started_at"]) + RETRY_WINDOW
                if current >= deadline:
                    self._finish_failed(
                        connection,
                        job_id,
                        worker_id,
                        safe_code,
                        safe_message,
                        current,
                    )
                else:
                    attempt_count = int(row["attempt_count"])
                    next_attempt = min(current + retry_delay(attempt_count), deadline)
                    cursor = connection.execute(
                        """
                        UPDATE signing_jobs
                        SET status = ?, next_attempt_at = ?, lease_owner = NULL,
                            lease_expires_at = NULL, last_error_code = ?,
                            last_error_message = ?, updated_at = ?
                        WHERE id = ? AND status = ? AND lease_owner = ?
                          AND lease_expires_at > ? AND cancel_requested_at IS NULL
                        """,
                        (
                            SigningJobStatus.QUEUED.value,
                            _dump_dt(next_attempt),
                            safe_code,
                            safe_message,
                            _dump_dt(current),
                            job_id,
                            SigningJobStatus.RUNNING.value,
                            worker_id,
                            _dump_dt(current),
                        ),
                    )
                    if cursor.rowcount == 0:
                        self._raise_lease_or_unknown(connection, job_id, worker_id, current)
        return self.get(job_id)

    def fail_permanent(
        self,
        job_id: str,
        *,
        worker_id: str,
        error_code: str,
        error_message: str,
        now: datetime | None = None,
    ) -> SigningJob:
        current = _as_utc(now or datetime.now(timezone.utc))
        safe_code, safe_message = _safe_error(error_code, error_message)
        with self.database.connect() as connection:
            row = self._require_lease(connection, job_id, worker_id, current)
            if row["cancel_requested_at"] is not None:
                self._finish_canceled(connection, job_id, worker_id, current)
            else:
                self._finish_failed(
                    connection,
                    job_id,
                    worker_id,
                    safe_code,
                    safe_message,
                    current,
                )
        return self.get(job_id)

    def cancel(self, job_id: str, *, now: datetime | None = None) -> SigningJob:
        """Cancel queued work, or request cancellation from its current worker.

        A running provider call cannot generally be interrupted.  Its lease
        owner will discard the result when acknowledging success/failure; if it
        crashes, queue maintenance finalizes cancellation after lease expiry.
        """

        current = _as_utc(now or datetime.now(timezone.utc))
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM signing_jobs WHERE id = ?", (job_id,)
            ).fetchone()
            if row is None:
                raise UnknownSigningJobError(f"Unknown signing job: {job_id}")
            status = SigningJobStatus(row["status"])
            if status is SigningJobStatus.CANCELED:
                return _signing_job_from_row(row)
            if status in {SigningJobStatus.SUCCEEDED, SigningJobStatus.FAILED}:
                raise InvalidSigningJobTransition(
                    f"Cannot cancel {status.value} signing job: {job_id}"
                )
            if status is SigningJobStatus.QUEUED:
                cursor = connection.execute(
                    """
                    UPDATE signing_jobs
                    SET status = ?, active_deduplication_key = NULL,
                        lease_owner = NULL, lease_expires_at = NULL,
                        cancel_requested_at = ?, completed_at = ?, updated_at = ?
                    WHERE id = ? AND status = ?
                    """,
                    (
                        SigningJobStatus.CANCELED.value,
                        _dump_dt(current),
                        _dump_dt(current),
                        _dump_dt(current),
                        job_id,
                        SigningJobStatus.QUEUED.value,
                    ),
                )
                # A worker may have claimed the row after our SELECT. Never
                # rewrite that RUNNING row to CANCELED while its provider call
                # can still have a side effect; request cooperative cancel.
                if cursor.rowcount == 0:
                    connection.execute(
                        """
                        UPDATE signing_jobs
                        SET cancel_requested_at = ?, updated_at = ?
                        WHERE id = ? AND status = ?
                        """,
                        (
                            _dump_dt(current),
                            _dump_dt(current),
                            job_id,
                            SigningJobStatus.RUNNING.value,
                        ),
                    )
            else:
                connection.execute(
                    """
                    UPDATE signing_jobs
                    SET cancel_requested_at = ?, updated_at = ?
                    WHERE id = ? AND status = ?
                    """,
                    (
                        _dump_dt(current),
                        _dump_dt(current),
                        job_id,
                        SigningJobStatus.RUNNING.value,
                    ),
                )
        return self.get(job_id)

    def retry_failed(self, job_id: str, *, now: datetime | None = None) -> SigningJob:
        """Start a fresh 24-hour retry window for a failed job."""

        current = _as_utc(now or datetime.now(timezone.utc))
        try:
            with self.database.connect() as connection:
                row = connection.execute(
                    "SELECT * FROM signing_jobs WHERE id = ?", (job_id,)
                ).fetchone()
                if row is None:
                    raise UnknownSigningJobError(f"Unknown signing job: {job_id}")
                if SigningJobStatus(row["status"]) is not SigningJobStatus.FAILED:
                    raise InvalidSigningJobTransition(
                        f"Only a failed signing job can be retried: {job_id}"
                    )
                key_row = connection.execute(
                    "SELECT status FROM cloud_keys WHERE id = ?",
                    (row["cloud_key_id"],),
                ).fetchone()
                if (
                    key_row is None
                    or CloudKeyStatus(key_row["status"]) is not CloudKeyStatus.ACTIVE
                ):
                    raise InvalidSigningJobTransition(
                        f"Cannot retry with an inactive cloud key: {job_id}"
                    )
                connection.execute(
                    """
                    UPDATE signing_jobs
                    SET status = ?, active_deduplication_key = deduplication_key,
                        attempt_count = 0, retry_window_started_at = ?,
                        next_attempt_at = ?, lease_owner = NULL,
                        lease_expires_at = NULL, cancel_requested_at = NULL,
                        last_error_code = NULL, last_error_message = NULL,
                        result_json = NULL, completed_at = NULL, updated_at = ?
                    WHERE id = ? AND status = ?
                    """,
                    (
                        SigningJobStatus.QUEUED.value,
                        _dump_dt(current),
                        _dump_dt(current),
                        _dump_dt(current),
                        job_id,
                        SigningJobStatus.FAILED.value,
                    ),
                )
        except IntegrityError as exc:
            failed = self.get(job_id)
            active = self._find_active_by_digest(failed.deduplication_key)
            if active is not None:
                raise DuplicateActiveSigningJob(active.id) from exc
            raise CloudRepositoryError(f"Could not retry signing job: {job_id}") from exc
        return self.get(job_id)

    def maintain(self, *, now: datetime | None = None) -> int:
        """Finalize expired cancellation requests and 24-hour retry windows."""

        current = _as_utc(now or datetime.now(timezone.utc))
        with self.database.connect() as connection:
            canceled = self._finish_expired_cancellations(connection, current)
            failed = self._expire_retry_windows(connection, current)
        return canceled + failed

    def _find_active_by_digest(self, digest: str) -> SigningJob | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM signing_jobs WHERE active_deduplication_key = ?",
                (digest,),
            ).fetchone()
        return None if row is None else _signing_job_from_row(row)

    def _cloud_key_exists(self, key_id: str) -> bool:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM cloud_keys WHERE id = ?", (key_id,)
            ).fetchone()
        return row is not None

    def _require_lease(self, connection, job_id: str, worker_id: str, now: datetime):
        row = connection.execute(
            "SELECT * FROM signing_jobs WHERE id = ?", (job_id,)
        ).fetchone()
        if row is None:
            raise UnknownSigningJobError(f"Unknown signing job: {job_id}")
        if (
            SigningJobStatus(row["status"]) is not SigningJobStatus.RUNNING
            or row["lease_owner"] != worker_id
            or row["lease_expires_at"] is None
            or _load_dt(row["lease_expires_at"]) <= now
        ):
            raise SigningJobLeaseLost(
                f"Worker {worker_id!r} does not hold an active lease for job {job_id}"
            )
        return row

    def _raise_lease_or_unknown(
        self, connection, job_id: str, worker_id: str, now: datetime
    ) -> None:
        self._require_lease(connection, job_id, worker_id, now)
        raise SigningJobLeaseLost(
            f"Lease for signing job {job_id} changed concurrently"
        )

    def _finish_failed(
        self,
        connection,
        job_id: str,
        worker_id: str,
        error_code: str,
        error_message: str,
        now: datetime,
    ) -> None:
        cursor = connection.execute(
            """
            UPDATE signing_jobs
            SET status = ?, active_deduplication_key = NULL,
                lease_owner = NULL, lease_expires_at = NULL,
                last_error_code = ?, last_error_message = ?,
                completed_at = ?, updated_at = ?
            WHERE id = ? AND status = ? AND lease_owner = ?
              AND lease_expires_at > ? AND cancel_requested_at IS NULL
            """,
            (
                SigningJobStatus.FAILED.value,
                error_code,
                error_message,
                _dump_dt(now),
                _dump_dt(now),
                job_id,
                SigningJobStatus.RUNNING.value,
                worker_id,
                _dump_dt(now),
            ),
        )
        if cursor.rowcount == 0:
            self._raise_lease_or_unknown(connection, job_id, worker_id, now)

    def _finish_canceled(
        self, connection, job_id: str, worker_id: str, now: datetime
    ) -> None:
        cursor = connection.execute(
            """
            UPDATE signing_jobs
            SET status = ?, active_deduplication_key = NULL,
                lease_owner = NULL, lease_expires_at = NULL,
                completed_at = ?, updated_at = ?
            WHERE id = ? AND status = ? AND lease_owner = ?
              AND lease_expires_at > ? AND cancel_requested_at IS NOT NULL
            """,
            (
                SigningJobStatus.CANCELED.value,
                _dump_dt(now),
                _dump_dt(now),
                job_id,
                SigningJobStatus.RUNNING.value,
                worker_id,
                _dump_dt(now),
            ),
        )
        if cursor.rowcount == 0:
            self._raise_lease_or_unknown(connection, job_id, worker_id, now)

    @staticmethod
    def _finish_expired_cancellations(connection, now: datetime) -> int:
        cursor = connection.execute(
            """
            UPDATE signing_jobs
            SET status = ?, active_deduplication_key = NULL,
                lease_owner = NULL, lease_expires_at = NULL,
                completed_at = ?, updated_at = ?
            WHERE status = ? AND cancel_requested_at IS NOT NULL
              AND lease_expires_at <= ?
            """,
            (
                SigningJobStatus.CANCELED.value,
                _dump_dt(now),
                _dump_dt(now),
                SigningJobStatus.RUNNING.value,
                _dump_dt(now),
            ),
        )
        return cursor.rowcount

    @staticmethod
    def _expire_retry_windows(connection, now: datetime) -> int:
        cutoff = now - RETRY_WINDOW
        cursor = connection.execute(
            """
            UPDATE signing_jobs
            SET status = ?, active_deduplication_key = NULL,
                lease_owner = NULL, lease_expires_at = NULL,
                last_error_code = ?, last_error_message = ?,
                completed_at = ?, updated_at = ?
            WHERE retry_window_started_at <= ?
              AND (
                status = ?
                OR (status = ? AND lease_expires_at <= ?)
              )
            """,
            (
                SigningJobStatus.FAILED.value,
                "retry_window_expired",
                "Signing did not succeed within the 24-hour retry window.",
                _dump_dt(now),
                _dump_dt(now),
                _dump_dt(cutoff),
                SigningJobStatus.QUEUED.value,
                SigningJobStatus.RUNNING.value,
                _dump_dt(now),
            ),
        )
        return cursor.rowcount


def retry_delay(attempt_count: int) -> timedelta:
    """Delay after an attempt: 30 s, 2 min, 5 min, then 15 min."""

    if attempt_count < 1:
        raise ValueError("attempt_count must be at least 1")
    return RETRY_DELAYS[min(attempt_count - 1, len(RETRY_DELAYS) - 1)]


def _cloud_key_from_row(row) -> CloudKey:
    return CloudKey(
        id=row["id"],
        provider=row["provider"],
        key_ref=row["key_ref"],
        label=row["label"],
        algorithm=row["algorithm"],
        protection=row["protection"],
        purpose=row["purpose"],
        ownership=CloudKeyOwnership(row["ownership"]),
        status=CloudKeyStatus(row["status"]),
        created_at=_load_dt(row["created_at"]),
        updated_at=_load_dt(row["updated_at"]),
    )


def _signing_job_from_row(row) -> SigningJob:
    return SigningJob(
        id=row["id"],
        cloud_key_id=row["cloud_key_id"],
        operation=row["operation"],
        resource_type=row["resource_type"],
        resource_id=row["resource_id"],
        payload=_load_object(row["payload_json"], "job payload"),
        status=SigningJobStatus(row["status"]),
        deduplication_key=row["deduplication_key"],
        attempt_count=int(row["attempt_count"]),
        retry_window_started_at=_load_dt(row["retry_window_started_at"]),
        next_attempt_at=_load_dt(row["next_attempt_at"]),
        lease_owner=row["lease_owner"],
        lease_expires_at=_load_optional_dt(row["lease_expires_at"]),
        cancel_requested_at=_load_optional_dt(row["cancel_requested_at"]),
        last_error_code=row["last_error_code"],
        last_error_message=row["last_error_message"],
        result=(
            None
            if row["result_json"] is None
            else _load_object(row["result_json"], "job result")
        ),
        created_at=_load_dt(row["created_at"]),
        updated_at=_load_dt(row["updated_at"]),
        completed_at=_load_optional_dt(row["completed_at"]),
    )


def _dedup_digest(cloud_key_id: str, operation: str, caller_key: str) -> str:
    encoded = json.dumps(
        [cloud_key_id, operation, caller_key],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _key_ref_digest(key_ref: str) -> str:
    """Return the portable indexed identity for an untruncated provider ref."""

    return hashlib.sha256(key_ref.encode("utf-8")).hexdigest()


def _dump_object(value: Mapping[str, Any], label: str) -> str:
    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must be a mapping")
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    except (TypeError, ValueError) as exc:
        raise CloudRepositoryError(f"{label} is not JSON serializable") from exc


def _load_object(value: str, label: str) -> Mapping[str, Any]:
    try:
        loaded = json.loads(value)
    except (TypeError, ValueError) as exc:  # pragma: no cover - corrupted database
        raise CloudRepositoryError(f"Stored {label} is not valid JSON") from exc
    if not isinstance(loaded, dict):  # pragma: no cover - repository always writes objects
        raise CloudRepositoryError(f"Stored {label} is not a JSON object")
    return loaded


def _safe_error(code: str, message: str) -> tuple[str, str]:
    clean_code = _required(code, "error code")[:191]
    clean_message = str(message).strip() or "Cloud signing operation failed."
    return clean_code, clean_message[:_MAX_ERROR_MESSAGE_LENGTH]


def _required(value: str, label: str) -> str:
    clean = str(value).strip()
    if not clean:
        raise ValueError(f"{label} must not be empty")
    return clean


def _positive_duration(value: timedelta, label: str) -> None:
    if value <= timedelta(0):
        raise ValueError(f"{label} must be positive")


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _dump_dt(value: datetime) -> str:
    return _as_utc(value).isoformat()


def _load_dt(value: str | datetime) -> datetime:
    loaded = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
    return _as_utc(loaded)


def _load_optional_dt(value: str | datetime | None) -> datetime | None:
    return None if value is None else _load_dt(value)
