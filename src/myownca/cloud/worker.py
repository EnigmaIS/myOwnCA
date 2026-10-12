from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from threading import Event, Thread
from typing import Any, Callable, Mapping, Protocol
from uuid import uuid4

from myownca.cloud.base import (
    PermanentSigningError,
    SigningJob,
    SigningJobLeaseLost,
    TransientSigningError,
)
from myownca.cloud.repository import DEFAULT_LEASE_DURATION, SigningJobRepository


logger = logging.getLogger(__name__)


class SigningJobHandler(Protocol):
    """Perform one provider operation and return a JSON-serializable result."""

    def __call__(self, job: SigningJob) -> Mapping[str, Any] | None: ...


class SigningJobTerminalCallback(Protocol):
    def __call__(self, job: SigningJob) -> None: ...


class _LeaseHeartbeat:
    """Keep a claimed job leased until its synchronous handler has returned."""

    def __init__(
        self,
        repository: SigningJobRepository,
        *,
        job_id: str,
        worker_id: str,
        lease_for: timedelta,
        interval: timedelta,
        clock: Callable[[], datetime],
    ) -> None:
        self.repository = repository
        self.job_id = job_id
        self.worker_id = worker_id
        self.lease_for = lease_for
        self.interval_seconds = interval.total_seconds()
        self.clock = clock
        self.lease_lost: SigningJobLeaseLost | None = None
        self.last_error: Exception | None = None
        self._stop = Event()
        self._thread = Thread(
            target=self._run,
            name=f"cloud-signing-heartbeat-{worker_id}",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        # Joining without a timeout is intentional: no acknowledgement may race
        # an in-flight heartbeat update against the terminal queue transition.
        self._thread.join()

    def _run(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            try:
                self.repository.heartbeat(
                    self.job_id,
                    worker_id=self.worker_id,
                    now=self.clock(),
                    lease_for=self.lease_for,
                )
                self.last_error = None
            except SigningJobLeaseLost as exc:
                self.lease_lost = exc
                return
            except Exception as exc:  # noqa: BLE001 - retry a transient DB heartbeat fault
                # A short persistence fault should not stop future heartbeats.
                # The guarded acknowledgement remains the final ownership check.
                self.last_error = exc


class CloudSigningWorker:
    """Small synchronous worker suitable for a scheduler or dedicated thread.

    Provider adapters classify expected failures by raising
    :class:`TransientSigningError` or :class:`PermanentSigningError`. Unknown
    exceptions are treated as transient, but their text is deliberately not
    persisted because it may contain credentials or provider response data.
    """

    def __init__(
        self,
        repository: SigningJobRepository,
        handler: SigningJobHandler,
        *,
        worker_id: str | None = None,
        lease_for: timedelta = DEFAULT_LEASE_DURATION,
        heartbeat_interval: timedelta | None = None,
        operations: tuple[str, ...] | None = None,
        on_terminal: SigningJobTerminalCallback | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if lease_for <= timedelta(0):
            raise ValueError("lease duration must be positive")
        effective_heartbeat_interval = (
            heartbeat_interval
            if heartbeat_interval is not None
            else lease_for / 3
        )
        if effective_heartbeat_interval <= timedelta(0):
            raise ValueError("heartbeat interval must be positive")
        if effective_heartbeat_interval >= lease_for:
            raise ValueError("heartbeat interval must be shorter than the lease")
        self.repository = repository
        self.handler = handler
        self.worker_id = worker_id or f"cloud-signing-{uuid4()}"
        self.lease_for = lease_for
        self.heartbeat_interval = effective_heartbeat_interval
        self.operations = operations
        self.on_terminal = on_terminal
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def run_once(self, *, now: datetime | None = None) -> SigningJob | None:
        claim_time = now or self.clock()
        job = self.repository.claim_next(
            worker_id=self.worker_id,
            now=claim_time,
            lease_for=self.lease_for,
            operations=self.operations,
        )
        if job is None:
            return None

        heartbeat = _LeaseHeartbeat(
            self.repository,
            job_id=job.id,
            worker_id=self.worker_id,
            lease_for=self.lease_for,
            interval=self.heartbeat_interval,
            clock=self.clock,
        )
        result: Mapping[str, Any] | None = None
        handler_error: Exception | None = None
        heartbeat.start()
        try:
            result = self.handler(job)
            if result is not None and not isinstance(result, Mapping):
                raise PermanentSigningError(
                    "invalid_handler_result",
                    "The signing handler returned an invalid result.",
                )
        except Exception as exc:  # noqa: BLE001 - classified after heartbeat shutdown
            handler_error = exc
        finally:
            heartbeat.stop()

        # If ownership was already lost, acknowledging with stale ownership
        # would be unsafe even if the provider operation itself succeeded.
        if heartbeat.lease_lost is not None:
            raise heartbeat.lease_lost

        if isinstance(handler_error, TransientSigningError):
            completed = self.repository.retry_transient(
                job.id,
                worker_id=self.worker_id,
                error_code=handler_error.code,
                error_message=handler_error.safe_message,
                now=now or self.clock(),
            )
        elif isinstance(handler_error, PermanentSigningError):
            completed = self.repository.fail_permanent(
                job.id,
                worker_id=self.worker_id,
                error_code=handler_error.code,
                error_message=handler_error.safe_message,
                now=now or self.clock(),
            )
        elif handler_error is not None:
            completed = self.repository.retry_transient(
                job.id,
                worker_id=self.worker_id,
                error_code="unexpected_handler_error",
                error_message="The cloud signing handler failed unexpectedly.",
                now=now or self.clock(),
            )
        else:
            completed = self.repository.succeed(
                job.id,
                worker_id=self.worker_id,
                result=result,
                now=now or self.clock(),
            )
        if completed.terminal and self.on_terminal is not None:
            try:
                self.on_terminal(completed)
            except Exception:  # noqa: BLE001 - the queue transition is already durable
                logger.exception(
                    "Cloud signing terminal callback failed for job %s",
                    completed.id,
                )
        return completed

    def run_available(
        self,
        *,
        max_jobs: int = 100,
        now: datetime | None = None,
    ) -> list[SigningJob]:
        """Process ready jobs until the queue is idle or ``max_jobs`` is reached."""

        if max_jobs < 1:
            raise ValueError("max_jobs must be positive")
        processed: list[SigningJob] = []
        while len(processed) < max_jobs:
            job = self.run_once(now=now)
            if job is None:
                break
            processed.append(job)
        return processed
