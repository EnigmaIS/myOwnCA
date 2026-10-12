from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Mapping


class CloudKeyOwnership(StrEnum):
    MANAGED = "managed"
    ATTACHED = "attached"


class CloudKeyStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"
    PENDING_DELETION = "pending_deletion"
    DELETED = "deleted"
    UNAVAILABLE = "unavailable"


class SigningJobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELED = "canceled"


TERMINAL_SIGNING_JOB_STATUSES = frozenset(
    {
        SigningJobStatus.SUCCEEDED,
        SigningJobStatus.FAILED,
        SigningJobStatus.CANCELED,
    }
)


@dataclass(frozen=True, slots=True)
class CloudKey:
    """Non-secret metadata for a remotely held signing key.

    ``key_ref`` is expected to be the provider's canonical, version-pinned
    reference.  Credentials and other provider secrets never belong here.
    """

    id: str
    provider: str
    key_ref: str
    label: str
    algorithm: str
    protection: str | None
    purpose: str
    ownership: CloudKeyOwnership
    status: CloudKeyStatus
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class SigningJob:
    """A durable request to perform one operation with a cloud key.

    Payloads must contain operation input only, never cloud credentials.  The
    deduplication key is stored as a digest and is therefore safe to expose in
    operational views without leaking a domain identifier chosen by a caller.
    """

    id: str
    cloud_key_id: str
    operation: str
    resource_type: str
    resource_id: str
    payload: Mapping[str, Any]
    status: SigningJobStatus
    deduplication_key: str
    attempt_count: int
    retry_window_started_at: datetime
    next_attempt_at: datetime
    created_at: datetime
    updated_at: datetime
    lease_owner: str | None = None
    lease_expires_at: datetime | None = None
    cancel_requested_at: datetime | None = None
    last_error_code: str | None = None
    last_error_message: str | None = None
    result: Mapping[str, Any] | None = None
    completed_at: datetime | None = None

    @property
    def terminal(self) -> bool:
        return self.status in TERMINAL_SIGNING_JOB_STATUSES

    @property
    def cancel_requested(self) -> bool:
        return self.cancel_requested_at is not None


@dataclass(frozen=True, slots=True)
class EnqueueResult:
    job: SigningJob
    created: bool


class CloudRepositoryError(RuntimeError):
    """Base class for cloud key and signing queue persistence errors."""


class UnknownCloudKeyError(CloudRepositoryError):
    pass


class UnknownSigningJobError(CloudRepositoryError):
    pass


class InvalidSigningJobTransition(CloudRepositoryError):
    pass


class SigningJobLeaseLost(CloudRepositoryError):
    pass


class DuplicateActiveSigningJob(CloudRepositoryError):
    def __init__(self, existing_job_id: str) -> None:
        self.existing_job_id = existing_job_id
        super().__init__(f"An active signing job already exists: {existing_job_id}")


class SigningOperationError(RuntimeError):
    """A handler error whose code and message are explicitly safe to persist."""

    def __init__(self, code: str, safe_message: str) -> None:
        self.code = code
        self.safe_message = safe_message
        super().__init__(safe_message)


class TransientSigningError(SigningOperationError):
    """A provider or transport failure which should follow the retry policy."""


class PermanentSigningError(SigningOperationError):
    """A failure which cannot succeed without changing the request/configuration."""

