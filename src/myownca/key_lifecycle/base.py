from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Protocol


ORPHAN_GRACE_PERIOD = timedelta(days=30)


class KeyOwnership(StrEnum):
    """Whether myOwnCA may destroy the provider's key material."""

    MANAGED = "managed"
    ATTACHED = "attached"


class KeyStatus(StrEnum):
    ACTIVE = "active"
    ORPHANED = "orphaned"
    DELETING = "deleting"
    DELETED = "deleted"
    DETACHED = "detached"
    ERROR = "error"


TERMINAL_KEY_STATUSES = frozenset({KeyStatus.DELETED, KeyStatus.DETACHED})


@dataclass(frozen=True, slots=True)
class RegisteredKey:
    """Non-secret metadata for a key explicitly adopted by myOwnCA.

    ``key_ref`` is a provider locator, never private key material or a provider
    credential.  Unknown provider keys are intentionally absent from this
    registry until an owning workflow calls ``register``.
    """

    id: str
    backend: str
    key_ref: str
    purpose: str
    ownership: KeyOwnership
    status: KeyStatus
    created_at: datetime
    updated_at: datetime
    orphaned_at: datetime | None = None
    delete_after: datetime | None = None
    cleanup_token: str | None = None
    cleanup_started_at: datetime | None = None
    cleanup_attempts: int = 0
    last_attempt_at: datetime | None = None
    last_error: str | None = None
    public_key_sha256: str | None = None

    @property
    def terminal(self) -> bool:
        return self.status in TERMINAL_KEY_STATUSES


@dataclass(frozen=True, slots=True)
class KeyBinding:
    key_id: str
    resource_type: str
    resource_id: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class CleanupClaim:
    key: RegisteredKey
    token: str


@dataclass(frozen=True, slots=True)
class CleanupOutcome:
    key_id: str
    backend: str
    ownership: KeyOwnership
    status: KeyStatus
    error: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.status in TERMINAL_KEY_STATUSES


class CleanupHandler(Protocol):
    """Idempotently delete or detach one provider key reference."""

    def __call__(self, key: RegisteredKey) -> None: ...


class KeyLifecycleError(RuntimeError):
    pass


class DuplicateKeyReferenceError(KeyLifecycleError):
    pass


class UnknownKeyError(KeyLifecycleError):
    pass


class InvalidKeyStateError(KeyLifecycleError):
    pass


class CleanupClaimLostError(KeyLifecycleError):
    pass


class KeyCleanupError(RuntimeError):
    """A backend failure whose message is explicitly safe to persist."""

    def __init__(self, safe_message: str) -> None:
        if not safe_message or not safe_message.strip():
            raise ValueError("safe cleanup error message is required")
        self.safe_message = safe_message
        super().__init__(safe_message)
