from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone

from myownca.key_lifecycle.base import (
    CleanupHandler,
    CleanupOutcome,
    KeyCleanupError,
    KeyOwnership,
    RegisteredKey,
)
from myownca.key_lifecycle.repository import KeyLifecycleRepository


DEFAULT_STALE_CLEANUP_AFTER = timedelta(minutes=15)
_UNEXPECTED_CLEANUP_ERROR = "The backend cleanup operation failed unexpectedly."


class KeyLifecycleService:
    """Application boundary for key adoption, bindings, and due cleanup.

    Destructive provider operations are supplied by the composition root.  A
    managed key uses the backend's deleter, while an attached key uses its
    detacher.  Every handler must be idempotent because a crashed worker can be
    retried after its claim expires.
    """

    def __init__(
        self,
        repository: KeyLifecycleRepository,
        *,
        deleters: Mapping[str, CleanupHandler] | None = None,
        detachers: Mapping[str, CleanupHandler] | None = None,
        purpose_deleters: Mapping[tuple[str, str], CleanupHandler] | None = None,
        purpose_detachers: Mapping[tuple[str, str], CleanupHandler] | None = None,
        clock: Callable[[], datetime] | None = None,
        stale_cleanup_after: timedelta = DEFAULT_STALE_CLEANUP_AFTER,
    ) -> None:
        if stale_cleanup_after <= timedelta(0):
            raise ValueError("stale cleanup duration must be positive")
        self.repository = repository
        self.deleters = dict(deleters or {})
        self.detachers = dict(detachers or {})
        # Some logical stores share a provider name while keeping material in
        # different locations.  Service-certificate software keys, for
        # example, live in ServiceKeyStore rather than the CA SoftwareHSM.
        # Purpose-specific handlers keep those destructive boundaries apart
        # without rewriting existing registry backend identifiers.
        self.purpose_deleters = dict(purpose_deleters or {})
        self.purpose_detachers = dict(purpose_detachers or {})
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.stale_cleanup_after = stale_cleanup_after

    def register_key(
        self,
        *,
        backend: str,
        key_ref: str,
        purpose: str,
        ownership: KeyOwnership,
        key_id: str | None = None,
        public_key_sha256: str | None = None,
        now: datetime | None = None,
    ) -> RegisteredKey:
        return self.repository.register(
            backend=backend,
            key_ref=key_ref,
            purpose=purpose,
            ownership=ownership,
            key_id=key_id,
            public_key_sha256=public_key_sha256,
            now=now or self.clock(),
        )

    def record_public_key_fingerprint(
        self,
        key_id: str,
        public_key_sha256: str,
        *,
        now: datetime | None = None,
    ) -> RegisteredKey:
        return self.repository.set_public_key_fingerprint(
            key_id,
            public_key_sha256,
            now=now or self.clock(),
        )

    def bind_key(
        self,
        key_id: str,
        *,
        resource_type: str,
        resource_id: str,
        now: datetime | None = None,
    ) -> RegisteredKey:
        return self.repository.bind(
            key_id,
            resource_type=resource_type,
            resource_id=resource_id,
            now=now or self.clock(),
        )

    def unbind_key(
        self,
        key_id: str,
        *,
        resource_type: str,
        resource_id: str,
        now: datetime | None = None,
    ) -> RegisteredKey:
        return self.repository.unbind(
            key_id,
            resource_type=resource_type,
            resource_id=resource_id,
            now=now or self.clock(),
        )

    def orphan_key(
        self, key_id: str, *, now: datetime | None = None
    ) -> RegisteredKey:
        return self.repository.mark_orphaned(key_id, now=now or self.clock())

    def complete_initial_setup_reset(
        self,
        key_id: str,
        *,
        now: datetime | None = None,
    ) -> RegisteredKey:
        return self.repository.complete_initial_setup_reset(
            key_id,
            now=now or self.clock(),
        )

    def reactivate_initial_setup_key(
        self,
        key_id: str,
        *,
        purpose: str,
        ownership: KeyOwnership,
        now: datetime | None = None,
    ) -> RegisteredKey:
        return self.repository.reactivate_initial_setup_key(
            key_id,
            purpose=purpose,
            ownership=ownership,
            now=now or self.clock(),
        )

    def preview_due(
        self, *, now: datetime | None = None, limit: int = 100
    ) -> list[RegisteredKey]:
        return self.repository.list_due(now=now or self.clock(), limit=limit)

    def cleanup_due(
        self, *, now: datetime | None = None, limit: int = 100
    ) -> list[CleanupOutcome]:
        """Claim and process each currently-due key at most once in this run."""

        current = now or self.clock()
        self.repository.recover_stale_cleanups(
            stale_before=current - self.stale_cleanup_after,
            now=current,
        )
        due = self.repository.list_due(now=current, limit=limit)
        outcomes: list[CleanupOutcome] = []
        for candidate in due:
            claim = self.repository.claim_cleanup(candidate.id, now=current)
            if claim is None:
                # Another worker won the compare-and-set claim, or a binding was
                # added after the due snapshot was read.
                continue
            handler = self._handler_for(claim.key)
            if handler is None:
                error = f"No {claim.key.ownership.value} cleanup handler is configured for backend {claim.key.backend}."
                failed = self.repository.fail_cleanup(
                    claim.key.id,
                    token=claim.token,
                    error=error,
                    now=current,
                )
                outcomes.append(_outcome(failed))
                continue
            try:
                handler(claim.key)
            except KeyCleanupError as exc:
                failed = self.repository.fail_cleanup(
                    claim.key.id,
                    token=claim.token,
                    error=exc.safe_message,
                    now=current,
                )
                outcomes.append(_outcome(failed))
            except Exception:  # noqa: BLE001 - provider details must not reach persistence
                failed = self.repository.fail_cleanup(
                    claim.key.id,
                    token=claim.token,
                    error=_UNEXPECTED_CLEANUP_ERROR,
                    now=current,
                )
                outcomes.append(_outcome(failed))
            else:
                completed = self.repository.complete_cleanup(
                    claim.key.id,
                    token=claim.token,
                    now=current,
                )
                outcomes.append(_outcome(completed))
        return outcomes

    # Naming used by scheduler-style integrations.
    run_due = cleanup_due

    def _handler_for(self, key: RegisteredKey) -> CleanupHandler | None:
        if key.ownership is KeyOwnership.MANAGED:
            specific = self.purpose_deleters
            handlers = self.deleters
        else:
            specific = self.purpose_detachers
            handlers = self.detachers
        return specific.get((key.backend, key.purpose)) or handlers.get(key.backend)


def _outcome(key: RegisteredKey) -> CleanupOutcome:
    return CleanupOutcome(
        key_id=key.id,
        backend=key.backend,
        ownership=key.ownership,
        status=key.status,
        error=key.last_error,
    )
