from __future__ import annotations

import hashlib
import hmac
import json
import threading
from datetime import datetime, timezone

from myownca.audit.base import (
    SEVERITY_INFO,
    SEVERITY_NOTICE,
    SEVERITY_WARNING,
    AuditActor,
    AuditCategory,
    AuditEvent,
    AuditOutcome,
)
from myownca.audit.repository import AuditRepository
from myownca.audit.syslog import forwarder_from_config

_SEVERITY_BY_OUTCOME = {
    AuditOutcome.SUCCESS: SEVERITY_NOTICE,
    AuditOutcome.FAILURE: SEVERITY_WARNING,
    AuditOutcome.DENIED: SEVERITY_WARNING,
}


class AuditService:
    """Central, tamper-evident audit log with optional remote syslog forwarding.

    ``record`` is serialized by a process-level lock so the hash chain stays
    consistent. Syslog delivery is best-effort and never affects the caller.
    """

    def __init__(self, repository: AuditRepository, encryption_secret: str) -> None:
        self.repository = repository
        self._pepper = hashlib.sha256(f"audit:{encryption_secret}".encode()).digest()
        self._lock = threading.RLock()

    def record(
        self,
        category: AuditCategory,
        action: str,
        *,
        actor: AuditActor | None = None,
        outcome: AuditOutcome = AuditOutcome.SUCCESS,
        object_type: str | None = None,
        object_id: str | None = None,
        details: dict[str, object] | None = None,
        now: datetime | None = None,
    ) -> AuditEvent:
        actor = actor or AuditActor.system()
        occurred_at = now or datetime.now(timezone.utc)
        with self._lock:
            event = self.repository.append(
                occurred_at=occurred_at,
                category=category,
                action=action,
                outcome=outcome,
                actor_id=actor.id,
                actor_email=actor.email,
                actor_role=actor.role,
                source_ip=actor.source_ip,
                object_type=object_type,
                object_id=object_id,
                details=details or {},
                hasher=self._hash,
            )
            self._forward(event)
        return event

    def list_events(
        self,
        *,
        category: str | None = None,
        actor_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEvent]:
        return self.repository.list_events(
            category=category, actor_id=actor_id, limit=limit, offset=offset
        )

    def verify_chain(self) -> dict[str, object]:
        ok, bad = self.repository.verify_chain(self._hash)
        return {"ok": ok, "first_bad_sequence": bad}

    # -- syslog config --------------------------------------------------------

    def get_syslog_config(self) -> dict[str, object]:
        return self.repository.get_syslog_config()

    def set_syslog_config(
        self, *, enabled: bool, host: str, port: int, protocol: str, facility: int
    ) -> dict[str, object]:
        if protocol not in {"udp", "tcp", "tls"}:
            raise ValueError("protocol must be one of udp, tcp, tls")
        if enabled and not host:
            raise ValueError("host is required when syslog is enabled")
        self.repository.set_syslog_config(
            enabled=enabled, host=host, port=port, protocol=protocol, facility=facility
        )
        return self.repository.get_syslog_config()

    # -- internals ------------------------------------------------------------

    def _hash(self, payload: str) -> str:
        return hmac.new(self._pepper, payload.encode(), hashlib.sha256).hexdigest()

    def _forward(self, event: AuditEvent) -> None:
        try:
            forwarder = forwarder_from_config(self.repository.get_syslog_config())
            if forwarder is None:
                return
            severity = _SEVERITY_BY_OUTCOME.get(event.outcome, SEVERITY_INFO)
            message = json.dumps(event.to_dict(), default=str)
            forwarder.emit(
                severity,
                f"{event.category.value}.{event.action}",
                message,
                occurred_at=event.occurred_at,
            )
        except Exception:  # noqa: BLE001 - forwarding must never break auditing
            return
