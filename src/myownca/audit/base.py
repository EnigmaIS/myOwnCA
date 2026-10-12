from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

GENESIS_HASH = "0" * 64
AUDIT_HASH_VERSION = 2


class AuditCategory(StrEnum):
    AUTH = "auth"
    USER = "user"
    PERMISSION = "permission"
    CERTIFICATE = "certificate"
    ISSUER = "issuer"
    HSM = "hsm"
    SERVICE_CERT = "service_cert"
    COMMS = "comms"
    AUDIT = "audit"
    API = "api"
    SYSTEM = "system"


class AuditOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


# Syslog severities (RFC 5424) chosen per outcome.
SEVERITY_NOTICE = 5
SEVERITY_WARNING = 4
SEVERITY_INFO = 6


@dataclass(frozen=True, slots=True)
class AuditActor:
    id: str | None = None
    email: str | None = None
    role: str | None = None
    source_ip: str | None = None

    @classmethod
    def system(cls) -> "AuditActor":
        return cls(id="system", email=None, role="system")


@dataclass(frozen=True, slots=True)
class AuditEvent:
    id: str
    sequence: int
    occurred_at: datetime
    category: AuditCategory
    action: str
    outcome: AuditOutcome
    prev_hash: str
    record_hash: str
    actor_id: str | None = None
    actor_email: str | None = None
    actor_role: str | None = None
    source_ip: str | None = None
    object_type: str | None = None
    object_id: str | None = None
    details: dict[str, object] = field(default_factory=dict)
    hash_version: int = AUDIT_HASH_VERSION

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "sequence": self.sequence,
            "occurred_at": self.occurred_at.isoformat(),
            "category": self.category.value,
            "action": self.action,
            "outcome": self.outcome.value,
            "actor_id": self.actor_id,
            "actor_email": self.actor_email,
            "actor_role": self.actor_role,
            "source_ip": self.source_ip,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "details": self.details,
            "record_hash": self.record_hash,
            "hash_version": self.hash_version,
        }
