from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime, timezone
from uuid import uuid4

from myownca.audit.base import (
    AUDIT_HASH_VERSION,
    GENESIS_HASH,
    AuditCategory,
    AuditEvent,
    AuditOutcome,
)
from myownca.storage.database import Database

Hasher = Callable[[str], str]


class AuditRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def append(
        self,
        *,
        occurred_at: datetime,
        category: AuditCategory,
        action: str,
        outcome: AuditOutcome,
        actor_id: str | None,
        actor_email: str | None,
        actor_role: str | None,
        source_ip: str | None,
        object_type: str | None,
        object_id: str | None,
        details: dict[str, object],
        hasher: Hasher,
    ) -> AuditEvent:
        """Append a hash-chained record. Callers must serialize via a lock."""
        details_json = json.dumps(details, sort_keys=True, default=str)
        occurred_iso = _dump_dt(occurred_at)
        event_id = str(uuid4())
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT sequence, record_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            sequence = (row["sequence"] + 1) if row else 1
            prev_hash = row["record_hash"] if row else GENESIS_HASH
            payload = _canonical_payload(
                prev_hash,
                sequence,
                occurred_iso,
                category.value,
                action,
                outcome.value,
                actor_id,
                object_type,
                object_id,
                details_json,
                hash_version=AUDIT_HASH_VERSION,
                event_id=event_id,
                actor_email=actor_email,
                actor_role=actor_role,
                source_ip=source_ip,
            )
            record_hash = hasher(payload)
            connection.execute(
                """
                INSERT INTO audit_events(
                    id, sequence, occurred_at, category, action, outcome,
                    actor_id, actor_email, actor_role, source_ip,
                    object_type, object_id, details_json, prev_hash, record_hash, hash_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    sequence,
                    occurred_iso,
                    category.value,
                    action,
                    outcome.value,
                    actor_id,
                    actor_email,
                    actor_role,
                    source_ip,
                    object_type,
                    object_id,
                    details_json,
                    prev_hash,
                    record_hash,
                    AUDIT_HASH_VERSION,
                ),
            )
        return AuditEvent(
            id=event_id,
            sequence=sequence,
            occurred_at=occurred_at,
            category=category,
            action=action,
            outcome=outcome,
            prev_hash=prev_hash,
            record_hash=record_hash,
            actor_id=actor_id,
            actor_email=actor_email,
            actor_role=actor_role,
            source_ip=source_ip,
            object_type=object_type,
            object_id=object_id,
            details=details,
            hash_version=AUDIT_HASH_VERSION,
        )

    def list_events(
        self,
        *,
        category: str | None = None,
        actor_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEvent]:
        clauses: list[str] = []
        params: list[object] = []
        if category:
            clauses.append("category = ?")
            params.append(category)
        if actor_id:
            clauses.append("actor_id = ?")
            params.append(actor_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([max(1, min(limit, 1000)), max(0, offset)])
        with self.database.connect() as connection:
            rows = connection.execute(
                f"SELECT * FROM audit_events {where} ORDER BY sequence DESC LIMIT ? OFFSET ?",
                params,
            ).fetchall()
        return [_event_from_row(row) for row in rows]

    def verify_chain(self, hasher: Hasher) -> tuple[bool, int | None]:
        """Re-walk the chain; return (ok, first_bad_sequence)."""
        prev_hash = GENESIS_HASH
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM audit_events ORDER BY sequence ASC"
            ).fetchall()
        for row in rows:
            version = row.get("hash_version")
            if type(version) is not int or version != AUDIT_HASH_VERSION:
                return False, row["sequence"]
            payload = _canonical_payload(
                prev_hash,
                row["sequence"],
                row["occurred_at"],
                row["category"],
                row["action"],
                row["outcome"],
                row["actor_id"],
                row["object_type"],
                row["object_id"],
                row["details_json"],
                hash_version=version,
                event_id=row["id"],
                actor_email=row["actor_email"],
                actor_role=row["actor_role"],
                source_ip=row["source_ip"],
            )
            if row["prev_hash"] != prev_hash or hasher(payload) != row["record_hash"]:
                return False, row["sequence"]
            prev_hash = row["record_hash"]
        return True, None

    # -- syslog config --------------------------------------------------------

    def get_syslog_config(self) -> dict[str, object]:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM audit_syslog_config WHERE id = 1"
            ).fetchone()
        if row is None:
            return {"enabled": False, "host": "", "port": 514, "protocol": "udp", "facility": 13,
                    "updated_at": None}
        return {
            "enabled": bool(row["enabled"]),
            "host": row["host"],
            "port": row["port"],
            "protocol": row["protocol"],
            "facility": row["facility"],
            "updated_at": row["updated_at"],
        }

    def set_syslog_config(
        self, *, enabled: bool, host: str, port: int, protocol: str, facility: int
    ) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO audit_syslog_config(id, enabled, host, port, protocol, facility, updated_at)
                VALUES (1, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    enabled = excluded.enabled, host = excluded.host, port = excluded.port,
                    protocol = excluded.protocol, facility = excluded.facility,
                    updated_at = excluded.updated_at
                """,
                (int(enabled), host, port, protocol, facility, _dump_dt(datetime.now(timezone.utc))),
            )


def _canonical_payload(
    prev_hash: str,
    sequence: int,
    occurred_iso: str,
    category: str,
    action: str,
    outcome: str,
    actor_id: str | None,
    object_type: str | None,
    object_id: str | None,
    details_json: str,
    *,
    hash_version: int,
    event_id: str,
    actor_email: str | None,
    actor_role: str | None,
    source_ip: str | None,
) -> str:
    """Version 2 authenticates exact stored values with unambiguous framing."""
    return json.dumps(
        {
            "hash_version": hash_version,
            "id": event_id,
            "prev_hash": prev_hash,
            "sequence": sequence,
            "occurred_at": occurred_iso,
            "category": category,
            "action": action,
            "outcome": outcome,
            "actor_id": actor_id,
            "actor_email": actor_email,
            "actor_role": actor_role,
            "source_ip": source_ip,
            "object_type": object_type,
            "object_id": object_id,
            "details_json": details_json,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _event_from_row(row) -> AuditEvent:
    return AuditEvent(
        id=row["id"],
        sequence=row["sequence"],
        occurred_at=_load_dt(row["occurred_at"]),
        category=AuditCategory(row["category"]),
        action=row["action"],
        outcome=AuditOutcome(row["outcome"]),
        prev_hash=row["prev_hash"],
        record_hash=row["record_hash"],
        actor_id=row["actor_id"],
        actor_email=row["actor_email"],
        actor_role=row["actor_role"],
        source_ip=row["source_ip"],
        object_type=row["object_type"],
        object_id=row["object_id"],
        details=json.loads(row["details_json"]),
        hash_version=row["hash_version"],
    )


def _dump_dt(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _load_dt(value: str) -> datetime:
    return datetime.fromisoformat(value)
