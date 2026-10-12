from __future__ import annotations

import hashlib
import hmac
import re
from datetime import datetime, timezone
from uuid import uuid4

from myownca.key_lifecycle.base import (
    ORPHAN_GRACE_PERIOD,
    CleanupClaim,
    CleanupClaimLostError,
    DuplicateKeyReferenceError,
    InvalidKeyStateError,
    KeyBinding,
    KeyOwnership,
    KeyStatus,
    RegisteredKey,
    UnknownKeyError,
)
from myownca.storage.database import Database, IntegrityError


_MAX_ERROR_LENGTH = 2_000
_STALE_CLEANUP_ERROR = "A previous cleanup worker lost its claim before completion."


class KeyLifecycleRepository:
    """Durable metadata and binding state for explicitly registered keys."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def register(
        self,
        *,
        backend: str,
        key_ref: str,
        purpose: str,
        ownership: KeyOwnership,
        now: datetime | None = None,
        key_id: str | None = None,
        public_key_sha256: str | None = None,
    ) -> RegisteredKey:
        backend = _required(backend, "backend")
        key_ref = _required(key_ref, "key reference")
        purpose = _required(purpose, "purpose")
        fingerprint = _public_key_sha256(public_key_sha256)
        if not isinstance(ownership, KeyOwnership):
            raise ValueError("ownership must be a KeyOwnership value")
        current = _as_utc(now or datetime.now(timezone.utc))
        identifier = _required(key_id, "key id") if key_id is not None else str(uuid4())
        try:
            with self.database.connect() as connection:
                connection.execute(
                    """
                    INSERT INTO key_lifecycle_keys(
                        id, backend, key_ref, key_ref_digest, purpose, ownership,
                        status, cleanup_attempts, public_key_sha256, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        identifier,
                        backend,
                        key_ref,
                        _key_ref_digest(key_ref),
                        purpose,
                        ownership.value,
                        KeyStatus.ACTIVE.value,
                        0,
                        fingerprint,
                        _dump_dt(current),
                        _dump_dt(current),
                    ),
                )
        except IntegrityError as exc:
            raise DuplicateKeyReferenceError(
                f"Key id or backend reference is already registered: {identifier}"
            ) from exc
        return self.get(identifier)

    def set_public_key_fingerprint(
        self,
        key_id: str,
        public_key_sha256: str,
        *,
        now: datetime | None = None,
    ) -> RegisteredKey:
        fingerprint = _public_key_sha256(public_key_sha256)
        assert fingerprint is not None
        current = _as_utc(now or datetime.now(timezone.utc))
        with self.database.connect() as connection:
            row = self._require_key(connection, key_id, lock=True)
            existing = row.get("public_key_sha256")
            if existing is not None and not hmac.compare_digest(existing, fingerprint):
                raise InvalidKeyStateError(
                    f"Registered key {key_id} already has a different public-key fingerprint"
                )
            connection.execute(
                """
                UPDATE key_lifecycle_keys
                SET public_key_sha256 = ?, updated_at = ?
                WHERE id = ?
                """,
                (fingerprint, _dump_dt(current), key_id),
            )
        return self.get(key_id)

    def get(self, key_id: str) -> RegisteredKey:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM key_lifecycle_keys WHERE id = ?", (key_id,)
            ).fetchone()
        if row is None:
            raise UnknownKeyError(f"Unknown registered key: {key_id}")
        return _key_from_row(row)

    def find(self, *, backend: str, key_ref: str) -> RegisteredKey | None:
        backend = _required(backend, "backend")
        key_ref = _required(key_ref, "key reference")
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM key_lifecycle_keys
                WHERE backend = ? AND key_ref_digest = ? AND key_ref = ?
                """,
                (backend, _key_ref_digest(key_ref), key_ref),
            ).fetchone()
        return None if row is None else _key_from_row(row)

    def list_all(
        self,
        *,
        backend: str | None = None,
        purpose: str | None = None,
        ownership: KeyOwnership | None = None,
        status: KeyStatus | None = None,
    ) -> list[RegisteredKey]:
        clauses: list[str] = []
        params: list[str] = []
        if backend is not None:
            clauses.append("backend = ?")
            params.append(_required(backend, "backend"))
        if purpose is not None:
            clauses.append("purpose = ?")
            params.append(_required(purpose, "purpose"))
        if ownership is not None:
            clauses.append("ownership = ?")
            params.append(ownership.value)
        if status is not None:
            clauses.append("status = ?")
            params.append(status.value)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self.database.connect() as connection:
            rows = connection.execute(
                f"SELECT * FROM key_lifecycle_keys{where} ORDER BY created_at, id",  # noqa: S608
                params,
            ).fetchall()
        return [_key_from_row(row) for row in rows]

    def list_bindings(self, key_id: str) -> list[KeyBinding]:
        with self.database.connect() as connection:
            self._require_key(connection, key_id)
            rows = connection.execute(
                """
                SELECT * FROM key_lifecycle_bindings
                WHERE key_id = ? ORDER BY created_at, resource_type, resource_id
                """,
                (key_id,),
            ).fetchall()
        return [_binding_from_row(row) for row in rows]

    def list_keys_for_resource(
        self,
        *,
        resource_type: str,
        resource_id: str,
    ) -> list[RegisteredKey]:
        """Return keys already bound to one durable application resource."""

        resource_type = _required(resource_type, "resource type")
        resource_id = _required(resource_id, "resource id")
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT keys.*
                FROM key_lifecycle_keys AS keys
                JOIN key_lifecycle_bindings AS bindings
                  ON bindings.key_id = keys.id
                WHERE bindings.resource_type = ? AND bindings.resource_id = ?
                ORDER BY keys.created_at, keys.id
                """,
                (resource_type, resource_id),
            ).fetchall()
        return [_key_from_row(row) for row in rows]

    def bind(
        self,
        key_id: str,
        *,
        resource_type: str,
        resource_id: str,
        now: datetime | None = None,
    ) -> RegisteredKey:
        """Bind a key and atomically cancel a pending orphan cleanup."""

        resource_type = _required(resource_type, "resource type")
        resource_id = _required(resource_id, "resource id")
        current = _as_utc(now or datetime.now(timezone.utc))
        with self.database.connect() as connection:
            row = self._require_key(connection, key_id, lock=True)
            state = KeyStatus(row["status"])
            if state is KeyStatus.DELETING or state in {KeyStatus.DELETED, KeyStatus.DETACHED}:
                raise InvalidKeyStateError(
                    f"Cannot bind key {key_id} while it is {state.value}"
                )
            existing = connection.execute(
                """
                SELECT 1 FROM key_lifecycle_bindings
                WHERE key_id = ? AND resource_type = ? AND resource_id = ?
                """,
                (key_id, resource_type, resource_id),
            ).fetchone()
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO key_lifecycle_bindings(
                        key_id, resource_type, resource_id, created_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (key_id, resource_type, resource_id, _dump_dt(current)),
                )
            connection.execute(
                """
                UPDATE key_lifecycle_keys
                SET status = ?, orphaned_at = NULL, delete_after = NULL,
                    cleanup_token = NULL, cleanup_started_at = NULL,
                    last_error = NULL, updated_at = ?
                WHERE id = ?
                """,
                (KeyStatus.ACTIVE.value, _dump_dt(current), key_id),
            )
            updated = connection.execute(
                "SELECT * FROM key_lifecycle_keys WHERE id = ?", (key_id,)
            ).fetchone()
        return _key_from_row(updated)

    def unbind(
        self,
        key_id: str,
        *,
        resource_type: str,
        resource_id: str,
        now: datetime | None = None,
    ) -> RegisteredKey:
        """Remove one binding; the final removal starts the fixed 30-day grace."""

        resource_type = _required(resource_type, "resource type")
        resource_id = _required(resource_id, "resource id")
        current = _as_utc(now or datetime.now(timezone.utc))
        with self.database.connect() as connection:
            row = self._require_key(connection, key_id, lock=True)
            binding = connection.execute(
                """
                SELECT 1 FROM key_lifecycle_bindings
                WHERE key_id = ? AND resource_type = ? AND resource_id = ?
                """,
                (key_id, resource_type, resource_id),
            ).fetchone()
            if binding is None:
                return _key_from_row(row)
            state = KeyStatus(row["status"])
            if state is KeyStatus.DELETING or state in {KeyStatus.DELETED, KeyStatus.DETACHED}:
                raise InvalidKeyStateError(
                    f"Cannot unbind key {key_id} while it is {state.value}"
                )
            connection.execute(
                """
                DELETE FROM key_lifecycle_bindings
                WHERE key_id = ? AND resource_type = ? AND resource_id = ?
                """,
                (key_id, resource_type, resource_id),
            )
            remaining = connection.execute(
                "SELECT COUNT(*) AS count FROM key_lifecycle_bindings WHERE key_id = ?",
                (key_id,),
            ).fetchone()["count"]
            if remaining == 0:
                self._schedule_orphan(connection, key_id, current)
            else:
                connection.execute(
                    """
                    UPDATE key_lifecycle_keys
                    SET status = ?, orphaned_at = NULL, delete_after = NULL,
                        cleanup_token = NULL, cleanup_started_at = NULL,
                        last_error = NULL, updated_at = ?
                    WHERE id = ?
                    """,
                    (KeyStatus.ACTIVE.value, _dump_dt(current), key_id),
                )
            updated = connection.execute(
                "SELECT * FROM key_lifecycle_keys WHERE id = ?", (key_id,)
            ).fetchone()
        return _key_from_row(updated)

    def mark_orphaned(
        self, key_id: str, *, now: datetime | None = None
    ) -> RegisteredKey:
        """Schedule an explicitly registered, unbound key after a failed workflow."""

        current = _as_utc(now or datetime.now(timezone.utc))
        with self.database.connect() as connection:
            row = self._require_key(connection, key_id, lock=True)
            binding_count = connection.execute(
                "SELECT COUNT(*) AS count FROM key_lifecycle_bindings WHERE key_id = ?",
                (key_id,),
            ).fetchone()["count"]
            if binding_count:
                raise InvalidKeyStateError(
                    f"Cannot orphan key {key_id} while it still has bindings"
                )
            state = KeyStatus(row["status"])
            if state is KeyStatus.ACTIVE:
                self._schedule_orphan(connection, key_id, current)
            elif state not in {KeyStatus.ORPHANED, KeyStatus.ERROR}:
                raise InvalidKeyStateError(
                    f"Cannot orphan key {key_id} while it is {state.value}"
                )
            updated = connection.execute(
                "SELECT * FROM key_lifecycle_keys WHERE id = ?", (key_id,)
            ).fetchone()
        return _key_from_row(updated)

    def list_due(
        self, *, now: datetime | None = None, limit: int = 100
    ) -> list[RegisteredKey]:
        if limit < 1:
            raise ValueError("limit must be positive")
        current = _as_utc(now or datetime.now(timezone.utc))
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM key_lifecycle_keys
                WHERE status IN (?, ?)
                  AND delete_after IS NOT NULL AND delete_after <= ?
                  AND NOT EXISTS (
                      SELECT 1 FROM key_lifecycle_bindings
                      WHERE key_lifecycle_bindings.key_id = key_lifecycle_keys.id
                  )
                ORDER BY delete_after, created_at, id
                LIMIT ?
                """,
                (
                    KeyStatus.ORPHANED.value,
                    KeyStatus.ERROR.value,
                    _dump_dt(current),
                    limit,
                ),
            ).fetchall()
        return [_key_from_row(row) for row in rows]

    def claim_cleanup(
        self,
        key_id: str,
        *,
        now: datetime | None = None,
        token: str | None = None,
    ) -> CleanupClaim | None:
        current = _as_utc(now or datetime.now(timezone.utc))
        claim_token = _required(token, "cleanup token") if token is not None else str(uuid4())
        with self.database.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE key_lifecycle_keys
                SET status = ?, cleanup_token = ?, cleanup_started_at = ?,
                    cleanup_attempts = cleanup_attempts + 1,
                    last_attempt_at = ?, last_error = NULL, updated_at = ?
                WHERE id = ? AND status IN (?, ?)
                  AND delete_after IS NOT NULL AND delete_after <= ?
                  AND NOT EXISTS (
                      SELECT 1 FROM key_lifecycle_bindings
                      WHERE key_lifecycle_bindings.key_id = key_lifecycle_keys.id
                  )
                """,
                (
                    KeyStatus.DELETING.value,
                    claim_token,
                    _dump_dt(current),
                    _dump_dt(current),
                    _dump_dt(current),
                    key_id,
                    KeyStatus.ORPHANED.value,
                    KeyStatus.ERROR.value,
                    _dump_dt(current),
                ),
            )
            if cursor.rowcount == 0:
                known = connection.execute(
                    "SELECT 1 FROM key_lifecycle_keys WHERE id = ?", (key_id,)
                ).fetchone()
                if known is None:
                    raise UnknownKeyError(f"Unknown registered key: {key_id}")
                return None
            row = connection.execute(
                "SELECT * FROM key_lifecycle_keys WHERE id = ?", (key_id,)
            ).fetchone()
        return CleanupClaim(key=_key_from_row(row), token=claim_token)

    def complete_cleanup(
        self,
        key_id: str,
        *,
        token: str,
        now: datetime | None = None,
    ) -> RegisteredKey:
        current = _as_utc(now or datetime.now(timezone.utc))
        token = _required(token, "cleanup token")
        with self.database.connect() as connection:
            row = self._require_key(connection, key_id, lock=True)
            final_status = (
                KeyStatus.DELETED
                if KeyOwnership(row["ownership"]) is KeyOwnership.MANAGED
                else KeyStatus.DETACHED
            )
            cursor = connection.execute(
                """
                UPDATE key_lifecycle_keys
                SET status = ?, cleanup_token = NULL, cleanup_started_at = NULL,
                    last_error = NULL, updated_at = ?
                WHERE id = ? AND status = ? AND cleanup_token = ?
                """,
                (
                    final_status.value,
                    _dump_dt(current),
                    key_id,
                    KeyStatus.DELETING.value,
                    token,
                ),
            )
            if cursor.rowcount == 0:
                raise CleanupClaimLostError(f"Cleanup claim was lost for key {key_id}")
            updated = connection.execute(
                "SELECT * FROM key_lifecycle_keys WHERE id = ?", (key_id,)
            ).fetchone()
        return _key_from_row(updated)

    def complete_initial_setup_reset(
        self,
        key_id: str,
        *,
        now: datetime | None = None,
    ) -> RegisteredKey:
        """Record immediate key cleanup performed by first-run setup reset."""

        current = _as_utc(now or datetime.now(timezone.utc))
        with self.database.connect() as connection:
            row = self._require_key(connection, key_id, lock=True)
            final_status = (
                KeyStatus.DELETED
                if KeyOwnership(row["ownership"]) is KeyOwnership.MANAGED
                else KeyStatus.DETACHED
            )
            connection.execute(
                "DELETE FROM key_lifecycle_bindings WHERE key_id = ?",
                (key_id,),
            )
            connection.execute(
                """
                UPDATE key_lifecycle_keys
                SET status = ?, orphaned_at = NULL, delete_after = NULL,
                    cleanup_token = NULL, cleanup_started_at = NULL,
                    last_error = NULL, updated_at = ?
                WHERE id = ?
                """,
                (final_status.value, _dump_dt(current), key_id),
            )
            updated = connection.execute(
                "SELECT * FROM key_lifecycle_keys WHERE id = ?", (key_id,)
            ).fetchone()
        return _key_from_row(updated)

    def reactivate_initial_setup_key(
        self,
        key_id: str,
        *,
        purpose: str,
        ownership: KeyOwnership,
        now: datetime | None = None,
    ) -> RegisteredKey:
        """Reuse a provider reference recreated after a first-run setup reset."""

        purpose = _required(purpose, "purpose")
        current = _as_utc(now or datetime.now(timezone.utc))
        with self.database.connect() as connection:
            row = self._require_key(connection, key_id, lock=True)
            if KeyStatus(row["status"]) not in {
                KeyStatus.DELETED,
                KeyStatus.DETACHED,
            }:
                raise InvalidKeyStateError(
                    f"Cannot reactivate key {key_id} while it is {row['status']}"
                )
            connection.execute(
                """
                UPDATE key_lifecycle_keys
                SET purpose = ?, ownership = ?, status = ?,
                    orphaned_at = NULL, delete_after = NULL,
                    cleanup_token = NULL, cleanup_started_at = NULL,
                    cleanup_attempts = 0, last_attempt_at = NULL,
                    last_error = NULL, updated_at = ?
                WHERE id = ?
                """,
                (
                    purpose,
                    ownership.value,
                    KeyStatus.ACTIVE.value,
                    _dump_dt(current),
                    key_id,
                ),
            )
            updated = connection.execute(
                "SELECT * FROM key_lifecycle_keys WHERE id = ?", (key_id,)
            ).fetchone()
        return _key_from_row(updated)

    def fail_cleanup(
        self,
        key_id: str,
        *,
        token: str,
        error: str,
        now: datetime | None = None,
    ) -> RegisteredKey:
        current = _as_utc(now or datetime.now(timezone.utc))
        token = _required(token, "cleanup token")
        safe_error = _required(error, "cleanup error")[:_MAX_ERROR_LENGTH]
        with self.database.connect() as connection:
            self._require_key(connection, key_id)
            cursor = connection.execute(
                """
                UPDATE key_lifecycle_keys
                SET status = ?, cleanup_token = NULL, cleanup_started_at = NULL,
                    last_error = ?, updated_at = ?
                WHERE id = ? AND status = ? AND cleanup_token = ?
                """,
                (
                    KeyStatus.ERROR.value,
                    safe_error,
                    _dump_dt(current),
                    key_id,
                    KeyStatus.DELETING.value,
                    token,
                ),
            )
            if cursor.rowcount == 0:
                raise CleanupClaimLostError(f"Cleanup claim was lost for key {key_id}")
            updated = connection.execute(
                "SELECT * FROM key_lifecycle_keys WHERE id = ?", (key_id,)
            ).fetchone()
        return _key_from_row(updated)

    def recover_stale_cleanups(
        self,
        *,
        stale_before: datetime,
        now: datetime | None = None,
    ) -> int:
        cutoff = _as_utc(stale_before)
        current = _as_utc(now or datetime.now(timezone.utc))
        with self.database.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE key_lifecycle_keys
                SET status = ?, cleanup_token = NULL, cleanup_started_at = NULL,
                    last_error = ?, updated_at = ?
                WHERE status = ?
                  AND (cleanup_started_at IS NULL OR cleanup_started_at <= ?)
                  AND NOT EXISTS (
                      SELECT 1 FROM key_lifecycle_bindings
                      WHERE key_lifecycle_bindings.key_id = key_lifecycle_keys.id
                  )
                """,
                (
                    KeyStatus.ERROR.value,
                    _STALE_CLEANUP_ERROR,
                    _dump_dt(current),
                    KeyStatus.DELETING.value,
                    _dump_dt(cutoff),
                ),
            )
        return cursor.rowcount

    def _require_key(self, connection, key_id: str, *, lock: bool = False):
        suffix = " FOR UPDATE" if lock and self.database.dialect != "sqlite" else ""
        row = connection.execute(
            f"SELECT * FROM key_lifecycle_keys WHERE id = ?{suffix}",  # noqa: S608
            (key_id,),
        ).fetchone()
        if row is None:
            raise UnknownKeyError(f"Unknown registered key: {key_id}")
        return row

    @staticmethod
    def _schedule_orphan(connection, key_id: str, current: datetime) -> None:
        connection.execute(
            """
            UPDATE key_lifecycle_keys
            SET status = ?, orphaned_at = ?, delete_after = ?,
                cleanup_token = NULL, cleanup_started_at = NULL,
                last_error = NULL, updated_at = ?
            WHERE id = ?
            """,
            (
                KeyStatus.ORPHANED.value,
                _dump_dt(current),
                _dump_dt(current + ORPHAN_GRACE_PERIOD),
                _dump_dt(current),
                key_id,
            ),
        )


def _key_ref_digest(key_ref: str) -> str:
    return hashlib.sha256(key_ref.encode("utf-8")).hexdigest()


def _required(value: str | None, name: str) -> str:
    if value is None or not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} is required")
    return value


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def _dump_dt(value: datetime | None) -> str | None:
    return None if value is None else _as_utc(value).isoformat()


def _load_dt(value: str | None) -> datetime | None:
    if value is None:
        return None
    return _as_utc(datetime.fromisoformat(value))


def _key_from_row(row) -> RegisteredKey:
    return RegisteredKey(
        id=row["id"],
        backend=row["backend"],
        key_ref=row["key_ref"],
        purpose=row["purpose"],
        ownership=KeyOwnership(row["ownership"]),
        status=KeyStatus(row["status"]),
        orphaned_at=_load_dt(row["orphaned_at"]),
        delete_after=_load_dt(row["delete_after"]),
        cleanup_token=row["cleanup_token"],
        cleanup_started_at=_load_dt(row["cleanup_started_at"]),
        cleanup_attempts=int(row["cleanup_attempts"]),
        last_attempt_at=_load_dt(row["last_attempt_at"]),
        last_error=row["last_error"],
        public_key_sha256=row.get("public_key_sha256"),
        created_at=_load_dt(row["created_at"]),
        updated_at=_load_dt(row["updated_at"]),
    )


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _public_key_sha256(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if _SHA256_RE.fullmatch(normalized) is None:
        raise ValueError("public_key_sha256 must be a lowercase SHA-256 hex digest")
    return normalized


def _binding_from_row(row) -> KeyBinding:
    return KeyBinding(
        key_id=row["key_id"],
        resource_type=row["resource_type"],
        resource_id=row["resource_id"],
        created_at=_load_dt(row["created_at"]),
    )
