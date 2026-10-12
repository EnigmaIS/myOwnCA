from __future__ import annotations

from datetime import datetime, timedelta, timezone

from myownca.holder.base import AccessRequest, AccessRequestStatus, LinkPurpose, SecureLink
from myownca.storage.database import Database
from myownca.storage.repositories import RepositoryError

_COLUMNS = (
    "id, token_hash, purpose, person_id, serial_number, certificate_id, created_by, "
    "created_at, expires_at, max_uses, use_count, revoked_at, locked_at, otp_hash, "
    "otp_expires_at, otp_attempts, session_token_hash, session_expires_at, last_used_at"
)
_READ_COLUMNS = (
    "sl.id AS id, sl.token_hash AS token_hash, sl.purpose AS purpose, "
    "sl.person_id AS person_id, sl.serial_number AS serial_number, "
    "COALESCE(ref.certificate_id, sl.certificate_id) AS certificate_id, "
    "sl.created_by AS created_by, sl.created_at AS created_at, "
    "sl.expires_at AS expires_at, sl.max_uses AS max_uses, "
    "sl.use_count AS use_count, sl.revoked_at AS revoked_at, "
    "sl.locked_at AS locked_at, sl.otp_hash AS otp_hash, "
    "sl.otp_expires_at AS otp_expires_at, sl.otp_attempts AS otp_attempts, "
    "sl.session_token_hash AS session_token_hash, "
    "sl.session_expires_at AS session_expires_at, sl.last_used_at AS last_used_at"
)
_READ_FROM = (
    "secure_links sl LEFT JOIN secure_link_certificate_refs ref ON ref.link_id = sl.id"
)


class SecureLinkRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def add_link(self, link: SecureLink) -> None:
        with self.database.connect() as connection:
            legacy_certificate_id = None
            if link.certificate_id is not None:
                shadow = connection.execute(
                    "SELECT certificate_id FROM issued_certificates "
                    "WHERE certificate_id = ?",
                    (link.certificate_id,),
                ).fetchone()
                if shadow is not None:
                    legacy_certificate_id = link.certificate_id
            connection.execute(
                f"""
                INSERT INTO secure_links({_COLUMNS})
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    link.id,
                    link.token_hash,
                    link.purpose.value,
                    link.person_id,
                    link.serial_number,
                    legacy_certificate_id,
                    link.created_by,
                    _dump_dt(link.created_at),
                    _dump_dt(link.expires_at),
                    link.max_uses,
                    link.use_count,
                    _dump_opt(link.revoked_at),
                    _dump_opt(link.locked_at),
                    link.otp_hash,
                    _dump_opt(link.otp_expires_at),
                    link.otp_attempts,
                    link.session_token_hash,
                    _dump_opt(link.session_expires_at),
                    _dump_opt(link.last_used_at),
                ),
            )
            if link.certificate_id is not None:
                connection.execute(
                    "INSERT INTO secure_link_certificate_refs(link_id, certificate_id) "
                    "VALUES (?, ?)",
                    (link.id, link.certificate_id),
                )

    def get_link(self, link_id: str) -> SecureLink:
        with self.database.connect() as connection:
            row = connection.execute(
                f"SELECT {_READ_COLUMNS} FROM {_READ_FROM} WHERE sl.id = ?",  # noqa: S608
                (link_id,),
            ).fetchone()
        if row is None:
            raise RepositoryError(f"Unknown secure link: {link_id}")
        return _load_link(row)

    def get_by_token_hash(self, token_hash: str) -> SecureLink | None:
        with self.database.connect() as connection:
            row = connection.execute(
                f"SELECT {_READ_COLUMNS} FROM {_READ_FROM} "  # noqa: S608
                "WHERE sl.token_hash = ?",
                (token_hash,),
            ).fetchone()
        return None if row is None else _load_link(row)

    def list_links(self) -> list[SecureLink]:
        with self.database.connect() as connection:
            rows = connection.execute(
                f"SELECT {_READ_COLUMNS} FROM {_READ_FROM} "  # noqa: S608
                "ORDER BY sl.created_at DESC, sl.id"
            ).fetchall()
        return [_load_link(row) for row in rows]

    def list_links_for_serial(
        self, serial_number: str, purpose: LinkPurpose | None = None
    ) -> list[SecureLink]:
        query = (
            f"SELECT {_READ_COLUMNS} FROM {_READ_FROM} "  # noqa: S608
            "WHERE sl.serial_number = ?"
        )
        params: list[object] = [serial_number]
        if purpose is not None:
            query += " AND sl.purpose = ?"
            params.append(purpose.value)
        with self.database.connect() as connection:
            rows = connection.execute(
                query + " ORDER BY sl.created_at DESC, sl.id", params
            ).fetchall()
        return [_load_link(row) for row in rows]

    def list_links_for_certificate(
        self,
        certificate_id: str,
        *,
        serial_number: str | None = None,
        purpose: LinkPurpose | None = None,
    ) -> list[SecureLink]:
        """List canonical links, including pre-migration serial-only records."""
        query = (
            f"SELECT {_READ_COLUMNS} FROM {_READ_FROM} "  # noqa: S608
            "WHERE COALESCE(ref.certificate_id, sl.certificate_id) = ?"
        )
        params: list[object] = [certificate_id]
        if serial_number is not None:
            query += (
                " OR (ref.certificate_id IS NULL AND sl.certificate_id IS NULL "
                "AND sl.serial_number = ?)"
            )
            params.append(serial_number)
        if purpose is not None:
            query = f"SELECT * FROM ({query}) AS certificate_links WHERE purpose = ?"
            params.append(purpose.value)
        with self.database.connect() as connection:
            rows = connection.execute(query + " ORDER BY created_at DESC, id", params).fetchall()
        return [_load_link(row) for row in rows]

    def set_otp_state(
        self,
        link_id: str,
        *,
        otp_hash: str | None,
        otp_expires_at: datetime | None,
        otp_attempts: int,
    ) -> None:
        with self.database.connect() as connection:
            connection.execute(
                "UPDATE secure_links SET otp_hash = ?, otp_expires_at = ?, otp_attempts = ? "
                "WHERE id = ?",
                (otp_hash, _dump_opt(otp_expires_at), otp_attempts, link_id),
            )

    def set_locked(self, link_id: str, locked_at: datetime) -> None:
        with self.database.connect() as connection:
            connection.execute(
                "UPDATE secure_links SET locked_at = ?, otp_hash = NULL, otp_expires_at = NULL "
                "WHERE id = ?",
                (_dump_dt(locked_at), link_id),
            )

    def set_revoked(self, link_id: str, revoked_at: datetime) -> None:
        with self.database.connect() as connection:
            connection.execute(
                "UPDATE secure_links SET revoked_at = ?, session_token_hash = NULL, "
                "session_expires_at = NULL, otp_hash = NULL, otp_expires_at = NULL "
                "WHERE id = ?",
                (_dump_dt(revoked_at), link_id),
            )

    def prune(self, now: datetime, *, keep_days: int = 30) -> int:
        """Delete links that have been dead (expired or revoked) for keep_days."""
        cutoff = _dump_dt(now - timedelta(days=keep_days))
        with self.database.connect() as connection:
            result = connection.execute(
                "DELETE FROM secure_links WHERE expires_at < ? "
                "OR (revoked_at IS NOT NULL AND revoked_at < ?)",
                (cutoff, cutoff),
            )
        return result.rowcount

    def consume(self, link_id: str, *, max_uses: int, last_used_at: datetime) -> None:
        """Spend all remaining uses and close any open session (job done)."""
        with self.database.connect() as connection:
            connection.execute(
                "UPDATE secure_links SET use_count = ?, last_used_at = ?, "
                "session_token_hash = NULL, session_expires_at = NULL, "
                "otp_hash = NULL, otp_expires_at = NULL WHERE id = ?",
                (max_uses, _dump_dt(last_used_at), link_id),
            )

    def start_session(
        self,
        link_id: str,
        *,
        session_token_hash: str,
        session_expires_at: datetime,
        use_count: int,
        last_used_at: datetime,
    ) -> None:
        """Open the (single) claim session and consume the OTP code."""
        with self.database.connect() as connection:
            connection.execute(
                "UPDATE secure_links SET session_token_hash = ?, session_expires_at = ?, "
                "use_count = ?, last_used_at = ?, otp_hash = NULL, otp_expires_at = NULL, "
                "otp_attempts = 0 WHERE id = ?",
                (
                    session_token_hash,
                    _dump_dt(session_expires_at),
                    use_count,
                    _dump_dt(last_used_at),
                    link_id,
                ),
            )


_ACCESS_COLUMNS = (
    "id, email, name, kind, message, status, created_at, verify_code_hash, "
    "verify_expires_at, verify_attempts, email_verified_at, decided_by, decided_at"
)


class AccessRequestRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def add(self, request: AccessRequest) -> None:
        with self.database.connect() as connection:
            connection.execute(
                f"""
                INSERT INTO access_requests({_ACCESS_COLUMNS})
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request.id,
                    request.email,
                    request.name,
                    request.kind,
                    request.message,
                    request.status.value,
                    _dump_dt(request.created_at),
                    request.verify_code_hash,
                    _dump_opt(request.verify_expires_at),
                    request.verify_attempts,
                    _dump_opt(request.email_verified_at),
                    request.decided_by,
                    _dump_opt(request.decided_at),
                ),
            )

    def get(self, request_id: str) -> AccessRequest:
        with self.database.connect() as connection:
            row = connection.execute(
                f"SELECT {_ACCESS_COLUMNS} FROM access_requests WHERE id = ?", (request_id,)
            ).fetchone()
        if row is None:
            raise RepositoryError(f"Unknown access request: {request_id}")
        return _access_from_row(row)

    def list(self, *, status: AccessRequestStatus | None = None) -> list[AccessRequest]:
        query = f"SELECT {_ACCESS_COLUMNS} FROM access_requests"
        params: tuple[object, ...] = ()
        if status is not None:
            query += " WHERE status = ?"
            params = (status.value,)
        query += " ORDER BY created_at DESC, id"
        with self.database.connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [_access_from_row(row) for row in rows]

    def count_recent_for_email(self, email: str, since: datetime) -> int:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS n FROM access_requests WHERE email = ? AND created_at >= ?",
                (email, _dump_dt(since)),
            ).fetchone()
        return row["n"]

    def set_verify_attempts(self, request_id: str, attempts: int, *, clear_code: bool) -> None:
        query = "UPDATE access_requests SET verify_attempts = ?"
        if clear_code:
            query += ", verify_code_hash = NULL, verify_expires_at = NULL"
        with self.database.connect() as connection:
            connection.execute(query + " WHERE id = ?", (attempts, request_id))

    def mark_verified(self, request_id: str, verified_at: datetime) -> None:
        with self.database.connect() as connection:
            connection.execute(
                "UPDATE access_requests SET status = ?, email_verified_at = ?, "
                "verify_code_hash = NULL, verify_expires_at = NULL, verify_attempts = 0 "
                "WHERE id = ?",
                (AccessRequestStatus.PENDING.value, _dump_dt(verified_at), request_id),
            )

    def decide(
        self,
        request_id: str,
        status: AccessRequestStatus,
        *,
        decided_by: str,
        decided_at: datetime,
    ) -> None:
        with self.database.connect() as connection:
            connection.execute(
                "UPDATE access_requests SET status = ?, decided_by = ?, decided_at = ? "
                "WHERE id = ?",
                (status.value, decided_by, _dump_dt(decided_at), request_id),
            )


def _access_from_row(row) -> AccessRequest:
    return AccessRequest(
        id=row["id"],
        email=row["email"],
        name=row["name"],
        kind=row["kind"],
        message=row["message"],
        status=AccessRequestStatus(row["status"]),
        created_at=_load_dt(row["created_at"]),
        verify_code_hash=row["verify_code_hash"],
        verify_expires_at=_load_opt(row["verify_expires_at"]),
        verify_attempts=row["verify_attempts"],
        email_verified_at=_load_opt(row["email_verified_at"]),
        decided_by=row["decided_by"],
        decided_at=_load_opt(row["decided_at"]),
    )


def _load_link(row) -> SecureLink:
    return SecureLink(
        id=row["id"],
        token_hash=row["token_hash"],
        purpose=LinkPurpose(row["purpose"]),
        person_id=row["person_id"],
        serial_number=row["serial_number"],
        certificate_id=row["certificate_id"],
        created_by=row["created_by"],
        created_at=_load_dt(row["created_at"]),
        expires_at=_load_dt(row["expires_at"]),
        max_uses=row["max_uses"],
        use_count=row["use_count"],
        revoked_at=_load_opt(row["revoked_at"]),
        locked_at=_load_opt(row["locked_at"]),
        otp_hash=row["otp_hash"],
        otp_expires_at=_load_opt(row["otp_expires_at"]),
        otp_attempts=row["otp_attempts"],
        session_token_hash=row["session_token_hash"],
        session_expires_at=_load_opt(row["session_expires_at"]),
        last_used_at=_load_opt(row["last_used_at"]),
    )


def _dump_dt(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _dump_opt(value: datetime | None) -> str | None:
    return None if value is None else _dump_dt(value)


def _load_dt(value: str) -> datetime:
    loaded = datetime.fromisoformat(value)
    return loaded if loaded.tzinfo else loaded.replace(tzinfo=timezone.utc)


def _load_opt(value: str | None) -> datetime | None:
    return None if value is None else _load_dt(value)
