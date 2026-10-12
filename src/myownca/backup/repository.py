from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from uuid import uuid4

from myownca.storage.database import Database

PROPOSAL_TTL = timedelta(hours=24)
DOWNLOAD_TTL = timedelta(minutes=30)


class BackupProposalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class BackupExportStatus(StrEnum):
    READY = "ready"
    DELIVERED = "delivered"
    EXPIRED = "expired"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class BackupProposal:
    id: str
    proposer_id: str
    proposer_email: str
    reason: str
    requester_salt_b64: str
    status: BackupProposalStatus
    created_at: datetime
    expires_at: datetime
    resolved_at: datetime | None = None
    approver_id: str | None = None
    approver_email: str | None = None
    approval_reason: str | None = None


class BackupRepositoryError(RuntimeError):
    pass


class ApplicationBackupRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create_proposal(
        self,
        *,
        proposer_id: str,
        proposer_email: str,
        reason: str,
        requester_salt_b64: str,
        requester_key_ciphertext: str,
        now: datetime | None = None,
    ) -> BackupProposal:
        current = _utc(now)
        with self.database.connect() as connection:
            self._expire(connection, current)
            actor = connection.execute(
                "SELECT role, is_active FROM users WHERE id = ?", (proposer_id,)
            ).fetchone()
            if actor is None or actor["role"] != "admin" or not bool(actor["is_active"]):
                raise BackupRepositoryError("An active administrator account is required")
            admins = connection.execute(
                "SELECT COUNT(*) AS count FROM users WHERE role = 'admin' AND is_active = 1"
            ).fetchone()
            if admins is None or int(admins["count"]) < 2:
                raise BackupRepositoryError("Application backup requires two active administrators")
            pending = connection.execute(
                "SELECT 1 FROM application_backup_proposals WHERE status = ? LIMIT 1",
                (BackupProposalStatus.PENDING.value,),
            ).fetchone()
            if pending is not None:
                raise BackupRepositoryError("An application backup proposal is already pending")
            proposal_id = str(uuid4())
            expires_at = current + PROPOSAL_TTL
            connection.execute(
                """
                INSERT INTO application_backup_proposals(
                    id, proposer_id, proposer_email, reason, requester_salt_b64,
                    pending_guard, status, created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
                """,
                (
                    proposal_id,
                    proposer_id,
                    proposer_email,
                    reason,
                    requester_salt_b64,
                    BackupProposalStatus.PENDING.value,
                    current.isoformat(),
                    expires_at.isoformat(),
                ),
            )
            connection.execute(
                """
                INSERT INTO application_backup_pending_secrets(
                    proposal_id, requester_key_ciphertext, created_at, expires_at
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    proposal_id,
                    requester_key_ciphertext,
                    current.isoformat(),
                    expires_at.isoformat(),
                ),
            )
        return self.get_proposal(proposal_id)

    def list_proposals(self, *, now: datetime | None = None) -> list[BackupProposal]:
        current = _utc(now)
        with self.database.connect() as connection:
            self._expire(connection, current)
            rows = connection.execute(
                """
                SELECT * FROM application_backup_proposals
                ORDER BY created_at DESC, id DESC LIMIT 100
                """
            ).fetchall()
        return [_proposal(row) for row in rows]

    def get_proposal(self, proposal_id: str) -> BackupProposal:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM application_backup_proposals WHERE id = ?", (proposal_id,)
            ).fetchone()
        if row is None:
            raise BackupRepositoryError("Unknown application backup proposal")
        return _proposal(row)

    def requester_key_ciphertext(self, proposal_id: str) -> str:
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT requester_key_ciphertext FROM application_backup_pending_secrets
                WHERE proposal_id = ?
                """,
                (proposal_id,),
            ).fetchone()
        if row is None:
            raise BackupRepositoryError("Application backup requester share is unavailable")
        return str(row["requester_key_ciphertext"])

    def approve_and_consume(
        self,
        proposal_id: str,
        *,
        approver_id: str,
        approver_email: str,
        reason: str,
        now: datetime | None = None,
    ) -> BackupProposal:
        current = _utc(now)
        with self.database.connect() as connection:
            self._expire(connection, current)
            row = connection.execute(
                "SELECT * FROM application_backup_proposals WHERE id = ?", (proposal_id,)
            ).fetchone()
            if row is None:
                raise BackupRepositoryError("Unknown application backup proposal")
            if row["status"] != BackupProposalStatus.PENDING.value:
                raise BackupRepositoryError("Only pending application backup proposals may be approved")
            if row["proposer_id"] == approver_id:
                raise BackupRepositoryError("The proposing administrator cannot approve the backup")
            proposer = connection.execute(
                "SELECT role, is_active FROM users WHERE id = ?", (row["proposer_id"],)
            ).fetchone()
            if (
                proposer is None
                or proposer["role"] != "admin"
                or not bool(proposer["is_active"])
            ):
                raise BackupRepositoryError("The proposing administrator is no longer active")
            actor = connection.execute(
                "SELECT role, is_active FROM users WHERE id = ?", (approver_id,)
            ).fetchone()
            if actor is None or actor["role"] != "admin" or not bool(actor["is_active"]):
                raise BackupRepositoryError("An active administrator account is required")
            secret = connection.execute(
                "SELECT 1 FROM application_backup_pending_secrets WHERE proposal_id = ?",
                (proposal_id,),
            ).fetchone()
            if secret is None:
                raise BackupRepositoryError("Application backup requester share is unavailable")
            cursor = connection.execute(
                """
                UPDATE application_backup_proposals
                SET status = ?, resolved_at = ?, approver_id = ?, approver_email = ?,
                    approval_reason = ?, pending_guard = NULL
                WHERE id = ? AND status = ?
                """,
                (
                    BackupProposalStatus.APPROVED.value,
                    current.isoformat(),
                    approver_id,
                    approver_email,
                    reason,
                    proposal_id,
                    BackupProposalStatus.PENDING.value,
                ),
            )
            if cursor.rowcount != 1:
                raise BackupRepositoryError("Application backup proposal changed concurrently")
            connection.execute(
                "DELETE FROM application_backup_pending_secrets WHERE proposal_id = ?",
                (proposal_id,),
            )
        return self.get_proposal(proposal_id)

    def reject(
        self, proposal_id: str, *, actor_id: str, now: datetime | None = None
    ) -> BackupProposal:
        current = _utc(now)
        with self.database.connect() as connection:
            actor = connection.execute(
                "SELECT role, is_active FROM users WHERE id = ?", (actor_id,)
            ).fetchone()
            if actor is None or actor["role"] != "admin" or not bool(actor["is_active"]):
                raise BackupRepositoryError("An active administrator account is required")
            cursor = connection.execute(
                """
                UPDATE application_backup_proposals SET status = ?, resolved_at = ?
                    , pending_guard = NULL WHERE id = ? AND status = ?
                """,
                (
                    BackupProposalStatus.REJECTED.value,
                    current.isoformat(),
                    proposal_id,
                    BackupProposalStatus.PENDING.value,
                ),
            )
            if cursor.rowcount != 1:
                raise BackupRepositoryError("Only pending application backup proposals may be rejected")
            connection.execute(
                "DELETE FROM application_backup_pending_secrets WHERE proposal_id = ?",
                (proposal_id,),
            )
        return self.get_proposal(proposal_id)

    def add_export(
        self,
        *,
        export_id: str,
        proposal: BackupProposal,
        filename: str,
        database_dialect: str,
        size: int,
        sha256: str,
        now: datetime | None = None,
    ) -> dict[str, object]:
        current = _utc(now)
        expires_at = current + DOWNLOAD_TTL
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO application_backup_exports(
                    id, proposal_id, requester_id, requester_email, approver_id,
                    approver_email, filename, database_dialect, size_bytes, sha256,
                    status, created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    export_id,
                    proposal.id,
                    proposal.proposer_id,
                    proposal.proposer_email,
                    proposal.approver_id,
                    proposal.approver_email,
                    filename,
                    database_dialect,
                    size,
                    sha256,
                    BackupExportStatus.READY.value,
                    current.isoformat(),
                    expires_at.isoformat(),
                ),
            )
        return self.get_export(export_id)

    def add_failed_export(
        self,
        *,
        export_id: str,
        proposal: BackupProposal,
        database_dialect: str,
        error: str,
        now: datetime | None = None,
    ) -> dict[str, object]:
        current = _utc(now)
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO application_backup_exports(
                    id, proposal_id, requester_id, requester_email, approver_id,
                    approver_email, filename, database_dialect, size_bytes, sha256,
                    status, created_at, expires_at, error
                ) VALUES (?, ?, ?, ?, ?, ?, '', ?, 0, '', ?, ?, ?, ?)
                """,
                (
                    export_id,
                    proposal.id,
                    proposal.proposer_id,
                    proposal.proposer_email,
                    proposal.approver_id,
                    proposal.approver_email,
                    database_dialect,
                    BackupExportStatus.FAILED.value,
                    current.isoformat(),
                    current.isoformat(),
                    error[:500],
                ),
            )
        return self.get_export(export_id)

    def get_export(self, export_id: str) -> dict[str, object]:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM application_backup_exports WHERE id = ?", (export_id,)
            ).fetchone()
        if row is None:
            raise BackupRepositoryError("Unknown application backup export")
        return _export(row)

    def list_exports(self, *, limit: int = 50) -> list[dict[str, object]]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM application_backup_exports
                ORDER BY created_at DESC, id DESC LIMIT ?
                """,
                (max(1, min(limit, 200)),),
            ).fetchall()
        return [_export(row) for row in rows]

    def mark_delivered(self, export_id: str, *, now: datetime | None = None) -> None:
        current = _utc(now)
        with self.database.connect() as connection:
            connection.execute(
                """
                UPDATE application_backup_exports
                SET status = ?, delivered_at = ? WHERE id = ? AND status = ?
                """,
                (
                    BackupExportStatus.DELIVERED.value,
                    current.isoformat(),
                    export_id,
                    BackupExportStatus.READY.value,
                ),
            )

    def expire_ready(self, *, now: datetime | None = None) -> list[str]:
        current = _utc(now)
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT id FROM application_backup_exports
                WHERE status = ? AND expires_at <= ?
                """,
                (BackupExportStatus.READY.value, current.isoformat()),
            ).fetchall()
            ids = [str(row["id"]) for row in rows]
            for export_id in ids:
                connection.execute(
                    "UPDATE application_backup_exports SET status = ? WHERE id = ?",
                    (BackupExportStatus.EXPIRED.value, export_id),
                )
        return ids

    def latest_delivered(self) -> dict[str, object] | None:
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM application_backup_exports
                WHERE status = ? ORDER BY delivered_at DESC, id DESC LIMIT 1
                """,
                (BackupExportStatus.DELIVERED.value,),
            ).fetchone()
        return _export(row) if row is not None else None

    def active_admin_count(self) -> int:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM users WHERE role = 'admin' AND is_active = 1"
            ).fetchone()
        return int(row["count"]) if row is not None else 0

    @staticmethod
    def _expire(connection, current: datetime) -> None:
        rows = connection.execute(
            """
            SELECT id FROM application_backup_proposals
            WHERE status = ? AND expires_at <= ?
            """,
            (BackupProposalStatus.PENDING.value, current.isoformat()),
        ).fetchall()
        for row in rows:
            connection.execute(
                """
                UPDATE application_backup_proposals
                SET status = ?, resolved_at = ?, pending_guard = NULL WHERE id = ?
                """,
                (BackupProposalStatus.EXPIRED.value, current.isoformat(), row["id"]),
            )
            connection.execute(
                "DELETE FROM application_backup_pending_secrets WHERE proposal_id = ?",
                (row["id"],),
            )


def _proposal(row) -> BackupProposal:
    return BackupProposal(
        id=str(row["id"]),
        proposer_id=str(row["proposer_id"]),
        proposer_email=str(row["proposer_email"]),
        reason=str(row["reason"]),
        requester_salt_b64=str(row["requester_salt_b64"]),
        status=BackupProposalStatus(row["status"]),
        created_at=_load_dt(row["created_at"]),
        expires_at=_load_dt(row["expires_at"]),
        resolved_at=_load_dt(row["resolved_at"]) if row["resolved_at"] else None,
        approver_id=str(row["approver_id"]) if row["approver_id"] else None,
        approver_email=str(row["approver_email"]) if row["approver_email"] else None,
        approval_reason=str(row["approval_reason"]) if row["approval_reason"] else None,
    )


def proposal_dict(item: BackupProposal) -> dict[str, object]:
    return {
        "id": item.id,
        "proposer_id": item.proposer_id,
        "proposer_email": item.proposer_email,
        "reason": item.reason,
        "status": item.status.value,
        "created_at": item.created_at.isoformat(),
        "expires_at": item.expires_at.isoformat(),
        "resolved_at": item.resolved_at.isoformat() if item.resolved_at else None,
        "approver_id": item.approver_id,
        "approver_email": item.approver_email,
        "approval_reason": item.approval_reason,
        "requires_different_admin": True,
    }


def _export(row) -> dict[str, object]:
    return {
        "id": str(row["id"]),
        "proposal_id": str(row["proposal_id"]),
        "requester_id": str(row["requester_id"]),
        "requester_email": str(row["requester_email"]),
        "approver_id": str(row["approver_id"]),
        "approver_email": str(row["approver_email"]),
        "filename": str(row["filename"]),
        "database_dialect": str(row["database_dialect"]),
        "size_bytes": int(row["size_bytes"]),
        "sha256": str(row["sha256"]),
        "status": str(row["status"]),
        "created_at": str(row["created_at"]),
        "expires_at": str(row["expires_at"]),
        "delivered_at": str(row["delivered_at"]) if row["delivered_at"] else None,
        "error": str(row["error"]) if row["error"] else None,
    }


def _utc(value: datetime | None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc)


def _load_dt(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
