from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from myownca.domain import (
    OfflineCeremonyRecord,
    OfflineRootAuthority,
    Revocation,
    RevocationReason,
    RootCRL,
    SubCA,
)


class OfflineStateError(RuntimeError):
    pass


class OfflineStateRepository:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def migrate(self) -> None:
        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS root_certificate (
                    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id = 1),
                    certificate_pem TEXT NOT NULL,
                    key_ref TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sub_cas (
                    id TEXT PRIMARY KEY,
                    certificate_pem TEXT NOT NULL,
                    key_ref TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    allowed_profiles_json TEXT NOT NULL DEFAULT '["user_auth","host_tls","smime"]'
                );

                CREATE TABLE IF NOT EXISTS root_revocations (
                    serial_number TEXT PRIMARY KEY,
                    reason TEXT NOT NULL,
                    revoked_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS root_crls (
                    number INTEGER PRIMARY KEY,
                    crl_pem TEXT NOT NULL,
                    generated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ceremony_log (
                    id TEXT PRIMARY KEY,
                    operation_type TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    operator_ids_json TEXT NOT NULL,
                    details_json TEXT NOT NULL
                );

                DROP TABLE IF EXISTS trusted_request_keys;
                """
            )
            sub_ca_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(sub_cas)").fetchall()
            }
            if "allowed_profiles_json" not in sub_ca_columns:
                connection.execute(
                    """
                    ALTER TABLE sub_cas ADD COLUMN allowed_profiles_json TEXT NOT NULL
                    DEFAULT '["user_auth","host_tls","smime"]'
                    """
                )

    def add_root(self, root: OfflineRootAuthority) -> None:
        try:
            with self.connect() as connection:
                connection.execute(
                    """
                    INSERT INTO root_certificate(
                        singleton_id, certificate_pem, key_ref, subject, created_at
                    ) VALUES (1, ?, ?, ?, ?)
                    """,
                    (
                        root.certificate_pem,
                        root.key_ref,
                        root.subject,
                        _dump_dt(root.created_at),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise OfflineStateError("Offline root already exists") from exc

    def get_root(self) -> OfflineRootAuthority:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM root_certificate WHERE singleton_id = 1").fetchone()
        if row is None:
            raise OfflineStateError("Offline root has not been created")
        return OfflineRootAuthority(
            certificate_pem=row["certificate_pem"],
            key_ref=row["key_ref"],
            subject=row["subject"],
            created_at=_load_dt(row["created_at"]),
        )

    def add_sub_ca(self, sub_ca: SubCA) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO sub_cas(
                    id, certificate_pem, key_ref, subject, created_at, allowed_profiles_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    sub_ca.id,
                    sub_ca.certificate_pem,
                    sub_ca.key_ref,
                    sub_ca.subject,
                    _dump_dt(sub_ca.created_at),
                    json.dumps([profile.value for profile in sub_ca.allowed_profiles]),
                ),
            )

    def add_root_revocation(self, revocation: Revocation) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO root_revocations(serial_number, reason, revoked_at)
                VALUES (?, ?, ?)
                """,
                (
                    revocation.serial_number,
                    revocation.reason.value,
                    _dump_dt(revocation.revoked_at),
                ),
            )

    def list_root_revocations(self) -> list[Revocation]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM root_revocations ORDER BY revoked_at"
            ).fetchall()
        return [
            Revocation(
                serial_number=row["serial_number"],
                reason=RevocationReason(row["reason"]),
                revoked_at=_load_dt(row["revoked_at"]),
            )
            for row in rows
        ]

    def next_root_crl_number(self) -> int:
        with self.connect() as connection:
            row = connection.execute("SELECT MAX(number) AS current FROM root_crls").fetchone()
        return (row["current"] or 0) + 1

    def add_root_crl(self, root_crl: RootCRL) -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO root_crls(number, crl_pem, generated_at) VALUES (?, ?, ?)",
                (root_crl.number, root_crl.crl_pem, _dump_dt(root_crl.generated_at)),
            )

    def list_root_crls(self) -> list[RootCRL]:
        with self.connect() as connection:
            rows = connection.execute("SELECT * FROM root_crls ORDER BY number").fetchall()
        return [
            RootCRL(
                number=row["number"],
                crl_pem=row["crl_pem"],
                generated_at=_load_dt(row["generated_at"]),
            )
            for row in rows
        ]

    def add_ceremony_record(
        self,
        record: OfflineCeremonyRecord,
        details: dict[str, object] | None = None,
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO ceremony_log(id, operation_type, occurred_at, operator_ids_json, details_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    record.id,
                    record.operation_type,
                    _dump_dt(record.occurred_at),
                    json.dumps(record.operator_ids),
                    json.dumps(details or {}, sort_keys=True),
                ),
            )

    def list_ceremony_records(self) -> list[OfflineCeremonyRecord]:
        with self.connect() as connection:
            rows = connection.execute("SELECT * FROM ceremony_log ORDER BY occurred_at").fetchall()
        return [
            OfflineCeremonyRecord(
                id=row["id"],
                operation_type=row["operation_type"],
                occurred_at=_load_dt(row["occurred_at"]),
                operator_ids=tuple(json.loads(row["operator_ids_json"])),
            )
            for row in rows
        ]


def _dump_dt(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _load_dt(value: str) -> datetime:
    return datetime.fromisoformat(value)
