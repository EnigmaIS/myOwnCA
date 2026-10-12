from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

from myownca.service_certs.base import (
    AcmeAccount,
    AcmeCertConfig,
    AcmeOrderCheckpoint,
    ChallengeType,
    KeyBackend,
    ServiceCertificate,
    ServiceCertSource,
    ServiceCertStatus,
)
from myownca.storage.database import Database, IntegrityError


class ServiceCertRepositoryError(RuntimeError):
    pass


# Keep the in-app error log bounded; the repository prunes to this many rows on insert.
_MAX_ERRORS = 100


class ServiceCertRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    # -- service certificates -------------------------------------------------

    def add(self, cert: ServiceCertificate) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO service_certificates(
                    id, name, source, status, key_backend, key_ref, csr_pem,
                    certificate_pem, chain_pem, subject, not_before, not_after,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cert.id,
                    cert.name,
                    cert.source.value,
                    cert.status.value,
                    cert.key_backend.value,
                    cert.key_ref,
                    cert.csr_pem,
                    cert.certificate_pem,
                    cert.chain_pem,
                    cert.subject,
                    _dump_dt(cert.not_before),
                    _dump_dt(cert.not_after),
                    _dump_dt(cert.created_at),
                    _dump_dt(cert.updated_at),
                ),
            )

    def get(self, cert_id: str) -> ServiceCertificate:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM service_certificates WHERE id = ?", (cert_id,)
            ).fetchone()
        if row is None:
            raise ServiceCertRepositoryError(f"Unknown service certificate: {cert_id}")
        return _cert_from_row(row)

    def get_by_name(self, name: str) -> ServiceCertificate | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM service_certificates WHERE name = ?", (name,)
            ).fetchone()
        return None if row is None else _cert_from_row(row)

    def list_all(self) -> list[ServiceCertificate]:
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM service_certificates ORDER BY name"
            ).fetchall()
        return [_cert_from_row(row) for row in rows]

    def update(self, cert: ServiceCertificate) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                UPDATE service_certificates SET
                    source = ?, status = ?, key_backend = ?, key_ref = ?, csr_pem = ?,
                    certificate_pem = ?, chain_pem = ?, subject = ?, not_before = ?,
                    not_after = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    cert.source.value,
                    cert.status.value,
                    cert.key_backend.value,
                    cert.key_ref,
                    cert.csr_pem,
                    cert.certificate_pem,
                    cert.chain_pem,
                    cert.subject,
                    _dump_dt(cert.not_before),
                    _dump_dt(cert.not_after),
                    _dump_dt(datetime.now(timezone.utc)),
                    cert.id,
                ),
            )

    def delete(self, cert_id: str) -> None:
        with self.database.connect() as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("DELETE FROM service_certificates WHERE id = ?", (cert_id,))

    # -- acme accounts --------------------------------------------------------

    def add_account(self, account: AcmeAccount) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO acme_accounts(
                    id, directory_url, account_url, account_key_ciphertext, contact, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    account.id,
                    account.directory_url,
                    account.account_url,
                    account.account_key_ciphertext,
                    account.contact,
                    _dump_dt(account.created_at),
                ),
            )

    def get_account(self, account_id: str) -> AcmeAccount:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM acme_accounts WHERE id = ?", (account_id,)
            ).fetchone()
        if row is None:
            raise ServiceCertRepositoryError(f"Unknown ACME account: {account_id}")
        return _account_from_row(row)

    def set_account_dns_provider(
        self, account_id: str, dns_provider: str | None, dns_credentials_ciphertext: str | None
    ) -> None:
        with self.database.connect() as connection:
            connection.execute(
                "UPDATE acme_accounts SET dns_provider = ?, dns_credentials_ciphertext = ? WHERE id = ?",
                (dns_provider, dns_credentials_ciphertext, account_id),
            )

    def list_accounts(self) -> list[AcmeAccount]:
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM acme_accounts ORDER BY created_at"
            ).fetchall()
        return [_account_from_row(row) for row in rows]

    def list_account_dependents(self, account_id: str) -> list[ServiceCertificate]:
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT sc.* FROM service_certificates sc "
                "JOIN acme_cert_configs cc ON cc.service_certificate_id = sc.id "
                "WHERE cc.account_id = ? ORDER BY sc.name",
                (account_id,),
            ).fetchall()
        return [_cert_from_row(row) for row in rows]

    def delete_account(self, account_id: str) -> None:
        with self.database.connect() as connection:
            connection.execute("DELETE FROM acme_cert_configs WHERE account_id = ?", (account_id,))
            connection.execute("DELETE FROM acme_accounts WHERE id = ?", (account_id,))

    # -- acme cert configs ----------------------------------------------------

    def set_cert_config(self, config: AcmeCertConfig) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO acme_cert_configs(
                    service_certificate_id, account_id, domains_json,
                    challenge_type, renew_before_days
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(service_certificate_id) DO UPDATE SET
                    account_id = excluded.account_id,
                    domains_json = excluded.domains_json,
                    challenge_type = excluded.challenge_type,
                    renew_before_days = excluded.renew_before_days
                """,
                (
                    config.service_certificate_id,
                    config.account_id,
                    json.dumps(list(config.domains)),
                    config.challenge_type.value,
                    config.renew_before_days,
                ),
            )

    def get_cert_config(self, service_certificate_id: str) -> AcmeCertConfig | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM acme_cert_configs WHERE service_certificate_id = ?",
                (service_certificate_id,),
            ).fetchone()
        if row is None:
            return None
        return AcmeCertConfig(
            service_certificate_id=row["service_certificate_id"],
            account_id=row["account_id"],
            domains=tuple(json.loads(row["domains_json"])),
            challenge_type=ChallengeType(row["challenge_type"]),
            renew_before_days=row["renew_before_days"],
        )

    # -- durable acme order checkpoints --------------------------------------

    def get_acme_order_checkpoint(
        self, idempotency_key: str
    ) -> AcmeOrderCheckpoint | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM acme_order_checkpoints WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
        return None if row is None else _checkpoint_from_row(row)

    def get_or_create_acme_order_checkpoint(
        self,
        *,
        idempotency_key: str,
        service_certificate_id: str,
        purpose: str,
        csr_pem: str,
        csr_sha256: str,
        prior_certificate_sha256: str | None,
        now: datetime | None = None,
    ) -> AcmeOrderCheckpoint:
        if not idempotency_key:
            raise ValueError("ACME idempotency key is required")
        if purpose not in {"issue", "renew"}:
            raise ValueError(f"Unsupported ACME checkpoint purpose: {purpose}")
        current = now or datetime.now(timezone.utc)
        try:
            with self.database.connect() as connection:
                connection.execute(
                    """
                    INSERT INTO acme_order_checkpoints(
                        idempotency_key, service_certificate_id, purpose, state,
                        csr_pem, csr_sha256, prior_certificate_sha256,
                        challenges_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        idempotency_key,
                        service_certificate_id,
                        purpose,
                        "prepared",
                        csr_pem,
                        csr_sha256,
                        prior_certificate_sha256,
                        "[]",
                        _dump_dt(current),
                        _dump_dt(current),
                    ),
                )
        except IntegrityError as exc:
            existing = self.get_acme_order_checkpoint(idempotency_key)
            if existing is None:
                raise ServiceCertRepositoryError(
                    "Could not create the ACME order checkpoint"
                ) from exc
            _assert_checkpoint_identity(
                existing,
                service_certificate_id=service_certificate_id,
                purpose=purpose,
                csr_sha256=csr_sha256,
            )
            return existing
        checkpoint = self.get_acme_order_checkpoint(idempotency_key)
        if checkpoint is None:  # pragma: no cover - defensive storage invariant
            raise ServiceCertRepositoryError("ACME order checkpoint was not persisted")
        return checkpoint

    def claim_acme_order_creation(
        self, idempotency_key: str, *, now: datetime | None = None
    ) -> bool:
        """Atomically grant the only automatic attempt to create an ACME order.

        If the provider processed ``newOrder`` but its response was lost, the
        checkpoint remains ``creating``.  Retrying it automatically could
        create a duplicate order, so recovery requires explicit operator
        reconciliation instead.
        """
        current = now or datetime.now(timezone.utc)
        with self.database.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE acme_order_checkpoints
                SET state = 'creating', updated_at = ?
                WHERE idempotency_key = ? AND state = 'prepared'
                    AND order_json IS NULL
                """,
                (_dump_dt(current), idempotency_key),
            )
        return cursor.rowcount == 1

    def save_acme_order(
        self,
        idempotency_key: str,
        *,
        order_url: str,
        order_json: str,
        challenges_json: str = "[]",
        now: datetime | None = None,
    ) -> AcmeOrderCheckpoint:
        """Persist the first order created for an operation and never replace it."""
        if not order_url or not order_json:
            raise ValueError("ACME order URL and state are required")
        current = now or datetime.now(timezone.utc)
        with self.database.connect() as connection:
            connection.execute(
                """
                UPDATE acme_order_checkpoints
                SET state = 'created', order_url = ?, order_json = ?,
                    challenges_json = ?, updated_at = ?
                WHERE idempotency_key = ? AND state = 'creating'
                    AND order_json IS NULL
                """,
                (
                    order_url,
                    order_json,
                    challenges_json,
                    _dump_dt(current),
                    idempotency_key,
                ),
            )
        checkpoint = self.get_acme_order_checkpoint(idempotency_key)
        if checkpoint is None:
            raise ServiceCertRepositoryError(
                f"Unknown ACME order checkpoint: {idempotency_key}"
            )
        return checkpoint

    def save_acme_fullchain(
        self,
        idempotency_key: str,
        fullchain_pem: str,
        *,
        now: datetime | None = None,
    ) -> AcmeOrderCheckpoint:
        """Checkpoint the first provider result before installing it locally."""
        if not fullchain_pem:
            raise ValueError("ACME returned an empty certificate chain")
        current = now or datetime.now(timezone.utc)
        with self.database.connect() as connection:
            connection.execute(
                """
                UPDATE acme_order_checkpoints
                SET state = 'completed', fullchain_pem = ?, updated_at = ?
                WHERE idempotency_key = ? AND fullchain_pem IS NULL
                """,
                (fullchain_pem, _dump_dt(current), idempotency_key),
            )
        checkpoint = self.get_acme_order_checkpoint(idempotency_key)
        if checkpoint is None:
            raise ServiceCertRepositoryError(
                f"Unknown ACME order checkpoint: {idempotency_key}"
            )
        return checkpoint

    # -- error log -------------------------------------------------------------

    def record_error(self, operation: str, target: str, message: str) -> None:
        with self.database.connect() as connection:
            connection.execute(
                "INSERT INTO service_cert_errors(id, created_at, operation, target, message) "
                "VALUES (?, ?, ?, ?, ?)",
                (str(uuid4()), _dump_dt(datetime.now(timezone.utc)), operation, target, message),
            )
            connection.execute(
                "DELETE FROM service_cert_errors WHERE id NOT IN ("
                "SELECT id FROM service_cert_errors ORDER BY created_at DESC, id DESC LIMIT ?)",
                (_MAX_ERRORS,),
            )

    def list_recent_errors(self, limit: int = 50) -> list[dict]:
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT id, created_at, operation, target, message FROM service_cert_errors "
                "ORDER BY created_at DESC, id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "created_at": row["created_at"],
                "operation": row["operation"],
                "target": row["target"],
                "message": row["message"],
            }
            for row in rows
        ]

    def clear_errors(self) -> None:
        with self.database.connect() as connection:
            connection.execute("DELETE FROM service_cert_errors")


def _cert_from_row(row) -> ServiceCertificate:
    return ServiceCertificate(
        id=row["id"],
        name=row["name"],
        source=ServiceCertSource(row["source"]),
        status=ServiceCertStatus(row["status"]),
        key_backend=KeyBackend(row["key_backend"]),
        key_ref=row["key_ref"],
        csr_pem=row["csr_pem"],
        certificate_pem=row["certificate_pem"],
        chain_pem=row["chain_pem"],
        subject=row["subject"],
        not_before=_load_dt(row["not_before"]),
        not_after=_load_dt(row["not_after"]),
        created_at=_load_dt(row["created_at"]),
        updated_at=_load_dt(row["updated_at"]),
    )


def _account_from_row(row) -> AcmeAccount:
    return AcmeAccount(
        id=row["id"],
        directory_url=row["directory_url"],
        account_url=row["account_url"],
        account_key_ciphertext=row["account_key_ciphertext"],
        contact=row["contact"],
        created_at=_load_dt(row["created_at"]),
        dns_provider=row["dns_provider"],
        dns_credentials_ciphertext=row["dns_credentials_ciphertext"],
    )


def _checkpoint_from_row(row) -> AcmeOrderCheckpoint:
    return AcmeOrderCheckpoint(
        idempotency_key=row["idempotency_key"],
        service_certificate_id=row["service_certificate_id"],
        purpose=row["purpose"],
        state=row["state"],
        csr_pem=row["csr_pem"],
        csr_sha256=row["csr_sha256"],
        prior_certificate_sha256=row["prior_certificate_sha256"],
        order_url=row["order_url"],
        order_json=row["order_json"],
        challenges_json=row["challenges_json"],
        fullchain_pem=row["fullchain_pem"],
        created_at=_load_dt(row["created_at"]),
        updated_at=_load_dt(row["updated_at"]),
    )


def _assert_checkpoint_identity(
    checkpoint: AcmeOrderCheckpoint,
    *,
    service_certificate_id: str,
    purpose: str,
    csr_sha256: str,
) -> None:
    if (
        checkpoint.service_certificate_id != service_certificate_id
        or checkpoint.purpose != purpose
        or checkpoint.csr_sha256 != csr_sha256
    ):
        raise ServiceCertRepositoryError(
            "ACME idempotency key is already bound to another operation"
        )


def _dump_dt(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _load_dt(value: str | None) -> datetime | None:
    return None if value is None else datetime.fromisoformat(value)
