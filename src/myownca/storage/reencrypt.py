"""Re-encrypt secrets held at rest under the domain-separated keys (finding F-1).

Before F-1, ``ca_auth``, ``comms`` and ``service_certs`` shared one Fernet key.
Each now derives its own (see :mod:`myownca.secret_keys`), and their service
ciphers read legacy ciphertext through a fallback — so nothing breaks without
this sweep. The sweep exists to *finish* the job: once every row is converted,
the legacy fallback can be retired and cross-subsystem reads stop working.

Design notes:

* **Scoped by table and column, never by "does it decrypt".** Under the old
  scheme a comms token also opens under the service-certs key, so selecting rows
  by decryptability would re-encrypt other subsystems' data into the wrong domain.
* **Idempotent by inspection, not by marker.** A row already readable under its
  domain key is left byte-identical. Re-running is free and safe, so a marker is
  an optimisation rather than a correctness gate.
* **Empty and NULL are normal.** ``''`` is how a comms channel with no secrets is
  stored and ``NULL`` how an ACME account with no DNS provider is stored; both are
  skipped, not treated as corruption.
* **A single bad row never aborts the run** — it is counted and reported. But if
  *every* row fails, that is a wrong operator secret rather than a corpus of junk,
  and the sweep refuses to write anything at all.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from cryptography.fernet import Fernet, InvalidToken

from myownca.secret_keys import (
    CA_AUTH_DOMAIN,
    COMMS_DOMAIN,
    SERVICE_CERTS_DOMAIN,
    derive_fernet_key,
    legacy_fernet_key,
)

#: (table, ciphertext column, primary-key column, domain)
TARGETS: tuple[tuple[str, str, str, str], ...] = (
    ("totp_factors", "secret_ciphertext", "user_id", CA_AUTH_DOMAIN),
    ("comms_channel_configs", "secret_ciphertext", "channel", COMMS_DOMAIN),
    ("acme_accounts", "account_key_ciphertext", "id", SERVICE_CERTS_DOMAIN),
    ("acme_accounts", "dns_credentials_ciphertext", "id", SERVICE_CERTS_DOMAIN),
)


@dataclass
class ReencryptResult:
    converted: int = 0
    already_current: int = 0
    skipped_empty: int = 0
    failed: int = 0
    failures: list[str] = field(default_factory=list)
    per_column: dict[str, int] = field(default_factory=dict)

    @property
    def considered(self) -> int:
        return self.converted + self.already_current + self.failed


def reencrypt_secrets(
    database,
    secret: str,
    *,
    to_legacy: bool = False,
    dry_run: bool = False,
) -> ReencryptResult:
    """Convert every stored secret to the domain keys (or back, with ``to_legacy``).

    Raises ``ValueError`` without writing anything if no row decrypts under either
    key, which means the configured operator secret is wrong.
    """
    legacy = Fernet(legacy_fernet_key(secret))
    result = ReencryptResult()
    pending: list[tuple[str, str, str, str, str]] = []  # table, col, pk_col, pk, new value

    for table, column, pk_col, domain in TARGETS:
        target = Fernet(derive_fernet_key(secret, domain))
        source, destination = (target, legacy) if to_legacy else (legacy, target)
        label = f"{table}.{column}"
        with database.connect() as connection:
            rows = connection.execute(
                f"SELECT {pk_col} AS pk, {column} AS value FROM {table}"
            ).fetchall()

        for row in rows:
            pk, value = row["pk"], row["value"]
            if not value:  # NULL or '' — both legitimate, nothing to convert
                result.skipped_empty += 1
                continue
            raw = value.encode()
            try:  # already in the destination domain?
                destination.decrypt(raw)
            except InvalidToken:
                pass
            else:
                result.already_current += 1
                continue
            try:
                plaintext = source.decrypt(raw)
            except InvalidToken:
                result.failed += 1
                result.failures.append(
                    f"{label}[{pk}]: does not decrypt under either key"
                )
                continue
            pending.append((table, column, pk_col, pk, destination.encrypt(plaintext).decode()))
            result.converted += 1
            result.per_column[label] = result.per_column.get(label, 0) + 1

    # Every row failing is a wrong secret, not junk data. Refuse rather than
    # rewrite a corpus we cannot actually read.
    if result.failed and not result.converted and not result.already_current:
        raise ValueError(
            "No stored secret could be decrypted. This almost certainly means "
            "MYOWNCA_AUTH_ENCRYPTION_SECRET differs from the value used when they "
            "were stored; nothing was modified."
        )

    if dry_run or not pending:
        return result

    with database.connect() as connection:
        for table, column, pk_col, pk, new_value in pending:
            connection.execute(
                f"UPDATE {table} SET {column} = ? WHERE {pk_col} = ?", (new_value, pk)
            )
    return result
