from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from myownca.storage.database import Database


@dataclass(frozen=True, slots=True)
class StoredChannelConfig:
    channel: str
    enabled: bool
    config_json: str
    secret_ciphertext: str
    updated_at: datetime


class CommsRepository:
    """Persistence for communication-channel configuration.

    Secrets are stored as opaque ciphertext; encryption/decryption is the
    service's responsibility, mirroring how AuthRepository/AuthService split
    storage from cryptography.
    """

    def __init__(self, database: Database) -> None:
        self.database = database

    def get(self, channel: str) -> StoredChannelConfig | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM comms_channel_configs WHERE channel = ?", (channel,)
            ).fetchone()
        return None if row is None else _from_row(row)

    def list_all(self) -> list[StoredChannelConfig]:
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM comms_channel_configs ORDER BY channel"
            ).fetchall()
        return [_from_row(row) for row in rows]

    def upsert(
        self,
        *,
        channel: str,
        enabled: bool,
        config_json: str,
        secret_ciphertext: str,
        updated_at: datetime | None = None,
    ) -> None:
        when = (updated_at or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO comms_channel_configs(
                    channel, enabled, config_json, secret_ciphertext, updated_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(channel) DO UPDATE SET
                    enabled = excluded.enabled,
                    config_json = excluded.config_json,
                    secret_ciphertext = excluded.secret_ciphertext,
                    updated_at = excluded.updated_at
                """,
                (channel, int(enabled), config_json, secret_ciphertext, when),
            )


def _from_row(row) -> StoredChannelConfig:
    return StoredChannelConfig(
        channel=row["channel"],
        enabled=bool(row["enabled"]),
        config_json=row["config_json"],
        secret_ciphertext=row["secret_ciphertext"],
        updated_at=datetime.fromisoformat(row["updated_at"]),
    )
