from __future__ import annotations

import json
from datetime import datetime, timezone


from myownca.secret_keys import (
    COMMS_DOMAIN,
    decrypt_secret,
    derive_fernet_key,
    domain_cipher,
)
from myownca.comms.base import (
    ChannelConfig,
    CommsConfigError,
    CommsError,
    DeliveryResult,
    Message,
    NotificationChannel,
)
from myownca.comms.email import send_email
from myownca.comms.httpreq import send_https
from myownca.comms.sms import send_sms
from myownca.comms.repository import CommsRepository
from myownca.comms.slack import send_slack
from myownca.comms.webhook import send_webhook

# Which secret keys each channel understands (used for redaction + merge).
_SECRET_KEYS: dict[NotificationChannel, tuple[str, ...]] = {
    NotificationChannel.EMAIL: ("password",),
    NotificationChannel.SMS: ("bearer_token", "password"),
    NotificationChannel.SLACK: ("bot_token",),
    NotificationChannel.WEBHOOK: ("signing_secret",),
    NotificationChannel.HTTPS: ("bearer_token",),
}

_NOTIFIERS = {
    NotificationChannel.EMAIL: send_email,
    NotificationChannel.SMS: send_sms,
    NotificationChannel.SLACK: send_slack,
    NotificationChannel.WEBHOOK: send_webhook,
    NotificationChannel.HTTPS: send_https,
}


class CommsService:
    """Transport-only notification dispatcher.

    Callers provide the channel, recipient, and message; this service loads the
    channel's stored (and decrypted) configuration and delivers it. It never
    composes content or resolves who a certificate holder is.
    """

    def __init__(self, repository: CommsRepository, encryption_secret: str) -> None:
        self.repository = repository
        self.cipher = domain_cipher(encryption_secret, COMMS_DOMAIN)

    def get_config(self, channel: NotificationChannel) -> ChannelConfig | None:
        stored = self.repository.get(channel.value)
        if stored is None:
            return None
        secrets = self._decrypt_secrets(stored.secret_ciphertext)
        return ChannelConfig(
            channel=channel,
            enabled=stored.enabled,
            config=json.loads(stored.config_json or "{}"),
            secrets=secrets,
            updated_at=stored.updated_at,
        )

    def list_configs_redacted(self) -> list[dict[str, object]]:
        results: list[dict[str, object]] = []
        for channel in NotificationChannel:
            config = self.get_config(channel)
            results.append(self._redact(channel, config))
        return results

    def set_config(
        self,
        channel: NotificationChannel,
        *,
        enabled: bool,
        config: dict[str, object],
        secrets: dict[str, str] | None = None,
    ) -> dict[str, object]:
        existing = self.get_config(channel)
        merged_secrets = dict(existing.secrets) if existing else {}
        for key, value in (secrets or {}).items():
            # Empty value means "leave the stored secret unchanged" so admins
            # need not re-enter passwords/tokens on every edit.
            if value:
                merged_secrets[key] = value
        secret_ciphertext = self._encrypt_secrets(merged_secrets)
        self.repository.upsert(
            channel=channel.value,
            enabled=enabled,
            config_json=json.dumps(config),
            secret_ciphertext=secret_ciphertext,
            updated_at=datetime.now(timezone.utc),
        )
        return self._redact(channel, self.get_config(channel))

    def send(
        self,
        channel: NotificationChannel,
        recipient: str,
        message: Message,
    ) -> DeliveryResult:
        if message.attachments and channel is not NotificationChannel.EMAIL:
            raise CommsError("Attachments are supported only by the email channel")
        config = self.get_config(channel)
        if config is None or not config.enabled:
            raise CommsConfigError(f"Channel '{channel.value}' is not configured or disabled")
        notifier = _NOTIFIERS[channel]
        return notifier(config, recipient, message)

    # -- internals ------------------------------------------------------------

    def _encrypt_secrets(self, secrets: dict[str, str]) -> str:
        if not secrets:
            return ""
        return self.cipher.encrypt(json.dumps(secrets).encode()).decode()

    def _decrypt_secrets(self, ciphertext: str) -> dict[str, str]:
        if not ciphertext:
            return {}
        return json.loads(
            decrypt_secret(self.cipher, ciphertext, what="Stored notification-channel secrets")
        )

    @staticmethod
    def _redact(channel: NotificationChannel, config: ChannelConfig | None) -> dict[str, object]:
        secret_keys = _SECRET_KEYS.get(channel, ())
        if config is None:
            return {
                "channel": channel.value,
                "enabled": False,
                "config": {},
                "secrets_set": {key: False for key in secret_keys},
                "updated_at": None,
            }
        return {
            "channel": channel.value,
            "enabled": config.enabled,
            "config": config.config,
            "secrets_set": {key: bool(config.secrets.get(key)) for key in secret_keys},
            "updated_at": config.updated_at.isoformat() if config.updated_at else None,
        }


def _derive_fernet_key(secret: str) -> bytes:
    """This subsystem's domain-separated Fernet key (see myownca.secret_keys)."""
    return derive_fernet_key(secret, COMMS_DOMAIN)
