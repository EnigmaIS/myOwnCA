from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

# Outbound network calls are best-effort and must never hang a request thread.
DEFAULT_TIMEOUT_SECONDS = 10


class NotificationChannel(StrEnum):
    EMAIL = "email"
    SMS = "sms"
    SLACK = "slack"
    WEBHOOK = "webhook"
    HTTPS = "https"


class CommsError(RuntimeError):
    """Raised when a notification cannot be delivered."""


class CommsConfigError(CommsError):
    """Raised when a channel is misconfigured or disabled."""


@dataclass(frozen=True, slots=True)
class Attachment:
    """A binary attachment carried by an outbound email."""

    content: bytes
    filename: str
    media_type: str = "application/octet-stream"


@dataclass(frozen=True, slots=True)
class Message:
    """Caller-provided content. The module never composes content itself."""

    body: str
    subject: str = ""
    metadata: dict[str, object] = field(default_factory=dict)
    attachments: tuple[Attachment, ...] = ()


@dataclass(frozen=True, slots=True)
class DeliveryResult:
    channel: NotificationChannel
    recipient: str
    success: bool
    detail: str = ""
    status_code: int | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "channel": self.channel.value,
            "recipient": self.recipient,
            "success": self.success,
            "detail": self.detail,
            "status_code": self.status_code,
        }


@dataclass(frozen=True, slots=True)
class ChannelConfig:
    """A channel's stored configuration, with secrets already decrypted.

    ``config`` holds non-secret settings (host, port, urls, …) and ``secrets``
    holds sensitive values (passwords, tokens). They are persisted separately so
    secrets can be encrypted at rest and redacted in API responses.
    """

    channel: NotificationChannel
    enabled: bool
    config: dict[str, object] = field(default_factory=dict)
    secrets: dict[str, str] = field(default_factory=dict)
    updated_at: datetime | None = None
