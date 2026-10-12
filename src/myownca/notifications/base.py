from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from myownca.comms import NotificationChannel


class NotificationEvent(StrEnum):
    EXPIRING = "expiring"
    ISSUED = "issued"
    REQUESTED = "requested"
    EXPIRED = "expired"
    OTP = "otp"
    ACCESS_REQUESTED = "access_requested"
    CLOUD_SIGNING_ALERT = "cloud_signing_alert"


class NotificationFormat(StrEnum):
    TEXT = "text"
    HTML = "html"


class NotificationAudience(StrEnum):
    HOLDER = "holder"
    REQUESTER = "requester"
    APPROVERS = "approvers"
    OPERATORS = "operators"


@dataclass(frozen=True, slots=True)
class NotificationTemplate:
    name: str
    event_type: NotificationEvent
    format: NotificationFormat = NotificationFormat.TEXT
    subject: str = ""
    body: str = ""
    updated_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class NotificationRule:
    id: str
    event_type: NotificationEvent
    template_name: str
    channel: NotificationChannel
    audience: NotificationAudience = NotificationAudience.HOLDER
    enabled: bool = True
    period_days: int = 1
    threshold_days: int = 30
    notification_text: str = ""
    last_run_at: datetime | None = None
    # expiring/expired rules: mint a renewal claim link per matched cert and
    # expose it to the template as $renewal_url / $link_expires.
    include_renewal_link: bool = False


@dataclass(frozen=True, slots=True)
class NotificationLogEntry:
    id: str
    event_type: str
    template_name: str
    channel: str
    recipient: str
    sent_at: datetime
    rule_id: str | None = None
    subject: str = ""
    object_ref: str | None = None
    success: bool = False
    detail: str = ""
    metadata: dict[str, object] = field(default_factory=dict)
