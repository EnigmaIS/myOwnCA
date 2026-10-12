from __future__ import annotations

import hashlib
import hmac
import json

from myownca.comms._http import http_send
from myownca.comms.base import (
    ChannelConfig,
    CommsConfigError,
    DeliveryResult,
    Message,
    NotificationChannel,
)


def send_webhook(config: ChannelConfig, recipient: str, message: Message) -> DeliveryResult:
    """POST a fixed JSON envelope to a preconfigured webhook URL.

    Optional ``signing_secret`` adds an HMAC-SHA256 signature header so the
    receiver can verify authenticity.
    """
    url = str(config.config.get("url") or "").strip()
    if not url:
        raise CommsConfigError("Webhook channel requires 'url'")

    payload = {
        "recipient": recipient,
        "subject": message.subject,
        "body": message.body,
        "metadata": message.metadata,
    }
    data = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    signing_secret = config.secrets.get("signing_secret")
    if signing_secret:
        signature = hmac.new(signing_secret.encode(), data, hashlib.sha256).hexdigest()
        headers["X-myOwnCA-Signature"] = f"sha256={signature}"

    status, body = http_send("POST", url, headers=headers, data=data)
    success = 200 <= status < 300
    return DeliveryResult(
        channel=NotificationChannel.WEBHOOK,
        recipient=recipient or url,
        success=success,
        detail=body[:500],
        status_code=status,
    )
