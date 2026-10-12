from __future__ import annotations

import json

from myownca.comms._http import http_send
from myownca.comms.base import (
    ChannelConfig,
    CommsConfigError,
    DeliveryResult,
    Message,
    NotificationChannel,
)

_DEFAULT_BODY_TEMPLATE = '{"recipient": "{recipient}", "subject": "{subject}", "body": "{body}"}'
_VALID_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}


def send_https(config: ChannelConfig, recipient: str, message: Message) -> DeliveryResult:
    """Send a fully configurable HTTPS request.

    The operator configures method, URL, headers, and a body template with
    ``{recipient}``, ``{subject}``, and ``{body}`` placeholders (substituted with
    JSON-escaped values). An optional ``bearer_token`` secret is sent as a
    Bearer Authorization header.
    """
    url = str(config.config.get("url") or "").strip()
    if not url:
        raise CommsConfigError("HTTPS channel requires 'url'")
    method = str(config.config.get("method") or "POST").upper()
    if method not in _VALID_METHODS:
        raise CommsConfigError(f"Unsupported HTTP method: {method}")

    headers = {str(k): str(v) for k, v in (config.config.get("headers") or {}).items()}
    headers.setdefault("Content-Type", "application/json")
    bearer_token = config.secrets.get("bearer_token")
    if bearer_token:
        headers.setdefault("Authorization", f"Bearer {bearer_token}")

    template = str(config.config.get("body_template") or _DEFAULT_BODY_TEMPLATE)
    rendered = _render(template, recipient, message)
    data = rendered.encode() if method not in {"GET", "DELETE"} else None

    status, body = http_send(method, url, headers=headers, data=data)
    success = 200 <= status < 300
    return DeliveryResult(
        channel=NotificationChannel.HTTPS,
        recipient=recipient or url,
        success=success,
        detail=body[:500],
        status_code=status,
    )


def _render(template: str, recipient: str, message: Message) -> str:
    # JSON-escape each value (without surrounding quotes) so substituting into a
    # JSON body template cannot break the document or allow injection.
    def esc(value: str) -> str:
        return json.dumps(value)[1:-1]

    return (
        template.replace("{recipient}", esc(recipient))
        .replace("{subject}", esc(message.subject))
        .replace("{body}", esc(message.body))
    )
