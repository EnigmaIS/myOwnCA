from __future__ import annotations

import json

from myownca.comms._http import http_send
from myownca.comms.base import (
    ChannelConfig,
    CommsConfigError,
    CommsError,
    DeliveryResult,
    Message,
    NotificationChannel,
)

_SLACK_API = "https://slack.com/api"


def send_slack(config: ChannelConfig, recipient: str, message: Message) -> DeliveryResult:
    """Direct-message a Slack user identified by handle, email, or user id.

    The bot token needs every scope the path below uses:

    - ``chat:write`` to post,
    - ``im:write`` to open the DM conversation,
    - ``users:read`` to resolve an ``@handle``,
    - ``users:read.email`` to resolve an email address.

    A bare ``U…``/``W…`` member id skips both lookups and needs only the first
    two. Slack answers a missing scope with ``missing_scope``, naming none, and
    each call is checked in turn -- so fixing one surfaces the next.
    """
    token = config.secrets.get("bot_token")
    if not token:
        raise CommsConfigError("Slack channel requires a bot token")
    if not recipient:
        raise CommsError("Slack recipient is required")

    user_id = _resolve_user_id(token, recipient)
    channel_id = _open_dm(token, user_id)
    text = f"*{message.subject}*\n\n{message.body}" if message.subject else message.body
    _api(token, "chat.postMessage", {"channel": channel_id, "text": text})

    return DeliveryResult(
        channel=NotificationChannel.SLACK,
        recipient=recipient,
        success=True,
        detail=f"delivered to {user_id}",
    )


def _resolve_user_id(token: str, recipient: str) -> str:
    handle = recipient.strip()
    # A bare Slack user/bot id (e.g. U012ABCDEF / W…) can be used directly.
    if handle and handle[0] in {"U", "W"} and "@" not in handle and " " not in handle:
        return handle
    if "@" in handle:
        result = _api(token, "users.lookupByEmail", {"email": handle}, method="GET")
        return result["user"]["id"]
    return _resolve_by_handle(token, handle.lstrip("@"))


def _resolve_by_handle(token: str, handle: str) -> str:
    cursor = ""
    needle = handle.lower()
    while True:
        params = {"limit": "200"}
        if cursor:
            params["cursor"] = cursor
        result = _api(token, "users.list", params, method="GET")
        for member in result.get("members", []):
            profile = member.get("profile", {})
            candidates = {
                str(member.get("name", "")).lower(),
                str(profile.get("display_name", "")).lower(),
                str(profile.get("display_name_normalized", "")).lower(),
            }
            if needle in candidates:
                return member["id"]
        cursor = result.get("response_metadata", {}).get("next_cursor", "")
        if not cursor:
            break
    raise CommsError(f"No Slack user found for handle '{handle}'")


def _open_dm(token: str, user_id: str) -> str:
    result = _api(token, "conversations.open", {"users": user_id})
    return result["channel"]["id"]


def _api(
    token: str,
    method_name: str,
    payload: dict[str, str],
    *,
    method: str = "POST",
) -> dict:
    headers = {"Authorization": f"Bearer {token}"}
    if method == "GET":
        query = "&".join(f"{key}={_quote(value)}" for key, value in payload.items())
        url = f"{_SLACK_API}/{method_name}?{query}"
        status, body = http_send("GET", url, headers=headers)
    else:
        headers["Content-Type"] = "application/json; charset=utf-8"
        url = f"{_SLACK_API}/{method_name}"
        status, body = http_send("POST", url, headers=headers, data=json.dumps(payload).encode())
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as exc:
        raise CommsError(f"Slack {method_name} returned status {status}") from exc
    if not parsed.get("ok"):
        raise CommsError(f"Slack {method_name} error: {parsed.get('error', 'unknown')}")
    return parsed


def _quote(value: str) -> str:
    from urllib.parse import quote

    return quote(value, safe="")
