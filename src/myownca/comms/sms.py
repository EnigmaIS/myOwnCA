from __future__ import annotations

import json
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from myownca.comms._http import http_send
from myownca.comms.base import (
    ChannelConfig,
    CommsConfigError,
    CommsError,
    DeliveryResult,
    Message,
    NotificationChannel,
)

_DEFAULT_BODY_TEMPLATE = '{"to":"{recipient}","message":"{body}"}'
_VALID_METHODS = {"GET", "POST", "PUT"}
_FORM_MEDIA_TYPE = "application/x-www-form-urlencoded"

# Chosen so that a channel configured before these options existed -- POST, no
# parameter names, no template -- produces the byte-identical request it always
# did: {"to": ..., "message": ...} as JSON.
_DEFAULT_RECIPIENT_PARAM = "to"
_DEFAULT_MESSAGE_PARAM = "message"


def send_sms(config: ChannelConfig, recipient: str, message: Message) -> DeliveryResult:
    """Send an SMS through a provider-neutral HTTP broker.

    Brokers disagree about almost everything, so the operator chooses the method,
    the parameter carrying the phone number, and the parameter carrying the text.

    - ``GET`` puts both parameters in the query string.
    - ``POST``/``PUT`` put them in the body: form-encoded when the configured
      ``Content-Type`` says so, otherwise JSON.
    - ``extra_params`` carries the static fields a broker requires alongside the
      message -- account, sender id, message type -- as ``name=value`` pairs.
    - Both parameter values and header values may reference ``{password}`` or
      ``{bearer_token}``, which pull in the encrypted secret at send time, so a
      broker credential is never stored in the cleartext config column.
    - ``body_template`` remains available for brokers that need a payload shape
      these parameters cannot express; when set it takes precedence.
    """
    url = str(config.config.get("url") or "").strip()
    if not url:
        raise CommsConfigError("SMS channel requires 'url'")
    if not recipient:
        raise CommsError("SMS recipient is required")

    method = str(config.config.get("method") or "POST").strip().upper()
    if method not in _VALID_METHODS:
        raise CommsConfigError(
            f"Unsupported SMS HTTP method: {method}. Use one of "
            + ", ".join(sorted(_VALID_METHODS))
        )

    # Header values take the same secret placeholders as the parameters, so a
    # broker wanting its credential in a custom header -- X-Api-Key, or a
    # non-Bearer Authorization scheme -- keeps it in the encrypted secret
    # instead of the cleartext config column.
    headers = {
        str(k): _substitute_secrets(str(v), config)
        for k, v in (config.config.get("headers") or {}).items()
    }
    bearer_token = config.secrets.get("bearer_token")
    if bearer_token:
        headers.setdefault("Authorization", f"Bearer {bearer_token}")

    template = str(config.config.get("body_template") or "").strip()
    if template and method == "GET":
        raise CommsConfigError(
            "A GET request has no body, so 'body_template' cannot be used with GET. "
            "Clear the template, or choose POST or PUT."
        )

    if template:
        headers.setdefault("Content-Type", "application/json")
        data = _rendered_template_body(template, recipient, message)
    elif method == "GET":
        url = _with_query(url, _parameters(config, recipient, message))
        data = None
    else:
        data, content_type = _parameter_body(config, recipient, message, headers)
        headers.setdefault("Content-Type", content_type)

    status, body = http_send(method, url, headers=headers, data=data)
    return DeliveryResult(
        channel=NotificationChannel.SMS,
        recipient=recipient,
        success=200 <= status < 300,
        detail=body[:500],
        status_code=status,
    )


def _parameters(
    config: ChannelConfig, recipient: str, message: Message
) -> dict[str, str]:
    # Strip before falling back, so a field left blank and a field holding only
    # spaces both mean "not set" rather than one defaulting and the other failing.
    recipient_param = (
        str(config.config.get("recipient_param") or "").strip() or _DEFAULT_RECIPIENT_PARAM
    )
    message_param = (
        str(config.config.get("message_param") or "").strip() or _DEFAULT_MESSAGE_PARAM
    )
    if recipient_param == message_param:
        # Otherwise one silently overwrites the other and the broker receives a
        # message addressed to the message text, or vice versa.
        raise CommsConfigError(
            "SMS 'recipient_param' and 'message_param' must differ; both are "
            f"set to '{recipient_param}'"
        )

    parameters = _extra_params(config)
    for name, label in ((recipient_param, "recipient_param"), (message_param, "message_param")):
        if name in parameters:
            # Silently letting one win would send the account name as the phone
            # number, or the message text as the sender id.
            raise CommsConfigError(
                f"SMS extra parameter '{name}' collides with {label}; "
                "remove it from the extra parameters or rename one of them"
            )
    parameters[recipient_param] = recipient
    parameters[message_param] = message.body
    return parameters


def _extra_params(config: ChannelConfig) -> dict[str, str]:
    """Static broker fields, with encrypted secrets substituted into values."""

    raw = config.config.get("extra_params") or {}
    if not isinstance(raw, dict):
        raise CommsConfigError("SMS 'extra_params' must be a mapping of name to value")
    resolved: dict[str, str] = {}
    for name, value in raw.items():
        name = str(name).strip()
        if not name:
            raise CommsConfigError("SMS extra parameters must each have a name")
        resolved[name] = _substitute_secrets(str(value), config)
    return resolved


def _substitute_secrets(value: str, config: ChannelConfig) -> str:
    for secret_name in ("password", "bearer_token"):
        placeholder = "{" + secret_name + "}"
        if placeholder in value:
            secret = config.secrets.get(secret_name) or ""
            if not secret:
                raise CommsConfigError(
                    f"SMS extra parameters reference {placeholder} but no "
                    f"{secret_name} is configured"
                )
            value = value.replace(placeholder, secret)
    return value


def _parameter_body(
    config: ChannelConfig,
    recipient: str,
    message: Message,
    headers: dict[str, str],
) -> tuple[bytes, str]:
    parameters = _parameters(config, recipient, message)
    declared = next(
        (value for key, value in headers.items() if key.lower() == "content-type"),
        "",
    )
    if _FORM_MEDIA_TYPE in declared.lower():
        return urlencode(parameters).encode(), _FORM_MEDIA_TYPE
    return json.dumps(parameters).encode(), "application/json"


def _rendered_template_body(template: str, recipient: str, message: Message) -> bytes:
    rendered = _render(template, recipient, message)
    try:
        json.loads(rendered)
    except json.JSONDecodeError as exc:
        raise CommsConfigError("SMS body_template must render valid JSON") from exc
    return rendered.encode()


def _with_query(url: str, parameters: dict[str, str]) -> str:
    # Preserve any query the broker URL already carries (an API key, say) rather
    # than replacing it.
    parts = urlsplit(url)
    existing = parse_qsl(parts.query, keep_blank_values=True)
    merged = existing + list(parameters.items())
    return urlunsplit(parts._replace(query=urlencode(merged)))


def _render(template: str, recipient: str, message: Message) -> str:
    def esc(value: str) -> str:
        return json.dumps(value)[1:-1]

    return (
        template.replace("{recipient}", esc(recipient))
        .replace("{subject}", esc(message.subject))
        .replace("{body}", esc(message.body))
    )
