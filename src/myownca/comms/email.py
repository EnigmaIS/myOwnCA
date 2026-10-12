from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage

from myownca.comms.base import (
    DEFAULT_TIMEOUT_SECONDS,
    ChannelConfig,
    CommsConfigError,
    CommsError,
    DeliveryResult,
    Message,
    NotificationChannel,
)

_VALID_SECURITY = {"none", "starttls", "ssl"}


def send_email(config: ChannelConfig, recipient: str, message: Message) -> DeliveryResult:
    """Deliver a message to one recipient via an external SMTP/SMTPS server."""
    host = str(config.config.get("host") or "").strip()
    from_address = str(config.config.get("from_address") or "").strip()
    if not host or not from_address:
        raise CommsConfigError("Email channel requires 'host' and 'from_address'")
    if not recipient:
        raise CommsError("Email recipient is required")
    security = str(config.config.get("security") or "starttls").lower()
    if security not in _VALID_SECURITY:
        raise CommsConfigError(f"Unknown email security mode: {security}")
    port = int(config.config.get("port") or (465 if security == "ssl" else 587))
    username = str(config.config.get("username") or "").strip()
    password = config.secrets.get("password") or ""

    email_message = EmailMessage()
    email_message["From"] = from_address
    email_message["To"] = recipient
    email_message["Subject"] = message.subject or "(no subject)"
    if message.metadata.get("content_type") == "html":
        email_message.set_content(message.body, subtype="html")
    else:
        email_message.set_content(message.body)
    for attachment in message.attachments:
        try:
            maintype, subtype = attachment.media_type.split("/", 1)
        except ValueError as exc:
            raise CommsError(f"Invalid attachment media type: {attachment.media_type}") from exc
        email_message.add_attachment(
            attachment.content,
            maintype=maintype,
            subtype=subtype,
            filename=attachment.filename,
        )

    context = ssl.create_default_context()
    try:
        if security == "ssl":
            server = smtplib.SMTP_SSL(host, port, timeout=DEFAULT_TIMEOUT_SECONDS, context=context)
        else:
            server = smtplib.SMTP(host, port, timeout=DEFAULT_TIMEOUT_SECONDS)
        with server:
            server.ehlo()
            if security == "starttls":
                server.starttls(context=context)
                server.ehlo()
            if username:
                server.login(username, password)
            server.send_message(email_message)
    except (smtplib.SMTPException, ssl.SSLError, OSError) as exc:
        raise CommsError(f"SMTP delivery failed: {exc}") from exc

    return DeliveryResult(
        channel=NotificationChannel.EMAIL,
        recipient=recipient,
        success=True,
        detail=f"sent via {host}:{port} ({security})",
    )
