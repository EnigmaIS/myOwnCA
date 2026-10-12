from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
from datetime import datetime, timezone
from urllib.parse import quote, urlencode


def generate_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def provisioning_uri(secret: str, email: str, issuer: str = "myOwnCA") -> str:
    label = quote(f"{issuer}:{email}")
    query = urlencode(
        {
            "secret": secret,
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": "6",
            "period": "30",
        }
    )
    return f"otpauth://totp/{label}?{query}"


def code_for_step(secret: str, step: int, digits: int = 6) -> str:
    padded = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded.upper())
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10**digits)).zfill(digits)


def current_step(now: datetime | None = None, period_seconds: int = 30) -> int:
    value = now or datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return int(value.timestamp()) // period_seconds
