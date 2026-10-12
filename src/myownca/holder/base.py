from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class LinkPurpose(StrEnum):
    DELIVERY = "delivery"
    RENEWAL = "renewal"
    ENROLLMENT = "enrollment"


class AccessRequestStatus(StrEnum):
    UNVERIFIED = "unverified"
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"


@dataclass(frozen=True, slots=True)
class AccessRequest:
    """A public "I need a certificate" request. Only email-verified (pending)
    requests reach the superuser queue; the verification code is hashed."""

    id: str
    email: str
    name: str
    kind: str  # user | device
    message: str
    status: AccessRequestStatus
    created_at: datetime
    verify_code_hash: str | None = None
    verify_expires_at: datetime | None = None
    verify_attempts: int = 0
    email_verified_at: datetime | None = None
    decided_by: str | None = None
    decided_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class SecureLink:
    """A single-purpose claim link. All secret material is stored hashed:
    ``token_hash`` (the URL token), ``otp_hash`` (current email code) and
    ``session_token_hash`` (the post-OTP claim session cookie)."""

    id: str
    token_hash: str
    purpose: LinkPurpose
    person_id: str | None
    serial_number: str | None
    created_by: str
    created_at: datetime
    expires_at: datetime
    max_uses: int
    certificate_id: str | None = None
    use_count: int = 0
    revoked_at: datetime | None = None
    locked_at: datetime | None = None
    otp_hash: str | None = None
    otp_expires_at: datetime | None = None
    otp_attempts: int = 0
    session_token_hash: str | None = None
    session_expires_at: datetime | None = None
    last_used_at: datetime | None = None
