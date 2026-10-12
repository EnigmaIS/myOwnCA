"""Public access requests with mandatory email verification.

Anyone can submit the form; only code-confirmed (``pending``) requests reach
the superuser queue and fire the ``access_requested`` notification. Codes are
hashed at rest, expire quickly, and lock after repeated failures. Rate
limiting is two-layered: per-email here (DB-backed), per-IP in the web layer.
"""

from __future__ import annotations

import hmac
import secrets
from datetime import datetime, timedelta
from uuid import uuid4

from myownca.holder.base import AccessRequest, AccessRequestStatus
from myownca.holder.links import OTP_DIGITS, _hash, _utc_now
from myownca.holder.repository import AccessRequestRepository
from myownca.storage.repositories import RepositoryError

VERIFY_TTL_MINUTES = 15
VERIFY_MAX_ATTEMPTS = 5
MAX_PER_EMAIL_PER_DAY = 3

_MAX_EMAIL = 200
_MAX_NAME = 200
_MAX_MESSAGE = 2000
_KINDS = ("user", "device")


class AccessRequestError(ValueError):
    """Invalid submission or an impossible state transition."""


class AccessRequestService:
    def __init__(self, repository: AccessRequestRepository) -> None:
        self.repository = repository

    def submit(
        self,
        *,
        email: str,
        name: str = "",
        kind: str = "user",
        message: str = "",
        now: datetime | None = None,
    ) -> tuple[AccessRequest, str] | None:
        """Create an unverified request and return it with the emailable code.

        Returns None (no row, no code) when the per-email budget is exhausted —
        callers respond identically either way (no enumeration, no flooding).
        """
        moment = _utc_now(now)
        email = email.strip().lower()[:_MAX_EMAIL]
        if "@" not in email or len(email) < 4:
            raise AccessRequestError("A valid email address is required")
        if kind not in _KINDS:
            raise AccessRequestError(f"Unknown certificate kind: {kind}")
        recent = self.repository.count_recent_for_email(
            email, moment - timedelta(days=1)
        )
        if recent >= MAX_PER_EMAIL_PER_DAY:
            return None
        code = f"{secrets.randbelow(10**OTP_DIGITS):0{OTP_DIGITS}d}"
        request = AccessRequest(
            id=str(uuid4()),
            email=email,
            name=name.strip()[:_MAX_NAME],
            kind=kind,
            message=message.strip()[:_MAX_MESSAGE],
            status=AccessRequestStatus.UNVERIFIED,
            created_at=moment,
            verify_code_hash=_hash(code),
            verify_expires_at=moment + timedelta(minutes=VERIFY_TTL_MINUTES),
        )
        self.repository.add(request)
        return request, code

    def verify(
        self, request_id: str, code: str | None, *, now: datetime | None = None
    ) -> AccessRequest | None:
        """The pending request on success; None on any failure (locks at 5)."""
        moment = _utc_now(now)
        try:
            request = self.repository.get(request_id)
        except RepositoryError:
            return None
        if request.status is not AccessRequestStatus.UNVERIFIED:
            return None
        valid = (
            request.verify_code_hash is not None
            and request.verify_expires_at is not None
            and request.verify_expires_at > moment
            and request.verify_attempts < VERIFY_MAX_ATTEMPTS
            and hmac.compare_digest(request.verify_code_hash, _hash(code or ""))
        )
        if valid:
            self.repository.mark_verified(request.id, moment)
            return self.repository.get(request.id)
        attempts = request.verify_attempts + 1
        self.repository.set_verify_attempts(
            request.id, attempts, clear_code=attempts >= VERIFY_MAX_ATTEMPTS
        )
        return None

    def decide(
        self,
        request_id: str,
        *,
        approve: bool,
        decided_by: str,
        now: datetime | None = None,
    ) -> AccessRequest:
        request = self.repository.get(request_id)  # RepositoryError on unknown
        if request.status is not AccessRequestStatus.PENDING:
            raise AccessRequestError(
                f"Only pending requests can be decided (status: {request.status.value})"
            )
        status = AccessRequestStatus.APPROVED if approve else AccessRequestStatus.DENIED
        self.repository.decide(
            request.id, status, decided_by=decided_by, decided_at=_utc_now(now)
        )
        return self.repository.get(request.id)

    def list_requests(self, *, status: AccessRequestStatus | None = None) -> list[AccessRequest]:
        return self.repository.list(status=status)
