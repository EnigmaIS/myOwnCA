"""Secure claim links for certificate holders.

A link is a 256-bit URL token bound to purpose + person + object. The token,
the email OTP code, and the post-OTP claim-session cookie are all stored
hashed; the plaintext token exists only in the outbound message, the code
only in the OTP email, the session value only in the holder's cookie.
Opening a link reveals nothing until the OTP step passes — the code always
goes to the registered person email, so a forwarded link is inert by itself.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from myownca.holder.base import LinkPurpose, SecureLink
from myownca.holder.repository import SecureLinkRepository
from myownca.storage.repositories import RepositoryError

OTP_DIGITS = 6
OTP_TTL_MINUTES = 10
OTP_MAX_ATTEMPTS = 5
SESSION_TTL_MINUTES = 30
_TOKEN_BYTES = 32

DEFAULT_EXPIRY_DAYS: dict[LinkPurpose, int] = {
    LinkPurpose.DELIVERY: 7,
    LinkPurpose.RENEWAL: 14,
    LinkPurpose.ENROLLMENT: 14,
}
DEFAULT_MAX_USES: dict[LinkPurpose, int] = {
    LinkPurpose.DELIVERY: 3,
    LinkPurpose.RENEWAL: 1,
    LinkPurpose.ENROLLMENT: 3,
}


class SecureLinkError(ValueError):
    """A link cannot be minted or used as requested."""


def link_policy(pki_repository, purpose: LinkPurpose) -> tuple[int, int]:
    """(expiry_days, max_uses) — superuser settings with library defaults."""
    expiry = _int_setting(
        pki_repository, f"holder_link_expiry_days_{purpose.value}", DEFAULT_EXPIRY_DAYS[purpose]
    )
    uses = _int_setting(
        pki_repository, f"holder_link_max_uses_{purpose.value}", DEFAULT_MAX_USES[purpose]
    )
    return expiry, uses


def mask_email(email: str) -> str:
    """A hint safe to show pre-OTP: 'j***@example.test'."""
    local, _, domain = email.partition("@")
    masked = f"{local[0]}***" if local else "***"
    return f"{masked}@{domain}" if domain else masked


class SecureLinkService:
    def __init__(self, repository: SecureLinkRepository, pki_repository) -> None:
        self.repository = repository
        self.pki_repository = pki_repository

    # -- minting ---------------------------------------------------------------

    def mint(
        self,
        purpose: LinkPurpose | str,
        *,
        created_by: str,
        serial_number: str | None = None,
        certificate_id: str | None = None,
        person_id: str | None = None,
        expires_days: int | None = None,
        max_uses: int | None = None,
        now: datetime | None = None,
    ) -> tuple[SecureLink, str]:
        """Create a link and return it with the plaintext token (shown once)."""
        purpose = LinkPurpose(purpose)
        moment = _utc_now(now)
        person, certificate = self._resolve_recipient(
            purpose,
            serial_number=serial_number,
            certificate_id=certificate_id,
            person_id=person_id,
        )
        if certificate is not None:
            serial_number = certificate.serial_number
            certificate_id = certificate.certificate_id or certificate.serial_number
        elif purpose is LinkPurpose.ENROLLMENT:
            certificate_id = None
        policy_expiry, policy_uses = link_policy(self.pki_repository, purpose)
        token = secrets.token_urlsafe(_TOKEN_BYTES)
        link = SecureLink(
            id=str(uuid4()),
            token_hash=_hash(token),
            purpose=purpose,
            person_id=person.id,
            serial_number=serial_number,
            certificate_id=certificate_id,
            created_by=created_by,
            created_at=moment,
            expires_at=moment + timedelta(days=expires_days or policy_expiry),
            max_uses=max_uses or policy_uses,
        )
        self.repository.add_link(link)
        return link, token

    def _resolve_recipient(
        self,
        purpose: LinkPurpose,
        *,
        serial_number: str | None,
        certificate_id: str | None,
        person_id: str | None,
    ):
        certificate = None
        try:
            if purpose is LinkPurpose.ENROLLMENT:
                if not person_id:
                    raise SecureLinkError("Enrollment links require a person")
                person = self.pki_repository.get_person(person_id)
            else:
                if certificate_id:
                    certificate = self.pki_repository.get_certificate_by_id(certificate_id)
                    if serial_number and certificate.serial_number != serial_number:
                        raise SecureLinkError(
                            "Certificate id does not match the supplied serial number"
                        )
                elif serial_number:
                    certificate = self.pki_repository.get_issued_certificate(serial_number)
                else:
                    raise SecureLinkError(
                        f"{purpose.value} links require a certificate id or serial"
                    )
                person = (
                    self.pki_repository.get_person(person_id)
                    if person_id
                    else self._holder_person(certificate)
                )
        except RepositoryError as exc:
            raise SecureLinkError(str(exc)) from exc
        if person is None or not person.email:
            raise SecureLinkError("Link recipient has no email address for the OTP step")
        return person, certificate

    def _holder_person(self, certificate):
        """The cert's person, or a device's responsible admin."""
        if certificate.holder_person_id:
            return self.pki_repository.get_person(certificate.holder_person_id)
        if certificate.holder_device_id:
            device = self.pki_repository.get_device(certificate.holder_device_id)
            return self.pki_repository.get_person(device.admin_id)
        return None

    # -- state -----------------------------------------------------------------

    def find_by_token(self, token: str | None) -> SecureLink | None:
        if not token:
            return None
        return self.repository.get_by_token_hash(_hash(token))

    def usability(self, link: SecureLink, *, now: datetime | None = None) -> str | None:
        """None when the link can start a new OTP cycle, else the reason."""
        moment = _utc_now(now)
        if link.revoked_at is not None:
            return "revoked"
        if link.locked_at is not None:
            return "locked"
        if link.expires_at <= moment:
            return "expired"
        if link.use_count >= link.max_uses:
            return "exhausted"
        return None

    def recipient_email(self, link: SecureLink) -> str:
        try:
            person = self.pki_repository.get_person(link.person_id)
        except RepositoryError as exc:
            raise SecureLinkError(str(exc)) from exc
        if not person.email:
            raise SecureLinkError("Link recipient no longer has an email address")
        return person.email

    # -- OTP + claim sessions ----------------------------------------------------

    def start_otp(self, link: SecureLink, *, now: datetime | None = None) -> str:
        """Generate a fresh code (caller sends it to ``recipient_email``).

        Re-sending replaces the code but keeps the failed-attempt counter —
        resending must not reset the lockout budget.
        """
        moment = _utc_now(now)
        reason = self.usability(link, now=moment)
        if reason:
            raise SecureLinkError(f"Link is {reason}")
        code = f"{secrets.randbelow(10**OTP_DIGITS):0{OTP_DIGITS}d}"
        current = self.repository.get_link(link.id)
        self.repository.set_otp_state(
            link.id,
            otp_hash=_hash(code),
            otp_expires_at=moment + timedelta(minutes=OTP_TTL_MINUTES),
            otp_attempts=current.otp_attempts,
        )
        return code

    def verify_otp(
        self, link: SecureLink, code: str | None, *, now: datetime | None = None
    ) -> str | None:
        """A claim-session token on success; None on failure (locks after 5)."""
        moment = _utc_now(now)
        current = self.repository.get_link(link.id)
        if self.usability(current, now=moment):
            return None
        valid = (
            current.otp_hash is not None
            and current.otp_expires_at is not None
            and current.otp_expires_at > moment
            and hmac.compare_digest(current.otp_hash, _hash(code or ""))
        )
        if valid:
            session_token = secrets.token_urlsafe(_TOKEN_BYTES)
            self.repository.start_session(
                current.id,
                session_token_hash=_hash(session_token),
                session_expires_at=moment + timedelta(minutes=SESSION_TTL_MINUTES),
                use_count=current.use_count + 1,
                last_used_at=moment,
            )
            return session_token
        attempts = current.otp_attempts + 1
        if attempts >= OTP_MAX_ATTEMPTS:
            self.repository.set_locked(current.id, moment)
        else:
            self.repository.set_otp_state(
                current.id,
                otp_hash=current.otp_hash,
                otp_expires_at=current.otp_expires_at,
                otp_attempts=attempts,
            )
        return None

    def session_link(
        self, token: str | None, session_token: str | None, *, now: datetime | None = None
    ) -> SecureLink | None:
        """The link when token + claim session are valid, else None.

        An exhausted link does NOT invalidate its already-open session — the
        last permitted session may run to its own expiry. Revocation, locking,
        and link expiry do.
        """
        moment = _utc_now(now)
        link = self.find_by_token(token)
        if link is None or not session_token:
            return None
        if link.revoked_at is not None or link.locked_at is not None:
            return None
        if link.expires_at <= moment:
            return None
        if (
            link.session_token_hash is None
            or link.session_expires_at is None
            or link.session_expires_at <= moment
        ):
            return None
        if not hmac.compare_digest(link.session_token_hash, _hash(session_token)):
            return None
        return link

    def consume(self, link: SecureLink, *, now: datetime | None = None) -> None:
        """Mark a link fully used (e.g. a renewal was submitted through it)."""
        self.repository.consume(link.id, max_uses=link.max_uses, last_used_at=_utc_now(now))

    # -- management --------------------------------------------------------------

    def revoke(self, link_id: str, *, now: datetime | None = None) -> SecureLink:
        link = self.repository.get_link(link_id)  # RepositoryError on unknown
        self.repository.set_revoked(link.id, _utc_now(now))
        return self.repository.get_link(link.id)

    def list_links(self) -> list[SecureLink]:
        return self.repository.list_links()


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _int_setting(pki_repository, key: str, default: int) -> int:
    raw = pki_repository.get_setting(key)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _utc_now(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    return current if current.tzinfo else current.replace(tzinfo=timezone.utc)
