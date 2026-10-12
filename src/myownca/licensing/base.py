from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

# Free tier: usable with no license at all.
FREE_TIER_LIMIT = 10
LICENSE_PRODUCT = "myownca-self-hosted"
LICENSE_SCHEMA = 2


class LicenseStatus(StrEnum):
    NONE = "none"            # no license installed → free tier
    VALID = "valid"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    INVALID = "invalid"      # signature/format failure → tamper signal


class LicenseError(ValueError):
    """A token cannot be decoded or its signature does not verify."""


class LicenseInstallationMismatchError(LicenseError):
    """A valid token belongs to a different installation."""


class LicenseLimitError(RuntimeError):
    """Issuing this certificate would exceed licensed lineage capacity."""


class DuplicateCertificateIdentityError(RuntimeError):
    """A first issuance duplicates an active certificate identity."""


class LicenseStateError(RuntimeError):
    """Licensing state cannot be trusted enough to authorize new growth."""


@dataclass(frozen=True, slots=True)
class License:
    """A signature-verified license payload.

    Holding an instance means the RSA-4096 PSS/SHA-256 signature checked out; whether it is
    *currently in force* still depends on its validity window (see
    ``status``/``is_active``), evaluated against the current time at use.
    """

    license_id: str
    licensed_to: str
    installation_id: str
    issued_at: datetime
    valid_from: datetime
    expires_at: datetime
    max_certificate_lineages: int
    key_id: str
    product: str = LICENSE_PRODUCT
    schema: int = LICENSE_SCHEMA

    def status(self, now: datetime) -> LicenseStatus:
        if now < self.valid_from:
            return LicenseStatus.NOT_YET_VALID
        if now >= self.expires_at:
            return LicenseStatus.EXPIRED
        return LicenseStatus.VALID

    def is_active(self, now: datetime) -> bool:
        return self.status(now) is LicenseStatus.VALID

    def days_remaining(self, now: datetime) -> int:
        return max((self.expires_at - now).days, 0)

    @property
    def max_active_certs(self) -> int:
        """One-release compatibility alias for schema-1 callers."""

        return self.max_certificate_lineages
