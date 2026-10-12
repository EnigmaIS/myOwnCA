"""Offline entitlement state and transactional certificate-lineage policy."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable
from uuid import uuid4

from myownca.ca_main.crypto import parse_csr
from myownca.ca_main.identity import certificate_identity_digest
from myownca.domain import CertificateRequest, RequestKind, RequestSource
from myownca.licensing.base import (
    FREE_TIER_LIMIT,
    License,
    LicenseError,
    LicenseInstallationMismatchError,
    LicenseLimitError,
    LicenseStateError,
    LicenseStatus,
)
from myownca.licensing.repository import LicenseRepository
from myownca.licensing.verify import verify_token


@dataclass(frozen=True, slots=True)
class IssuanceAuthorization:
    lineage_id: str
    reservation_request_id: str | None = None


def _utc_now(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    return (
        current.replace(tzinfo=timezone.utc)
        if current.tzinfo is None
        else current.astimezone(timezone.utc)
    )


class LicenseService:
    def __init__(
        self,
        repository: LicenseRepository,
        pki_repository,
        *,
        public_keys: dict[str, str] | None = None,
        key_configuration_error: str | None = None,
    ) -> None:
        self.repository = repository
        self.pki_repository = pki_repository
        self.public_keys = dict(public_keys or {})
        self.key_configuration_error = key_configuration_error
        self._installation_id = repository.installation_id()
        self._last_known_good: License | None = None
        self._last_load_error: str | None = None
        self._event_listener: Callable[[str, dict[str, object]], None] | None = None
        try:
            repository.ensure_lineages(datetime.now(timezone.utc))
        except LicenseStateError:
            # The repository records the diagnostic and issuance enters safe
            # mode; the CA must still start so revocation/CRL/OCSP stay usable.
            pass

    @property
    def installation_id(self) -> str:
        return self._installation_id

    def set_event_listener(
        self, listener: Callable[[str, dict[str, object]], None] | None
    ) -> None:
        self._event_listener = listener

    # -- current license -------------------------------------------------------

    def current(self) -> License | None:
        license, _error = self._load()
        return license

    def verification_error(self) -> str | None:
        _license, error = self._load()
        return error

    def identity(self, now: datetime | None = None) -> dict[str, object]:
        """Public display identity from verified state, without capacity diagnostics."""
        license, error = self._load()
        status = (
            license.status(_utc_now(now))
            if license is not None
            else LicenseStatus.INVALID if error else LicenseStatus.NONE
        )
        return {
            "licensed_to": license.licensed_to if license is not None else None,
            "status": status.value,
            "verification_warning": error is not None,
        }

    def _trusted_public_keys(self) -> dict[str, str]:
        return self.public_keys

    def _load(self) -> tuple[License | None, str | None]:
        try:
            row = self.repository.get()
        except Exception as exc:  # noqa: BLE001 - use a verified in-memory fallback
            error = f"License state unavailable: {exc}"
            self._last_load_error = error
            cached = self._last_known_good
            return cached, error
        if row is None:
            self._last_known_good = None
            self._last_load_error = None
            return None, None
        try:
            if self.key_configuration_error:
                raise LicenseError(self.key_configuration_error)
            license = verify_token(
                row["token"],
                public_keys=self._trusted_public_keys(),
            )
            if license.installation_id != self._installation_id:
                raise LicenseInstallationMismatchError(
                    "License belongs to installation "
                    f"{license.installation_id}, not {self._installation_id}"
                )
        except LicenseError as exc:
            error = str(exc)
            self._last_load_error = error
            cached = self._last_known_good
            if cached is not None and cached.is_active(datetime.now(timezone.utc)):
                return cached, error
            return None, error
        self._last_known_good = license
        self._last_load_error = None
        return license, None

    # -- limits and issuance policy -------------------------------------------

    def active_count(self, now: datetime | None = None) -> int:
        """Compatibility alias: active certificate-lineage count."""

        return self.repository.active_lineage_count(_utc_now(now))

    def reserved_count(self, now: datetime | None = None) -> int:
        return self.repository.reserved_lineage_count(_utc_now(now))

    def effective_limit(self, now: datetime | None = None) -> int:
        moment = _utc_now(now)
        license, _error = self._load()
        if license is not None and license.is_active(moment):
            return max(FREE_TIER_LIMIT, license.max_certificate_lineages)
        return FREE_TIER_LIMIT

    def status(self, now: datetime | None = None) -> LicenseStatus:
        moment = _utc_now(now)
        license, error = self._load()
        if error is not None and license is None:
            return LicenseStatus.INVALID
        if license is None:
            return LicenseStatus.NONE
        return license.status(moment)

    def check_first_issuance(self, now: datetime | None = None) -> None:
        """Compatibility preflight; reservation is the authoritative check."""

        moment = _utc_now(now)
        active = self.active_count(moment)
        reserved = self.reserved_count(moment)
        limit = self.effective_limit(moment)
        if active + reserved >= limit:
            raise LicenseLimitError(
                f"Certificate lineage limit reached ({active}+{reserved}/{limit}). "
                "Free a lineage or install a higher-tier license."
            )

    def authorize_issuance(
        self, request: CertificateRequest, now: datetime | None = None
    ) -> IssuanceAuthorization:
        moment = _utc_now(now)
        if request.kind is RequestKind.RENEWAL:
            lineage_id = request.lineage_id or self.repository.lineage_for_request(request.id)
            if lineage_id is None:
                raise LicenseStateError("Renewal request has no certificate lineage")
            # A genuine renewal never creates capacity: it remains attached to
            # the existing certificate identity regardless of license state.
            return IssuanceAuthorization(lineage_id=lineage_id)

        if (request.holder_person_id is None) == (request.holder_device_id is None):
            raise LicenseStateError("First issuance must have exactly one holder before reserving")
        limit = self.effective_limit(moment)
        digest = certificate_identity_digest(parse_csr(request.csr_pem))
        lineage_id, reservation_expires_at = self.repository.reserve_lineage(
            request_id=request.id,
            template_id=request.template_id,
            holder_person_id=request.holder_person_id,
            holder_device_id=request.holder_device_id,
            identity_digest=digest,
            allow_lineage_reuse=request.source is RequestSource.IMPORT,
            limit=limit,
            now=moment,
        )
        return IssuanceAuthorization(
            lineage_id=lineage_id,
            reservation_request_id=(
                request.id if reservation_expires_at is not None else None
            ),
        )

    def release_issuance(self, authorization: IssuanceAuthorization) -> None:
        if authorization.reservation_request_id is not None:
            self.repository.release_reservation(authorization.reservation_request_id)

    # -- management ------------------------------------------------------------

    def install(self, token: str, *, uploaded_by: str, now: datetime | None = None) -> License:
        if self.key_configuration_error:
            raise LicenseError(self.key_configuration_error)
        license = verify_token(
            token,
            public_keys=self._trusted_public_keys(),
        )
        moment = _utc_now(now)
        if license.installation_id != self._installation_id:
            raise LicenseInstallationMismatchError(
                "License belongs to installation "
                f"{license.installation_id}, not {self._installation_id}"
            )
        status = license.status(moment)
        if status is LicenseStatus.NOT_YET_VALID:
            raise LicenseError("License is not active yet")
        if status is LicenseStatus.EXPIRED:
            raise LicenseError("License is expired")
        self.repository.replace(
            id=str(uuid4()),
            token=token.strip(),
            license_id=license.license_id,
            licensed_to=license.licensed_to,
            valid_from=license.valid_from,
            expires_at=license.expires_at,
            max_active_certs=license.max_certificate_lineages,
            uploaded_by=uploaded_by,
            uploaded_at=moment,
        )
        self._last_known_good = license
        self._last_load_error = None
        return license

    def remove(self) -> bool:
        removed = self.repository.clear()
        if removed:
            self._last_known_good = None
            self._last_load_error = None
        return removed

    # -- summary ---------------------------------------------------------------

    def summary(self, now: datetime | None = None) -> dict[str, object]:
        moment = _utc_now(now)
        license, error = self._load()
        if error is not None and license is None:
            status = LicenseStatus.INVALID
        elif license is None:
            status = LicenseStatus.NONE
        else:
            status = license.status(moment)
        active = self.active_count(moment)
        reserved = self.reserved_count(moment)
        limit = (
            max(FREE_TIER_LIMIT, license.max_certificate_lineages)
            if license is not None and license.is_active(moment)
            else FREE_TIER_LIMIT
        )
        lineage_state, lineage_error = self.repository.lineage_state()
        new_allowed = lineage_state == "ready" and active + reserved < limit
        expiry_warning_threshold = self._expiry_warning_threshold(status, license, moment)
        reason_codes: list[str] = []
        if lineage_state != "ready":
            reason_codes.append("license_state_unavailable")
        if (
            error
            and error.startswith("License state unavailable")
            and "license_state_unavailable" not in reason_codes
        ):
            reason_codes.append("license_state_unavailable")
        if active + reserved >= limit:
            reason_codes.append("license_limit_reached")
        if error:
            reason_codes.append("license_verification_failed")
        if self.key_configuration_error:
            reason_codes.append("license_key_configuration_invalid")
        elif not self.public_keys:
            reason_codes.append("license_key_configuration_missing")
        body: dict[str, object] = {
            "status": status.value,
            "usage_unit": "certificate_lineage",
            "installation_id": self._installation_id,
            "production_key_configured": bool(self.public_keys)
            and self.key_configuration_error is None,
            "trusted_key_ids": sorted(self._trusted_public_keys()),
            "key_configuration_error": self.key_configuration_error,
            "free_tier": FREE_TIER_LIMIT,
            "active_lineages": active,
            "reserved_lineages": reserved,
            "lineage_limit": limit,
            "active_count": active,
            "effective_limit": limit,
            "new_issuance_allowed": new_allowed,
            # Deprecated compatibility alias for one release. Renewals never
            # consume a lineage slot and therefore are always license-eligible.
            "renewal_allowed": True,
            "reason_codes": reason_codes,
            "lineage_state": lineage_state,
            "lineage_error": lineage_error,
            "licensed_to": None,
            "license_id": None,
            "key_id": None,
            "schema": None,
            "valid_from": None,
            "expires_at": None,
            # Deprecated compatibility alias for one release.
            "renewal_grace_ends_at": None,
            "max_certificate_lineages": None,
            "max_active_certs": None,
            "days_remaining": None,
            "expiry_warning_threshold_days": expiry_warning_threshold,
            "verification_error": error,
        }
        if license is not None:
            body.update(
                {
                    "licensed_to": license.licensed_to,
                    "license_id": license.license_id,
                    "valid_from": license.valid_from.isoformat(),
                    "expires_at": license.expires_at.isoformat(),
                    "max_certificate_lineages": license.max_certificate_lineages,
                    "max_active_certs": license.max_certificate_lineages,
                    "days_remaining": license.days_remaining(moment),
                    "key_id": license.key_id,
                    "schema": license.schema,
                }
            )
        self._notify_status_transition(status, body)
        self._notify_expiry_milestone(expiry_warning_threshold, body)
        return body

    def _notify_status_transition(
        self, status: LicenseStatus, summary: dict[str, object]
    ) -> None:
        current = status.value
        try:
            previous = self.repository.observe_status(current)
        except Exception:  # noqa: BLE001 - status reads must remain read-safe
            return
        if previous == current:
            return
        if self._event_listener is None or previous is None:
            return
        action = {
            LicenseStatus.INVALID.value: "license_verification_failed",
            LicenseStatus.EXPIRED.value: "license_expired",
            LicenseStatus.VALID.value: "license_became_valid",
            LicenseStatus.NONE.value: "license_became_unlicensed",
        }.get(current, "license_status_changed")
        try:
            self._event_listener(
                action,
                {
                    "previous_status": previous,
                    "status": current,
                    "license_id": summary.get("license_id"),
                    "reason_codes": summary.get("reason_codes", []),
                },
            )
        except Exception:  # noqa: BLE001 - diagnostics must not break status reads
            return

    @staticmethod
    def _expiry_warning_threshold(
        status: LicenseStatus, license: License | None, now: datetime
    ) -> int | None:
        if status is not LicenseStatus.VALID or license is None:
            return None
        remaining = license.days_remaining(now)
        candidates = [threshold for threshold in (30, 14, 7, 1) if remaining <= threshold]
        return min(candidates) if candidates else None

    def _notify_expiry_milestone(
        self, threshold: int | None, summary: dict[str, object]
    ) -> None:
        milestone = "none" if threshold is None else str(threshold)
        try:
            previous = self.repository.observe_expiry_milestone(milestone)
        except Exception:  # noqa: BLE001 - diagnostics must not break status reads
            return
        if previous == milestone or self._event_listener is None or threshold is None:
            return
        try:
            self._event_listener(
                "license_expiry_warning",
                {
                    "license_id": summary.get("license_id"),
                    "days_remaining": summary.get("days_remaining"),
                    "warning_threshold_days": threshold,
                    "expires_at": summary.get("expires_at"),
                },
            )
        except Exception:  # noqa: BLE001 - diagnostics must not break status reads
            return


__all__ = [
    "IssuanceAuthorization",
    "LicenseLimitError",
    "LicenseService",
    "LicenseStateError",
]
