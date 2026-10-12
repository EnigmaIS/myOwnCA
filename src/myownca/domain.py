from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from myownca_core.keygen import CERTIFICATE_ALGORITHMS


class Role(StrEnum):
    ADMIN = "admin"
    SUPERUSER = "superuser"
    USER = "user"
    AUDITOR = "auditor"


PRIVILEGED_ROLES = (Role.ADMIN, Role.SUPERUSER, Role.AUDITOR)
DEFAULT_TOTP_REQUIRED_ROLES = (Role.ADMIN, Role.SUPERUSER)
# Compatibility alias for callers that describe the historical default. Runtime
# enforcement must use AuthRepository.is_totp_required() instead.
TOTP_REQUIRED_ROLES = DEFAULT_TOTP_REQUIRED_ROLES


class CertificateProfile(StrEnum):
    USER_AUTH = "user_auth"
    HOST_TLS = "host_tls"
    SMIME = "smime"


class KeyUsageName(StrEnum):
    DIGITAL_SIGNATURE = "digital_signature"
    CONTENT_COMMITMENT = "content_commitment"
    KEY_ENCIPHERMENT = "key_encipherment"
    DATA_ENCIPHERMENT = "data_encipherment"
    KEY_AGREEMENT = "key_agreement"
    ENCIPHER_ONLY = "encipher_only"
    DECIPHER_ONLY = "decipher_only"


class ExtendedKeyUsageName(StrEnum):
    CLIENT_AUTH = "client_auth"
    SERVER_AUTH = "server_auth"
    EMAIL_PROTECTION = "email_protection"


@dataclass(frozen=True, slots=True)
class CertificateProfilePreset:
    profile: CertificateProfile
    display_name: str
    key_usages: tuple[KeyUsageName, ...]
    extended_key_usages: tuple[ExtendedKeyUsageName, ...]


PROFILE_PRESETS: dict[CertificateProfile, CertificateProfilePreset] = {
    CertificateProfile.USER_AUTH: CertificateProfilePreset(
        profile=CertificateProfile.USER_AUTH,
        display_name="User authentication",
        key_usages=(KeyUsageName.DIGITAL_SIGNATURE,),
        extended_key_usages=(ExtendedKeyUsageName.CLIENT_AUTH,),
    ),
    CertificateProfile.HOST_TLS: CertificateProfilePreset(
        profile=CertificateProfile.HOST_TLS,
        display_name="Host / server TLS",
        key_usages=(
            KeyUsageName.DIGITAL_SIGNATURE,
            KeyUsageName.KEY_ENCIPHERMENT,
        ),
        extended_key_usages=(ExtendedKeyUsageName.SERVER_AUTH,),
    ),
    CertificateProfile.SMIME: CertificateProfilePreset(
        profile=CertificateProfile.SMIME,
        display_name="S/MIME",
        key_usages=(
            KeyUsageName.DIGITAL_SIGNATURE,
            KeyUsageName.CONTENT_COMMITMENT,
            KeyUsageName.KEY_ENCIPHERMENT,
        ),
        extended_key_usages=(ExtendedKeyUsageName.EMAIL_PROTECTION,),
    ),
}


class RequestKind(StrEnum):
    FIRST_ISSUANCE = "first_issuance"
    RENEWAL = "renewal"


class RequestStatus(StrEnum):
    PENDING = "pending"
    ISSUED = "issued"
    REJECTED = "rejected"


class RequestSource(StrEnum):
    REQUEST = "request"
    IMPORT = "import"


class SessionStage(StrEnum):
    ACTIVE = "active"
    PASSWORD_CHANGE_REQUIRED = "password_change_required"
    PASSWORD_RECOVERY_REQUIRED = "password_recovery_required"
    TOTP_ENROLLMENT_REQUIRED = "totp_enrollment_required"
    TOTP_REQUIRED = "totp_required"


class GovernanceMode(StrEnum):
    SINGLE_ADMIN = "single_admin"
    DUAL_CONTROL = "dual_control"


class AdminChangeType(StrEnum):
    PRIVILEGED_ROLE_GRANT = "privileged_role_grant"
    PRIVILEGED_PASSWORD_RESET = "privileged_password_reset"
    PRIVILEGED_TOTP_RESET = "privileged_totp_reset"
    ROLE_TOTP_POLICY_CHANGE = "role_totp_policy_change"
    GOVERNANCE_MODE_DOWNGRADE = "governance_mode_downgrade"
    HSM_RAW_BACKUP_EXPORT = "hsm_raw_backup_export"


class AdminChangeStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class CertificateStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"


class CertificateSource(StrEnum):
    ISSUED = "issued"
    IMPORTED = "imported"


class RevocationReason(StrEnum):
    UNSPECIFIED = "unspecified"
    KEY_COMPROMISE = "key_compromise"
    CA_COMPROMISE = "ca_compromise"
    AFFILIATION_CHANGED = "affiliation_changed"
    SUPERSEDED = "superseded"
    CESSATION_OF_OPERATION = "cessation_of_operation"
    CERTIFICATE_HOLD = "certificate_hold"
    PRIVILEGE_WITHDRAWN = "privilege_withdrawn"
    AA_COMPROMISE = "aa_compromise"


@dataclass(frozen=True, slots=True)
class User:
    id: str
    email: str
    role: Role
    is_active: bool = True


@dataclass(frozen=True, slots=True)
class CertificateTemplate:
    id: str
    name: str
    profile: CertificateProfile
    validity_days: int = 365
    first_issuance_approvals: int = 2
    renewal_approvals: int = 1
    key_usages: tuple[KeyUsageName, ...] | None = None
    extended_key_usages: tuple[ExtendedKeyUsageName, ...] | None = None
    key_usage_critical: bool = True
    extended_key_usage_critical: bool = False
    allowed_key_algorithms: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        preset = PROFILE_PRESETS[self.profile]
        key_usages = _normalize_key_usages(
            self.key_usages if self.key_usages is not None else preset.key_usages
        )
        extended_key_usages = _normalize_extended_key_usages(
            self.extended_key_usages
            if self.extended_key_usages is not None
            else preset.extended_key_usages
        )
        _validate_template_usage_policy(self.profile, key_usages, extended_key_usages)
        allowed_key_algorithms = tuple(
            self.allowed_key_algorithms
            if self.allowed_key_algorithms is not None
            else CERTIFICATE_ALGORITHMS
        )
        if not allowed_key_algorithms:
            raise ValueError("Certificate templates must allow at least one key algorithm")
        if len(allowed_key_algorithms) != len(set(allowed_key_algorithms)):
            raise ValueError("Certificate template key algorithms must not contain duplicates")
        unsupported_algorithms = set(allowed_key_algorithms) - set(CERTIFICATE_ALGORITHMS)
        if unsupported_algorithms:
            raise ValueError(
                "Unsupported certificate key algorithms: "
                + ", ".join(sorted(unsupported_algorithms))
            )
        object.__setattr__(self, "key_usages", key_usages)
        object.__setattr__(self, "extended_key_usages", extended_key_usages)
        object.__setattr__(self, "allowed_key_algorithms", allowed_key_algorithms)


@dataclass(frozen=True, slots=True)
class Person:
    id: str
    name: str
    surname: str
    email: str
    created_at: datetime
    phone: str = ""
    slack_handle: str = ""
    company: str = ""
    comments: str = ""

    @property
    def full_name(self) -> str:
        return f"{self.name} {self.surname}".strip()


@dataclass(frozen=True, slots=True)
class Device:
    id: str
    device_name: str
    admin_id: str
    created_at: datetime
    fqdn: str = ""
    comments: str = ""


@dataclass(frozen=True, slots=True)
class CertificateRequest:
    id: str
    template_id: str
    csr_pem: str
    kind: RequestKind
    status: RequestStatus
    created_at: datetime
    requested_by_user_id: str | None = None
    renewal_of_serial_number: str | None = None
    # Stable reference used by the canonical certificate inventory.  The
    # serial field remains a compatibility/display hint only.
    renewal_of_certificate_id: str | None = None
    holder_person_id: str | None = None
    holder_device_id: str | None = None
    lineage_id: str | None = None
    # How a holder-link renewal authenticated: "mtls" (possession proven) or
    # "otp" (email code only — forces at least one superuser approval).
    via_link_auth: str | None = None
    source: RequestSource = RequestSource.REQUEST
    key_registry_id: str | None = None


@dataclass(frozen=True, slots=True)
class ApprovalRecord:
    request_id: str
    superuser_id: str
    approved_at: datetime


@dataclass(frozen=True, slots=True)
class IssuedCertificate:
    serial_number: str
    request_id: str
    template_id: str
    certificate_pem: str
    subject: str
    issued_at: datetime
    expires_at: datetime
    status: CertificateStatus
    holder_person_id: str | None = None
    holder_device_id: str | None = None
    lineage_id: str | None = None
    certificate_id: str = ""
    source: CertificateSource = CertificateSource.ISSUED
    issuer_id: str | None = None
    chain_pem: str = ""
    archived_at: datetime | None = None
    key_registry_id: str | None = None


@dataclass(frozen=True, slots=True)
class Revocation:
    serial_number: str
    reason: RevocationReason
    revoked_at: datetime
    certificate_id: str | None = None
    invalidity_date: datetime | None = None


@dataclass(frozen=True, slots=True)
class PendingSubCARequest:
    id: str
    key_ref: str
    csr_pem: str
    subject: str
    created_at: datetime
    allowed_profiles: tuple[CertificateProfile, ...] = tuple(CertificateProfile)
    key_backend: str | None = None
    token_label: str | None = None


@dataclass(frozen=True, slots=True)
class SubCA:
    id: str
    certificate_pem: str
    key_ref: str
    subject: str
    created_at: datetime
    allowed_profiles: tuple[CertificateProfile, ...] = tuple(CertificateProfile)
    key_backend: str | None = None
    token_label: str | None = None


@dataclass(frozen=True, slots=True)
class OfflineRootAuthority:
    certificate_pem: str
    key_ref: str
    subject: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class RootCRL:
    number: int
    crl_pem: str
    generated_at: datetime


@dataclass(frozen=True, slots=True)
class IssuerCRL:
    issuer_subject: str
    number: int
    crl_pem: str
    generated_at: datetime
    issuer_id: str | None = None
    this_update: datetime | None = None
    next_update: datetime | None = None
    source: str = "local"
    sha256: str = ""


@dataclass(frozen=True, slots=True)
class CRLJob:
    issuer_id: str
    issuer_subject: str
    job_id: str
    status: str
    requested_generation: int
    completed_generation: int
    next_attempt_at: datetime
    attempt_count: int
    reserved_number: int | None = None
    lease_owner: str | None = None
    lease_expires_at: datetime | None = None
    last_error: str | None = None


@dataclass(frozen=True, slots=True)
class OcspResponder:
    issuer_subject: str
    cert_pem: str
    key_ref: str
    not_after: datetime
    created_at: datetime


@dataclass(frozen=True, slots=True)
class OcspStoredResponse:
    issuer_subject: str
    serial_number: str
    cert_id_hash: str
    response_b64: str
    this_update: datetime
    next_update: datetime
    produced_at: datetime


@dataclass(frozen=True, slots=True)
class OfflineCeremonyRecord:
    id: str
    operation_type: str
    occurred_at: datetime
    operator_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AdminChangeProposal:
    id: str
    change_type: AdminChangeType
    proposer_id: str
    target_user_id: str
    payload_json: str
    status: AdminChangeStatus
    created_at: datetime
    expires_at: datetime
    resolved_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class PasswordCredential:
    user_id: str
    password_hash: str
    must_change_password: bool
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class TOTPFactor:
    user_id: str
    secret_ciphertext: str
    confirmed_at: datetime | None
    last_verified_step: int | None


@dataclass(frozen=True, slots=True)
class AuthSession:
    id: str
    token_hash: str
    user_id: str
    csrf_token: str
    stage: SessionStage
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    absolute_expires_at: datetime
    revoked_at: datetime | None = None
    mfa_verified_at: datetime | None = None
    password_verified_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class EmailRecoveryChallenge:
    id: str
    user_id: str
    code_hash: str
    created_at: datetime
    expires_at: datetime
    consumed_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class RecoveryChallenge:
    id: str
    user_id: str
    purpose: str
    channel: str
    code_hash: str
    created_at: datetime
    expires_at: datetime
    consumed_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class AuthEvent:
    id: str
    event_type: str
    occurred_at: datetime
    user_id: str | None = None
    email: str | None = None
    source_ip: str | None = None
    details_json: str = "{}"


@dataclass(frozen=True, slots=True)
class AdminChangeApproval:
    proposal_id: str
    admin_id: str
    approved_at: datetime


def certificate_profile_presets() -> tuple[CertificateProfilePreset, ...]:
    return tuple(PROFILE_PRESETS[profile] for profile in CertificateProfile)


def _normalize_key_usages(
    values: tuple[KeyUsageName, ...] | list[KeyUsageName] | tuple[str, ...] | list[str],
) -> tuple[KeyUsageName, ...]:
    normalized = tuple(
        value if isinstance(value, KeyUsageName) else KeyUsageName(value) for value in values
    )
    if len(set(normalized)) != len(normalized):
        raise ValueError("Key usages must not contain duplicates")
    return normalized


def _normalize_extended_key_usages(
    values: tuple[ExtendedKeyUsageName, ...]
    | list[ExtendedKeyUsageName]
    | tuple[str, ...]
    | list[str],
) -> tuple[ExtendedKeyUsageName, ...]:
    normalized = tuple(
        value if isinstance(value, ExtendedKeyUsageName) else ExtendedKeyUsageName(value)
        for value in values
    )
    if len(set(normalized)) != len(normalized):
        raise ValueError("Extended key usages must not contain duplicates")
    return normalized


def _validate_template_usage_policy(
    profile: CertificateProfile,
    key_usages: tuple[KeyUsageName, ...],
    extended_key_usages: tuple[ExtendedKeyUsageName, ...],
) -> None:
    if not key_usages:
        raise ValueError("Templates must declare at least one key usage")
    if not extended_key_usages:
        raise ValueError("Templates must declare at least one extended key usage")
    if (
        KeyUsageName.ENCIPHER_ONLY in key_usages or KeyUsageName.DECIPHER_ONLY in key_usages
    ) and KeyUsageName.KEY_AGREEMENT not in key_usages:
        raise ValueError("encipher_only and decipher_only require key_agreement")
    required_eku = PROFILE_PRESETS[profile].extended_key_usages[0]
    if required_eku not in extended_key_usages:
        raise ValueError(f"{profile.value} templates must include {required_eku.value}")
