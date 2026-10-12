from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
import urllib.parse
from dataclasses import replace
from urllib.parse import urlparse
from binascii import Error as BinasciiError
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import uvicorn
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, SecretStr
from starlette.concurrency import run_in_threadpool

from myownca import __version__, keygen
from myownca.audit import AuditActor, AuditCategory, AuditOutcome, AuditRepository, AuditService
from myownca.backup.repository import (
    ApplicationBackupRepository,
    BackupExportStatus,
    BackupRepositoryError,
    proposal_dict as backup_proposal_dict,
)
from myownca.backup.service import ApplicationBackupService, BackupServiceError
from myownca.ca_auth.repository import AuthRepository, decode_payload
from myownca.ca_auth.service import (
    AuthError,
    AuthenticationError,
    AuthService,
    AuthorizationError,
    CSRFError,
    ThrottledError,
    recent_mfa_status,
    sensitive_auth_status,
)
from myownca.ca_hsm import HSMPinVault, HSMProxy, create_hsm
from myownca.ca_hsm.ceremony import HSMCeremonyService
from myownca.ca_hsm.base import (
    KeyImportError,
    imported_key_algorithm,
    public_keys_match,
)
from myownca.ca_hsm.pkcs11 import HSMLockedError, PKCS11Error
from myownca.ca_hsm.recovery import (
    HSMKeyRecoveryService,
    KeyRecoveryConflictError,
    KeyRecoveryError,
)
from myownca.ca_hsm.remote import CloudBackendError, algorithm_name_for
from myownca.ca_hsm.scctl import ScHsmCtl, ScHsmError
from myownca.cloud import (
    CloudKey,
    CloudKeyOwnership,
    CloudKeyRepository,
    CloudKeyStatus,
    CloudRepositoryError,
    CloudSigningWorker,
    PermanentSigningError,
    SigningJob,
    SigningJobRepository,
    SigningJobStatus,
    TransientSigningError,
)
from myownca.comms import (
    Attachment,
    CommsError,
    CommsRepository,
    CommsService,
    Message,
    NotificationChannel,
)
from myownca.notifications import (
    SAMPLE_CONTEXT,
    TEMPLATE_VARIABLES,
    NotificationAudience,
    NotificationEvent,
    NotificationFormat,
    NotificationRepository,
    NotificationRule,
    NotificationService,
    NotificationTemplate,
    context_for_certificate,
    render as render_notification,
)
from myownca.service_certs import (
    AcmeOrderIndeterminate,
    ChallengeType,
    KeyBackend,
    ServiceCertError,
    ServiceCertRepository,
    ServiceCertService,
    ServiceCertUnavailable,
    ServiceCertificate,
    ServiceCertStatus,
    ServiceKeyStore,
)
from myownca.service_certs.base import AcmeAccountInUseError
from myownca.service_certs.repository import ServiceCertRepositoryError
from myownca.online.scheduler import IntervalScheduler
from myownca.notifications.schedule import NotificationSchedule, NotificationScheduleSettings
from myownca.online.crl_worker import CRLMaintenanceWorker
from myownca.service_certs.renewal import RenewalScheduler
from myownca.ca_main.crypto import (
    IssuerMaterial,
    cert_pem_to_der,
    certificate_to_pem,
    crl_pem_to_der,
    create_lab_ca_chain,
    create_lab_ca_chain_from_existing_keys,
    validate_end_entity_validity,
    verify_certificate_signature,
)
from myownca_core.leaf import IssuerValidityError
from myownca.ca_main.export import (
    KEY_BEARING_FORMATS,
    ExportError,
    ExportFormat,
    build_chain_pems,
)
from myownca.ca_main.export import (
    export_certificate as build_export,
)
from myownca.ca_main.policy import ApprovalPolicyError, required_approvals
from myownca.ca_main.server_keys import RequestKeyVault, ServerKeyError, build_csr_for_key
from myownca.ca_main.imports import (
    LeafImportError,
    ValidatedLeafBundle,
    build_csr_from_certificate,
    build_rotated_csr_from_certificate,
    create_identity_csr,
    leaf_matches_template,
    parse_bundle,
    validate_leaf_bundle,
)
from myownca.ca_main.service import CAMainService
from myownca.holder import (
    AccessRequestError,
    AccessRequestRepository,
    AccessRequestService,
    AccessRequestStatus,
    LinkPurpose,
    SecureLinkError,
    SecureLinkRepository,
    SecureLinkService,
    mask_email,
)
from myownca.holder.access import VERIFY_TTL_MINUTES
from myownca.holder.links import OTP_TTL_MINUTES
from myownca.licensing import (
    DuplicateCertificateIdentityError,
    LicenseError,
    LicenseInstallationMismatchError,
    LicenseLimitError,
    LicenseRepository,
    LicenseService,
    LicenseStateError,
)
from myownca.key_lifecycle import (
    KeyCleanupError,
    KeyLifecycleError,
    KeyLifecycleRepository,
    KeyLifecycleService,
    KeyOwnership,
    KeyStatus,
)
from myownca.config import Settings
from myownca.domain import (
    AdminChangeStatus,
    AdminChangeType,
    CertificateRequest,
    CertificateProfile,
    CertificateSource,
    CertificateStatus,
    CertificateTemplate,
    Device,
    ExtendedKeyUsageName,
    GovernanceMode,
    IssuedCertificate,
    KeyUsageName,
    Person,
    RequestKind,
    RequestSource,
    RequestStatus,
    RevocationReason,
    Role,
    SessionStage,
    User,
    certificate_profile_presets,
)
from myownca.storage.database import Database, IntegrityError
from myownca.online.access_request_gate import is_request_allowed, normalize_domains
from myownca.online.branding import (
    DEFAULT_ACCENT_COLOR,
    MAX_LOGO_BYTES,
    BrandingError,
    load_logo,
    normalize_theme_color,
    reset_logo,
    save_logo,
    theme_css_for_color,
)
from myownca.online import portal_tls
from myownca.online.ceremony import OnlineCeremonyService
from myownca.online.ocsp_service import OcspService
from myownca.online.operations import (
    DashboardAlertMuteRepository,
    OperationsService,
)
from myownca.people_sync import ensure_people_for_all_users, ensure_person_for_user
from myownca.setup.cleanup import cleanup_completed_setup
from myownca.setup.state import is_setup_complete, resolve_state_dir
from myownca.setup.startup import require_existing_database, require_existing_issuer
from myownca.storage.repositories import (
    AmbiguousCertificateSerialError,
    DuplicateApprovalError,
    PKIRepository,
    RepositoryError,
)

logger = logging.getLogger(__name__)

# HTTP methods whose /internal requests are recorded by the audit middleware.
_AUDITED_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

# Stable, non-empty id for the lab/test issuer (which has no SubCA row), so its
# CRL distribution URL is never an empty "/crl/.crl".
LAB_ISSUER_ID = "myOwnCA_Lab_CA"
MAX_CERTIFICATE_IMPORT_BYTES = 5 * 1024 * 1024
_ISSUER_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class TemplateCreate(BaseModel):
    id: str
    name: str
    profile: CertificateProfile
    validity_days: int = Field(default=365, ge=1)
    first_issuance_approvals: int = Field(default=2, ge=0)
    renewal_approvals: int = Field(default=1, ge=0)
    key_usages: list[KeyUsageName] | None = None
    extended_key_usages: list[ExtendedKeyUsageName] | None = None
    key_usage_critical: bool = True
    extended_key_usage_critical: bool = False
    allowed_key_algorithms: list[str] | None = None


class TemplateUpdate(BaseModel):
    name: str
    profile: CertificateProfile
    validity_days: int = Field(default=365, ge=1)
    first_issuance_approvals: int = Field(default=2, ge=0)
    renewal_approvals: int = Field(default=1, ge=0)
    key_usages: list[KeyUsageName] | None = None
    extended_key_usages: list[ExtendedKeyUsageName] | None = None
    key_usage_critical: bool = True
    extended_key_usage_critical: bool = False
    allowed_key_algorithms: list[str] | None = None


class DestructiveActionConfirmation(BaseModel):
    reason: str = Field(min_length=10, max_length=500)
    confirmation: str = Field(min_length=1)


class UserCreate(BaseModel):
    id: str
    email: str
    temporary_password: str
    role: Role = Role.USER


class RequestCreate(BaseModel):
    template_id: str
    csr_pem: str
    kind: RequestKind = RequestKind.FIRST_ISSUANCE
    renewal_of_serial_number: str | None = None
    renewal_of_certificate_id: str | None = None


class RequestGenerate(BaseModel):
    template_id: str
    common_name: str = Field(min_length=1)
    dns_names: list[str] = Field(default_factory=list)
    email_addresses: list[str] = Field(default_factory=list)
    algorithm: str = "ecdsa-p256"


class CertificateExportRequest(BaseModel):
    format: str
    password: str | None = None


class CertificateRenewalCreate(BaseModel):
    mode: str = Field(default="reuse", pattern="^(reuse|rotate|csr)$")
    csr_pem: str | None = None
    algorithm: str = "ecdsa-p256"


class CertificateArchive(DestructiveActionConfirmation):
    pass


class LinkCreate(BaseModel):
    purpose: str = "delivery"
    certificate_id: str | None = None  # canonical inventory id
    serial_number: str | None = None  # delivery/renewal
    person_id: str | None = None  # enrollment (or recipient override)
    send_email: bool = True


class ClaimEnroll(BaseModel):
    template_id: str
    csr_pem: str | None = None
    common_name: str | None = None
    dns_names: list[str] = Field(default_factory=list)
    email_addresses: list[str] = Field(default_factory=list)
    algorithm: str = "ecdsa-p256"


class LinkQrRequest(BaseModel):
    data: str = Field(min_length=1, max_length=2000)


class ClaimOtpVerify(BaseModel):
    code: str = Field(min_length=1)


class ClaimDownload(BaseModel):
    format: str
    password: str | None = None


class ClaimRenew(BaseModel):
    # rotate (new server keypair), reuse (anchor CSR), csr (paste a fresh CSR);
    # None picks rotate when a server key is held, else reuse.
    mode: str | None = None
    csr_pem: str | None = None


class HolderPortalUpdate(BaseModel):
    portal_base_url: str | None = None
    download_receipts: bool | None = None
    mtls_base_url: str | None = None
    mtls_proxy_secret: str | None = None
    server_key_purge_days: int | None = Field(default=None, ge=0)


class ServiceUrlsUpdate(BaseModel):
    admin_base_url: str | None = None
    superuser_base_url: str | None = None
    crl_base_url: str | None = None
    aia_base_url: str | None = None
    ocsp_url: str | None = None


class OcspSettingsUpdate(BaseModel):
    enabled: bool | None = None
    responder_validity_days: int | None = None


class AccessRequestCreate(BaseModel):
    email: str
    name: str = ""
    kind: str = "user"
    message: str = ""
    # Honeypot: invisible to humans; a filled value means a bot.
    website: str = ""


class AccessRequestVerify(BaseModel):
    code: str = Field(min_length=1)


class AccessRequestConfigUpdate(BaseModel):
    enabled: bool
    allowed_domains: str = ""  # raw textarea text; normalized server-side


class EntropySourceUpdate(BaseModel):
    # None or "" = explicitly use the OS CSPRNG alone (overrides the env var).
    entropy_source: str | None = None


class LicenseUpload(BaseModel):
    token: str = Field(min_length=1)


class ApplicationBackupProposalCreate(DestructiveActionConfirmation):
    requester_passphrase: SecretStr = Field(min_length=16, max_length=1024)
    requester_passphrase_confirmation: SecretStr = Field(min_length=16, max_length=1024)


class ApplicationBackupProposalApprove(DestructiveActionConfirmation):
    approver_passphrase: SecretStr = Field(min_length=16, max_length=1024)
    approver_passphrase_confirmation: SecretStr = Field(min_length=16, max_length=1024)


class DashboardAlertMuteUpdate(BaseModel):
    muted: bool


class BrandingLogoUpload(BaseModel):
    content_type: str
    data_b64: str


class BrandingThemeUpdate(BaseModel):
    accent_color: str = Field(min_length=1)


class RevocationCreate(BaseModel):
    reason: RevocationReason = RevocationReason.UNSPECIFIED


class PersonCreate(BaseModel):
    name: str = Field(min_length=1)
    surname: str = Field(min_length=1)
    email: str = Field(min_length=1)
    phone: str = ""
    slack_handle: str = ""
    company: str = ""
    comments: str = ""
    id: str | None = None


class PersonUpdate(BaseModel):
    name: str = Field(min_length=1)
    surname: str = Field(min_length=1)
    email: str = Field(min_length=1)
    phone: str = ""
    slack_handle: str = ""
    company: str = ""
    comments: str = ""


class DeviceCreate(BaseModel):
    device_name: str = Field(min_length=1)
    admin_id: str = Field(min_length=1)
    fqdn: str = ""
    comments: str = ""
    id: str | None = None


class DeviceUpdate(BaseModel):
    device_name: str = Field(min_length=1)
    admin_id: str = Field(min_length=1)
    fqdn: str = ""
    comments: str = ""


class LeafImportAnalyze(BaseModel):
    bundle_b64: str = Field(min_length=1)
    private_key_b64: str | None = None
    password: str | None = None


class LeafImportCommit(LeafImportAnalyze):
    template_id: str = Field(min_length=1)
    person_id: str | None = None
    device_id: str | None = None
    new_person: PersonCreate | None = None
    new_device: DeviceCreate | None = None


class RequestHolderAssign(BaseModel):
    person_id: str | None = None
    device_id: str | None = None


class CommsChannelConfigUpdate(BaseModel):
    enabled: bool = False
    config: dict[str, object] = Field(default_factory=dict)
    secrets: dict[str, str] = Field(default_factory=dict)


class FirstLoginGuideDismiss(BaseModel):
    outcome: str = Field(pattern="^(completed|skipped)$")


class CommsSendRequest(BaseModel):
    channel: NotificationChannel
    recipient: str = Field(min_length=1)
    body: str = Field(min_length=1)
    subject: str = ""
    metadata: dict[str, object] = Field(default_factory=dict)


class CertificateSendRequest(BaseModel):
    channel: NotificationChannel = NotificationChannel.EMAIL
    recipient_override: str | None = None


class CertificatePKCS12SendRequest(BaseModel):
    password_channel: NotificationChannel
    # Default on: a device cannot trust the issued certificate without them, and
    # the copies carried inside the bundle are not installable as trust anchors.
    include_ca_certificates: bool = True


class CACertificateSendRequest(BaseModel):
    person_id: str = Field(min_length=1)


class NotificationTemplateCreate(BaseModel):
    name: str = Field(min_length=1)
    event_type: NotificationEvent
    format: NotificationFormat = NotificationFormat.TEXT
    subject: str = ""
    body: str = ""


class NotificationTemplateUpdate(BaseModel):
    event_type: NotificationEvent
    format: NotificationFormat = NotificationFormat.TEXT
    subject: str = ""
    body: str = ""


class NotificationTemplatePreview(BaseModel):
    # Optional draft content: when present the editor's unsaved text is
    # rendered; when absent the stored template is loaded by name.
    subject: str | None = None
    body: str | None = None
    format: NotificationFormat = NotificationFormat.TEXT


class NotificationRuleCreate(BaseModel):
    id: str | None = None
    event_type: NotificationEvent
    template_name: str = Field(min_length=1)
    channel: NotificationChannel
    audience: NotificationAudience = NotificationAudience.HOLDER
    enabled: bool = True
    period_days: int = Field(default=1, ge=1)
    threshold_days: int = Field(default=30, ge=0)
    notification_text: str = ""
    include_renewal_link: bool = False


class NotificationRuleUpdate(BaseModel):
    event_type: NotificationEvent
    template_name: str = Field(min_length=1)
    channel: NotificationChannel
    audience: NotificationAudience = NotificationAudience.HOLDER
    enabled: bool = True
    period_days: int = Field(default=1, ge=1)
    threshold_days: int = Field(default=30, ge=0)
    notification_text: str = ""
    include_renewal_link: bool = False


class ServiceCsrCreate(BaseModel):
    name: str = Field(min_length=1)
    common_name: str = Field(min_length=1)
    dns_names: list[str] = Field(default_factory=list)
    key_backend: KeyBackend | None = None
    algorithm: str = Field(
        default="ecdsa-p256",
        pattern="^(rsa-(2048|3072|4096)|ecdsa-p(256|384|521))$",
    )


class ServiceCertImportSigned(BaseModel):
    certificate_pem: str = Field(min_length=1)
    chain_pem: str | None = None


class ServiceImportPem(BaseModel):
    name: str = Field(min_length=1)
    certificate_pem: str = Field(min_length=1)
    private_key_pem: str = Field(min_length=1)
    chain_pem: str | None = None
    key_passphrase: str | None = None


class ServiceImportP12(BaseModel):
    name: str = Field(min_length=1)
    p12_base64: str = Field(min_length=1)
    password: str | None = None


class AcmeAccountCreate(BaseModel):
    directory_url: str = Field(min_length=1)
    contact: str = ""


class AcmeDnsProviderUpdate(BaseModel):
    provider: str = Field(min_length=1)
    username: str = ""
    token: str = ""


class AcmeOrderCreate(BaseModel):
    name: str = Field(min_length=1)
    account_id: str = Field(min_length=1)
    domains: list[str] = Field(min_length=1)
    challenge_type: ChallengeType = ChallengeType.HTTP_01
    key_backend: KeyBackend | None = None
    algorithm: str = Field(
        default="ecdsa-p256",
        pattern="^(rsa-(2048|3072|4096)|ecdsa-p(256|384|521))$",
    )
    renew_before_days: int = Field(default=30, ge=1)


class SyslogConfigUpdate(BaseModel):
    enabled: bool = False
    host: str = ""
    port: int = Field(default=514, ge=1, le=65535)
    protocol: str = Field(default="udp", pattern="^(udp|tcp|tls)$")
    facility: int = Field(default=13, ge=0, le=23)


class HSMPinUnlock(BaseModel):
    pin: str = Field(min_length=1)


class HSMPolicyUpdate(BaseModel):
    operator_unlock_allowed: bool


class CloudKeyAction(DestructiveActionConfirmation):
    pass


class HSMKeyCreate(BaseModel):
    label: str = Field(min_length=1)
    algorithm: str = "rsa-2048"


class DKEKShareImport(DestructiveActionConfirmation):
    password: str = Field(min_length=1)


class HSMKeyBackup(DestructiveActionConfirmation):
    key_reference: str = Field(min_length=1)


class HSMRawBackupExport(DestructiveActionConfirmation):
    pass


class LoginCreate(BaseModel):
    email: str
    password: str


class PasswordChangeCreate(BaseModel):
    new_password: str


class PasswordReauthenticate(BaseModel):
    password: str = Field(min_length=1)


class TOTPCodeCreate(BaseModel):
    code: str


class RecoveryChannelCreate(BaseModel):
    channel: NotificationChannel


class RecoveryChannelVerify(RecoveryChannelCreate):
    code: str = Field(min_length=1)


class PasswordRecoveryRequest(BaseModel):
    email: str = Field(min_length=1)
    channel: NotificationChannel


class PasswordRecoveryVerify(PasswordRecoveryRequest):
    code: str = Field(min_length=1)


class RoleTOTPPolicyChange(DestructiveActionConfirmation):
    required_roles: list[Role]


class PasswordResetCreate(BaseModel):
    temporary_password: str


class PrivilegedRoleGrantCreate(BaseModel):
    id: str
    email: str
    role: Role
    temporary_password: str


class PrivilegedResetCreate(BaseModel):
    target_user_id: str
    temporary_password: str | None = None


def _qr_svg_data_uri(data: str) -> str:
    """Render ``data`` as an SVG QR code returned as a ``data:`` URI for an <img>.

    Used to make a TOTP ``otpauth://`` provisioning URI scannable. The output is
    a self-contained SVG (QR modules as <path>), so embedding it via <img src>
    needs no extra request and keeps the secret in the same response.
    """
    import base64  # noqa: PLC0415
    import io  # noqa: PLC0415

    import qrcode  # noqa: PLC0415
    import qrcode.image.svg  # noqa: PLC0415

    image = qrcode.make(data, image_factory=qrcode.image.svg.SvgPathImage)
    buffer = io.BytesIO()
    image.save(buffer)
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/svg+xml;base64,{encoded}"


def _decode_import_artifact(data_b64: str, *, label: str) -> bytes:
    if len(data_b64) > (MAX_CERTIFICATE_IMPORT_BYTES * 4) // 3 + 16:
        raise HTTPException(
            status_code=413,
            detail=f"{label} exceeds the 5 MiB upload limit",
        )
    try:
        data = base64.b64decode(data_b64, validate=True)
    except (ValueError, BinasciiError) as exc:
        raise HTTPException(status_code=400, detail=f"{label} is not valid base64") from exc
    if not data:
        raise HTTPException(status_code=400, detail=f"{label} is empty")
    if len(data) > MAX_CERTIFICATE_IMPORT_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"{label} exceeds the 5 MiB upload limit",
        )
    return data


def create_app(
    database_path: str | Path | None = None,
    lab_mode: bool | None = None,
    online_key_dir: str | Path | None = None,
) -> FastAPI:
    # Read the canonical setup files directly as well as environment
    # overrides.  The launcher applies the same layer to os.environ, but
    # create_app is also used directly by tests and alternate ASGI runners.
    state_root = resolve_state_dir()
    settings = Settings.load(state_root)
    resolved_lab_mode = settings.lab_mode if lab_mode is None else lab_mode
    if online_key_dir is not None:
        resolved_key_dir = Path(online_key_dir)
    elif settings.online_key_dir == Path("./var/online-keys") and state_root != Path("./var"):
        # A direct ASGI/test invocation with only MYOWNCA_STATE_DIR should not
        # accidentally share the current working directory's development keys.
        resolved_key_dir = state_root / "online-keys"
    else:
        resolved_key_dir = settings.online_key_dir

    # Explicit path arg (tests) wins; else an optional DATABASE_URL (MariaDB);
    # else the default SQLite file.
    if database_path is not None:
        database_target: "str | Path" = Path(database_path)
    elif settings.database_url:
        database_target = settings.database_url
    else:
        database_target = settings.database_path

    setup_complete = is_setup_complete(state_root)
    if setup_complete:
        require_existing_database(database_target)
    database = Database(database_target)
    database.migrate()
    repository = PKIRepository(database)
    key_lifecycle_repository = KeyLifecycleRepository(database)
    cloud_keys = CloudKeyRepository(database)
    signing_jobs = SigningJobRepository(database)
    _apply_pending_root(repository)
    _seed_service_urls(settings, repository)
    _reencrypt_stored_secrets(database, settings.auth_encryption_secret)
    auth_repository = AuthRepository(database)
    if settings.governance_mode is not None:
        try:
            configured_governance = GovernanceMode(settings.governance_mode)
        except ValueError as exc:
            raise ValueError(
                "MYOWNCA_GOVERNANCE_MODE must be single_admin or dual_control"
            ) from exc
        auth_repository.initialize_governance_mode(
            configured_governance,
            datetime.now(timezone.utc),
        )
    if settings.totp_required_roles is not None:
        auth_repository.initialize_totp_policy(
            {Role(value) for value in settings.totp_required_roles},
            datetime.now(timezone.utc),
        )

    def current_entropy_source() -> str | None:
        # Admin-portal setting wins ("" = explicitly OS CSPRNG alone), env var
        # is the fallback. Resolved per key generation, so changes apply live.
        stored = repository.get_setting("entropy_source")
        if stored is not None:
            return stored or None
        return settings.entropy_source

    pin_vault = HSMPinVault()
    persisted_active_sub_ca = repository.get_active_sub_ca()

    def recorded_key_backend(
        *,
        resource_type: str,
        resource_id: str,
        key_ref: str,
    ) -> str | None:
        backends = {
            key.backend
            for key in key_lifecycle_repository.list_keys_for_resource(
                resource_type=resource_type,
                resource_id=resource_id,
            )
            if key.key_ref == key_ref
        }
        if len(backends) > 1:
            raise RuntimeError(
                f"Conflicting key backends are bound to {resource_type} {resource_id}"
            )
        return next(iter(backends), None)

    persisted_backend_name = (
        persisted_active_sub_ca.key_backend
        or recorded_key_backend(
            resource_type="sub_ca",
            resource_id=persisted_active_sub_ca.id,
            key_ref=persisted_active_sub_ca.key_ref,
        )
        if persisted_active_sub_ca is not None
        else None
    )
    persisted_token_label = (
        persisted_active_sub_ca.token_label
        if persisted_active_sub_ca is not None and persisted_backend_name == "pkcs11"
        else None
    )
    initial_backend, initial_backend_name = create_hsm(
        settings,
        pin_vault=pin_vault,
        key_dir=resolved_key_dir,
        backend_name=persisted_backend_name,
        entropy_source=current_entropy_source,
        pkcs11_token_label=persisted_token_label,
    )
    hsm = HSMProxy(initial_backend, initial_backend_name)
    if setup_complete:
        require_existing_issuer(
            repository, initial_backend, initial_backend_name, lab_mode=resolved_lab_mode
        )
    try:
        default_service_key_backend = KeyBackend(settings.service_key_backend)
    except ValueError as exc:
        raise ValueError(
            "MYOWNCA_SERVICE_KEY_BACKEND must be software, pkcs11, aws_kms, or azure_key_vault"
        ) from exc
    if (
        default_service_key_backend is not KeyBackend.SOFTWARE
        and default_service_key_backend.value != initial_backend_name
    ):
        raise ValueError(
            "MYOWNCA_SERVICE_KEY_BACKEND must be software or match MYOWNCA_HSM_BACKEND"
        )
    licensing = LicenseService(
        LicenseRepository(database),
        repository,
        public_keys=settings.license_public_keys,
        key_configuration_error=settings.license_public_keys_error,
    )
    service = CAMainService(repository, hsm, issuance_policy=licensing)
    key_vault = RequestKeyVault(repository, settings.auth_encryption_secret)

    def _delete_registered_key(key) -> None:
        if key.backend == "request_vault":
            request_ids = repository.list_request_private_key_ids_for_registry(key.id)
            if key.key_ref not in request_ids:
                request_ids.append(key.key_ref)
            for request_id in request_ids:
                key_vault.purge(request_id)
            return
        if hsm.active_backend_name() != key.backend:
            raise KeyCleanupError(
                f"Backend {key.backend} is not active; key cleanup will be retried."
            )
        deleter = getattr(hsm.backend, "delete_key", None)
        if deleter is None:
            raise KeyCleanupError(f"Backend {key.backend} does not support key deletion.")
        deleter(key.key_ref)

        cloud_key = cloud_keys.find(provider=key.backend, key_ref=key.key_ref)
        if cloud_key is not None:
            cloud_keys.set_status(cloud_key.id, CloudKeyStatus.PENDING_DELETION)

    def _detach_registered_key(key) -> None:
        # An attached key is provider-owned. Completing cleanup only removes
        # myOwnCA's durable binding/reference state; provider material is never
        # touched here.
        cloud_key = cloud_keys.find(provider=key.backend, key_ref=key.key_ref)
        if cloud_key is not None:
            cloud_keys.set_status(cloud_key.id, CloudKeyStatus.DELETED)

    def _azure_key_name_identity(key_ref: str) -> str:
        parsed = urllib.parse.urlsplit(key_ref)
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) < 2 or parts[0].casefold() != "keys":
            return key_ref.casefold()
        return f"{parsed.scheme.casefold()}://{parsed.netloc.casefold()}/keys/{parts[1].casefold()}"

    def _delete_managed_azure_key(key) -> None:
        """Delete a managed Azure key name only after proving exclusive ownership."""

        if hsm.active_backend_name() != KeyBackend.AZURE_KEY_VAULT.value:
            raise KeyCleanupError("Azure Key Vault is not active; key cleanup will be retried.")
        cloud_key = cloud_keys.find(provider=key.backend, key_ref=key.key_ref)
        if cloud_key is None or cloud_key.ownership is not CloudKeyOwnership.MANAGED:
            raise KeyCleanupError(
                "Azure key deletion requires a tracked myOwnCA-managed cloud key."
            )
        name_identity = _azure_key_name_identity(key.key_ref)
        terminal = {KeyStatus.DELETED, KeyStatus.DETACHED}
        related_versions = [
            candidate
            for candidate in key_lifecycle_repository.list_all(backend=key.backend)
            if candidate.id != key.id
            and candidate.status not in terminal
            and _azure_key_name_identity(candidate.key_ref) == name_identity
        ]
        if related_versions:
            raise KeyCleanupError(
                "Another registered Azure key version with the same name is still present."
            )
        validator = getattr(hsm.backend, "validate_managed_key_for_deletion", None)
        if not callable(validator):
            raise KeyCleanupError(
                "The Azure backend cannot prove managed-key ownership for deletion."
            )
        validator(key.key_ref)
        deleter = getattr(hsm.backend, "delete_key", None)
        if not callable(deleter):
            raise KeyCleanupError("The Azure backend does not support key deletion.")
        deleter(key.key_ref)
        cloud_keys.set_status(cloud_key.id, CloudKeyStatus.PENDING_DELETION)

    def _delete_service_certificate_key(key) -> None:
        """Delete a service key from its own store, not the CA key store."""

        if key.backend == KeyBackend.SOFTWARE.value:
            service_cert_keystore.delete(key.key_ref, KeyBackend.SOFTWARE)
            return
        if key.backend != KeyBackend.PKCS11.value:
            raise KeyCleanupError(f"Unsupported service-certificate key backend: {key.backend}.")
        if hsm.active_backend_name() != KeyBackend.PKCS11.value:
            raise KeyCleanupError(
                "The PKCS#11 backend is not active; service-key cleanup will be retried."
            )
        deleter = getattr(hsm.backend, "delete_key", None)
        if deleter is None:
            raise KeyCleanupError("The PKCS#11 backend does not support key deletion.")
        deleter(key.key_ref)

    key_lifecycle = KeyLifecycleService(
        key_lifecycle_repository,
        deleters={
            "request_vault": _delete_registered_key,
            "software": _delete_registered_key,
            "pkcs11": _delete_registered_key,
            "aws_kms": _delete_registered_key,
            "azure_key_vault": _delete_managed_azure_key,
        },
        detachers={
            "software": _detach_registered_key,
            "pkcs11": _detach_registered_key,
            "aws_kms": _detach_registered_key,
            "azure_key_vault": _detach_registered_key,
        },
        purpose_deleters={
            (KeyBackend.SOFTWARE.value, "service_certificate"): _delete_service_certificate_key,
            (KeyBackend.PKCS11.value, "service_certificate"): _delete_service_certificate_key,
        },
    )
    comms = CommsService(CommsRepository(database), settings.auth_encryption_secret)
    secure_links = SecureLinkService(SecureLinkRepository(database), repository)
    access_requests = AccessRequestService(AccessRequestRepository(database))
    notifications = NotificationService(
        NotificationRepository(database), repository, comms, secure_links=secure_links
    )
    audit = AuditService(AuditRepository(database), settings.auth_encryption_secret)
    licensing.set_event_listener(
        lambda action, details: audit.record(
            AuditCategory.SYSTEM,
            action,
            actor=AuditActor.system(),
            object_type="license",
            object_id=str(details.get("license_id") or "active"),
            details=details,
        )
    )
    auth_service = AuthService(
        auth_repository,
        settings.auth_encryption_secret,
        comms=comms,
        notifications=notifications,
        contacts=repository,
    )
    _apply_pending_admins(auth_service)
    cleanup_completed_setup(state_root, auth_repository)
    service_cert_keystore = ServiceKeyStore(
        settings.service_key_dir,
        passphrase=settings.online_key_passphrase,
        hsm=hsm,
        entropy_source=current_entropy_source,
    )
    service_certs = ServiceCertService(
        ServiceCertRepository(database),
        service_cert_keystore,
        settings.auth_encryption_secret,
    )

    def _materialize_portal_tls(cert_id: str) -> None:
        """Write the selected cert's leaf+chain+key to the portal TLS path.

        Raises ServiceCertError (HSM-keyed / no issued cert) or
        portal_tls.PortalTlsError (pair mismatch / expired).
        """
        cert_pem, chain_pem, key_pem = service_certs.portal_tls_material(cert_id)
        portal_tls.materialize(cert_pem, chain_pem, key_pem, resolve_state_dir())

    def _portal_tls_status() -> dict[str, object]:
        cert_id = repository.get_setting("portal_tls_service_cert_id") or ""
        crt_path, key_path = portal_tls.portal_paths(resolve_state_dir())
        files_present = crt_path.exists() and key_path.exists()
        body: dict[str, object] = {
            "service_cert_id": cert_id or None,
            "files_present": files_present,
            "crt_path": str(crt_path),
            "key_path": str(key_path),
        }
        if not cert_id:
            return body
        try:
            cert = service_certs.get_cert(cert_id)
        except Exception:  # noqa: BLE001 - selection may have been deleted
            body["missing"] = True
            return body
        body["name"] = cert.name
        body["subject"] = cert.subject
        body["not_after"] = cert.not_after.isoformat() if cert.not_after else None
        body["key_backend"] = cert.key_backend.value
        return body

    ceremony = OnlineCeremonyService(repository, hsm)
    lab_chain = (
        _load_or_create_lab_chain(hsm, settings.lab_common_name, allow_create=not setup_complete)
        if resolved_lab_mode and initial_backend_name == "software"
        else None
    )

    def _get_lab_chain():
        nonlocal lab_chain
        if not resolved_lab_mode:
            return None
        if hsm.active_backend_name() != "software":
            raise RuntimeError(
                "Test/Lab issuer generation is available only with the local software backend"
            )
        if lab_chain is None:
            lab_chain = _load_or_create_lab_chain(
                hsm, settings.lab_common_name, allow_create=not setup_complete
            )
            app.state.lab_chain = lab_chain
        return lab_chain

    def certificate_chain_pems(certificate_pem: str) -> list[str]:
        """Signature-verified [sub-CA, root] chain for an issued leaf."""
        candidates = [sub_ca.certificate_pem for sub_ca in repository.list_sub_cas()]
        root_pems: list[str | None] = []
        stored_root = repository.get_root_certificate_pem()
        if stored_root:
            root_pems.append(stored_root)
        current_lab_chain = lab_chain
        if current_lab_chain is not None:
            candidates.append(certificate_to_pem(current_lab_chain.issuer.certificate))
            root_pems.append(certificate_to_pem(current_lab_chain.root.certificate))
        best: list[str] = []
        for root_pem in root_pems or [None]:
            chain = build_chain_pems(
                certificate_pem, issuer_candidates=candidates, root_pem=root_pem
            )
            if len(chain) > len(best):
                best = chain
        return best

    def ca_certificate_attachments() -> list[Attachment]:
        """The CA certificates a holder must install, as individual DER files.

        A root that arrives inside a PKCS#12 is installed with the identity but
        is not trusted: iOS only offers the trust toggle for a root installed as
        a certificate in its own right, and desktop trust stores likewise import
        a .cer on open. So the chain is attached separately as well as being
        carried inside the bundle.
        """

        attachments: list[Attachment] = []
        issuer = current_issuer()
        if issuer is not None:
            attachments.append(
                Attachment(
                    content=issuer.certificate.public_bytes(serialization.Encoding.DER),
                    filename="sub-ca.cer",
                    media_type="application/pkix-cert",
                )
            )
        root_pem = _root_certificate_status().get("root_certificate_pem")
        if isinstance(root_pem, str) and root_pem:
            root = x509.load_pem_x509_certificate(root_pem.encode())
            # A self-issued lab root can equal the issuer; sending it twice would
            # have the holder install the same certificate under two names.
            already = any(
                item.content == root.public_bytes(serialization.Encoding.DER)
                for item in attachments
            )
            if not already:
                attachments.append(
                    Attachment(
                        content=root.public_bytes(serialization.Encoding.DER),
                        filename="root-ca.cer",
                        media_type="application/pkix-cert",
                    )
                )
        return attachments

    @asynccontextmanager
    async def _lifespan(served_app: FastAPI):
        crl_worker = served_app.state.crl_worker
        crl_worker.start()
        logger.info("CRL maintenance worker started (event-driven, 300s safety reconciliation)")
        scheduler = served_app.state.renewal_scheduler
        key_cleanup_scheduler = served_app.state.key_cleanup_scheduler
        key_cleanup_scheduler.start()
        logger.info("Private-key lifecycle cleanup scheduler started (every 3600s)")
        backup_cleanup_scheduler = served_app.state.application_backup_cleanup_scheduler
        backup_cleanup_scheduler.start()
        logger.info("Application backup staging cleanup scheduler started (every 300s)")
        notification_scheduler = served_app.state.notification_scheduler
        notification_scheduler.start()
        notification_settings = served_app.state.notification_schedule.settings()
        logger.info(
            "Expiry notification worker started (enabled=%s, every %ss)",
            notification_settings.enabled, notification_settings.interval_seconds,
        )
        if settings.acme_auto_renew:
            scheduler.start()
            logger.info(
                "ACME auto-renewal scheduler started (every %ss)",
                settings.acme_renew_interval_seconds,
            )
        ocsp_scheduler = served_app.state.ocsp_scheduler
        if settings.ocsp_auto:
            ocsp_scheduler.start()
            logger.info(
                "OCSP refresh scheduler started (every %ss)",
                settings.ocsp_refresh_interval_seconds,
            )
        cloud_schedulers = (
            served_app.state.cloud_signing_scheduler,
            served_app.state.cloud_acme_scheduler,
            served_app.state.cloud_alert_scheduler,
        )
        if initial_backend_name in {"aws_kms", "azure_key_vault"}:
            for cloud_scheduler in cloud_schedulers:
                cloud_scheduler.start()
            logger.info("Cloud signing, ACME, and alert queue workers started")
        try:
            yield
        finally:
            crl_worker.stop()
            scheduler.stop()
            key_cleanup_scheduler.stop()
            backup_cleanup_scheduler.stop()
            notification_scheduler.stop()
            ocsp_scheduler.stop()
            for cloud_scheduler in cloud_schedulers:
                cloud_scheduler.stop()

    app = FastAPI(title="myOwnCA Online API", version=__version__, lifespan=_lifespan)

    @app.exception_handler(HSMLockedError)
    async def hsm_locked_error(_request: Request, exc: HSMLockedError) -> JSONResponse:
        # Without this, a locked token surfaces as an opaque 500 on every route
        # that signs. It is a recoverable state, so it gets its own status and a
        # machine-readable code the portals can act on.
        return JSONResponse(
            status_code=409,
            content={"detail": HSM_LOCKED_MESSAGE, "code": "hsm_locked"},
        )

    @app.exception_handler(RequestValidationError)
    async def sanitized_validation_error(
        _request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        # Pydantic includes the rejected `input` and sometimes `ctx` in its
        # default payload. Import endpoints carry PINs/passwords/key material,
        # so validation responses expose only structural diagnostics.
        details = [
            {
                "loc": list(error.get("loc", ())),
                "type": str(error.get("type", "value_error")),
                "msg": str(error.get("msg", "Invalid request value")),
            }
            for error in exc.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": details})

    static_dir = Path(__file__).with_name("static")
    app.mount("/app/assets", StaticFiles(directory=static_dir), name="app-assets")
    app.state.repository = repository
    app.state.auth_repository = auth_repository
    app.state.auth_service = auth_service
    app.state.service = service
    app.state.ceremony = ceremony
    app.state.lab_chain = lab_chain
    app.state.hsm = hsm
    app.state.pin_vault = pin_vault
    app.state.comms = comms
    app.state.notifications = notifications
    app.state.notification_schedule = NotificationSchedule(repository, notifications)
    app.state.notification_scheduler = app.state.notification_schedule.scheduler
    app.state.service_certs = service_certs
    app.state.cloud_keys = cloud_keys
    app.state.signing_jobs = signing_jobs

    def _renewal_audit(action: str, cert) -> None:
        if action == "acme_auto_renewed" and cert.key_backend in {
            KeyBackend.AWS_KMS,
            KeyBackend.AZURE_KEY_VAULT,
        }:
            action = "acme_auto_renew_queued"
        audit.record(
            AuditCategory.SERVICE_CERT,
            action,
            actor=AuditActor.system(),
            object_type="service_cert",
            object_id=cert.id,
        )

    def renew_or_queue_service_certificate(cert) -> object:
        if cert.key_backend in {KeyBackend.AWS_KMS, KeyBackend.AZURE_KEY_VAULT}:
            return enqueue_cloud_acme_renew(cert)
        return service_certs.renew(cert.id)

    renewal_scheduler = RenewalScheduler(
        service_certs,
        interval_seconds=settings.acme_renew_interval_seconds,
        on_event=_renewal_audit,
        renew_callback=renew_or_queue_service_certificate,
    )
    app.state.renewal_scheduler = renewal_scheduler  # started/stopped by _lifespan

    app.state.audit = audit
    app.state.key_vault = key_vault
    app.state.secure_links = secure_links
    app.state.access_requests = access_requests
    app.state.licensing = licensing
    app.state.key_lifecycle = key_lifecycle

    def ensure_request_key_registered(request_id: str, *, bind_request: bool = True):
        certificate_request = repository.get_request(request_id)
        registered = (
            key_lifecycle_repository.get(certificate_request.key_registry_id)
            if certificate_request.key_registry_id is not None
            else key_lifecycle_repository.find(backend="request_vault", key_ref=request_id)
        )
        if registered is None:
            registered = key_lifecycle.register_key(
                backend="request_vault",
                key_ref=request_id,
                purpose="leaf_certificate",
                ownership=KeyOwnership.MANAGED,
            )
        if certificate_request.key_registry_id != registered.id:
            repository.set_request_key_registry_id(request_id, registered.id)
        if bind_request and registered.status not in {
            KeyStatus.DELETED,
            KeyStatus.DETACHED,
            KeyStatus.DELETING,
        }:
            registered = key_lifecycle.bind_key(
                registered.id,
                resource_type="certificate_request",
                resource_id=request_id,
            )
        return registered

    def reuse_request_key_registration(certificate: IssuedCertificate, target_request_id: str):
        source = repository.get_certificate_by_id(certificate.certificate_id)
        if source.key_registry_id is None:
            registered = ensure_request_key_registered(source.request_id, bind_request=False)
            repository.set_certificate_key_registry_id_by_id(source.certificate_id, registered.id)
        else:
            registered = key_lifecycle_repository.get(source.key_registry_id)
        repository.set_request_key_registry_id(target_request_id, registered.id)
        return key_lifecycle.bind_key(
            registered.id,
            resource_type="certificate_request",
            resource_id=target_request_id,
        )

    def ensure_registered_key(
        *,
        backend: str,
        key_ref: str,
        purpose: str,
        ownership: KeyOwnership,
    ):
        registered = key_lifecycle_repository.find(backend=backend, key_ref=key_ref)
        if registered is None:
            registered = key_lifecycle.register_key(
                backend=backend,
                key_ref=key_ref,
                purpose=purpose,
                ownership=ownership,
            )
        return registered

    def schedule_unbound_key_retirement(
        *,
        backend: str,
        key_ref: str,
        purpose: str,
        ownership: KeyOwnership,
        now: datetime | None = None,
    ):
        registered = ensure_registered_key(
            backend=backend,
            key_ref=key_ref,
            purpose=purpose,
            ownership=ownership,
        )
        bindings = key_lifecycle_repository.list_bindings(registered.id)
        for binding in bindings:
            registered = key_lifecycle.unbind_key(
                registered.id,
                resource_type=binding.resource_type,
                resource_id=binding.resource_id,
                now=now,
            )
        if not bindings and registered.status is KeyStatus.ACTIVE:
            registered = key_lifecycle.orphan_key(registered.id, now=now)
        return registered

    def bind_service_certificate_key(
        certificate: ServiceCertificate,
        *,
        ownership: KeyOwnership = KeyOwnership.MANAGED,
    ):
        registered = ensure_registered_key(
            backend=certificate.key_backend.value,
            key_ref=certificate.key_ref,
            purpose="service_certificate",
            ownership=ownership,
        )
        return key_lifecycle.bind_key(
            registered.id,
            resource_type="service_certificate",
            resource_id=certificate.id,
        )

    def service_certificate_key_ownership(
        certificate: ServiceCertificate,
    ) -> KeyOwnership:
        if certificate.key_backend in {
            KeyBackend.AWS_KMS,
            KeyBackend.AZURE_KEY_VAULT,
        }:
            cloud_key = cloud_keys.find(
                provider=certificate.key_backend.value,
                key_ref=certificate.key_ref,
            )
            if cloud_key is not None and cloud_key.ownership is CloudKeyOwnership.ATTACHED:
                return KeyOwnership.ATTACHED
        # Software and PKCS#11 service keys are created or imported into the
        # application-managed ServiceKeyStore.  A cloud key generated by a
        # service workflow is likewise managed unless metadata says attached.
        return KeyOwnership.MANAGED

    def retire_registered_resource_key(
        *,
        backend: str,
        key_ref: str,
        purpose: str,
        ownership: KeyOwnership,
        resource_type: str,
        resource_id: str,
        when: datetime | None = None,
    ):
        registered = key_lifecycle_repository.find(
            backend=backend,
            key_ref=key_ref,
        )
        if registered is None:
            registered = ensure_registered_key(
                backend=backend,
                key_ref=key_ref,
                purpose=purpose,
                ownership=ownership,
            )
        bindings = key_lifecycle_repository.list_bindings(registered.id)
        matching = next(
            (
                binding
                for binding in bindings
                if binding.resource_type == resource_type and binding.resource_id == resource_id
            ),
            None,
        )
        if matching is not None:
            registered = key_lifecycle.unbind_key(
                registered.id,
                resource_type=matching.resource_type,
                resource_id=matching.resource_id,
                now=when,
            )

        # A cloud-key registry row is metadata rather than a cryptographic
        # consumer.  Remove that self-binding when the last real workflow or
        # certificate binding is gone, otherwise it would suppress orphaning
        # forever after a restart.
        remaining = key_lifecycle_repository.list_bindings(registered.id)
        real_bindings = [binding for binding in remaining if binding.resource_type != "cloud_key"]
        if not real_bindings:
            for binding in remaining:
                if binding.resource_type == "cloud_key":
                    registered = key_lifecycle.unbind_key(
                        registered.id,
                        resource_type=binding.resource_type,
                        resource_id=binding.resource_id,
                        now=when,
                    )

        remaining = key_lifecycle_repository.list_bindings(registered.id)
        if not remaining and registered.status is KeyStatus.ACTIVE:
            registered = key_lifecycle.orphan_key(registered.id, now=when)
        return registered

    def retire_service_certificate_key(
        certificate: ServiceCertificate,
        *,
        when: datetime | None = None,
    ):
        registered = retire_registered_resource_key(
            backend=certificate.key_backend.value,
            key_ref=certificate.key_ref,
            purpose="service_certificate",
            ownership=service_certificate_key_ownership(certificate),
            resource_type="service_certificate",
            resource_id=certificate.id,
            when=when,
        )
        if registered.status in {KeyStatus.ORPHANED, KeyStatus.ERROR}:
            cloud_key = cloud_keys.find(
                provider=certificate.key_backend.value,
                key_ref=certificate.key_ref,
            )
            if cloud_key is not None:
                cloud_keys.set_status(
                    cloud_key.id,
                    CloudKeyStatus.PENDING_DELETION,
                    now=when,
                )
        return registered

    def bind_request_key_to_certificate(certificate: IssuedCertificate) -> str | None:
        if not key_vault.held(certificate.request_id):
            return None
        registered = ensure_request_key_registered(certificate.request_id)
        key_lifecycle.bind_key(
            registered.id,
            resource_type="certificate",
            resource_id=certificate.certificate_id or certificate.serial_number,
        )
        key_lifecycle.unbind_key(
            registered.id,
            resource_type="certificate_request",
            resource_id=certificate.request_id,
        )
        repository.set_certificate_key_registry_id_by_id(certificate.certificate_id, registered.id)
        return registered.id

    def retire_request_key(request_id: str, *, when: datetime | None = None) -> None:
        if not key_vault.held(request_id):
            return
        registered = ensure_request_key_registered(request_id, bind_request=False)
        bindings = key_lifecycle_repository.list_bindings(registered.id)
        request_binding = next(
            (
                binding
                for binding in bindings
                if binding.resource_type == "certificate_request"
                and binding.resource_id == request_id
            ),
            None,
        )
        if request_binding is not None:
            key_lifecycle.unbind_key(
                registered.id,
                resource_type="certificate_request",
                resource_id=request_id,
                now=when,
            )
        elif not bindings and registered.status is KeyStatus.ACTIVE:
            key_lifecycle.orphan_key(registered.id, now=when)

    def retire_certificate_key(
        certificate: IssuedCertificate, *, when: datetime | None = None
    ) -> None:
        key_id = certificate.key_registry_id
        if key_id is None and key_vault.held(certificate.request_id):
            registered = ensure_request_key_registered(certificate.request_id, bind_request=False)
            key_id = registered.id
            repository.set_certificate_key_registry_id_by_id(certificate.certificate_id, key_id)
        if key_id is None:
            return
        bindings = key_lifecycle_repository.list_bindings(key_id)
        resource_id = certificate.certificate_id or certificate.serial_number
        if any(
            binding.resource_type == "certificate" and binding.resource_id == resource_id
            for binding in bindings
        ):
            key_lifecycle.unbind_key(
                key_id,
                resource_type="certificate",
                resource_id=resource_id,
                now=when,
            )
        elif not bindings:
            registered = key_lifecycle_repository.get(key_id)
            if registered.status is KeyStatus.ACTIVE:
                key_lifecycle.orphan_key(key_id, now=when)

    def reconcile_known_key_inventory() -> None:
        """Backfill durable registry entries for application-owned references."""

        moment = datetime.now(timezone.utc)

        def bind(
            *,
            backend: str,
            key_ref: str,
            purpose: str,
            ownership: KeyOwnership,
            resource_type: str,
            resource_id: str,
        ) -> None:
            registered = ensure_registered_key(
                backend=backend,
                key_ref=key_ref,
                purpose=purpose,
                ownership=ownership,
            )
            if registered.status not in {
                KeyStatus.DELETED,
                KeyStatus.DETACHED,
                KeyStatus.DELETING,
            }:
                key_lifecycle.bind_key(
                    registered.id,
                    resource_type=resource_type,
                    resource_id=resource_id,
                )

        for cloud_key in cloud_keys.list_all():
            ownership = (
                KeyOwnership.ATTACHED
                if cloud_key.ownership is CloudKeyOwnership.ATTACHED
                else KeyOwnership.MANAGED
            )
            if cloud_key.status in {CloudKeyStatus.ACTIVE, CloudKeyStatus.DISABLED}:
                bind(
                    backend=cloud_key.provider,
                    key_ref=cloud_key.key_ref,
                    purpose=cloud_key.purpose,
                    ownership=ownership,
                    resource_type="cloud_key",
                    resource_id=cloud_key.id,
                )
            elif cloud_key.status is CloudKeyStatus.PENDING_DELETION:
                schedule_unbound_key_retirement(
                    backend=cloud_key.provider,
                    key_ref=cloud_key.key_ref,
                    purpose=cloud_key.purpose,
                    ownership=ownership,
                )

        def ownership_for(backend: str, key_ref: str) -> KeyOwnership:
            cloud_key = cloud_keys.find(provider=backend, key_ref=key_ref)
            if cloud_key is not None and cloud_key.ownership is CloudKeyOwnership.MANAGED:
                return KeyOwnership.MANAGED
            # Legacy local/HSM rows do not encode provenance. Treating them as
            # attached is the safe migration default and prevents accidental purge.
            return KeyOwnership.ATTACHED

        for sub_ca in repository.list_sub_cas():
            backend_name = (
                sub_ca.key_backend
                or recorded_key_backend(
                    resource_type="sub_ca",
                    resource_id=sub_ca.id,
                    key_ref=sub_ca.key_ref,
                )
                or hsm.active_backend_name()
            )
            bind(
                backend=backend_name,
                key_ref=sub_ca.key_ref,
                purpose="sub_ca",
                ownership=ownership_for(backend_name, sub_ca.key_ref),
                resource_type="sub_ca",
                resource_id=sub_ca.id,
            )
        for pending in repository.list_pending_sub_cas():
            backend_name = (
                pending.key_backend
                or recorded_key_backend(
                    resource_type="pending_sub_ca",
                    resource_id=pending.id,
                    key_ref=pending.key_ref,
                )
                or hsm.active_backend_name()
            )
            bind(
                backend=backend_name,
                key_ref=pending.key_ref,
                purpose="sub_ca",
                ownership=ownership_for(backend_name, pending.key_ref),
                resource_type="pending_sub_ca",
                resource_id=pending.id,
            )
        for certificate in service_certs.list_certs():
            is_live = certificate.status is ServiceCertStatus.PENDING or (
                certificate.status is ServiceCertStatus.ACTIVE
                and (certificate.not_after is None or certificate.not_after > moment)
            )
            if not is_live:
                continue
            backend = certificate.key_backend.value
            bind(
                backend=backend,
                key_ref=certificate.key_ref,
                purpose="service_certificate",
                ownership=service_certificate_key_ownership(certificate),
                resource_type="service_certificate",
                resource_id=certificate.id,
            )

    def reconcile_key_lifecycle(now: datetime | None = None) -> None:
        moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        revocations = {
            revocation.certificate_id: revocation for revocation in repository.list_revocations()
        }
        for certificate in repository.list_issued_certificates(include_archived=True):
            if not key_vault.held(certificate.request_id):
                continue
            try:
                bind_request_key_to_certificate(certificate)
                orphaned_at = None
                if certificate.archived_at is not None:
                    orphaned_at = certificate.archived_at
                elif certificate.status is CertificateStatus.REVOKED:
                    revocation = revocations.get(certificate.certificate_id)
                    orphaned_at = revocation.revoked_at if revocation else moment
                elif certificate.expires_at <= moment:
                    orphaned_at = certificate.expires_at
                if orphaned_at is not None:
                    retire_certificate_key(certificate, when=orphaned_at)
            except KeyLifecycleError:
                logger.warning(
                    "Could not reconcile key lifecycle for certificate %s",
                    certificate.serial_number,
                    exc_info=True,
                )
        issued_request_ids = {
            certificate.request_id
            for certificate in repository.list_issued_certificates(include_archived=True)
        }
        requests = {item.id: item for item in repository.list_requests(include_imports=True)}
        for row in repository.list_request_private_keys():
            request_id = row["request_id"]
            if request_id in issued_request_ids:
                continue
            certificate_request = requests.get(request_id)
            try:
                if (
                    certificate_request is not None
                    and certificate_request.status is RequestStatus.PENDING
                ):
                    ensure_request_key_registered(request_id)
                else:
                    orphaned_at = certificate_request.created_at if certificate_request else moment
                    retire_request_key(request_id, when=orphaned_at)
            except KeyLifecycleError:
                logger.warning(
                    "Could not reconcile key lifecycle for request %s",
                    request_id,
                    exc_info=True,
                )

        for certificate in service_certs.list_certs():
            is_live = certificate.status is ServiceCertStatus.PENDING or (
                certificate.status is ServiceCertStatus.ACTIVE
                and (certificate.not_after is None or certificate.not_after > moment)
            )
            try:
                if is_live:
                    bind_service_certificate_key(
                        certificate,
                        ownership=service_certificate_key_ownership(certificate),
                    )
                    continue
                orphaned_at = (
                    certificate.not_after
                    if (
                        certificate.status is ServiceCertStatus.ACTIVE
                        and certificate.not_after is not None
                        and certificate.not_after <= moment
                    )
                    else certificate.updated_at
                )
                retire_service_certificate_key(certificate, when=orphaned_at)
            except KeyLifecycleError:
                logger.warning(
                    "Could not reconcile service-key lifecycle for certificate %s",
                    certificate.id,
                    exc_info=True,
                )

    reconcile_known_key_inventory()
    reconcile_key_lifecycle()

    def run_key_cleanup_pass() -> None:
        reconcile_key_lifecycle()
        outcomes = key_lifecycle.cleanup_due()
        for outcome in outcomes:
            audit.record(
                AuditCategory.HSM,
                "key_cleanup",
                actor=AuditActor.system(),
                object_type="registered_key",
                object_id=outcome.key_id,
                outcome=(AuditOutcome.SUCCESS if outcome.succeeded else AuditOutcome.FAILURE),
                details={
                    "backend": outcome.backend,
                    "ownership": outcome.ownership.value,
                    "status": outcome.status.value,
                    "error": outcome.error,
                },
            )

    key_cleanup_scheduler = IntervalScheduler(
        run_key_cleanup_pass,
        interval_seconds=3600,
        name="key-lifecycle-cleanup",
    )
    app.state.key_cleanup_scheduler = key_cleanup_scheduler

    try:
        ensure_people_for_all_users(repository)
    except Exception:  # noqa: BLE001 - boot must not fail if a mirror can't be written
        logger.warning("people backfill on boot failed", exc_info=True)

    _portal_tls_selection = repository.get_setting("portal_tls_service_cert_id") or ""
    if _portal_tls_selection:
        try:
            _materialize_portal_tls(_portal_tls_selection)
        except Exception:  # noqa: BLE001 - boot must not fail if the cert/key is unusable
            logger.warning(
                "portal TLS re-materialize on boot failed for %s",
                _portal_tls_selection,
                exc_info=True,
            )

    scctl = ScHsmCtl(settings.sc_hsm_tool_path, settings.sc_hsm_reader)
    app.state.scctl = scctl

    def hsm_ceremony_service() -> HSMCeremonyService:
        return HSMCeremonyService(hsm.backend, scctl)

    def hsm_recovery_service() -> HSMKeyRecoveryService:
        return HSMKeyRecoveryService(hsm.backend, scctl)

    def _hsm_operation_http_error(exc: BaseException) -> HTTPException:
        detail = str(exc) or exc.__class__.__name__
        if isinstance(exc, PKCS11Error) and "HSM PIN is locked" in detail:
            detail = "Unlock the HSM PIN before running this HSM operation"
        return HTTPException(status_code=400, detail=detail)

    def current_issuer() -> IssuerMaterial | None:
        active_issuer = ceremony.active_issuer_material()
        if active_issuer is not None:
            return active_issuer
        current_lab_chain = lab_chain
        if current_lab_chain is not None:
            return current_lab_chain.issuer
        return None

    def _audit_generated_crl(crl) -> None:
        audit.record(
            AuditCategory.CERTIFICATE,
            "crl_generate",
            actor=AuditActor.system(),
            object_type="crl",
            object_id=str(crl.number),
            details={
                "issuer_id": crl.issuer_id,
                "source": crl.source,
            },
        )

    crl_worker = CRLMaintenanceWorker(
        repository,
        service,
        current_issuer,
        on_generated=_audit_generated_crl,
    )
    service.crl_change_listener = crl_worker.kick
    app.state.crl_worker = crl_worker

    def issuer_id_for(issuer: IssuerMaterial) -> str | None:
        # Lab issuer has no SubCA row → the fixed constant. A real current
        # issuer is identified by the active record, not a key label that can
        # legitimately exist on several backends.
        current_lab_chain = lab_chain
        if current_lab_chain is not None and issuer is current_lab_chain.issuer:
            return LAB_ISSUER_ID
        active_sub_ca = repository.get_active_sub_ca()
        if active_sub_ca is None or active_sub_ca.key_ref != issuer.key_ref:
            return None
        active_certificate = x509.load_pem_x509_certificate(active_sub_ca.certificate_pem.encode())
        if active_certificate.public_bytes(serialization.Encoding.DER) == (
            issuer.certificate.public_bytes(serialization.Encoding.DER)
        ):
            return active_sub_ca.id
        return None

    def reconcile_certificate_inventory_metadata() -> None:
        """Backfill canonical issuer fingerprints and chains for legacy rows."""

        issuer_certificates = [
            x509.load_pem_x509_certificate(item.certificate_pem.encode())
            for item in repository.list_sub_cas()
        ]
        if lab_chain is not None:
            issuer_certificates.append(lab_chain.issuer.certificate)
        if not issuer_certificates:
            return
        for issuer_certificate in issuer_certificates:
            repository.reconcile_issuer_crl_history(issuer_certificate)
        for certificate in repository.list_issued_certificates(include_archived=True):
            try:
                parsed = x509.load_pem_x509_certificate(certificate.certificate_pem.encode())
            except ValueError:
                continue
            matched = None
            for candidate in issuer_certificates:
                if parsed.issuer != candidate.subject:
                    continue
                try:
                    verify_certificate_signature(parsed, candidate)
                except (InvalidSignature, ValueError):
                    continue
                matched = candidate
                break
            if matched is None:
                continue
            issuer_fingerprint = matched.fingerprint(hashes.SHA256()).hex()
            chain_pem = certificate.chain_pem or "".join(
                certificate_chain_pems(certificate.certificate_pem)
            )
            if certificate.issuer_id != issuer_fingerprint or certificate.chain_pem != chain_pem:
                repository.update_certificate_inventory_metadata_by_id(
                    certificate.certificate_id,
                    issuer_id=issuer_fingerprint,
                    chain_pem=chain_pem,
                )
        # Revocations migrated from the pre-issuer_id schema were keyed by the
        # synthetic fingerprint. The inventory update above already re-adds them
        # under the corrected one, so this clears the leftover synthetic rows and
        # rescues any that had no certificate_revocations source to re-add from.
        rekeyed = repository.reconcile_issuer_revocations()
        if rekeyed:
            logger.info(
                "Reconciled %s legacy revocation row(s) onto their issuer fingerprint.",
                rekeyed,
            )

    reconcile_certificate_inventory_metadata()

    def issuer_crl_url(issuer: IssuerMaterial) -> str | None:
        base = (repository.get_setting("crl_base_url") or "").strip().rstrip("/")
        if not base:
            return None
        issuer_id = issuer_id_for(issuer)
        if issuer_id is None:
            return None
        return f"{base}/crl/{issuer_id}.crl"

    service.crl_url_resolver = issuer_crl_url

    def issuer_aia(issuer: IssuerMaterial) -> tuple[str | None, str | None]:
        ocsp_enabled = (repository.get_setting("ocsp_enabled") or "").strip() == "true"
        ocsp_url = (
            (repository.get_setting("ocsp_url") or "").strip() or None if ocsp_enabled else None
        )
        aia_base = (repository.get_setting("aia_base_url") or "").strip().rstrip("/")
        issuer_id = issuer_id_for(issuer)
        ca_issuers_url = f"{aia_base}/aia/{issuer_id}.cer" if aia_base and issuer_id else None
        return ocsp_url, ca_issuers_url

    service.aia_resolver = issuer_aia

    def _ocsp_enabled() -> bool:
        return (repository.get_setting("ocsp_enabled") or "").strip() == "true"

    def _ocsp_validity_days() -> int:
        raw = repository.get_setting("ocsp_responder_validity_days")
        try:
            value = int(raw) if raw else 30
        except ValueError:
            value = 30
        return value if value > 0 else 30

    ocsp_service = OcspService(
        repository,
        hsm,
        service_cert_keystore,
        current_issuer,
        validity_days_provider=_ocsp_validity_days,
        enabled_provider=_ocsp_enabled,
    )
    app.state.ocsp_service = ocsp_service
    service.cert_change_listener = ocsp_service.refresh_response

    def run_ocsp_scheduled_pass() -> None:
        if not _ocsp_enabled():
            return
        issuer = current_issuer()
        if issuer is None:
            return
        if hsm.active_backend_name() in {"aws_kms", "azure_key_vault"}:
            enqueue_cloud_ocsp(issuer)
            return
        ocsp_service.generate_responses(issuer)

    ocsp_scheduler = IntervalScheduler(
        run_ocsp_scheduled_pass,
        interval_seconds=settings.ocsp_refresh_interval_seconds,
        name="ocsp-refresh",
    )
    app.state.ocsp_scheduler = ocsp_scheduler

    cloud_backend_names = {"aws_kms", "azure_key_vault"}

    def ensure_cloud_key(
        *,
        key_ref: str,
        algorithm: str,
        purpose: str,
        ownership: CloudKeyOwnership = CloudKeyOwnership.ATTACHED,
        label: str = "",
        provider: str | None = None,
    ):
        provider = provider or hsm.active_backend_name()
        if provider not in cloud_backend_names:
            raise ValueError("The active signing backend is not a cloud provider")
        existing = cloud_keys.find(provider=provider, key_ref=key_ref)
        if existing is not None:
            if existing.status is not CloudKeyStatus.ACTIVE:
                raise CloudRepositoryError(f"Registered cloud key is not active: {existing.id}")
            if (
                ownership is CloudKeyOwnership.MANAGED
                and existing.ownership is CloudKeyOwnership.ATTACHED
            ):
                raise CloudRepositoryError(
                    "A newly generated key reference collides with an attached key"
                )
            if existing.algorithm != algorithm:
                raise CloudRepositoryError(
                    "Registered cloud key algorithm does not match the requested key"
                )
            return existing
        return cloud_keys.register(
            provider=provider,
            key_ref=key_ref,
            algorithm=algorithm,
            purpose=purpose,
            ownership=ownership,
            label=label,
            protection=(settings.azure_key_protection if provider == "azure_key_vault" else None),
        )

    def _track_and_compensate_managed_cloud_key(
        *,
        key_ref: str,
        algorithm: str,
        purpose: str,
        label: str,
        resource_type: str,
        resource_id: str,
        registered_key: CloudKey | None = None,
        request: Request | None = None,
    ) -> bool:
        """Adopt a key left by a failed cloud saga and start the 30-day grace."""

        tracked = registered_key
        if tracked is None:
            try:
                tracked = cloud_keys.find(provider=hsm.active_backend_name(), key_ref=key_ref)
                if tracked is None:
                    tracked = cloud_keys.register(
                        provider=hsm.active_backend_name(),
                        key_ref=key_ref,
                        algorithm=algorithm,
                        purpose=purpose,
                        ownership=CloudKeyOwnership.MANAGED,
                        label=label,
                        protection=(
                            settings.azure_key_protection
                            if hsm.active_backend_name() == "azure_key_vault"
                            else None
                        ),
                    )
            except Exception:  # noqa: BLE001 - compensation must preserve original error
                logger.exception(
                    "Could not persist cloud key metadata during %s compensation",
                    resource_type,
                )

        # A collision with an explicitly attached key must always favor safety:
        # myOwnCA never deletes a key recorded as owned by somebody else.
        if tracked is not None and tracked.ownership is CloudKeyOwnership.ATTACHED:
            logger.error(
                "Refusing managed-key compensation because the key is registered as attached"
            )
            return False

        try:
            scheduled = schedule_unbound_key_retirement(
                backend=hsm.active_backend_name(),
                key_ref=key_ref,
                purpose=purpose,
                ownership=KeyOwnership.MANAGED,
            )
            if tracked is not None:
                tracked = cloud_keys.set_status(tracked.id, CloudKeyStatus.PENDING_DELETION)
        except Exception:  # noqa: BLE001 - keep the original endpoint failure
            logger.exception(
                "Could not schedule delayed cleanup for cloud key created for %s %s",
                resource_type,
                resource_id,
            )
            return False

        try:
            audit.record(
                AuditCategory.HSM,
                "cloud_key_creation_compensated",
                actor=audit_actor(request) if request is not None else AuditActor.system(),
                object_type=resource_type,
                object_id=resource_id,
                details={
                    "provider": hsm.active_backend_name(),
                    "cloud_key_id": tracked.id if tracked is not None else None,
                    "deletion_scheduled": True,
                    "delete_after": scheduled.delete_after.isoformat()
                    if scheduled.delete_after
                    else None,
                },
            )
        except Exception:  # noqa: BLE001 - audit failure must not hide compensation
            logger.exception("Could not audit managed cloud-key compensation")
        return True

    def _discard_prepared_cloud_service_cert(
        cert: ServiceCertificate | str,
    ) -> bool:
        """Remove a pending CSR/ACME row whose signing job was not enqueued."""

        cert_id = cert.id if isinstance(cert, ServiceCertificate) else cert
        try:
            # Cloud deletion is handled by the saga helper below.  Deleting the
            # repository row also cascades ACME config/checkpoint rows.
            service_certs.repository.delete(cert_id)
        except Exception:  # noqa: BLE001 - compensation must preserve original error
            logger.exception(
                "Could not discard pending service certificate %s after queue failure",
                cert_id,
            )
            return False
        return True

    def cloud_key_for_issuer(issuer: IssuerMaterial):
        return ensure_cloud_key(
            key_ref=issuer.key_ref,
            algorithm=algorithm_name_for(issuer.certificate.public_key()),
            purpose="subca",
            # A legacy key absent from the registry is conservatively attached:
            # myOwnCA must never infer ownership and delete it.
            ownership=CloudKeyOwnership.ATTACHED,
            label=issuer_id_for(issuer) or "issuing-ca",
        )

    def enqueue_cloud_issuance(request_id: str, issuer: IssuerMaterial) -> SigningJob:
        certificate_request = repository.get_request(request_id)
        validate_end_entity_validity(
            repository.get_template(certificate_request.template_id), issuer
        )
        key = cloud_key_for_issuer(issuer)
        issuer_id = issuer_id_for(issuer)
        if issuer_id is None:
            raise ValueError("Cloud signing requires a registered issuing sub-CA")
        return signing_jobs.enqueue(
            cloud_key_id=key.id,
            operation="issue_certificate",
            resource_type="certificate_request",
            resource_id=request_id,
            payload={"request_id": request_id, "issuer_id": issuer_id},
            deduplication_key=request_id,
        ).job

    def enqueue_cloud_crl(issuer: IssuerMaterial) -> SigningJob:
        key = cloud_key_for_issuer(issuer)
        issuer_id = issuer_id_for(issuer)
        if issuer_id is None:
            raise ValueError("Cloud signing requires a registered issuing sub-CA")
        return signing_jobs.enqueue(
            cloud_key_id=key.id,
            operation="generate_crl",
            resource_type="subca",
            resource_id=issuer_id,
            payload={"issuer_id": issuer_id},
            deduplication_key=f"crl:{issuer_id}",
        ).job

    def enqueue_cloud_ocsp(issuer: IssuerMaterial) -> SigningJob:
        key = cloud_key_for_issuer(issuer)
        issuer_id = issuer_id_for(issuer)
        if issuer_id is None:
            raise ValueError("Cloud signing requires a registered issuing sub-CA")
        return signing_jobs.enqueue(
            cloud_key_id=key.id,
            operation="refresh_ocsp",
            resource_type="subca",
            resource_id=issuer_id,
            payload={"issuer_id": issuer_id},
            deduplication_key=f"ocsp:{issuer_id}",
        ).job

    def enqueue_cloud_acme_renew(cert) -> SigningJob:
        if cert.key_backend.value != hsm.active_backend_name():
            raise ValueError("The service certificate cloud provider is not the active backend")
        if cert.certificate_pem:
            public_key = x509.load_pem_x509_certificate(cert.certificate_pem.encode()).public_key()
        else:
            public_key = service_cert_keystore.public_key(cert.key_ref, cert.key_backend)
        key = ensure_cloud_key(
            key_ref=cert.key_ref,
            algorithm=algorithm_name_for(public_key),
            purpose="service_certificate",
            ownership=CloudKeyOwnership.ATTACHED,
            label=cert.id,
        )
        renewal_generation = hashlib.sha256(
            (cert.certificate_pem or cert.csr_pem or cert.id).encode()
        ).hexdigest()
        return signing_jobs.enqueue(
            cloud_key_id=key.id,
            operation="acme_renew",
            resource_type="service_certificate",
            resource_id=cert.id,
            payload={
                "certificate_id": cert.id,
                "acme_operation_id": (f"acme-renew:{cert.id}:{renewal_generation}"),
            },
            deduplication_key=f"acme-renew:{cert.id}",
        ).job

    def _cloud_provider_failure(exc: CloudBackendError) -> None:
        code = exc.code or "provider_error"
        # Provider exception details can contain account/resource identifiers;
        # the durable queue stores a deliberately bounded, credential-free text.
        safe_message = f"{exc.provider} could not complete {exc.operation}."
        if exc.retryable:
            raise TransientSigningError(code, safe_message) from exc
        raise PermanentSigningError(code, safe_message) from exc

    def handle_cloud_signing_job(job: SigningJob) -> dict[str, object]:
        try:
            if job.operation == "service_csr":
                cert, csr_pem = service_certs.complete_csr(
                    str(job.payload["certificate_id"]),
                    common_name=str(job.payload["common_name"]),
                    dns_names=tuple(str(value) for value in job.payload.get("dns_names", [])),
                )
                audit.record(
                    AuditCategory.SERVICE_CERT,
                    "csr_created",
                    actor=AuditActor.system(),
                    object_type="service_cert",
                    object_id=cert.id,
                    details={"signing_job_id": job.id},
                )
                return {"certificate_id": cert.id, "csr_pem": csr_pem}

            if job.operation == "acme_order":
                result = service_certs.complete_acme_certificate(
                    str(job.payload["certificate_id"]),
                    idempotency_key=str(job.payload.get("acme_operation_id") or job.id),
                )
                audit.record(
                    AuditCategory.SERVICE_CERT,
                    "acme_order_complete",
                    actor=AuditActor.system(),
                    object_type="service_cert",
                    object_id=str(result["certificate_id"]),
                    details={"signing_job_id": job.id},
                )
                return dict(result)

            if job.operation == "acme_renew":
                cert_id = str(job.payload["certificate_id"])
                result = service_certs.renew(
                    cert_id,
                    idempotency_key=str(job.payload.get("acme_operation_id") or job.id),
                )
                audit.record(
                    AuditCategory.SERVICE_CERT,
                    "acme_auto_renewed",
                    actor=AuditActor.system(),
                    object_type="service_cert",
                    object_id=cert_id,
                    details={"signing_job_id": job.id},
                )
                return dict(result)

            if job.operation == "issue_certificate":
                request_id = str(job.payload["request_id"])
                already_issued = repository.get_issued_certificate_by_request_id(request_id)
                if already_issued is not None:
                    return {"serial_number": already_issued.serial_number}
                issuer = ceremony.issuer_material(str(job.payload["issuer_id"]))
                certificate, error = perform_issuance(
                    request_id,
                    issuer,
                    AuditActor.system(),
                )
                if certificate is None:
                    code = str((error or {}).get("code") or "issuance_rejected")
                    message = str(
                        (error or {}).get("message") or "Certificate issuance was rejected."
                    )
                    raise PermanentSigningError(code, message)
                return {"serial_number": certificate.serial_number}

            if job.operation == "generate_crl":
                issuer = ceremony.issuer_material(str(job.payload["issuer_id"]))
                crl_job = crl_worker.enqueue(issuer)
                return {"crl_job_id": crl_job.job_id}

            if job.operation == "refresh_ocsp":
                issuer = ceremony.issuer_material(str(job.payload["issuer_id"]))
                count = ocsp_service.generate_responses(issuer)
                audit.record(
                    AuditCategory.CERTIFICATE,
                    "ocsp_generate",
                    actor=AuditActor.system(),
                    object_type="ocsp",
                    object_id=str(count),
                    details={"signing_job_id": job.id},
                )
                return {"response_count": count}

            raise PermanentSigningError(
                "unknown_operation",
                "The queued cloud signing operation is not supported.",
            )
        except CloudBackendError as exc:
            _cloud_provider_failure(exc)
        except AcmeOrderIndeterminate as exc:
            raise PermanentSigningError(
                "acme_order_indeterminate",
                "The ACME provider may have created an order whose response was lost; "
                "operator reconciliation is required.",
            ) from exc
        except (
            KeyError,
            RepositoryError,
            ServiceCertRepositoryError,
            ServiceCertUnavailable,
            ValueError,
        ) as exc:
            raise PermanentSigningError(
                "invalid_job_state",
                "The resource for this cloud signing job is missing or invalid.",
            ) from exc

    _abandoned_key_workflow_operations = frozenset({"service_csr", "acme_order"})

    def retire_abandoned_cloud_workflow(job: SigningJob) -> None:
        """Retire a newly-created key once its owning job is canceled."""

        if (
            job.status is not SigningJobStatus.CANCELED
            or job.operation not in _abandoned_key_workflow_operations
        ):
            return
        try:
            cloud_key = cloud_keys.get(job.cloud_key_id)
            ownership = (
                KeyOwnership.ATTACHED
                if cloud_key.ownership is CloudKeyOwnership.ATTACHED
                else KeyOwnership.MANAGED
            )
            registered_before = key_lifecycle_repository.find(
                backend=cloud_key.provider,
                key_ref=cloud_key.key_ref,
            )
            had_binding = bool(
                registered_before
                and any(
                    binding.resource_type == "service_certificate"
                    and binding.resource_id == job.resource_id
                    for binding in key_lifecycle_repository.list_bindings(registered_before.id)
                )
            )
            resource_changed = False
            try:
                certificate = service_certs.get_cert(job.resource_id)
            except (ServiceCertError, RuntimeError):
                certificate = None
            if certificate is not None:
                if certificate.status is not ServiceCertStatus.SUPERSEDED:
                    certificate = replace(
                        certificate,
                        status=ServiceCertStatus.SUPERSEDED,
                        updated_at=job.completed_at or datetime.now(timezone.utc),
                    )
                    service_certs.repository.update(certificate)
                    resource_changed = True
                registered = retire_service_certificate_key(
                    certificate,
                    when=job.completed_at,
                )
            else:
                registered = retire_registered_resource_key(
                    backend=cloud_key.provider,
                    key_ref=cloud_key.key_ref,
                    purpose="service_certificate",
                    ownership=ownership,
                    resource_type="service_certificate",
                    resource_id=job.resource_id,
                    when=job.completed_at,
                )
            if registered.status in {KeyStatus.ORPHANED, KeyStatus.ERROR}:
                cloud_keys.set_status(
                    cloud_key.id,
                    CloudKeyStatus.PENDING_DELETION,
                    now=job.completed_at,
                )
            if had_binding or resource_changed:
                audit.record(
                    AuditCategory.HSM,
                    "cloud_signing_canceled_key_retired",
                    actor=AuditActor.system(),
                    object_type="signing_job",
                    object_id=job.id,
                    details={
                        "cloud_key_id": cloud_key.id,
                        "resource_type": job.resource_type,
                        "resource_id": job.resource_id,
                        "delete_after": (
                            registered.delete_after.isoformat() if registered.delete_after else None
                        ),
                    },
                )
        except Exception:  # noqa: BLE001 - terminal queue state must remain durable
            logger.exception(
                "Could not retire key for canceled cloud signing job %s",
                job.id,
            )

    def reconcile_abandoned_cloud_workflows() -> None:
        for canceled in signing_jobs.list_all(
            status=SigningJobStatus.CANCELED,
            limit=1_000,
        ):
            retire_abandoned_cloud_workflow(canceled)

    short_signing_operations = (
        "service_csr",
        "issue_certificate",
        "generate_crl",
        "refresh_ocsp",
    )
    cloud_signing_worker = CloudSigningWorker(
        signing_jobs,
        handle_cloud_signing_job,
        operations=short_signing_operations,
        on_terminal=retire_abandoned_cloud_workflow,
    )
    cloud_acme_worker = CloudSigningWorker(
        signing_jobs,
        handle_cloud_signing_job,
        operations=("acme_order", "acme_renew"),
        on_terminal=retire_abandoned_cloud_workflow,
    )

    def dispatch_cloud_signing_alerts() -> None:
        now = datetime.now(timezone.utc)
        for job in signing_jobs.list_alerting(now=now, alert_after=timedelta(minutes=15)):
            context = {
                "cloud_job_id": job.id,
                "cloud_job_status": job.status.value,
                "cloud_operation": job.operation,
                "cloud_resource": f"{job.resource_type}:{job.resource_id}",
                "cloud_error_code": job.last_error_code or "",
                "cloud_error_message": job.last_error_message or "",
            }
            # A manual retry starts a new retry window and therefore a new
            # notification identity. Rules provide the per-channel cadence.
            object_ref = (
                f"cloud-signing:{job.id}:{job.status.value}:"
                f"{job.retry_window_started_at.isoformat()}"
            )
            notifications.notify_event(
                NotificationEvent.CLOUD_SIGNING_ALERT,
                context_override=context,
                object_ref=object_ref,
                now=now,
            )

    def run_cloud_signing_pass() -> None:
        cloud_signing_worker.run_available(max_jobs=25)
        signing_jobs.maintain()
        reconcile_abandoned_cloud_workflows()

    def run_cloud_acme_pass() -> None:
        # ACME validation can wait on DNS propagation.  Its dedicated worker
        # keeps certificate issuance, CRL, OCSP, and CSR jobs flowing.
        cloud_acme_worker.run_available(max_jobs=1)
        signing_jobs.maintain()
        reconcile_abandoned_cloud_workflows()

    def run_cloud_alert_pass() -> None:
        dispatch_cloud_signing_alerts()

    cloud_signing_scheduler = IntervalScheduler(
        run_cloud_signing_pass,
        interval_seconds=5,
        name="cloud-signing",
    )
    cloud_acme_scheduler = IntervalScheduler(
        run_cloud_acme_pass,
        interval_seconds=5,
        name="cloud-acme",
    )
    cloud_alert_scheduler = IntervalScheduler(
        run_cloud_alert_pass,
        interval_seconds=30,
        name="cloud-signing-alerts",
    )
    app.state.cloud_signing_worker = cloud_signing_worker
    app.state.cloud_acme_worker = cloud_acme_worker
    app.state.cloud_signing_scheduler = cloud_signing_scheduler
    app.state.cloud_acme_scheduler = cloud_acme_scheduler
    app.state.cloud_alert_scheduler = cloud_alert_scheduler

    def _ocsp_status() -> dict[str, object]:
        issuer = current_issuer()
        subject = issuer.certificate.subject.rfc4514_string() if issuer is not None else None
        responder = repository.get_ocsp_responder(subject) if subject else None
        return {
            "enabled": _ocsp_enabled(),
            "responder_validity_days": _ocsp_validity_days(),
            "responder_not_after": responder.not_after.isoformat() if responder else None,
            "responder_url": (repository.get_setting("ocsp_url") or "").strip() or None,
            "warning": (repository.get_setting("ocsp_responder_warning") or "").strip() or None,
        }

    application_backup_repository = ApplicationBackupRepository(database)
    application_backup_service = ApplicationBackupService(
        database=database,
        state_dir=state_root,
        settings=settings,
        repository=application_backup_repository,
        pki_repository=repository,
        backend_name=hsm.active_backend_name(),
        online_key_dir=resolved_key_dir,
        service_key_dir=settings.service_key_dir,
    )
    application_backup_cleanup_scheduler = IntervalScheduler(
        application_backup_service.cleanup_expired,
        interval_seconds=300,
        name="application-backup-cleanup",
    )
    app.state.application_backup_service = application_backup_service
    app.state.application_backup_repository = application_backup_repository
    app.state.application_backup_cleanup_scheduler = application_backup_cleanup_scheduler

    operations = OperationsService(
        repository=repository,
        notification_repository=notifications.repository,
        service_cert_repository=service_certs.repository,
        comms_repository=comms.repository,
        licensing_service=licensing,
        audit_service=audit,
        proposal_repository=auth_repository,
        backup_repository=application_backup_repository,
        signing_job_repository=signing_jobs,
        issuer_provider=current_issuer,
        hsm_backend_provider=hsm.active_backend_name,
        lab_mode=resolved_lab_mode,
    )
    dashboard_alert_mutes = DashboardAlertMuteRepository(database)
    app.state.operations = operations
    app.state.dashboard_alert_mutes = dashboard_alert_mutes

    @app.get("/internal/admin/ocsp")
    def ocsp_settings(request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN)
        return _ocsp_status()

    @app.put("/internal/admin/ocsp")
    def update_ocsp_settings(payload: OcspSettingsUpdate, request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN, csrf=True)
        if payload.responder_validity_days is not None:
            if payload.responder_validity_days <= 0:
                raise HTTPException(
                    status_code=400, detail="responder_validity_days must be a positive integer"
                )
            repository.set_setting(
                "ocsp_responder_validity_days", str(payload.responder_validity_days)
            )
        if payload.enabled is not None:
            repository.set_setting("ocsp_enabled", "true" if payload.enabled else "false")
            if payload.enabled:
                issuer = current_issuer()
                if issuer is not None:
                    if hsm.active_backend_name() in {"aws_kms", "azure_key_vault"}:
                        enqueue_cloud_ocsp(issuer)
                    else:
                        ocsp_service.generate_responses(issuer)
        audit.record(
            AuditCategory.SYSTEM,
            "ocsp_settings",
            actor=audit_actor(request),
            object_type="setting",
            object_id="ocsp",
        )
        return _ocsp_status()

    @app.post("/internal/ocsp", status_code=201, response_model=None)
    def generate_ocsp(request: Request) -> dict[str, object] | JSONResponse:
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        if not _ocsp_enabled():
            raise HTTPException(status_code=409, detail="OCSP is disabled")
        issuer = current_issuer()
        if issuer is None:
            raise HTTPException(status_code=503, detail="No issuer configured")
        if hsm.active_backend_name() in {"aws_kms", "azure_key_vault"}:
            try:
                job = enqueue_cloud_ocsp(issuer)
            except (CloudRepositoryError, ValueError) as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc
            audit.record(
                AuditCategory.CERTIFICATE,
                "ocsp_queued",
                actor=audit_actor(request),
                object_type="signing_job",
                object_id=job.id,
            )
            return JSONResponse(
                status_code=202,
                content={"status": "queued", "signing_job_id": job.id},
            )
        count = ocsp_service.generate_responses(issuer)
        audit.record(
            AuditCategory.CERTIFICATE,
            "ocsp_generate",
            actor=audit_actor(request),
            object_type="ocsp",
            object_id=str(count),
        )
        return {"response_count": count, **_ocsp_status()}

    @app.post("/ocsp", include_in_schema=False)
    async def ocsp_post(request: Request) -> Response:
        if not _ocsp_enabled():
            raise HTTPException(status_code=404, detail="OCSP is disabled")
        body = await request.body()
        return Response(content=ocsp_service.respond(body), media_type="application/ocsp-response")

    @app.get("/ocsp/{encoded:path}", include_in_schema=False)
    def ocsp_get(encoded: str) -> Response:
        if not _ocsp_enabled():
            raise HTTPException(status_code=404, detail="OCSP is disabled")
        try:
            der = base64.b64decode(encoded)
        except (ValueError, BinasciiError):  # bad base64 ⇒ malformed
            der = b""
        return Response(content=ocsp_service.respond(der), media_type="application/ocsp-response")

    def attempt_issuance(request_id: str, actor: AuditActor | None = None):
        """Try to issue an approved request; returns (certificate|None, error|None)."""
        issuer = current_issuer()
        if issuer is None:
            return None, _auto_issue_error("no_issuer", "No issuer configured")
        if hsm.active_backend_name() in {"aws_kms", "azure_key_vault"}:
            try:
                job = enqueue_cloud_issuance(request_id, issuer)
            except IssuerValidityError as exc:
                return None, _auto_issue_error_from_exception(exc)
            except (CloudRepositoryError, ValueError) as exc:
                return None, _auto_issue_error("cloud_queue_error", str(exc))
            audit.record(
                AuditCategory.CERTIFICATE,
                "issuance_queued",
                actor=actor or AuditActor.system(),
                object_type="request",
                object_id=request_id,
                details={"signing_job_id": job.id},
            )
            return None, {
                "code": "cloud_signing_queued",
                "message": "Certificate issuance is queued for cloud signing.",
                "job_id": job.id,
            }
        return perform_issuance(request_id, issuer, actor)

    def perform_issuance(
        request_id: str,
        issuer: IssuerMaterial,
        actor: AuditActor | None = None,
    ):
        """Run issuance synchronously (local path or a claimed queue job)."""
        certificate_request = repository.get_request(request_id)
        renewal_anchor = (
            repository.get_certificate_by_id(certificate_request.renewal_of_certificate_id)
            if certificate_request.kind is RequestKind.RENEWAL
            and certificate_request.renewal_of_certificate_id is not None
            else repository.get_issued_certificate(certificate_request.renewal_of_serial_number)
            if certificate_request.kind is RequestKind.RENEWAL
            and certificate_request.renewal_of_serial_number is not None
            else None
        )
        try:
            certificate = service.issue_certificate(request_id, issuer)
        except DuplicateCertificateIdentityError as exc:
            audit.record(
                AuditCategory.CERTIFICATE,
                "issuance_blocked_duplicate_identity",
                actor=actor or AuditActor.system(),
                object_type="request",
                object_id=request_id,
                details={"detail": str(exc)},
            )
            return None, _auto_issue_error("duplicate_certificate_identity", str(exc))
        except LicenseLimitError as exc:
            audit.record(
                AuditCategory.CERTIFICATE,
                "issuance_blocked_license_limit",
                actor=actor or AuditActor.system(),
                object_type="request",
                object_id=request_id,
                details={"detail": str(exc)},
            )
            return None, _auto_issue_error("license_limit_reached", str(exc))
        except LicenseStateError as exc:
            audit.record(
                AuditCategory.CERTIFICATE,
                "issuance_blocked_license_state",
                actor=actor or AuditActor.system(),
                object_type="request",
                object_id=request_id,
                details={"detail": str(exc)},
            )
            return None, _auto_issue_error("license_state_unavailable", str(exc))
        except HSMLockedError as exc:
            # A locked token is an operator-recoverable state, not a fault. The
            # approval is already recorded, so report it as a structured error
            # and leave the request in the queue to be issued once unlocked.
            audit.record(
                AuditCategory.CERTIFICATE,
                "issuance_blocked_hsm_locked",
                actor=actor or AuditActor.system(),
                object_type="request",
                object_id=request_id,
                details={"detail": str(exc)},
            )
            return None, _auto_issue_error("hsm_locked", HSM_LOCKED_MESSAGE)
        except (ApprovalPolicyError, RepositoryError, ValueError) as exc:
            return None, _auto_issue_error_from_exception(exc)
        replacement_key_bound = not key_vault.held(certificate.request_id)
        try:
            bind_request_key_to_certificate(certificate)
            replacement_key_bound = True
        except KeyLifecycleError:
            logger.error(
                "Certificate %s was issued but its key lifecycle binding failed",
                certificate.serial_number,
                exc_info=True,
            )
        if renewal_anchor is not None and replacement_key_bound:
            revocation = next(
                (
                    item
                    for item in repository.list_revocations()
                    if item.certificate_id == renewal_anchor.certificate_id
                ),
                None,
            )
            try:
                retire_certificate_key(
                    renewal_anchor,
                    when=(revocation.revoked_at if revocation is not None else None),
                )
            except KeyLifecycleError:
                # Reconciliation retries this without weakening the successful,
                # atomic certificate replacement.
                logger.error(
                    "Certificate %s was superseded but its old key binding could not be retired",
                    renewal_anchor.serial_number,
                    exc_info=True,
                )
        audit.record(
            AuditCategory.CERTIFICATE,
            "issue",
            actor=actor or AuditActor.system(),
            object_type="certificate",
            object_id=certificate.certificate_id or certificate.serial_number,
            details={"request_id": request_id, "subject": certificate.subject},
        )
        try:
            notifications.notify_event(NotificationEvent.ISSUED, certificate=certificate)
        except Exception:  # noqa: BLE001 - notifications must never block issuance
            pass
        try:
            # Link-originated requests (renewal/enrollment claims) close the
            # loop automatically: mint + email a fresh delivery link.
            if repository.get_request(request_id).via_link_auth:
                send_delivery_link_for(certificate)
        except Exception:  # noqa: BLE001 - delivery links must never block issuance
            pass
        return certificate, None

    def current_session(request: Request, *, allow_incomplete: bool = False):
        try:
            return auth_service.require_session(
                request.cookies.get("myownca_session"),
                allow_incomplete=allow_incomplete,
            )
        except AuthenticationError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

    def active_user(request: Request, *roles: Role, csrf: bool = False):
        session, user = current_session(request)
        if roles:
            try:
                auth_service.require_role(user, *roles)
            except AuthorizationError as exc:
                raise HTTPException(status_code=403, detail=str(exc)) from exc
        if csrf:
            try:
                auth_service.require_csrf(session, request.headers.get("x-csrf-token"))
            except CSRFError as exc:
                raise HTTPException(status_code=403, detail=str(exc)) from exc
        return session, user

    def own_person(user: User) -> Person:
        target = user.email.casefold()
        for person in repository.list_people():
            if person.email.casefold() == target:
                return person
        ensure_person_for_user(repository, user)
        for person in repository.list_people():
            if person.email.casefold() == target:
                return person
        raise HTTPException(status_code=409, detail="Login account has no Person record")

    def require_holder_scope(
        user: User,
        *,
        person_id: str | None = None,
        device_id: str | None = None,
    ) -> None:
        if user.role in {Role.ADMIN, Role.SUPERUSER}:
            return
        if user.role is not Role.USER:
            raise HTTPException(status_code=403, detail="Auditors have read-only access")
        person = own_person(user)
        if person_id is not None and person_id != person.id:
            raise HTTPException(status_code=403, detail="Person is outside your scope")
        if device_id is not None:
            try:
                device = repository.get_device(device_id)
            except RepositoryError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
            if device.admin_id != person.id:
                raise HTTPException(status_code=403, detail="Device is outside your scope")

    def require_certificate_scope(user: User, certificate: IssuedCertificate) -> None:
        if user.role in {Role.ADMIN, Role.SUPERUSER, Role.AUDITOR}:
            return
        require_holder_scope(
            user,
            person_id=certificate.holder_person_id,
            device_id=certificate.holder_device_id,
        )

    def certificate_in_user_scope(user: User, certificate: IssuedCertificate) -> bool:
        if user.role is not Role.USER:
            return True
        person = own_person(user)
        if certificate.holder_person_id == person.id:
            return True
        device = _repository_device_or_none(repository, certificate.holder_device_id)
        return device is not None and device.admin_id == person.id

    def request_in_user_scope(user: User, item: CertificateRequest) -> bool:
        if user.role is not Role.USER:
            return True
        if item.requested_by_user_id == user.id:
            return True
        person = own_person(user)
        if item.holder_person_id == person.id:
            return True
        device = _repository_device_or_none(repository, item.holder_device_id)
        return device is not None and device.admin_id == person.id

    def audit_actor(request: Request) -> AuditActor:
        user = auth_service.identify(request.cookies.get("myownca_session"))
        source_ip = request.client.host if request.client else None
        if user is None:
            return AuditActor(id=None, email=None, role="anonymous", source_ip=source_ip)
        return AuditActor(id=user.id, email=user.email, role=user.role.value, source_ip=source_ip)

    def require_recent_sensitive_action(
        request: Request,
        *,
        category: AuditCategory,
        action: str,
        object_type: str,
        object_id: str,
        roles: tuple[Role, ...] = (Role.ADMIN,),
    ):
        session, user = active_user(request, *roles, csrf=True)
        try:
            auth_service.require_recent_sensitive_auth(session, user)
        except AuthenticationError as exc:
            audit.record(
                category,
                f"{action}_denied",
                actor=audit_actor(request),
                outcome=AuditOutcome.DENIED,
                object_type=object_type,
                object_id=object_id,
                details={
                    "guard": (
                        "recent_mfa" if auth_service.totp_required(user.role) else "recent_password"
                    )
                },
            )
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        return session, user

    def require_destructive_action(
        request: Request,
        payload: DestructiveActionConfirmation,
        *,
        expected_confirmation: str,
        category: AuditCategory,
        action: str,
        object_type: str,
        object_id: str,
        require_sensitive_auth: bool = True,
        roles: tuple[Role, ...] = (Role.ADMIN,),
    ):
        session, user = active_user(request, *roles, csrf=True)
        reason = payload.reason.strip()

        def deny(guard: str, detail: str) -> None:
            audit.record(
                category,
                f"{action}_denied",
                actor=audit_actor(request),
                outcome=AuditOutcome.DENIED,
                object_type=object_type,
                object_id=object_id,
                details={"guard": guard, "reason": reason or None},
            )
            raise HTTPException(status_code=403, detail=detail)

        if require_sensitive_auth:
            try:
                auth_service.require_recent_sensitive_auth(session, user)
            except AuthenticationError as exc:
                deny(
                    "recent_mfa" if auth_service.totp_required(user.role) else "recent_password",
                    str(exc),
                )
        if len(reason) < 10:
            deny("audit_reason", "Audit reason must contain at least 10 characters after trimming")
        if payload.confirmation != expected_confirmation:
            deny(
                "typed_confirmation",
                f'Typed confirmation must exactly match "{expected_confirmation}"',
            )
        return session, user, reason

    @contextmanager
    def audit_destructive_failures(
        request: Request,
        *,
        reason: str,
        category: AuditCategory,
        action: str,
        object_type: str,
        object_id: str,
    ):
        try:
            yield
        except Exception:
            # Keep the mandatory operator reason, but never persist exception
            # text: lower layers may include PINs, passwords, or command lines.
            audit.record(
                category,
                f"{action}_failed",
                actor=audit_actor(request),
                outcome=AuditOutcome.FAILURE,
                object_type=object_type,
                object_id=object_id,
                details={"reason": reason},
            )
            raise

    @contextmanager
    def audit_sensitive_failures(
        request: Request,
        *,
        category: AuditCategory,
        action: str,
        object_type: str,
        object_id: str,
    ):
        try:
            yield
        except Exception:
            # Exception text and request fields can contain passwords or key
            # material.  Record only stable operation metadata.
            audit.record(
                category,
                f"{action}_failed",
                actor=audit_actor(request),
                outcome=AuditOutcome.FAILURE,
                object_type=object_type,
                object_id=object_id,
                details={},
            )
            raise

    def _log_api_request(request: Request, status: int) -> None:
        try:
            if status < 400:
                outcome = AuditOutcome.SUCCESS
            elif status in (401, 403):
                outcome = AuditOutcome.DENIED
            else:
                outcome = AuditOutcome.FAILURE
            audit.record(
                AuditCategory.API,
                f"{request.method} {request.url.path}",
                actor=audit_actor(request),
                outcome=outcome,
                object_type="endpoint",
                object_id=request.url.path,
                details={"status": status},
            )
        except Exception:  # noqa: BLE001 - auditing must never break a request
            pass

    @app.middleware("http")
    async def audit_requests(request: Request, call_next):
        response = await call_next(request)
        if request.method in _AUDITED_METHODS and request.url.path.startswith("/internal/"):
            # Run the synchronous DB write off the event loop.
            await run_in_threadpool(_log_api_request, request, response.status_code)
        return response

    def set_session_cookie(response: Response, token: str) -> None:
        response.set_cookie(
            key="myownca_session",
            value=token,
            httponly=True,
            secure=settings.session_cookie_secure,
            samesite="lax",
            path="/",
        )

    def clear_session_cookie(response: Response) -> None:
        response.delete_cookie("myownca_session", path="/")

    def authenticated_page(request: Request, filename: str, *roles: Role):
        try:
            _, user = current_session(request)
        except HTTPException:
            return RedirectResponse("/login", status_code=303)
        if roles and user.role not in roles:
            raise HTTPException(
                status_code=403, detail="This portal is not available for your role"
            )
        return FileResponse(
            static_dir / filename,
            headers={"Cache-Control": "no-cache"},
        )

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse("/login", status_code=303)

    @app.get("/login", include_in_schema=False)
    def login_page(request: Request) -> Response:
        try:
            session, _ = current_session(request, allow_incomplete=True)
        except HTTPException:
            session = None
        if session is not None and session.stage is SessionStage.ACTIVE:
            return RedirectResponse("/app", status_code=303)
        return FileResponse(
            static_dir / "login.html",
            headers={"Cache-Control": "no-store"},
        )

    _THEME_SETTING_KEY = "branding_accent_color"

    def _theme_status() -> dict[str, object]:
        accent = (repository.get_setting(_THEME_SETTING_KEY) or "").strip()
        return {
            "accent_color": accent or DEFAULT_ACCENT_COLOR,
            "custom": bool(accent),
        }

    @app.get("/theme.css", include_in_schema=False)
    def theme_css() -> Response:
        css = (Path(__file__).parents[1] / "ui_theme.css").read_text()
        accent = (repository.get_setting(_THEME_SETTING_KEY) or "").strip()
        if accent:
            css += "\n\n/* Admin branding override */\n" + theme_css_for_color(accent)
        return Response(
            content=css,
            media_type="text/css",
            headers={"Cache-Control": "no-cache"},
        )

    _LOGO_HEADERS = {
        "Content-Security-Policy": "script-src 'none'",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-cache",
    }

    @app.get("/branding/logo", include_in_schema=False)
    def branding_logo() -> Response:
        loaded = load_logo(resolve_state_dir())
        if loaded is not None:
            data, content_type = loaded
            return Response(content=data, media_type=content_type, headers=_LOGO_HEADERS)
        return FileResponse(
            static_dir / "branding" / "logo.svg",
            media_type="image/svg+xml",
            headers=_LOGO_HEADERS,
        )

    @app.post("/internal/branding/logo", status_code=201)
    def upload_branding_logo(payload: BrandingLogoUpload, request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN, csrf=True)
        # Reject an oversized payload before decoding it into memory (base64 is
        # ~4/3 of the raw size); save_logo enforces the exact byte cap too.
        if len(payload.data_b64) > (MAX_LOGO_BYTES * 4) // 3 + 16:
            raise HTTPException(status_code=400, detail="Logo is too large (max 2 MB)")
        try:
            data = base64.b64decode(payload.data_b64, validate=True)
        except (ValueError, BinasciiError) as exc:
            raise HTTPException(status_code=400, detail="data_b64 is not valid base64") from exc
        try:
            save_logo(resolve_state_dir(), payload.content_type, data)
        except BrandingError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"stored": True}

    @app.delete("/internal/branding/logo")
    def delete_branding_logo(request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN, csrf=True)
        reset_logo(resolve_state_dir())
        return {"reset": True}

    @app.get("/internal/branding/theme")
    def get_branding_theme(request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN)
        return _theme_status()

    @app.put("/internal/branding/theme")
    def update_branding_theme(payload: BrandingThemeUpdate, request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN, csrf=True)
        try:
            accent = normalize_theme_color(payload.accent_color)
        except BrandingError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        repository.set_setting(_THEME_SETTING_KEY, accent)
        return _theme_status()

    @app.delete("/internal/branding/theme")
    def reset_branding_theme(request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN, csrf=True)
        repository.set_setting(_THEME_SETTING_KEY, "")
        return {"accent_color": DEFAULT_ACCENT_COLOR, "custom": False}

    @app.get("/console", include_in_schema=False)
    def console() -> RedirectResponse:
        return RedirectResponse("/app", status_code=303)

    @app.get("/app", include_in_schema=False)
    def app_home(request: Request) -> RedirectResponse:
        try:
            _, user = current_session(request)
        except HTTPException:
            return RedirectResponse("/login", status_code=303)
        if user.role is Role.ADMIN:
            return RedirectResponse("/app/admin", status_code=303)
        if user.role is Role.SUPERUSER:
            return RedirectResponse("/app/superuser", status_code=303)
        if user.role is Role.USER:
            return RedirectResponse("/app/user", status_code=303)
        return RedirectResponse("/app/auditor", status_code=303)

    @app.get("/app/user", include_in_schema=False)
    def user_portal(request: Request):
        return authenticated_page(request, "user.html", Role.USER, Role.ADMIN, Role.SUPERUSER)

    @app.get("/app/superuser", include_in_schema=False)
    def superuser_portal(request: Request):
        return authenticated_page(request, "superuser.html", Role.SUPERUSER)

    @app.get("/app/admin", include_in_schema=False)
    def admin_portal(request: Request):
        return authenticated_page(request, "admin.html", Role.ADMIN)

    @app.get("/app/auditor", include_in_schema=False)
    def auditor_portal(request: Request):
        return authenticated_page(request, "auditor.html", Role.AUDITOR)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/.well-known/acme-challenge/{token}", include_in_schema=False)
    def acme_http01_challenge(token: str) -> Response:
        # Unauthenticated by necessity: the ACME server fetches this during
        # HTTP-01 validation. It only ever returns key authorizations for tokens
        # we are actively serving for an in-flight order.
        key_authorization = service_certs.http01_keyauth(token)
        if key_authorization is None:
            raise HTTPException(status_code=404, detail="Unknown challenge token")
        return Response(content=key_authorization, media_type="text/plain")

    # -- holder claim pages & API (public, token-gated) -------------------------
    # No login: possession of the (hashed-at-rest) URL token plus an email OTP
    # to the registered person gate everything. Tokens never appear in logs.

    def portal_base_url() -> str | None:
        value = (repository.get_setting("portal_base_url") or "").strip().rstrip("/")
        return value or None

    def download_receipts_enabled() -> bool:
        return (repository.get_setting("holder_download_receipts") or "1") != "0"

    def set_claim_cookie(response: Response, token: str) -> None:
        response.set_cookie(
            key="myownca_claim",
            value=token,
            httponly=True,
            secure=settings.session_cookie_secure,
            samesite="strict",
            path="/",
        )

    def link_audit_actor(request: Request, link) -> AuditActor:
        source_ip = request.client.host if request.client else None
        return AuditActor(id=f"link:{link.id}", email=None, role="holder", source_ip=source_ip)

    def claim_link_or_404(token: str):
        link = secure_links.find_by_token(token)
        if link is None:
            raise HTTPException(status_code=404, detail="Unknown link")
        return link

    def certificate_for_link(link) -> IssuedCertificate:
        if link.certificate_id:
            return repository.get_certificate_by_id(link.certificate_id)
        if link.serial_number:
            return _serial_certificate(link.serial_number)
        raise RepositoryError("Secure link has no certificate reference")

    def claim_session_or_401(token: str, request: Request):
        link = secure_links.session_link(token, request.cookies.get("myownca_claim"))
        if link is None:
            raise HTTPException(status_code=401, detail="Verification required")
        return link

    def mtls_presented_certificate(request: Request) -> x509.Certificate | None:
        """The client certificate forwarded by the trusted mTLS reverse proxy.

        Only honoured when the proxy authenticates itself with the shared
        secret — a client can never inject these headers across the proxy
        (nginx overwrites them) or directly (secret unknown, compared in
        constant time).
        """
        secret = repository.get_setting("mtls_proxy_secret") or ""
        if not secret:
            return None
        provided = request.headers.get("x-bb-proxy-auth") or ""
        if not hmac.compare_digest(provided.encode(), secret.encode()):
            return None
        raw = request.headers.get("x-bb-client-cert") or ""
        if not raw:
            return None
        try:
            return x509.load_pem_x509_certificate(urllib.parse.unquote(raw).encode())
        except ValueError:
            return None

    def link_possession_proven(request: Request, certificate: IssuedCertificate) -> bool:
        """mTLS proof: the presented cert IS the link's certificate (byte-equal)."""
        presented = mtls_presented_certificate(request)
        if presented is None:
            return False
        try:
            stored = x509.load_pem_x509_certificate(certificate.certificate_pem.encode())
        except ValueError:
            return False
        return presented == stored and certificate.status is not CertificateStatus.REVOKED

    def link_summary(link) -> dict[str, object]:
        try:
            email = secure_links.recipient_email(link)
        except SecureLinkError:
            email = None
        return {
            "id": link.id,
            "purpose": link.purpose.value,
            "certificate_id": link.certificate_id,
            "serial_number": link.serial_number,
            "person_id": link.person_id,
            "person_email": email,
            "created_by": link.created_by,
            "created_at": link.created_at.isoformat(),
            "expires_at": link.expires_at.isoformat(),
            "max_uses": link.max_uses,
            "use_count": link.use_count,
            "last_used_at": link.last_used_at.isoformat() if link.last_used_at else None,
            "status": secure_links.usability(link) or "active",
        }

    def send_delivery_link_for(certificate: IssuedCertificate) -> None:
        """Mint + email a delivery link (issuance of link-originated requests).

        Uses an 'issued' notification template when one exists (with $claim_url
        and $link_expires available), else a built-in plain message.
        """
        base = portal_base_url()
        if base is None:
            return
        link, token = secure_links.mint(
            LinkPurpose.DELIVERY,
            created_by="system:issuance",
            certificate_id=certificate.certificate_id,
        )
        audit.record(
            AuditCategory.CERTIFICATE,
            "link_created",
            actor=AuditActor.system(),
            object_type="secure_link",
            object_id=link.id,
            details={
                "purpose": "delivery",
                "certificate_id": link.certificate_id,
                "serial_number": certificate.serial_number,
                "trigger": "link_originated_issuance",
            },
        )
        claim_url = f"{base}/claim/{token}"
        link_expires = link.expires_at.date().isoformat()
        subject = f"Your certificate is ready: {certificate.subject}"
        body = (
            f"Your certificate ({certificate.subject}) has been issued.\n\n"
            f"Download it here: {claim_url}\n\n"
            f"The link expires on {link_expires}. Opening it will email a "
            "verification code to this address."
        )
        try:
            template = next(
                (
                    candidate
                    for candidate in notifications.repository.list_templates()
                    if candidate.event_type is NotificationEvent.ISSUED
                ),
                None,
            )
            if template is not None:
                person = notifications.holder_person(certificate)
                context = {
                    "portal_url": base,
                    "claim_url": claim_url,
                    "link_expires": link_expires,
                    "notification_text": "",
                    **context_for_certificate(certificate, person, now=datetime.now(timezone.utc)),
                }
                subject, body = render_notification(template, context)
        except Exception:  # noqa: BLE001 - template problems fall back to the plain text
            pass
        comms.send(
            NotificationChannel.EMAIL,
            secure_links.recipient_email(link),
            Message(body=body, subject=subject),
        )

    _CLAIM_PAGE_HEADERS = {"Referrer-Policy": "no-referrer", "X-Robots-Tag": "noindex"}

    @app.get("/claim/{token}", include_in_schema=False)
    def claim_page(token: str) -> FileResponse:  # noqa: ARG001 - shell page; JS reads the token
        return FileResponse(static_dir / "holder.html", headers=_CLAIM_PAGE_HEADERS)

    @app.get("/internal/claim/{token}/state")
    def claim_state(token: str, request: Request) -> dict[str, object]:
        link = claim_link_or_404(token)
        auth = None
        certificate = (
            certificate_for_link(link) if link.certificate_id or link.serial_number else None
        )
        if (
            link.purpose is LinkPurpose.RENEWAL
            and certificate is not None
            and link_possession_proven(request, certificate)
            and secure_links.usability(link) is None
        ):
            auth = "mtls"
        elif secure_links.session_link(token, request.cookies.get("myownca_claim")):
            auth = "otp"
        if auth is None:
            reason = secure_links.usability(link)
            if reason:
                return {"status": "unusable", "reason": reason, "purpose": link.purpose.value}
            try:
                hint = mask_email(secure_links.recipient_email(link))
            except SecureLinkError:
                return {
                    "status": "unusable",
                    "reason": "recipient_missing",
                    "purpose": link.purpose.value,
                }
            now = datetime.now(timezone.utc)
            otp_pending = link.otp_expires_at is not None and link.otp_expires_at > now
            return {
                "status": "otp_required",
                "purpose": link.purpose.value,
                "recipient_hint": hint,
                "otp_pending": otp_pending,
            }
        body: dict[str, object] = {
            "status": "ready",
            "purpose": link.purpose.value,
            "auth": auth,
            "license_identity": licensing.identity(),
        }
        if certificate is not None:
            body["certificate"] = {
                "subject": certificate.subject,
                "serial_number": certificate.serial_number,
                "expires_at": certificate.expires_at.isoformat(),
                "status": certificate.status.value,
            }
            body["server_key_held"] = repository.has_request_private_key(certificate.request_id)
        if link.purpose is LinkPurpose.ENROLLMENT:
            body["templates"] = [
                {
                    "id": template.id,
                    "name": template.name,
                    "profile": template.profile.value,
                    "allowed_key_algorithms": list(template.allowed_key_algorithms),
                }
                for template in repository.list_templates()
            ]
            body["algorithms"] = list(keygen.CERTIFICATE_ALGORITHMS)
            person = _repository_person_or_none(repository, link.person_id)
            body["holder_defaults"] = {
                "common_name": person.full_name if person else "",
                "email_address": person.email if person else "",
            }
        return body

    @app.post("/internal/claim/{token}/otp/send")
    def claim_otp_send(token: str, request: Request) -> dict[str, object]:
        link = claim_link_or_404(token)
        moment = datetime.now(timezone.utc)
        if link.otp_expires_at is not None:
            sent_at = link.otp_expires_at - timedelta(minutes=OTP_TTL_MINUTES)
            if sent_at <= moment < sent_at + timedelta(seconds=60):
                raise HTTPException(
                    status_code=429, detail="Please wait a minute before requesting another code"
                )
        try:
            email = secure_links.recipient_email(link)
            code = secure_links.start_otp(link)
        except SecureLinkError as exc:
            raise HTTPException(status_code=410, detail=str(exc)) from exc
        rendered = None
        try:
            rendered = notifications.render_otp(
                code=code, email=email, expires_minutes=OTP_TTL_MINUTES
            )
        except Exception:  # noqa: BLE001 - custom templates must never block the code
            rendered = None
        subject, body = rendered or (
            "Your myOwnCA verification code",
            f"Your verification code is {code}. It expires in {OTP_TTL_MINUTES} minutes.",
        )
        try:
            result = comms.send(
                NotificationChannel.EMAIL, email, Message(body=body, subject=subject)
            )
        except CommsError as exc:
            raise HTTPException(
                status_code=502, detail="Could not send the verification code"
            ) from exc
        if not result.success:
            raise HTTPException(status_code=502, detail="Could not send the verification code")
        audit.record(
            AuditCategory.COMMS,
            "link_otp_sent",
            actor=link_audit_actor(request, link),
            object_type="secure_link",
            object_id=link.id,
        )
        return {"sent": True, "recipient_hint": mask_email(email)}

    @app.post("/internal/claim/{token}/otp/verify")
    def claim_otp_verify(
        token: str, payload: ClaimOtpVerify, request: Request, response: Response
    ) -> dict[str, object]:
        link = claim_link_or_404(token)
        session_token = secure_links.verify_otp(link, payload.code)
        if session_token is None:
            fresh = secure_links.repository.get_link(link.id)
            if fresh.locked_at is not None:
                audit.record(
                    AuditCategory.AUTH,
                    "link_locked",
                    actor=link_audit_actor(request, link),
                    object_type="secure_link",
                    object_id=link.id,
                )
                raise HTTPException(
                    status_code=423, detail="Too many attempts; this link is now locked"
                )
            raise HTTPException(status_code=400, detail="Invalid or expired code")
        set_claim_cookie(response, session_token)
        audit.record(
            AuditCategory.AUTH,
            "link_session_opened",
            actor=link_audit_actor(request, link),
            object_type="secure_link",
            object_id=link.id,
        )
        return {"status": "ready", "purpose": link.purpose.value}

    @app.post("/internal/claim/{token}/download")
    def claim_download(token: str, payload: ClaimDownload, request: Request) -> Response:
        link = claim_session_or_401(token, request)
        if link.purpose is not LinkPurpose.DELIVERY:
            raise HTTPException(
                status_code=400, detail="This link does not deliver certificate files"
            )
        certificate = certificate_for_link(link)
        try:
            fmt = ExportFormat(payload.format)
        except ValueError as exc:
            raise HTTPException(
                status_code=400, detail=f"Unknown export format: {payload.format}"
            ) from exc
        key_pem = None
        if fmt in KEY_BEARING_FORMATS:
            try:
                key_pem = key_vault.load_pem(certificate.request_id)
            except ServerKeyError as exc:
                raise HTTPException(status_code=500, detail=str(exc)) from exc
            if key_pem is None:
                raise HTTPException(
                    status_code=409, detail="No server-held private key for this certificate"
                )
        chain = (
            certificate_chain_pems(certificate.certificate_pem)
            if fmt in (ExportFormat.PEM_CHAIN, ExportFormat.PKCS12)
            else ()
        )
        try:
            result = build_export(
                certificate.certificate_pem,
                fmt,
                serial_number=certificate.serial_number,
                chain_pems=chain,
                private_key_pem=key_pem,
                password=payload.password,
            )
        except ExportError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        audit.record(
            AuditCategory.CERTIFICATE,
            "link_download",
            actor=link_audit_actor(request, link),
            object_type="certificate",
            object_id=certificate.certificate_id or certificate.serial_number,
            details={"format": fmt.value, "link_id": link.id},
        )
        if fmt in KEY_BEARING_FORMATS and download_receipts_enabled():
            # Receipt makes a stolen-link download a detected incident.
            try:
                comms.send(
                    NotificationChannel.EMAIL,
                    secure_links.recipient_email(link),
                    Message(
                        subject="Your certificate bundle was downloaded",
                        body=(
                            f"The private-key bundle for {certificate.subject} was downloaded "
                            f"at {datetime.now(timezone.utc).isoformat(timespec='seconds')}. "
                            "If this was not you, contact your administrator immediately."
                        ),
                    ),
                )
            except Exception:  # noqa: BLE001 - receipts are best-effort
                pass
        return _export_response(result)

    @app.post("/internal/claim/{token}/renew", status_code=201)
    def claim_renew(token: str, payload: ClaimRenew, request: Request) -> dict[str, object]:
        link = claim_link_or_404(token)
        if link.purpose is not LinkPurpose.RENEWAL:
            raise HTTPException(status_code=400, detail="This link does not allow renewal")
        claim_session = secure_links.session_link(token, request.cookies.get("myownca_claim"))
        reason = secure_links.usability(link)
        if reason and claim_session is None:
            raise HTTPException(status_code=410, detail=f"Link is {reason}")
        certificate = certificate_for_link(link)
        # mTLS proof of possession wins; the email-OTP session is the fallback
        # and marks the renewal for mandatory superuser approval.
        if link_possession_proven(request, certificate):
            auth_method = "mtls"
        elif claim_session is not None:
            auth_method = "otp"
        else:
            raise HTTPException(
                status_code=401,
                detail="Present your current certificate or verify with the emailed code",
            )
        if certificate.status is CertificateStatus.REVOKED:
            raise HTTPException(status_code=409, detail="Revoked certificates cannot be renewed")
        anchor_request = repository.get_request(certificate.request_id)
        template = repository.get_template(certificate.template_id)
        server_key_held = repository.has_request_private_key(certificate.request_id)
        mode = payload.mode or ("rotate" if server_key_held else "reuse")
        new_key = None
        algorithm = None
        if mode == "csr":
            if not (payload.csr_pem or "").strip():
                raise HTTPException(status_code=400, detail="csr mode requires csr_pem")
            csr_pem = payload.csr_pem
        elif mode == "rotate":
            if not server_key_held:
                raise HTTPException(
                    status_code=409,
                    detail="No server-held key to rotate; paste a new CSR or reuse the old one",
                )
            key_row = repository.get_request_private_key(certificate.request_id)
            algorithm = key_row["algorithm"]
            if algorithm not in template.allowed_key_algorithms:
                raise HTTPException(
                    status_code=400,
                    detail="The certificate template no longer allows this key algorithm",
                )
            try:
                new_key = keygen.generate_private_key(
                    algorithm, entropy_source=current_entropy_source
                )
            except keygen.EntropyError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc
            stored = x509.load_pem_x509_certificate(certificate.certificate_pem.encode())
            common_names = stored.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            common_name = str(common_names[0].value) if common_names else certificate.subject
            try:
                subject_alt_names = stored.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value
            except x509.ExtensionNotFound:
                subject_alt_names = None
            dns_names = (
                tuple(subject_alt_names.get_values_for_type(x509.DNSName))
                if subject_alt_names is not None
                else ()
            )
            email_addresses = (
                tuple(subject_alt_names.get_values_for_type(x509.RFC822Name))
                if subject_alt_names is not None
                else ()
            )
            try:
                csr_pem = build_csr_for_key(
                    new_key,
                    common_name=common_name,
                    dns_names=dns_names,
                    email_addresses=email_addresses,
                )
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        elif mode == "reuse":
            csr_pem = anchor_request.csr_pem
        else:
            raise HTTPException(status_code=400, detail=f"Unknown renewal mode: {mode}")
        try:
            renewal = service.submit_request(
                template_id=certificate.template_id,
                csr_pem=csr_pem,
                kind=RequestKind.RENEWAL,
                requested_by_user_id=anchor_request.requested_by_user_id,
                renewal_of_serial_number=certificate.serial_number,
                renewal_of_certificate_id=certificate.certificate_id,
                via_link_auth=auth_method,
            )
        except AmbiguousCertificateSerialError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except (RepositoryError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        # Holder + key carry-over so issuance and later delivery just work.
        if certificate.holder_person_id or certificate.holder_device_id:
            service.assign_request_holder(
                renewal.id,
                person_id=certificate.holder_person_id,
                device_id=certificate.holder_device_id,
            )
        if mode == "rotate":
            key_vault.store(renewal.id, new_key, algorithm)
            ensure_request_key_registered(renewal.id)
        elif mode == "reuse" and server_key_held:
            key_vault.copy(certificate.request_id, renewal.id)
            reuse_request_key_registration(certificate, renewal.id)
        secure_links.consume(link)
        audit.record(
            AuditCategory.CERTIFICATE,
            "link_renewal_submitted",
            actor=link_audit_actor(request, link),
            object_type="request",
            object_id=renewal.id,
            details={
                "auth": auth_method,
                "mode": mode,
                "renewal_of": certificate.serial_number,
            },
        )
        renewal = repository.get_request(renewal.id)
        template = repository.get_template(renewal.template_id)
        needed = required_approvals(renewal, template)
        issued_serial = None
        issue_error = None
        if needed == 0:
            issued, issue_error = attempt_issuance(renewal.id, link_audit_actor(request, link))
            issued_serial = issued.serial_number if issued else None
        return {
            "status": "submitted",
            "request_id": renewal.id,
            "auth": auth_method,
            "mode": mode,
            "required_approvals": needed,
            "requires_approval": needed > 0,
            "issued_serial_number": issued_serial,
            "auto_issue_error": issue_error,
        }

    @app.post("/internal/claim/{token}/enroll", status_code=201)
    def claim_enroll(token: str, payload: ClaimEnroll, request: Request) -> dict[str, object]:
        """First-issuance request through an enrollment invitation link."""
        link = claim_session_or_401(token, request)
        if link.purpose is not LinkPurpose.ENROLLMENT:
            raise HTTPException(status_code=400, detail="This link does not allow enrollment")
        try:
            repository.get_template(payload.template_id)
        except RepositoryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        new_key = None
        if (payload.csr_pem or "").strip():
            csr_pem = payload.csr_pem
        else:
            common_name = (payload.common_name or "").strip()
            if not common_name:
                raise HTTPException(
                    status_code=400,
                    detail="Provide a CSR or a common name for server key generation",
                )
            template = repository.get_template(payload.template_id)
            if payload.algorithm not in template.allowed_key_algorithms:
                raise HTTPException(
                    status_code=400, detail=f"Key algorithm is not allowed by the certificate template: {payload.algorithm}"
                )
            try:
                new_key = keygen.generate_private_key(
                    payload.algorithm, entropy_source=current_entropy_source
                )
            except keygen.EntropyError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc
            dns_names = tuple(name.strip() for name in payload.dns_names if name.strip())
            email_addresses = tuple(
                address.strip() for address in payload.email_addresses if address.strip()
            )
            try:
                csr_pem = build_csr_for_key(
                    new_key,
                    common_name=common_name,
                    dns_names=dns_names,
                    email_addresses=email_addresses,
                )
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        try:
            enrollment = service.submit_request(payload.template_id, csr_pem, via_link_auth="otp")
        except (RepositoryError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        service.assign_request_holder(enrollment.id, person_id=link.person_id)
        if new_key is not None:
            key_vault.store(enrollment.id, new_key, payload.algorithm)
            ensure_request_key_registered(enrollment.id)
        secure_links.consume(link)
        audit.record(
            AuditCategory.CERTIFICATE,
            "link_enrollment_submitted",
            actor=link_audit_actor(request, link),
            object_type="request",
            object_id=enrollment.id,
            details={
                "template_id": payload.template_id,
                "server_key": new_key is not None,
                "person_id": link.person_id,
            },
        )
        enrollment = repository.get_request(enrollment.id)
        template = repository.get_template(enrollment.template_id)
        needed = required_approvals(enrollment, template)
        return {
            "status": "submitted",
            "request_id": enrollment.id,
            "required_approvals": needed,
            "requires_approval": needed > 0,
            "server_key": new_key is not None,
        }

    # -- secure link management (superuser portal) ------------------------------

    @app.get("/internal/links")
    def list_secure_links(request: Request) -> list[dict[str, object]]:
        active_user(request, Role.ADMIN, Role.SUPERUSER)
        return [link_summary(link) for link in secure_links.list_links()]

    @app.post("/internal/links", status_code=201)
    def create_secure_link(payload: LinkCreate, request: Request) -> dict[str, object]:
        _, user = active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        try:
            purpose = LinkPurpose(payload.purpose)
        except ValueError as exc:
            raise HTTPException(
                status_code=400, detail=f"Unknown link purpose: {payload.purpose}"
            ) from exc
        try:
            link, token = secure_links.mint(
                purpose,
                created_by=user.id,
                certificate_id=payload.certificate_id,
                serial_number=payload.serial_number,
                person_id=payload.person_id,
            )
        except SecureLinkError as exc:
            status_code = 409 if isinstance(exc.__cause__, AmbiguousCertificateSerialError) else 400
            raise HTTPException(status_code=status_code, detail=str(exc)) from exc
        audit.record(
            AuditCategory.CERTIFICATE,
            "link_created",
            actor=audit_actor(request),
            object_type="secure_link",
            object_id=link.id,
            details={
                "purpose": purpose.value,
                "certificate_id": link.certificate_id,
                "serial_number": link.serial_number,
            },
        )
        # Renewal links live on the mTLS endpoint when one is configured.
        base = portal_base_url()
        if purpose is LinkPurpose.RENEWAL:
            mtls_base = (repository.get_setting("mtls_base_url") or "").strip().rstrip("/")
            base = mtls_base or base
        claim_url = f"{base}/claim/{token}" if base else None
        email_sent = False
        email_error = None
        if payload.send_email:
            if claim_url is None:
                raise HTTPException(
                    status_code=409,
                    detail="Set the portal base URL (admin portal → Holder portal) "
                    "before emailing links",
                )
            if purpose is LinkPurpose.ENROLLMENT:
                subject = "Your certificate enrollment invitation"
                intro = "You have been invited to request a certificate"
            else:
                certificate = certificate_for_link(link)
                if purpose is LinkPurpose.RENEWAL:
                    subject = f"Renew your certificate: {certificate.subject}"
                    intro = f"A secure renewal link for your certificate ({certificate.subject}) has been prepared"
                else:
                    subject = f"Your certificate: {certificate.subject}"
                    intro = f"A secure download link for your certificate ({certificate.subject}) has been prepared"
            body = (
                f"{intro}:\n\n{claim_url}\n\n"
                f"The link expires on {link.expires_at.date().isoformat()}. Opening it "
                "will email a verification code to this address."
            )
            try:
                result = comms.send(
                    NotificationChannel.EMAIL,
                    secure_links.recipient_email(link),
                    Message(body=body, subject=subject),
                )
                email_sent = result.success
                email_error = None if result.success else result.detail
            except (CommsError, SecureLinkError) as exc:
                email_error = str(exc)
        return {
            **link_summary(link),
            "claim_url": claim_url,
            "claim_path": f"/claim/{token}",
            "email_sent": email_sent,
            "email_error": email_error,
        }

    @app.post("/internal/links/qr")
    def link_qr(payload: LinkQrRequest, request: Request) -> Response:
        """Render arbitrary short text (a claim URL) as an SVG QR code.

        POST (not GET) so the secret-bearing URL never lands in access logs.
        """
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        import io  # noqa: PLC0415

        import qrcode  # noqa: PLC0415
        import qrcode.image.svg  # noqa: PLC0415

        image = qrcode.make(payload.data, image_factory=qrcode.image.svg.SvgPathImage)
        buffer = io.BytesIO()
        image.save(buffer)
        return Response(content=buffer.getvalue(), media_type="image/svg+xml")

    @app.post("/internal/links/{link_id}/revoke", status_code=201)
    def revoke_secure_link(link_id: str, request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        try:
            link = secure_links.revoke(link_id)
        except RepositoryError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        audit.record(
            AuditCategory.CERTIFICATE,
            "link_revoked",
            actor=audit_actor(request),
            object_type="secure_link",
            object_id=link.id,
        )
        return link_summary(link)

    def _holder_portal_status() -> dict[str, object]:
        mtls_base = (repository.get_setting("mtls_base_url") or "").strip().rstrip("/")
        return {
            "portal_base_url": portal_base_url(),
            "download_receipts": download_receipts_enabled(),
            "mtls_base_url": mtls_base or None,
            # write-only secret: report presence, never the value
            "mtls_proxy_secret_set": bool(repository.get_setting("mtls_proxy_secret")),
            "server_key_purge_days": 30,
        }

    # -- public access requests ("I need a certificate") ------------------------

    _access_hits: dict[str, list[datetime]] = {}

    def _access_rate_limited(request: Request) -> bool:
        """Per-IP budget: 5 submissions per hour (in-memory, best-effort)."""
        source = request.client.host if request.client else "unknown"
        now = datetime.now(timezone.utc)
        hits = [hit for hit in _access_hits.get(source, []) if now - hit < timedelta(hours=1)]
        limited = len(hits) >= 5
        if not limited:
            hits.append(now)
        _access_hits[source] = hits
        return limited

    def _access_response(access_request) -> dict[str, object]:
        return {
            "id": access_request.id,
            "email": access_request.email,
            "name": access_request.name,
            "kind": access_request.kind,
            "message": access_request.message,
            "status": access_request.status.value,
            "created_at": access_request.created_at.isoformat(),
            "email_verified_at": access_request.email_verified_at.isoformat()
            if access_request.email_verified_at
            else None,
            "decided_by": access_request.decided_by,
            "decided_at": access_request.decided_at.isoformat()
            if access_request.decided_at
            else None,
        }

    def _access_request_config() -> tuple[bool, list[str]]:
        enabled = repository.get_setting("access_request_enabled") == "true"
        raw = repository.get_setting("access_request_allowed_domains")
        domains = json.loads(raw) if raw else []
        return enabled, domains

    @app.get("/access-request/config", include_in_schema=False)
    def access_request_public_config() -> dict[str, object]:
        enabled, domains = _access_request_config()
        # "Enabled but no domains" allows nobody, so report it as off to the
        # public surface — keeps the login link hidden and the page unreachable.
        return {"enabled": enabled and bool(domains)}

    @app.get("/internal/access-request/config")
    def get_access_request_config(request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN)
        enabled, domains = _access_request_config()
        return {"enabled": enabled, "allowed_domains": domains}

    @app.put("/internal/access-request/config")
    def update_access_request_config(
        payload: AccessRequestConfigUpdate, request: Request
    ) -> dict[str, object]:
        active_user(request, Role.ADMIN, csrf=True)
        try:
            domains = normalize_domains(payload.allowed_domains)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        repository.set_setting("access_request_enabled", "true" if payload.enabled else "false")
        repository.set_setting("access_request_allowed_domains", json.dumps(domains))
        audit.record(
            AuditCategory.AUDIT,
            "access_request_config_update",
            actor=audit_actor(request),
            object_type="access_request_config",
            details={"enabled": payload.enabled, "domain_count": len(domains)},
        )
        return {"enabled": payload.enabled, "allowed_domains": domains}

    @app.get("/request-access", include_in_schema=False)
    def request_access_page() -> FileResponse:
        enabled, domains = _access_request_config()
        if not (enabled and domains):
            raise HTTPException(status_code=404, detail="Not found")
        return FileResponse(static_dir / "request-access.html", headers=_CLAIM_PAGE_HEADERS)

    @app.post("/internal/access-requests")
    def submit_access_request(payload: AccessRequestCreate, request: Request) -> dict[str, object]:
        enabled, allowed_domains = _access_request_config()
        if not (enabled and allowed_domains):
            raise HTTPException(status_code=404, detail="Self-service requests are not available")
        # Uniform response shape regardless of outcome — no enumeration, and
        # honeypot/rate-limited submissions get a dead-end id.
        generic = {
            "submitted": True,
            "detail": "If the address is valid, a verification code has been emailed.",
        }
        if payload.website or _access_rate_limited(request):
            return {**generic, "request_id": str(uuid4())}
        if not is_request_allowed(enabled, allowed_domains, payload.email):
            raise HTTPException(
                status_code=400,
                detail=(
                    "Your email domain is not permitted to self-request a certificate. "
                    "Contact the CA operator."
                ),
            )
        try:
            result = access_requests.submit(
                email=payload.email,
                name=payload.name,
                kind=payload.kind,
                message=payload.message,
            )
        except AccessRequestError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if result is None:  # per-email budget exhausted
            return {**generic, "request_id": str(uuid4())}
        access_request, code = result
        try:
            comms.send(
                NotificationChannel.EMAIL,
                access_request.email,
                Message(
                    subject="Your myOwnCA verification code",
                    body=(
                        f"Your verification code is {code}. It expires in "
                        f"{VERIFY_TTL_MINUTES} minutes.\n\nIf you did not request a "
                        "certificate, ignore this message."
                    ),
                ),
            )
        except CommsError:
            pass  # uniform response; an unreachable mail server must not leak state
        return {**generic, "request_id": access_request.id}

    @app.post("/internal/access-requests/{request_id}/verify")
    def verify_access_request(
        request_id: str, payload: AccessRequestVerify, request: Request
    ) -> dict[str, object]:
        verified = access_requests.verify(request_id, payload.code)
        if verified is None:
            raise HTTPException(status_code=400, detail="Invalid or expired code")
        source_ip = request.client.host if request.client else None
        audit.record(
            AuditCategory.USER,
            "access_request_verified",
            actor=AuditActor(id=f"access:{verified.id}", role="public", source_ip=source_ip),
            object_type="access_request",
            object_id=verified.id,
            details={"email": verified.email, "kind": verified.kind},
        )
        try:
            notifications.notify_event(
                NotificationEvent.ACCESS_REQUESTED,
                context_override={
                    "access_email": verified.email,
                    "access_name": verified.name,
                    "access_kind": verified.kind,
                    "access_message": verified.message,
                },
                object_ref=verified.id,
            )
        except Exception:  # noqa: BLE001 - notifications must never block verification
            pass
        return {
            "status": "pending",
            "detail": "Thanks — your request is now waiting for a Certificate Operator.",
        }

    @app.get("/internal/access-requests")
    def list_access_requests(request: Request) -> list[dict[str, object]]:
        active_user(request, Role.ADMIN, Role.SUPERUSER)
        return [
            _access_response(access_request)
            for access_request in access_requests.list_requests()
            if access_request.status is not AccessRequestStatus.UNVERIFIED
        ]

    @app.post("/internal/access-requests/{request_id}/approve", status_code=201)
    def approve_access_request(request_id: str, request: Request) -> dict[str, object]:
        return _decide_access_request(request_id, request, approve=True)

    @app.post("/internal/access-requests/{request_id}/deny", status_code=201)
    def deny_access_request(request_id: str, request: Request) -> dict[str, object]:
        return _decide_access_request(request_id, request, approve=False)

    def _decide_access_request(
        request_id: str, request: Request, *, approve: bool
    ) -> dict[str, object]:
        _, user = active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        try:
            decided = access_requests.decide(request_id, approve=approve, decided_by=user.id)
        except RepositoryError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except AccessRequestError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        audit.record(
            AuditCategory.USER,
            "access_request_approved" if approve else "access_request_denied",
            actor=audit_actor(request),
            object_type="access_request",
            object_id=decided.id,
            details={"email": decided.email, "kind": decided.kind},
        )
        return _access_response(decided)

    # -- licensing --------------------------------------------------------------

    @app.get("/internal/license/identity")
    def license_identity(request: Request) -> dict[str, object]:
        active_user(request)
        return licensing.identity()

    @app.get("/internal/admin/license")
    def license_status(request: Request) -> dict[str, object]:
        # Readable by superusers/auditors so the issuance UI can show the meter;
        # only admins upload/remove.
        active_user(request, Role.ADMIN, Role.SUPERUSER, Role.AUDITOR)
        return licensing.summary()

    @app.put("/internal/admin/license", status_code=201)
    def install_license(payload: LicenseUpload, request: Request) -> dict[str, object]:
        _, user = active_user(request, Role.ADMIN, csrf=True)
        previous = licensing.summary()
        try:
            license = licensing.install(payload.token, uploaded_by=user.id)
        except LicenseInstallationMismatchError as exc:
            audit.record(
                AuditCategory.SYSTEM,
                "license_installation_mismatch",
                actor=audit_actor(request),
                outcome=AuditOutcome.DENIED,
                object_type="license",
                object_id="upload",
                details={"detail": str(exc)},
            )
            raise HTTPException(
                status_code=409,
                detail={"code": "license_installation_mismatch", "message": str(exc)},
            ) from exc
        except LicenseError as exc:
            raise HTTPException(
                status_code=400,
                detail={"code": "invalid_license", "message": str(exc)},
            ) from exc
        audit.record(
            AuditCategory.SYSTEM,
            "license_replaced" if previous.get("license_id") else "license_installed",
            actor=audit_actor(request),
            object_type="license",
            object_id=license.license_id,
            details={
                "licensed_to": license.licensed_to,
                "expires_at": license.expires_at.isoformat(),
                "max_certificate_lineages": license.max_certificate_lineages,
                "installation_id": license.installation_id,
                "previous_license_id": previous.get("license_id"),
            },
        )
        return licensing.summary()

    @app.delete("/internal/admin/license")
    def remove_license(request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN, csrf=True)
        before = licensing.summary()
        removed = licensing.remove()
        if removed:
            audit.record(
                AuditCategory.SYSTEM,
                "license_removed",
                actor=audit_actor(request),
                object_type="license",
                object_id=str(before.get("license_id") or "active"),
                details={
                    "active_lineages": before.get("active_lineages"),
                    "free_tier": before.get("free_tier"),
                    "new_identities_blocked": (
                        int(before.get("active_lineages") or 0) > int(before.get("free_tier") or 0)
                    ),
                    "renewals_remain_allowed": True,
                },
            )
        return licensing.summary()

    @app.get("/internal/admin/risk-summary")
    def admin_risk_summary(request: Request) -> dict[str, int]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, Role.AUDITOR)
        return _risk_summary(
            repository,
            notifications.repository,
            service_certs.repository,
            now=datetime.now(timezone.utc),
        )

    @app.get("/internal/admin/operations")
    def admin_operations(request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN)
        return operations.overview()

    @app.get("/internal/dashboard-alert-mutes")
    def list_dashboard_alert_mutes(request: Request) -> dict[str, list[str]]:
        _, user = active_user(request, Role.ADMIN, Role.SUPERUSER)
        return {
            "muted_alert_ids": dashboard_alert_mutes.list_muted(
                user_id=user.id,
                portal=user.role.value,
            )
        }

    @app.put("/internal/dashboard-alert-mutes/{alert_id}")
    def update_dashboard_alert_mute(
        alert_id: str,
        payload: DashboardAlertMuteUpdate,
        request: Request,
    ) -> dict[str, object]:
        _, user = active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        if re.fullmatch(r"[a-z0-9][a-z0-9._:-]{0,190}", alert_id) is None:
            raise HTTPException(status_code=400, detail="Invalid dashboard alert id")
        dashboard_alert_mutes.set_muted(
            user_id=user.id,
            portal=user.role.value,
            alert_id=alert_id,
            muted=payload.muted,
        )
        return {
            "alert_id": alert_id,
            "muted": payload.muted,
            "muted_alert_ids": dashboard_alert_mutes.list_muted(
                user_id=user.id,
                portal=user.role.value,
            ),
        }

    @app.get("/internal/admin/readiness")
    def admin_readiness(request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN)
        return operations.readiness()

    @app.get("/internal/admin/backups")
    def application_backup_status(request: Request) -> dict[str, object]:
        _, user = active_user(request, Role.ADMIN)
        return application_backup_service.status(current_user_id=user.id)

    @app.post("/internal/admin/backups/proposals", status_code=201)
    def propose_application_backup(
        payload: ApplicationBackupProposalCreate,
        request: Request,
    ) -> dict[str, object]:
        _, user, reason = require_destructive_action(
            request,
            payload,
            expected_confirmation="REQUEST APPLICATION BACKUP",
            category=AuditCategory.SYSTEM,
            action="application_backup_proposal",
            object_type="application_backup",
            object_id="new",
        )
        requester_share = payload.requester_passphrase.get_secret_value()
        if requester_share != payload.requester_passphrase_confirmation.get_secret_value():
            raise HTTPException(status_code=400, detail="Requester backup passphrase shares do not match")
        try:
            proposal = application_backup_service.request_backup(
                proposer_id=user.id,
                proposer_email=user.email,
                reason=reason,
                requester_passphrase=requester_share,
            )
        except (BackupRepositoryError, BackupServiceError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        audit.record(
            AuditCategory.SYSTEM,
            "application_backup_proposed",
            actor=audit_actor(request),
            object_type="application_backup_proposal",
            object_id=proposal.id,
            details={"reason": reason, "expires_at": proposal.expires_at.isoformat()},
        )
        return backup_proposal_dict(proposal)

    @app.post("/internal/admin/backups/proposals/{proposal_id}/approve", status_code=201)
    def approve_application_backup(
        proposal_id: str,
        payload: ApplicationBackupProposalApprove,
        request: Request,
    ) -> dict[str, object]:
        _, user, reason = require_destructive_action(
            request,
            payload,
            expected_confirmation="APPROVE APPLICATION BACKUP",
            category=AuditCategory.SYSTEM,
            action="application_backup_approval",
            object_type="application_backup_proposal",
            object_id=proposal_id,
        )
        approver_share = payload.approver_passphrase.get_secret_value()
        if approver_share != payload.approver_passphrase_confirmation.get_secret_value():
            raise HTTPException(status_code=400, detail="Approver backup passphrase shares do not match")
        try:
            result = application_backup_service.approve_and_create(
                proposal_id,
                approver_id=user.id,
                approver_email=user.email,
                reason=reason,
                approver_passphrase=approver_share,
            )
        except BackupRepositoryError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except (BackupServiceError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        audit.record(
            AuditCategory.SYSTEM,
            "application_backup_export_ready",
            actor=audit_actor(request),
            object_type="application_backup",
            object_id=str(result["id"]),
            details={
                "proposal_id": proposal_id,
                "reason": reason,
                "size": result["size_bytes"],
                "sha256": result["sha256"],
                "persisted_until_download": True,
            },
        )
        return result

    @app.post("/internal/admin/backups/proposals/{proposal_id}/reject", status_code=201)
    def reject_application_backup(proposal_id: str, request: Request) -> dict[str, object]:
        _, user = active_user(request, Role.ADMIN, csrf=True)
        try:
            proposal = application_backup_service.reject(proposal_id, actor_id=user.id)
        except BackupRepositoryError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        audit.record(
            AuditCategory.SYSTEM,
            "application_backup_rejected",
            actor=audit_actor(request),
            object_type="application_backup_proposal",
            object_id=proposal_id,
        )
        return backup_proposal_dict(proposal)

    @app.get("/internal/admin/backups/exports/{export_id}/download")
    def download_application_backup(export_id: str, request: Request) -> StreamingResponse:
        _, user = active_user(request, Role.ADMIN)
        application_backup_service.cleanup_expired()
        try:
            item = application_backup_repository.get_export(export_id)
        except BackupRepositoryError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        if item["approver_id"] != user.id:
            raise HTTPException(status_code=403, detail="Only the approving administrator may download this backup")
        if item["status"] != BackupExportStatus.READY.value:
            raise HTTPException(status_code=409, detail="Application backup is not available for download")
        path = application_backup_service.export_path(export_id)
        if not path.is_file():
            raise HTTPException(status_code=410, detail="Application backup download has expired")

        def stream_archive():
            completed = False
            try:
                with path.open("rb") as handle:
                    while chunk := handle.read(1024 * 1024):
                        yield chunk
                completed = True
            finally:
                if completed:
                    application_backup_repository.mark_delivered(export_id)
                    path.unlink(missing_ok=True)
                    audit.record(
                        AuditCategory.SYSTEM,
                        "application_backup_delivered",
                        actor=audit_actor(request),
                        object_type="application_backup",
                        object_id=export_id,
                        details={
                            "proposal_id": item["proposal_id"],
                            "size": item["size_bytes"],
                            "sha256": item["sha256"],
                            "off_host_storage_verified": False,
                            "restore_verified": False,
                        },
                    )

        return StreamingResponse(
            stream_archive(),
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{item["filename"]}"',
                "Content-Length": str(item["size_bytes"]),
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "X-Content-Type-Options": "nosniff",
            },
        )

    _SERVICE_URL_KEYS = (
        "admin_base_url",
        "superuser_base_url",
        "crl_base_url",
        "aia_base_url",
        "ocsp_url",
    )
    _SERVICE_BASE_URL_KEYS = {
        "admin_base_url",
        "superuser_base_url",
        "crl_base_url",
        "aia_base_url",
    }

    def _service_url_suggestions() -> dict[str, str]:
        # Defaults derived from the configured portal host. http scheme: relying parties
        # fetch CRL/AIA/OCSP without needing TLS. Shown in the UI; applied only on Save.
        host = urlparse(portal_base_url() or "").hostname
        if not host:
            return {}
        origin = f"http://{host}"
        return {"crl_base_url": origin, "aia_base_url": origin, "ocsp_url": f"{origin}/ocsp"}

    def _service_urls_status() -> dict[str, object]:
        status: dict[str, object] = {
            key: (repository.get_setting(key) or None) for key in _SERVICE_URL_KEYS
        }
        status["suggested"] = _service_url_suggestions()
        return status

    @app.get("/internal/admin/service-urls")
    def service_urls(request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN)
        return _service_urls_status()

    @app.put("/internal/admin/service-urls")
    def update_service_urls(payload: ServiceUrlsUpdate, request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN, csrf=True)
        for key in _SERVICE_URL_KEYS:
            value = getattr(payload, key)
            if value is None:
                continue
            value = value.strip()
            if key in _SERVICE_BASE_URL_KEYS:
                value = value.rstrip("/")
            if value and not value.startswith(("http://", "https://")):
                raise HTTPException(
                    status_code=400, detail=f"{key} must start with http:// or https://"
                )
            repository.set_setting(key, value)
        audit.record(
            AuditCategory.SYSTEM,
            "service_urls",
            actor=audit_actor(request),
            object_type="setting",
            object_id="service_urls",
        )
        return _service_urls_status()

    @app.get("/internal/admin/holder-portal")
    def holder_portal_settings(request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN)
        return _holder_portal_status()

    @app.put("/internal/admin/holder-portal")
    def update_holder_portal_settings(
        payload: HolderPortalUpdate, request: Request
    ) -> dict[str, object]:
        active_user(request, Role.ADMIN, csrf=True)
        for field, key in (
            ("portal_base_url", "portal_base_url"),
            ("mtls_base_url", "mtls_base_url"),
        ):
            value = getattr(payload, field)
            if value is None:
                continue
            value = value.strip().rstrip("/")
            if value and not value.startswith(("http://", "https://")):
                raise HTTPException(
                    status_code=400,
                    detail=f"{field} must start with http:// or https://",
                )
            repository.set_setting(key, value)
        if payload.download_receipts is not None:
            repository.set_setting(
                "holder_download_receipts", "1" if payload.download_receipts else "0"
            )
        if payload.mtls_proxy_secret is not None:
            repository.set_setting("mtls_proxy_secret", payload.mtls_proxy_secret.strip())
        if payload.server_key_purge_days is not None:
            if payload.server_key_purge_days != 30:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Private-key retention is fixed at 30 days after expiry or "
                        "orphaning and cannot be overridden"
                    ),
                )
            repository.set_setting("server_key_purge_days", "30")
        audit.record(
            AuditCategory.SYSTEM,
            "holder_portal_settings",
            actor=audit_actor(request),
            object_type="setting",
            object_id="holder_portal",
        )
        return _holder_portal_status()

    @app.post("/internal/auth/login")
    def login(payload: LoginCreate, response: Response) -> dict[str, object]:
        try:
            created = auth_service.login(payload.email, payload.password)
        except ThrottledError as exc:
            raise HTTPException(status_code=429, detail=str(exc)) from exc
        except AuthenticationError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        set_session_cookie(response, created.token)
        return _auth_response(created.session, created.user, auth_service)

    @app.get("/internal/auth/recovery/channels")
    def recovery_channels() -> dict[str, list[str]]:
        return {"channels": auth_service.available_recovery_channels()}

    @app.post("/internal/auth/password/recovery/request", status_code=202)
    def request_password_recovery(
        payload: PasswordRecoveryRequest,
        request: Request,
    ) -> dict[str, object]:
        auth_service.request_password_recovery(
            payload.email,
            payload.channel,
            source_ip=request.client.host if request.client else None,
        )
        return {
            "sent": True,
            "detail": (
                "If the account and selected delivery method are available, "
                "a recovery code has been sent."
            ),
        }

    @app.post("/internal/auth/password/recovery/verify")
    def verify_password_recovery(
        payload: PasswordRecoveryVerify,
        request: Request,
        response: Response,
    ) -> dict[str, object]:
        try:
            created = auth_service.verify_password_recovery(
                payload.email,
                payload.channel,
                payload.code,
                source_ip=request.client.host if request.client else None,
            )
        except ThrottledError as exc:
            raise HTTPException(status_code=429, detail=str(exc)) from exc
        except AuthenticationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        set_session_cookie(response, created.token)
        return _auth_response(created.session, created.user, auth_service)

    @app.get("/internal/auth/me")
    def auth_me(request: Request) -> dict[str, object]:
        session, user = current_session(request, allow_incomplete=True)
        return _auth_response(session, user, auth_service)

    def _first_login_guide_status(user: User) -> dict[str, object]:
        eligible = user.role in {Role.ADMIN, Role.SUPERUSER}
        outcome = (
            auth_repository.get_first_login_guide_outcome(user.id)
            if eligible
            else None
        )
        templates = repository.list_templates() if eligible else []
        recovery_channel_names = (
            auth_service.available_recovery_channels() if eligible else []
        )
        active_certificate_operators = (
            [
                candidate
                for candidate in repository.list_users()
                if candidate.role is Role.SUPERUSER and candidate.is_active
            ]
            if eligible
            else []
        )
        action_needed = eligible and (
            not templates
            or not recovery_channel_names
            or (user.role is Role.ADMIN and not active_certificate_operators)
        )
        return {
            "eligible": eligible,
            "show": eligible and outcome is None,
            "action_needed": action_needed,
            "outcome": outcome,
            "role": user.role.value,
            "prerequisites": {
                "certificate_operator": {
                    "ready": bool(active_certificate_operators),
                    "count": len(active_certificate_operators),
                },
                "certificate_templates": {
                    "ready": bool(templates),
                    "count": len(templates),
                },
                "password_recovery": {
                    "ready": bool(recovery_channel_names),
                    "channels": recovery_channel_names,
                },
            },
        }

    @app.get("/internal/auth/first-login-guide")
    def first_login_guide(request: Request) -> dict[str, object]:
        _, user = active_user(request)
        return _first_login_guide_status(user)

    @app.post("/internal/auth/first-login-guide/dismiss")
    def dismiss_first_login_guide(
        payload: FirstLoginGuideDismiss,
        request: Request,
    ) -> dict[str, object]:
        _, user = active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        auth_repository.dismiss_first_login_guide(
            user.id,
            outcome=payload.outcome,
            dismissed_at=datetime.now(timezone.utc),
        )
        return _first_login_guide_status(user)

    @app.post("/internal/auth/password/change")
    def change_password(
        payload: PasswordChangeCreate,
        request: Request,
    ) -> dict[str, object]:
        session, user = current_session(request, allow_incomplete=True)
        recovering = session.stage is SessionStage.PASSWORD_RECOVERY_REQUIRED
        try:
            auth_service.require_csrf(session, request.headers.get("x-csrf-token"))
            created = auth_service.change_password(
                request.cookies.get("myownca_session", ""),
                payload.new_password,
            )
        except (AuthError, CSRFError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if recovering:
            audit.record(
                AuditCategory.AUTH,
                "password_recovery_completed",
                actor=AuditActor(
                    id=user.id,
                    email=user.email,
                    role=user.role.value,
                    source_ip=request.client.host if request.client else None,
                ),
                object_type="user",
                object_id=user.id,
            )
        return _auth_response(created.session, created.user, auth_service)

    @app.post("/internal/auth/totp/enroll")
    def begin_totp_enrollment(request: Request) -> dict[str, str]:
        session, _ = current_session(request, allow_incomplete=True)
        try:
            auth_service.require_csrf(session, request.headers.get("x-csrf-token"))
            enrollment = auth_service.begin_totp_enrollment(
                request.cookies.get("myownca_session", "")
            )
        except (AuthError, CSRFError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        # Make the provisioning URI scannable: the authenticator app reads the QR
        # instead of the operator hand-typing the secret.
        enrollment["qr_svg"] = _qr_svg_data_uri(enrollment["provisioning_uri"])
        return enrollment

    @app.post("/internal/auth/totp/enroll/confirm")
    def confirm_totp_enrollment(
        payload: TOTPCodeCreate,
        request: Request,
    ) -> dict[str, object]:
        session, _ = current_session(request, allow_incomplete=True)
        try:
            auth_service.require_csrf(session, request.headers.get("x-csrf-token"))
            created = auth_service.confirm_totp_enrollment(
                request.cookies.get("myownca_session", ""),
                payload.code,
            )
        except ThrottledError as exc:
            raise HTTPException(status_code=429, detail=str(exc)) from exc
        except (AuthError, CSRFError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return _auth_response(created.session, created.user, auth_service)

    @app.post("/internal/auth/totp/challenge")
    def verify_totp_challenge(
        payload: TOTPCodeCreate,
        request: Request,
    ) -> dict[str, object]:
        session, _ = current_session(request, allow_incomplete=True)
        try:
            auth_service.require_csrf(session, request.headers.get("x-csrf-token"))
            created = auth_service.verify_totp_challenge(
                request.cookies.get("myownca_session", ""),
                payload.code,
            )
        except ThrottledError as exc:
            raise HTTPException(status_code=429, detail=str(exc)) from exc
        except (AuthError, CSRFError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return _auth_response(created.session, created.user, auth_service)

    @app.post("/internal/auth/totp/reauthenticate")
    def reauthenticate_totp(
        payload: TOTPCodeCreate,
        request: Request,
    ) -> dict[str, object]:
        session, _ = current_session(request)
        try:
            auth_service.require_csrf(session, request.headers.get("x-csrf-token"))
            created = auth_service.reauthenticate_totp(
                request.cookies.get("myownca_session", ""),
                payload.code,
            )
        except ThrottledError as exc:
            raise HTTPException(status_code=429, detail=str(exc)) from exc
        except (AuthError, CSRFError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return _auth_response(created.session, created.user, auth_service)

    @app.post("/internal/auth/password/reauthenticate")
    def reauthenticate_password(
        payload: PasswordReauthenticate,
        request: Request,
    ) -> dict[str, object]:
        session, _ = current_session(request)
        try:
            auth_service.require_csrf(session, request.headers.get("x-csrf-token"))
            created = auth_service.reauthenticate_password(
                request.cookies.get("myownca_session", ""),
                payload.password,
            )
        except ThrottledError as exc:
            raise HTTPException(status_code=429, detail=str(exc)) from exc
        except AuthenticationError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        except (AuthError, CSRFError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return _auth_response(created.session, created.user, auth_service)

    @app.post("/internal/auth/recovery/codes/regenerate")
    def regenerate_recovery_codes(request: Request) -> dict[str, object]:
        session, _ = current_session(request)
        try:
            auth_service.require_csrf(session, request.headers.get("x-csrf-token"))
            codes = auth_service.regenerate_recovery_codes(
                request.cookies.get("myownca_session", "")
            )
        except (AuthError, CSRFError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"recovery_codes": codes}

    @app.post("/internal/auth/recovery/code")
    def verify_recovery_code(payload: TOTPCodeCreate, request: Request) -> dict[str, object]:
        session, _ = current_session(request, allow_incomplete=True)
        try:
            auth_service.require_csrf(session, request.headers.get("x-csrf-token"))
            created = auth_service.verify_recovery_code(
                request.cookies.get("myownca_session", ""),
                payload.code,
            )
        except ThrottledError as exc:
            raise HTTPException(status_code=429, detail=str(exc)) from exc
        except (AuthError, CSRFError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return _auth_response(created.session, created.user, auth_service)

    @app.post("/internal/auth/recovery/email/request", status_code=202)
    def request_email_recovery(request: Request) -> dict[str, bool]:
        session, _ = current_session(request, allow_incomplete=True)
        try:
            auth_service.require_csrf(session, request.headers.get("x-csrf-token"))
            auth_service.request_email_recovery(request.cookies.get("myownca_session", ""))
        except ThrottledError as exc:
            raise HTTPException(status_code=429, detail=str(exc)) from exc
        except (AuthError, CSRFError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"sent": True}

    @app.post("/internal/auth/recovery/delivery/request", status_code=202)
    def request_delivery_recovery(
        payload: RecoveryChannelCreate,
        request: Request,
    ) -> dict[str, bool]:
        session, _ = current_session(request, allow_incomplete=True)
        try:
            auth_service.require_csrf(session, request.headers.get("x-csrf-token"))
            auth_service.request_delivery_recovery(
                request.cookies.get("myownca_session", ""),
                payload.channel,
            )
        except ThrottledError as exc:
            raise HTTPException(status_code=429, detail=str(exc)) from exc
        except (AuthError, CSRFError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"sent": True}

    @app.post("/internal/auth/recovery/email/verify")
    def verify_email_recovery(payload: TOTPCodeCreate, request: Request) -> dict[str, object]:
        session, _ = current_session(request, allow_incomplete=True)
        try:
            auth_service.require_csrf(session, request.headers.get("x-csrf-token"))
            created = auth_service.verify_email_recovery(
                request.cookies.get("myownca_session", ""),
                payload.code,
            )
        except ThrottledError as exc:
            raise HTTPException(status_code=429, detail=str(exc)) from exc
        except (AuthError, CSRFError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return _auth_response(created.session, created.user, auth_service)

    @app.post("/internal/auth/recovery/delivery/verify")
    def verify_delivery_recovery(
        payload: RecoveryChannelVerify,
        request: Request,
    ) -> dict[str, object]:
        session, _ = current_session(request, allow_incomplete=True)
        try:
            auth_service.require_csrf(session, request.headers.get("x-csrf-token"))
            created = auth_service.verify_delivery_recovery(
                request.cookies.get("myownca_session", ""),
                payload.channel,
                payload.code,
            )
        except ThrottledError as exc:
            raise HTTPException(status_code=429, detail=str(exc)) from exc
        except (AuthError, CSRFError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return _auth_response(created.session, created.user, auth_service)

    @app.post("/internal/auth/logout", status_code=204)
    def logout(request: Request, response: Response) -> None:
        session, _ = current_session(request, allow_incomplete=True)
        try:
            auth_service.require_csrf(session, request.headers.get("x-csrf-token"))
        except CSRFError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        auth_service.logout(request.cookies.get("myownca_session"))
        pin_vault.lock(session.id)
        clear_session_cookie(response)

    @app.get("/internal/admin/issuer")
    def issuer_status(request: Request) -> dict[str, str | bool | None | list[str]]:
        active_user(request, Role.ADMIN)
        active_sub_ca = repository.get_active_sub_ca()
        if active_sub_ca is not None:
            certificate = x509.load_pem_x509_certificate(active_sub_ca.certificate_pem.encode())
            return {
                "configured": True,
                "source": "imported_sub_ca",
                "sub_ca_id": active_sub_ca.id,
                "subject": active_sub_ca.subject,
                "issuer": certificate.issuer.rfc4514_string(),
                "not_before": certificate.not_valid_before_utc.isoformat(),
                "not_after": certificate.not_valid_after_utc.isoformat(),
                "certificate_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
                "key_backend": active_sub_ca.key_backend,
                "token_label": active_sub_ca.token_label,
                "allowed_profiles": [profile.value for profile in active_sub_ca.allowed_profiles],
            }
        current_lab_chain = lab_chain
        if current_lab_chain is not None:
            return {
                "configured": True,
                "source": "lab_chain",
                "sub_ca_id": None,
                "subject": current_lab_chain.issuer.certificate.subject.rfc4514_string(),
                "issuer": current_lab_chain.issuer.certificate.issuer.rfc4514_string(),
                "not_before": current_lab_chain.issuer.certificate.not_valid_before_utc.isoformat(),
                "not_after": current_lab_chain.issuer.certificate.not_valid_after_utc.isoformat(),
                "certificate_sha256": current_lab_chain.issuer.certificate.fingerprint(
                    hashes.SHA256()
                ).hex(),
                "key_backend": "software",
                "token_label": None,
                "allowed_profiles": None,
            }
        return {
            "configured": False,
            "source": None,
            "sub_ca_id": None,
            "subject": None,
            "issuer": None,
            "not_before": None,
            "not_after": None,
            "certificate_sha256": None,
            "key_backend": None,
            "token_label": None,
            "allowed_profiles": None,
        }

    def _root_certificate_status() -> dict[str, object]:
        stored = repository.get_root_certificate_pem()
        if stored is not None:
            certificate = x509.load_pem_x509_certificate(stored.encode())
            return {
                "configured": True,
                "source": "stored",
                "subject": certificate.subject.rfc4514_string(),
                "not_before": certificate.not_valid_before_utc.isoformat(),
                "not_after": certificate.not_valid_after_utc.isoformat(),
                "certificate_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
                "root_certificate_pem": stored,
            }
        current_lab_chain = lab_chain
        if current_lab_chain is not None:
            return {
                "configured": True,
                "source": "lab_chain",
                "subject": current_lab_chain.root.certificate.subject.rfc4514_string(),
                "not_before": current_lab_chain.root.certificate.not_valid_before_utc.isoformat(),
                "not_after": current_lab_chain.root.certificate.not_valid_after_utc.isoformat(),
                "certificate_sha256": current_lab_chain.root.certificate.fingerprint(
                    hashes.SHA256()
                ).hex(),
                "root_certificate_pem": certificate_to_pem(current_lab_chain.root.certificate),
            }
        return {
            "configured": False,
            "source": None,
            "subject": None,
            "not_before": None,
            "not_after": None,
            "certificate_sha256": None,
            "root_certificate_pem": None,
        }

    @app.get("/internal/admin/root-certificate")
    def root_certificate_status(request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN)
        return _root_certificate_status()

    def _entropy_source_status() -> dict[str, object]:
        stored = repository.get_setting("entropy_source")
        if stored is not None:
            origin = "setting"
        elif settings.entropy_source:
            origin = "env"
        else:
            origin = "default"
        return {"entropy_source": current_entropy_source(), "origin": origin}

    @app.get("/internal/admin/entropy-source")
    def entropy_source_status(request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN)
        return _entropy_source_status()

    @app.put("/internal/admin/entropy-source")
    def set_entropy_source(payload: EntropySourceUpdate, request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN, csrf=True)
        value = (payload.entropy_source or "").strip()
        if value:
            try:
                keygen.validate_entropy_source(value)
            except keygen.EntropyError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        repository.set_setting("entropy_source", value)
        audit.record(
            AuditCategory.SYSTEM,
            "entropy_source_set",
            actor=audit_actor(request),
            object_type="setting",
            object_id="entropy_source",
            details={"entropy_source": value or "os-csprng"},
        )
        return _entropy_source_status()

    @app.post("/internal/admin/entropy-source/validate")
    def validate_entropy_source_route(
        payload: EntropySourceUpdate, request: Request
    ) -> dict[str, object]:
        active_user(request, Role.ADMIN)
        value = (payload.entropy_source or "").strip()
        if not value:
            raise HTTPException(status_code=400, detail="Provide a device path to validate")
        try:
            keygen.validate_entropy_source(value)
        except keygen.EntropyError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"ok": True, "entropy_source": value}

    @app.get("/internal/templates/presets")
    def list_template_presets(request: Request) -> list[dict[str, object]]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, Role.AUDITOR)
        return [
            {
                "profile": preset.profile.value,
                "display_name": preset.display_name,
                "key_usages": [usage.value for usage in preset.key_usages],
                "extended_key_usages": [usage.value for usage in preset.extended_key_usages],
            }
            for preset in certificate_profile_presets()
        ]

    @app.get("/internal/templates")
    def list_templates(request: Request) -> list[dict[str, object]]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, Role.AUDITOR)
        return [_template_response(template) for template in repository.list_templates()]

    @app.post("/internal/templates", status_code=201)
    def create_template(payload: TemplateCreate, request: Request) -> dict[str, str]:
        active_user(request, Role.ADMIN, csrf=True)
        try:
            template = CertificateTemplate(**payload.model_dump())
            repository.add_template(template)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:  # sqlite uniqueness errors become a concise API conflict
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        audit.record(
            AuditCategory.CERTIFICATE,
            "template_create",
            actor=audit_actor(request),
            object_type="template",
            object_id=template.id,
            details={"profile": template.profile.value},
        )
        return {"id": template.id}

    @app.put("/internal/templates/{template_id}")
    def update_template(
        template_id: str, payload: TemplateUpdate, request: Request
    ) -> dict[str, object]:
        active_user(request, Role.ADMIN, csrf=True)
        try:
            repository.get_template(template_id)
        except RepositoryError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        try:
            template = CertificateTemplate(id=template_id, **payload.model_dump())
            repository.update_template(template)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except RepositoryError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        audit.record(
            AuditCategory.CERTIFICATE,
            "template_update",
            actor=audit_actor(request),
            object_type="template",
            object_id=template.id,
            details={"profile": template.profile.value},
        )
        return _template_response(template)

    @app.delete("/internal/templates/{template_id}")
    def delete_template(template_id: str, request: Request) -> dict[str, str]:
        active_user(request, Role.ADMIN, csrf=True)
        try:
            repository.delete_template(template_id)
        except RepositoryError as exc:
            status = 404 if "Unknown" in str(exc) else 409
            raise HTTPException(status_code=status, detail=str(exc)) from exc
        audit.record(
            AuditCategory.CERTIFICATE,
            "template_delete",
            actor=audit_actor(request),
            object_type="template",
            object_id=template_id,
        )
        return {"id": template_id}

    @app.get("/internal/users")
    def list_users(request: Request) -> list[dict[str, object]]:
        active_user(request, Role.ADMIN, Role.SUPERUSER)
        return [_user_response(user, auth_service) for user in repository.list_users()]

    @app.post("/internal/users", status_code=201)
    def create_user(payload: UserCreate, request: Request) -> dict[str, str]:
        _, actor = active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        try:
            if payload.role is not Role.USER:
                raise AuthError("Privileged roles require the governed role-grant endpoint")
            user = auth_service.create_ordinary_user(
                actor,
                user_id=payload.id,
                email=payload.email,
                temporary_password=payload.temporary_password,
            )
        except (AuthError, Exception) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        audit.record(
            AuditCategory.USER,
            "create",
            actor=audit_actor(request),
            object_type="user",
            object_id=user.id,
            details={"email": user.email, "role": user.role.value},
        )
        ensure_person_for_user(repository, user)
        return {"id": user.id}

    @app.post("/internal/users/{user_id}/password-reset", status_code=201)
    def reset_ordinary_password(
        user_id: str,
        payload: PasswordResetCreate,
        request: Request,
    ) -> dict[str, str]:
        _, actor = active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        try:
            auth_service.reset_ordinary_password(
                actor,
                target_user_id=user_id,
                temporary_password=payload.temporary_password,
            )
        except (AuthError, RepositoryError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"user_id": user_id}

    @app.post("/internal/users/{user_id}/totp-reset", status_code=201)
    def reset_ordinary_totp(user_id: str, request: Request) -> dict[str, str]:
        _, actor = active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        try:
            auth_service.reset_ordinary_totp(actor, target_user_id=user_id)
        except (AuthError, RepositoryError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        audit.record(
            AuditCategory.USER,
            "totp_reset",
            actor=audit_actor(request),
            object_type="user",
            object_id=user_id,
        )
        return {"user_id": user_id}

    def _set_user_active(user_id: str, request: Request, *, active: bool) -> dict[str, object]:
        _, actor = active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        try:
            user = auth_service.set_user_active(actor, target_user_id=user_id, active=active)
        except RepositoryError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except AuthError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        audit.record(
            AuditCategory.USER,
            "reactivate" if active else "deactivate",
            actor=audit_actor(request),
            object_type="user",
            object_id=user.id,
            details={"role": user.role.value},
        )
        return _user_response(user, auth_service)

    @app.post("/internal/users/{user_id}/deactivate", status_code=201)
    def deactivate_user(user_id: str, request: Request) -> dict[str, object]:
        return _set_user_active(user_id, request, active=False)

    @app.post("/internal/users/{user_id}/reactivate", status_code=201)
    def reactivate_user(user_id: str, request: Request) -> dict[str, object]:
        return _set_user_active(user_id, request, active=True)

    @app.get("/internal/admin/proposals")
    def list_pending_proposals(request: Request) -> list[dict[str, object]]:
        _, actor = active_user(request, Role.ADMIN)
        return [
            _proposal_response(proposal, auth_repository)
            for proposal in auth_service.list_pending_proposals(actor)
        ]

    def _governance_status_response() -> dict[str, object]:
        body = auth_service.governance_status(lab_mode=resolved_lab_mode)
        body["install_type"] = "lab" if resolved_lab_mode else "production"
        pending = auth_repository.get_pending_governance_downgrade()
        body["pending_downgrade"] = (
            _proposal_response(pending, auth_repository) if pending is not None else None
        )
        return body

    @app.get("/internal/admin/governance")
    def governance_status(request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN)
        return _governance_status_response()

    def _totp_policy_status_response() -> dict[str, object]:
        policy = auth_service.totp_policy()
        pending = next(
            (
                proposal
                for proposal in auth_repository.list_pending_proposals()
                if proposal.change_type is AdminChangeType.ROLE_TOTP_POLICY_CHANGE
            ),
            None,
        )
        return {
            "roles": {
                role.value: {
                    "totp_required": policy[role],
                    "recommended": role in {Role.ADMIN, Role.SUPERUSER},
                }
                for role in Role
            },
            "required_roles": sorted(role.value for role, required in policy.items() if required),
            "governance_mode": auth_service.governance_mode().value,
            "pending_change": (
                _proposal_response(pending, auth_repository) if pending is not None else None
            ),
        }

    @app.get("/internal/admin/auth-policy")
    def totp_policy_status(request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN)
        return _totp_policy_status_response()

    @app.post("/internal/admin/auth-policy/changes", status_code=201)
    def change_totp_policy(
        payload: RoleTOTPPolicyChange,
        request: Request,
    ) -> dict[str, object]:
        requested_roles = set(payload.required_roles)
        current_policy = auth_service.totp_policy()
        current_required_roles = {role for role, required in current_policy.items() if required}
        strengthening_only = current_required_roles.issubset(requested_roles)
        _, actor, reason = require_destructive_action(
            request,
            payload,
            expected_confirmation="CHANGE TOTP POLICY",
            category=AuditCategory.PERMISSION,
            action="totp_policy_change",
            object_type="role_totp_policy",
            object_id="installation",
            require_sensitive_auth=not strengthening_only,
        )
        with audit_destructive_failures(
            request,
            reason=reason,
            category=AuditCategory.PERMISSION,
            action="totp_policy_change",
            object_type="role_totp_policy",
            object_id="installation",
        ):
            try:
                proposal = auth_service.create_totp_policy_change(
                    actor,
                    required_roles=requested_roles,
                    reason=reason,
                    strengthening_only=strengthening_only,
                )
            except AuthError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        audit.record(
            AuditCategory.PERMISSION,
            "totp_policy_change_created",
            actor=AuditActor(
                id=actor.id,
                email=actor.email,
                role=actor.role.value,
                source_ip=request.client.host if request.client else None,
            ),
            object_type="admin_change_proposal",
            object_id=proposal.id,
            details={
                "reason": reason,
                "required_roles": sorted(role.value for role in payload.required_roles),
                "status": proposal.status.value,
            },
        )
        return {
            "proposal": _proposal_response(proposal, auth_repository),
            "policy": _totp_policy_status_response(),
        }

    @app.post(
        "/internal/admin/auth-policy/proposals/{proposal_id}/approve",
        status_code=201,
    )
    def approve_totp_policy_change(
        proposal_id: str,
        payload: DestructiveActionConfirmation,
        request: Request,
    ) -> dict[str, object]:
        _, actor, reason = require_destructive_action(
            request,
            payload,
            expected_confirmation="APPROVE TOTP POLICY",
            category=AuditCategory.PERMISSION,
            action="totp_policy_change_approval",
            object_type="admin_change_proposal",
            object_id=proposal_id,
            require_sensitive_auth=False,
        )
        audit_identity = AuditActor(
            id=actor.id,
            email=actor.email,
            role=actor.role.value,
            source_ip=request.client.host if request.client else None,
        )
        with audit_destructive_failures(
            request,
            reason=reason,
            category=AuditCategory.PERMISSION,
            action="totp_policy_change_approval",
            object_type="admin_change_proposal",
            object_id=proposal_id,
        ):
            try:
                pending = auth_repository.get_proposal(proposal_id)
                if pending.change_type is not AdminChangeType.ROLE_TOTP_POLICY_CHANGE:
                    raise AuthError("Proposal is not a TOTP policy change")
                approved = auth_service.approve_proposal(proposal_id, actor)
            except (AuthError, RepositoryError) as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        audit.record(
            AuditCategory.PERMISSION,
            "totp_policy_change_approved",
            actor=audit_identity,
            object_type="admin_change_proposal",
            object_id=proposal_id,
            details={"reason": reason},
        )
        return {
            "proposal": _proposal_response(approved, auth_repository),
            "policy": _totp_policy_status_response(),
        }

    @app.post("/internal/admin/governance/enable-dual-control")
    def enable_dual_control(
        payload: DestructiveActionConfirmation,
        request: Request,
    ) -> dict[str, object]:
        _, actor, reason = require_destructive_action(
            request,
            payload,
            expected_confirmation="ENABLE DUAL CONTROL",
            category=AuditCategory.PERMISSION,
            action="governance_mode_upgrade",
            object_type="governance_mode",
            object_id=GovernanceMode.DUAL_CONTROL.value,
            require_sensitive_auth=False,
        )
        with audit_destructive_failures(
            request,
            reason=reason,
            category=AuditCategory.PERMISSION,
            action="governance_mode_upgrade",
            object_type="governance_mode",
            object_id=GovernanceMode.DUAL_CONTROL.value,
        ):
            try:
                auth_service.enable_dual_control(actor)
            except AuthError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        audit.record(
            AuditCategory.PERMISSION,
            "governance_mode_changed",
            actor=audit_actor(request),
            object_type="governance_mode",
            object_id=GovernanceMode.DUAL_CONTROL.value,
            details={
                "reason": reason,
                "previous_mode": GovernanceMode.SINGLE_ADMIN.value,
                "new_mode": GovernanceMode.DUAL_CONTROL.value,
                "active_admin_count": auth_repository.count_active_users_with_role(Role.ADMIN),
            },
        )
        return _governance_status_response()

    @app.post("/internal/admin/governance/single-admin-proposals", status_code=201)
    def propose_single_admin_governance(
        payload: DestructiveActionConfirmation,
        request: Request,
    ) -> dict[str, object]:
        _, actor, reason = require_destructive_action(
            request,
            payload,
            expected_confirmation="REQUEST SINGLE ADMIN",
            category=AuditCategory.PERMISSION,
            action="governance_mode_downgrade_proposal",
            object_type="governance_mode",
            object_id=GovernanceMode.SINGLE_ADMIN.value,
        )
        with audit_destructive_failures(
            request,
            reason=reason,
            category=AuditCategory.PERMISSION,
            action="governance_mode_downgrade_proposal",
            object_type="governance_mode",
            object_id=GovernanceMode.SINGLE_ADMIN.value,
        ):
            try:
                proposal = auth_service.create_governance_downgrade_proposal(
                    actor,
                    reason=reason,
                )
            except AuthError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        audit.record(
            AuditCategory.PERMISSION,
            "governance_mode_downgrade_proposed",
            actor=audit_actor(request),
            object_type="admin_change_proposal",
            object_id=proposal.id,
            details={
                "reason": reason,
                "from_mode": GovernanceMode.DUAL_CONTROL.value,
                "to_mode": GovernanceMode.SINGLE_ADMIN.value,
                "required_approvals": 1,
            },
        )
        return _proposal_response(proposal, auth_repository)

    @app.post(
        "/internal/admin/governance/single-admin-proposals/{proposal_id}/approve",
        status_code=201,
    )
    def approve_single_admin_governance(
        proposal_id: str,
        payload: DestructiveActionConfirmation,
        request: Request,
    ) -> dict[str, object]:
        _, actor, reason = require_destructive_action(
            request,
            payload,
            expected_confirmation="APPROVE SINGLE ADMIN",
            category=AuditCategory.PERMISSION,
            action="governance_mode_downgrade_approval",
            object_type="admin_change_proposal",
            object_id=proposal_id,
        )
        with audit_destructive_failures(
            request,
            reason=reason,
            category=AuditCategory.PERMISSION,
            action="governance_mode_downgrade_approval",
            object_type="admin_change_proposal",
            object_id=proposal_id,
        ):
            try:
                proposal = auth_repository.get_proposal(proposal_id)
                if proposal.change_type is not AdminChangeType.GOVERNANCE_MODE_DOWNGRADE:
                    raise AuthError("Proposal is not a governance-mode downgrade")
                approved = auth_service.approve_proposal(proposal_id, actor)
            except (AuthError, RepositoryError) as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        proposal_payload = decode_payload(proposal.payload_json)
        audit.record(
            AuditCategory.PERMISSION,
            "governance_mode_downgrade_approved",
            actor=audit_actor(request),
            object_type="admin_change_proposal",
            object_id=proposal_id,
            details={
                "reason": reason,
                "proposal_reason": proposal_payload.get("reason"),
                "previous_mode": GovernanceMode.DUAL_CONTROL.value,
                "new_mode": GovernanceMode.SINGLE_ADMIN.value,
            },
        )
        return _proposal_response(approved, auth_repository)

    @app.post("/internal/admin/proposals/privileged-role-grants", status_code=201)
    def propose_privileged_role_grant(
        payload: PrivilegedRoleGrantCreate,
        request: Request,
    ) -> dict[str, object]:
        _, actor = active_user(request, Role.ADMIN, csrf=True)
        try:
            proposal = auth_service.create_privileged_role_grant_proposal(
                actor,
                user_id=payload.id,
                email=payload.email,
                role=payload.role,
                temporary_password=payload.temporary_password,
            )
        except AuthError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if proposal.status is AdminChangeStatus.APPROVED:
            try:
                ensure_people_for_all_users(repository)
            except Exception:  # noqa: BLE001 - mirror failure cannot undo governed creation
                logger.warning(
                    "people mirror after immediate role grant failed",
                    exc_info=True,
                )
        return _proposal_response(proposal, auth_repository)

    @app.post("/internal/admin/proposals/privileged-password-resets", status_code=201)
    def propose_privileged_password_reset(
        payload: PrivilegedResetCreate,
        request: Request,
    ) -> dict[str, object]:
        _, actor = active_user(request, Role.ADMIN, csrf=True)
        if payload.temporary_password is None:
            raise HTTPException(status_code=400, detail="temporary_password is required")
        try:
            proposal = auth_service.create_privileged_password_reset_proposal(
                actor,
                target_user_id=payload.target_user_id,
                temporary_password=payload.temporary_password,
            )
        except (AuthError, RepositoryError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return _proposal_response(proposal, auth_repository)

    @app.post("/internal/admin/proposals/privileged-totp-resets", status_code=201)
    def propose_privileged_totp_reset(
        payload: PrivilegedResetCreate,
        request: Request,
    ) -> dict[str, object]:
        _, actor = active_user(request, Role.ADMIN, csrf=True)
        try:
            proposal = auth_service.create_privileged_totp_reset_proposal(
                actor,
                target_user_id=payload.target_user_id,
            )
        except (AuthError, RepositoryError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return _proposal_response(proposal, auth_repository)

    @app.post("/internal/admin/proposals/{proposal_id}/approve", status_code=201)
    def approve_proposal(proposal_id: str, request: Request) -> dict[str, object]:
        _, actor = active_user(request, Role.ADMIN, csrf=True)
        try:
            pending = auth_repository.get_proposal(proposal_id)
            if pending.change_type in {
                AdminChangeType.GOVERNANCE_MODE_DOWNGRADE,
                AdminChangeType.ROLE_TOTP_POLICY_CHANGE,
            }:
                raise AuthError(
                    "Use the dedicated approval endpoint for this security-sensitive change"
                )
            proposal = auth_service.approve_proposal(proposal_id, actor)
        except (AuthError, RepositoryError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        try:
            ensure_people_for_all_users(repository)
        except Exception:  # noqa: BLE001 - never fail an approval on a mirror error
            logger.warning("people mirror after proposal approval failed", exc_info=True)
        return _proposal_response(proposal, auth_repository)

    @app.post("/internal/admin/proposals/{proposal_id}/reject", status_code=201)
    def reject_proposal(proposal_id: str, request: Request) -> dict[str, object]:
        _, actor = active_user(request, Role.ADMIN, csrf=True)
        try:
            pending = auth_repository.get_proposal(proposal_id)
            proposal = auth_service.reject_proposal(proposal_id, actor)
        except (AuthError, RepositoryError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if pending.change_type is AdminChangeType.GOVERNANCE_MODE_DOWNGRADE:
            proposal_payload = decode_payload(pending.payload_json)
            audit.record(
                AuditCategory.PERMISSION,
                "governance_mode_downgrade_rejected",
                actor=audit_actor(request),
                object_type="admin_change_proposal",
                object_id=proposal_id,
                details={
                    "reason": proposal_payload.get("reason"),
                    "from_mode": GovernanceMode.DUAL_CONTROL.value,
                    "to_mode": GovernanceMode.SINGLE_ADMIN.value,
                },
            )
        return _proposal_response(proposal, auth_repository)

    @app.get("/internal/certificate-requests")
    def list_certificate_requests(request: Request) -> list[dict[str, object]]:
        _, user = active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, Role.AUDITOR)
        requests = repository.list_requests()
        if user.role is Role.USER:
            requests = [
                certificate_request
                for certificate_request in requests
                if request_in_user_scope(user, certificate_request)
            ]
        return [
            _request_response(certificate_request, repository, current_user=user)
            for certificate_request in requests
        ]

    @app.post("/internal/certificate-requests", status_code=201)
    def create_request(payload: RequestCreate, request: Request) -> dict[str, object]:
        _, user = active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, csrf=True)
        try:
            certificate_request = service.submit_request(
                **payload.model_dump(),
                requested_by_user_id=user.id,
            )
        except AmbiguousCertificateSerialError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except (RepositoryError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        try:
            notifications.notify_event(
                NotificationEvent.REQUESTED,
                request=certificate_request,
                requester_email=user.email,
            )
        except Exception:  # noqa: BLE001 - notifications must never block submission
            pass
        return _request_response(certificate_request, repository, current_user=user)

    @app.post("/internal/certificate-requests/generate", status_code=201)
    def generate_request(payload: RequestGenerate, request: Request) -> dict[str, object]:
        _, user = active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, csrf=True)
        common_name = payload.common_name.strip()
        if not common_name:
            raise HTTPException(status_code=400, detail="common_name must not be empty")
        try:
            template = repository.get_template(payload.template_id)  # validate before paying for keygen
        except RepositoryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if payload.algorithm not in template.allowed_key_algorithms:
            raise HTTPException(
                status_code=400,
                detail=f"Key algorithm is not allowed by the certificate template: {payload.algorithm}",
            )
        try:
            private_key = keygen.generate_private_key(
                payload.algorithm, entropy_source=current_entropy_source
            )
        except keygen.EntropyError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        dns_names = tuple(name.strip() for name in payload.dns_names if name.strip())
        email_addresses = tuple(
            address.strip() for address in payload.email_addresses if address.strip()
        )
        try:
            csr_pem = build_csr_for_key(
                private_key,
                common_name=common_name,
                dns_names=dns_names,
                email_addresses=email_addresses,
            )
            certificate_request = service.submit_request(
                payload.template_id, csr_pem, requested_by_user_id=user.id
            )
        except (RepositoryError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        key_vault.store(certificate_request.id, private_key, payload.algorithm)
        ensure_request_key_registered(certificate_request.id)
        audit.record(
            AuditCategory.CERTIFICATE,
            "server_key_generated",
            actor=audit_actor(request),
            object_type="request",
            object_id=certificate_request.id,
            details={"algorithm": payload.algorithm, "template_id": payload.template_id},
        )
        try:
            notifications.notify_event(
                NotificationEvent.REQUESTED,
                request=certificate_request,
                requester_email=user.email,
            )
        except Exception:  # noqa: BLE001 - notifications must never block submission
            pass
        return _request_response(certificate_request, repository, current_user=user)

    @app.delete("/internal/certificate-requests/{request_id}/server-key")
    def purge_server_key(request_id: str, request: Request) -> dict[str, object]:
        _, user = active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, csrf=True)
        try:
            certificate_request = repository.get_request(request_id)
        except RepositoryError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        if user.role is Role.USER and not request_in_user_scope(user, certificate_request):
            raise HTTPException(status_code=403, detail="Certificate request is not yours")
        if not key_vault.held(request_id):
            raise HTTPException(status_code=404, detail="No server-held key for this request")
        issued_for_request = repository.get_issued_certificate_by_request_id(request_id)
        if issued_for_request is not None and (
            issued_for_request.archived_at is None
            and issued_for_request.status is CertificateStatus.ACTIVE
            and issued_for_request.expires_at > datetime.now(timezone.utc)
        ):
            raise HTTPException(
                status_code=409,
                detail=(
                    "The key is still bound to an active certificate. Archive the "
                    "certificate to start the 30-day key-retention period."
                ),
            )
        if issued_for_request is not None:
            retire_certificate_key(issued_for_request)
        else:
            retire_request_key(request_id)
        registered = key_lifecycle_repository.find(backend="request_vault", key_ref=request_id)
        audit.record(
            AuditCategory.CERTIFICATE,
            "server_key_retirement_scheduled",
            actor=audit_actor(request),
            object_type="request",
            object_id=request_id,
        )
        return {
            "request_id": request_id,
            "server_key_held": key_vault.held(request_id),
            "key_status": registered.status.value if registered else "orphaned",
            "delete_after": (
                registered.delete_after.isoformat()
                if registered and registered.delete_after
                else None
            ),
        }

    @app.get("/internal/certificate-requests/{request_id}")
    def get_certificate_request(request_id: str, request: Request) -> dict[str, object]:
        _, user = active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, Role.AUDITOR)
        try:
            certificate_request = repository.get_request(request_id)
        except RepositoryError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        if user.role is Role.USER and not request_in_user_scope(user, certificate_request):
            raise HTTPException(status_code=403, detail="Certificate request is not yours")
        return _request_response(
            certificate_request, repository, current_user=user, include_csr=True
        )

    @app.post("/internal/certificate-requests/{request_id}/approvals", status_code=201)
    def approve_request(request_id: str, request: Request) -> dict[str, object]:
        _, user = active_user(request, Role.SUPERUSER, csrf=True)
        try:
            approval = service.approve_request(request_id, user.id)
        except DuplicateApprovalError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except RepositoryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        certificate_request = repository.get_request(request_id)
        template = repository.get_template(certificate_request.template_id)
        approvals = repository.list_approvals(request_id)
        needed_approvals = required_approvals(certificate_request, template)
        body = _request_response(certificate_request, repository, current_user=user)
        body.update(
            {
                "request_id": approval.request_id,
                "superuser_id": approval.superuser_id,
                "auto_issued": False,
                "auto_issue_error": None,
                "issued_certificate": None,
            }
        )

        if len({record.superuser_id for record in approvals}) < needed_approvals:
            return body

        certificate, auto_issue_error = attempt_issuance(request_id, audit_actor(request))
        if certificate is None:
            body["auto_issue_error"] = auto_issue_error
            return body

        updated_request = repository.get_request(request_id)
        body = _request_response(updated_request, repository, current_user=user)
        body.update(
            {
                "request_id": approval.request_id,
                "superuser_id": approval.superuser_id,
                "auto_issued": True,
                "auto_issue_error": None,
                "issued_certificate": _certificate_response(
                    certificate,
                    repository,
                    include_pem=True,
                ),
            }
        )
        return body

    @app.post("/internal/certificate-requests/{request_id}/reject", status_code=201)
    def reject_certificate_request(request_id: str, request: Request) -> dict[str, object]:
        _, user = active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, csrf=True)
        try:
            certificate_request = repository.get_request(request_id)
        except RepositoryError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        if user.role is Role.USER and not request_in_user_scope(user, certificate_request):
            raise HTTPException(
                status_code=403,
                detail=("Only the request owner or a Certificate Operator may reject this request"),
            )
        try:
            rejected = service.reject_request(request_id)
        except RepositoryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        # A rejected request will never be issued. Its key becomes orphaned and
        # remains protected by the mandatory 30-day grace period.
        retire_request_key(request_id)
        return _request_response(rejected, repository, current_user=user)

    def _validated_leaf_import(payload: LeafImportAnalyze) -> ValidatedLeafBundle:
        issuer = current_issuer()
        if issuer is None:
            raise HTTPException(status_code=409, detail="No active Sub-CA is configured")
        bundle_data = _decode_import_artifact(payload.bundle_b64, label="Certificate bundle")
        key_data = (
            _decode_import_artifact(payload.private_key_b64, label="Private key")
            if payload.private_key_b64
            else None
        )
        try:
            parsed = parse_bundle(
                bundle_data,
                private_key_data=key_data,
                password=payload.password,
            )
            return validate_leaf_bundle(parsed, issuer.certificate)
        except LeafImportError as exc:
            raise HTTPException(
                status_code=400,
                detail={"code": exc.code.value, "message": str(exc)},
            ) from exc

    def _leaf_template_candidates(bundle: ValidatedLeafBundle) -> list[CertificateTemplate]:
        issuer = current_issuer()
        if issuer is None:
            return []
        try:
            certificate_algorithm = keygen.certificate_algorithm_for_public_key(
                bundle.certificate.public_key()
            )
        except keygen.KeygenError:
            return []
        return [
            template
            for template in repository.list_templates()
            if leaf_matches_template(
                bundle,
                template,
                allowed_profiles=issuer.allowed_profiles,
            )
            and certificate_algorithm in template.allowed_key_algorithms
        ]

    def _leaf_analysis(bundle: ValidatedLeafBundle) -> dict[str, object]:
        candidates = _leaf_template_candidates(bundle)
        issuer = current_issuer()
        issuer_id = (
            issuer.certificate.fingerprint(hashes.SHA256()).hex() if issuer is not None else ""
        )
        historical_revocation = repository.get_issuer_revocation(
            issuer_id, format(bundle.certificate.serial_number, "x")
        )
        return {
            "fingerprint_sha256": bundle.fingerprint_sha256,
            "serial_number": format(bundle.certificate.serial_number, "x"),
            "subject": bundle.certificate.subject.rfc4514_string(),
            "issuer": bundle.certificate.issuer.rfc4514_string(),
            "not_before": bundle.certificate.not_valid_before_utc.isoformat(),
            "not_after": bundle.certificate.not_valid_after_utc.isoformat(),
            "has_private_key": bundle.has_private_key,
            "source_format": bundle.source_format.value,
            "signals": {
                "key_usages": list(bundle.signals.key_usages),
                "extended_key_usages": list(bundle.signals.extended_key_usages),
                "extended_key_usage_oids": list(bundle.signals.extended_key_usage_oids),
                "subject_alt_names": [
                    {"kind": item.kind, "value": item.value, "oid": item.oid}
                    for item in bundle.signals.subject_alt_names
                ],
                "key_usage_critical": bundle.signals.key_usage_critical,
                "extended_key_usage_critical": (bundle.signals.extended_key_usage_critical),
                "subject_alt_name_critical": bundle.signals.subject_alt_name_critical,
            },
            "template_candidates": [_template_response(item) for item in candidates],
            "recommended_template_id": candidates[0].id if len(candidates) == 1 else None,
            "requires_template": not candidates,
            "revocation": (
                {
                    "status": CertificateStatus.REVOKED.value,
                    "reason": historical_revocation.reason.value,
                    "revoked_at": historical_revocation.revoked_at.isoformat(),
                }
                if historical_revocation is not None
                else None
            ),
        }

    @app.post("/internal/certificates/import/analyze")
    def analyze_leaf_import(payload: LeafImportAnalyze, request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, csrf=True)
        return _leaf_analysis(_validated_leaf_import(payload))

    def _create_import_holder(
        payload: LeafImportCommit, user: User
    ) -> tuple[str | None, str | None, tuple[str, str] | None]:
        choices = (
            payload.person_id,
            payload.device_id,
            payload.new_person,
            payload.new_device,
        )
        if sum(value is not None for value in choices) != 1:
            raise HTTPException(
                status_code=400,
                detail="Choose exactly one existing or new Person/Device holder",
            )
        if payload.person_id:
            repository.get_person(payload.person_id)
            require_holder_scope(user, person_id=payload.person_id)
            return payload.person_id, None, None
        if payload.device_id:
            repository.get_device(payload.device_id)
            require_holder_scope(user, device_id=payload.device_id)
            return None, payload.device_id, None
        if payload.new_person is not None:
            if user.role is Role.USER:
                raise HTTPException(
                    status_code=403, detail="Users cannot create additional Person records"
                )
            item = payload.new_person
            person = Person(
                id=item.id or str(uuid4()),
                name=item.name,
                surname=item.surname,
                email=item.email,
                phone=item.phone,
                slack_handle=item.slack_handle,
                company=item.company,
                comments=item.comments,
                created_at=datetime.now(timezone.utc),
            )
            repository.add_person(person)
            return person.id, None, ("person", person.id)
        assert payload.new_device is not None
        item = payload.new_device
        admin_id = own_person(user).id if user.role is Role.USER else item.admin_id
        repository.get_person(admin_id)
        device = Device(
            id=item.id or str(uuid4()),
            device_name=item.device_name,
            admin_id=admin_id,
            fqdn=item.fqdn,
            comments=item.comments,
            created_at=datetime.now(timezone.utc),
        )
        repository.add_device(device)
        return None, device.id, ("device", device.id)

    @app.post("/internal/certificates/import", status_code=201)
    def commit_leaf_import(payload: LeafImportCommit, request: Request) -> dict[str, object]:
        _, user = active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, csrf=True)
        bundle = _validated_leaf_import(payload)
        serial_number = format(bundle.certificate.serial_number, "x")
        issuer = current_issuer()
        assert issuer is not None
        issuer_id = issuer.certificate.fingerprint(hashes.SHA256()).hex()

        def retry_holder_ids(
            candidate: IssuedCertificate,
        ) -> tuple[str | None, str | None]:
            selected_person = payload.person_id
            selected_device = payload.device_id
            if payload.new_person is not None:
                matching_person = repository.get_person_by_email(payload.new_person.email)
                selected_person = matching_person.id if matching_person is not None else None
            elif payload.new_device is not None:
                item = payload.new_device
                if item.id is not None:
                    try:
                        selected_device = repository.get_device(item.id).id
                    except RepositoryError:
                        selected_device = None
                elif candidate.holder_device_id is not None:
                    # The UI intentionally lets the server allocate holder IDs.
                    # Resolve a lost-response retry only against the device
                    # already bound to this exact certificate.
                    try:
                        bound_device = repository.get_device(candidate.holder_device_id)
                        expected_admin_id = (
                            own_person(user).id if user.role is Role.USER else item.admin_id
                        )
                        same_device = (
                            bound_device.device_name.strip() == item.device_name.strip()
                            and bound_device.fqdn.strip().casefold() == item.fqdn.strip().casefold()
                            and bound_device.admin_id == expected_admin_id
                            and bound_device.comments.strip() == item.comments.strip()
                        )
                        if same_device:
                            selected_device = bound_device.id
                    except RepositoryError:
                        selected_device = None
            return selected_person, selected_device

        existing = None
        try:
            existing = repository.get_certificate_by_issuer_and_serial(issuer_id, serial_number)
        except RepositoryError:
            pass
        if existing is not None:
            existing_der = x509.load_pem_x509_certificate(
                existing.certificate_pem.encode()
            ).public_bytes(serialization.Encoding.DER)
            imported_der = bundle.certificate.public_bytes(serialization.Encoding.DER)
            same_certificate = hmac.compare_digest(existing_der, imported_der)
            selected_person, selected_device = retry_holder_ids(existing)
            if (
                same_certificate
                and selected_person == existing.holder_person_id
                and selected_device == existing.holder_device_id
            ):
                require_certificate_scope(user, existing)
                return _certificate_response(existing, repository, include_pem=True)
            raise HTTPException(
                status_code=409,
                detail="Certificate serial already exists with different content or holder",
            )

        candidates = {item.id for item in _leaf_template_candidates(bundle)}
        if payload.template_id not in candidates:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Selected template does not match the certificate KU/EKU, SAN, "
                    "profile, or active issuer policy; "
                    "an Administrator must create or choose a matching template"
                ),
            )

        template = repository.get_template(payload.template_id)
        try:
            imported_algorithm = keygen.certificate_algorithm_for_public_key(
                bundle.certificate.public_key()
            )
        except keygen.KeygenError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if imported_algorithm not in template.allowed_key_algorithms:
            raise HTTPException(
                status_code=400,
                detail="Certificate key algorithm is not allowed by the selected template",
            )

        created_holder: tuple[str, str] | None = None
        import_request = None
        registered_key_id: str | None = None
        imported: IssuedCertificate | None = None
        try:
            person_id, device_id, created_holder = _create_import_holder(payload, user)
            csr_pem = (
                build_csr_from_certificate(bundle.private_key, bundle.certificate)
                if bundle.private_key is not None
                else create_identity_csr(bundle.certificate)
            )
            import_request = service.submit_request(
                template_id=payload.template_id,
                csr_pem=csr_pem,
                requested_by_user_id=user.id,
                request_id=f"import-{uuid4()}",
                source=RequestSource.IMPORT,
            )
            service.assign_request_holder(
                import_request.id, person_id=person_id, device_id=device_id
            )
            import_request = repository.get_request(import_request.id)
            authorization = licensing.authorize_issuance(import_request)
            certificate_id = str(uuid4())
            if bundle.private_key is not None:
                algorithm = imported_key_algorithm(bundle.private_key)
                registered = ensure_request_key_registered(import_request.id)
                registered_key_id = registered.id
                key_vault.store(import_request.id, bundle.private_key, algorithm)
                # Stage the final binding before the inventory transaction.  A
                # lifecycle failure can then be compensated without ever
                # exposing a live certificate with an untracked private key.
                key_lifecycle.bind_key(
                    registered.id,
                    resource_type="certificate",
                    resource_id=certificate_id,
                )
                key_lifecycle.unbind_key(
                    registered.id,
                    resource_type="certificate_request",
                    resource_id=import_request.id,
                )
            chain = certificate_chain_pems(bundle.certificate_pem)
            historical_revocation = repository.get_issuer_revocation(issuer_id, serial_number)
            imported = IssuedCertificate(
                serial_number=serial_number,
                request_id=import_request.id,
                template_id=payload.template_id,
                certificate_pem=bundle.certificate_pem,
                subject=bundle.certificate.subject.rfc4514_string(),
                issued_at=bundle.certificate.not_valid_before_utc,
                expires_at=bundle.certificate.not_valid_after_utc,
                status=(
                    CertificateStatus.REVOKED
                    if historical_revocation is not None
                    else CertificateStatus.ACTIVE
                ),
                holder_person_id=person_id,
                holder_device_id=device_id,
                lineage_id=authorization.lineage_id,
                certificate_id=certificate_id,
                source=CertificateSource.IMPORTED,
                issuer_id=issuer_id,
                chain_pem="".join(chain),
                key_registry_id=registered_key_id,
            )
            repository.finalize_issued_certificate(
                imported,
                reservation_request_id=authorization.reservation_request_id,
            )
        except Exception as exc:
            if import_request is not None:
                try:
                    repository.rollback_import_workflow(
                        import_request.id,
                        created_person_id=(
                            created_holder[1]
                            if created_holder is not None and created_holder[0] == "person"
                            else None
                        ),
                        created_device_id=(
                            created_holder[1]
                            if created_holder is not None and created_holder[0] == "device"
                            else None
                        ),
                    )
                except Exception:  # noqa: BLE001 - preserve the primary error
                    logger.exception(
                        "Failed to roll back leaf import request %s", import_request.id
                    )
                registered = (
                    key_lifecycle_repository.get(registered_key_id)
                    if registered_key_id is not None
                    else key_lifecycle_repository.find(
                        backend="request_vault", key_ref=import_request.id
                    )
                )
                if registered is not None:
                    try:
                        for binding in key_lifecycle_repository.list_bindings(registered.id):
                            if (
                                binding.resource_type == "certificate_request"
                                and binding.resource_id == import_request.id
                            ) or (
                                imported is not None
                                and binding.resource_type == "certificate"
                                and binding.resource_id == imported.certificate_id
                            ):
                                key_lifecycle.unbind_key(
                                    registered.id,
                                    resource_type=binding.resource_type,
                                    resource_id=binding.resource_id,
                                )
                        registered = key_lifecycle_repository.get(registered.id)
                        if (
                            registered.status is KeyStatus.ACTIVE
                            and not key_lifecycle_repository.list_bindings(registered.id)
                        ):
                            key_lifecycle.orphan_key(registered.id)
                    except KeyLifecycleError:
                        logger.exception(
                            "Failed to orphan key for leaf import request %s",
                            import_request.id,
                        )
            elif created_holder is not None:
                try:
                    kind, holder_id = created_holder
                    if kind == "person":
                        repository.delete_person(holder_id)
                    else:
                        repository.delete_device(holder_id)
                except RepositoryError:
                    pass
            if isinstance(exc, IntegrityError):
                try:
                    concurrent = repository.get_certificate_by_issuer_and_serial(
                        issuer_id, serial_number
                    )
                except RepositoryError:
                    concurrent = None
                if concurrent is not None:
                    concurrent_der = x509.load_pem_x509_certificate(
                        concurrent.certificate_pem.encode()
                    ).public_bytes(serialization.Encoding.DER)
                    selected_person, selected_device = retry_holder_ids(concurrent)
                    if (
                        hmac.compare_digest(
                            concurrent_der,
                            bundle.certificate.public_bytes(serialization.Encoding.DER),
                        )
                        and concurrent.holder_person_id == selected_person
                        and concurrent.holder_device_id == selected_device
                    ):
                        require_certificate_scope(user, concurrent)
                        return _certificate_response(concurrent, repository, include_pem=True)
                raise HTTPException(
                    status_code=409,
                    detail="Certificate serial already exists with different content or holder",
                ) from exc
            if isinstance(exc, (LicenseLimitError, LicenseStateError)):
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            if isinstance(exc, KeyLifecycleError):
                raise HTTPException(
                    status_code=503,
                    detail="Private-key lifecycle registration failed; the import was rolled back",
                ) from exc
            if isinstance(exc, HTTPException):
                raise
            if isinstance(exc, (LeafImportError, KeyImportError, RepositoryError, ValueError)):
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            raise

        assert imported is not None

        audit.record(
            AuditCategory.CERTIFICATE,
            "certificate_imported",
            actor=audit_actor(request),
            object_type="certificate",
            object_id=imported.certificate_id,
            details={
                "serial_number": imported.serial_number,
                "template_id": imported.template_id,
                "holder_person_id": imported.holder_person_id,
                "holder_device_id": imported.holder_device_id,
                "private_key_imported": bundle.has_private_key,
            },
        )
        try:
            notifications.notify_event(NotificationEvent.ISSUED, certificate=imported)
        except Exception:  # noqa: BLE001 - notifications never roll back an import
            pass
        return _certificate_response(imported, repository, include_pem=True)

    def _revoke_certificate_target(
        certificate: IssuedCertificate,
        payload: RevocationCreate,
        request: Request,
    ) -> dict[str, str]:
        _, user = active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, csrf=True)
        require_certificate_scope(user, certificate)
        try:
            revocation = service.revoke_certificate_by_id(
                certificate.certificate_id, payload.reason
            )
        except RepositoryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        retire_certificate_key(certificate, when=revocation.revoked_at)
        audit.record(
            AuditCategory.CERTIFICATE,
            "revoke",
            actor=audit_actor(request),
            object_type="certificate",
            object_id=(
                revocation.certificate_id or certificate.certificate_id or revocation.serial_number
            ),
            details={"reason": revocation.reason.value},
        )
        return {"serial_number": revocation.serial_number, "reason": revocation.reason.value}

    @app.post("/internal/certificates/{serial_number}/revoke", status_code=201)
    def revoke_certificate(
        serial_number: str,
        payload: RevocationCreate,
        request: Request,
    ) -> dict[str, str]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, csrf=True)
        return _revoke_certificate_target(_serial_certificate(serial_number), payload, request)

    def _archive_certificate_target(
        certificate: IssuedCertificate,
        payload: CertificateArchive,
        request: Request,
    ) -> dict[str, object]:
        serial_number = certificate.serial_number
        _, user, reason = require_destructive_action(
            request,
            payload,
            expected_confirmation=f"ARCHIVE CERTIFICATE {serial_number}",
            category=AuditCategory.CERTIFICATE,
            action="certificate_archive",
            object_type="certificate",
            object_id=certificate.certificate_id or serial_number,
            roles=(Role.ADMIN, Role.SUPERUSER, Role.USER),
        )
        require_certificate_scope(user, certificate)
        moment = datetime.now(timezone.utc)
        if certificate.status is CertificateStatus.ACTIVE and certificate.expires_at > moment:
            try:
                service.revoke_certificate_by_id(
                    certificate.certificate_id,
                    RevocationReason.CESSATION_OF_OPERATION,
                    now=moment,
                )
            except RepositoryError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
        repository.archive_certificate_by_id(certificate.certificate_id, moment)
        certificate = repository.get_certificate_by_id(certificate.certificate_id)
        retire_certificate_key(certificate, when=moment)
        audit.record(
            AuditCategory.CERTIFICATE,
            "certificate_archived",
            actor=audit_actor(request),
            object_type="certificate",
            object_id=certificate.certificate_id or serial_number,
            details={"reason": reason, "serial_number": serial_number},
        )
        return _certificate_response(certificate, repository, include_pem=False)

    @app.delete("/internal/certificates/{serial_number}")
    def archive_certificate(
        serial_number: str,
        payload: CertificateArchive,
        request: Request,
    ) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, csrf=True)
        return _archive_certificate_target(_serial_certificate(serial_number), payload, request)

    @app.get("/internal/certificates")
    def list_certificates(
        request: Request, include_archived: bool = False
    ) -> list[dict[str, object]]:
        _, user = active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, Role.AUDITOR)
        certificates = repository.list_issued_certificates(include_archived=include_archived)
        if user.role is Role.USER:
            certificates = [
                certificate
                for certificate in certificates
                if certificate_in_user_scope(user, certificate)
            ]
        return [
            _certificate_response(certificate, repository, include_pem=False)
            for certificate in certificates
        ]

    @app.get("/internal/certificate-inventory")
    def list_certificate_inventory(
        request: Request, include_archived: bool = False
    ) -> list[dict[str, object]]:
        """Canonical ID-based inventory; the serial route remains compatible."""

        return list_certificates(request, include_archived=include_archived)

    def _inventory_certificate(certificate_id: str) -> IssuedCertificate:
        try:
            return repository.get_certificate_by_id(certificate_id)
        except RepositoryError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    def _serial_certificate(serial_number: str) -> IssuedCertificate:
        try:
            return repository.get_issued_certificate(serial_number)
        except AmbiguousCertificateSerialError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except RepositoryError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/internal/certificate-inventory/{certificate_id}")
    def get_inventory_certificate(certificate_id: str, request: Request) -> dict[str, object]:
        _, user = active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, Role.AUDITOR)
        certificate = _inventory_certificate(certificate_id)
        require_certificate_scope(user, certificate)
        return _certificate_response(certificate, repository, include_pem=True)

    @app.get("/internal/certificates/{serial_number}")
    def get_certificate(serial_number: str, request: Request) -> dict[str, object]:
        _, user = active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, Role.AUDITOR)
        certificate = _serial_certificate(serial_number)
        require_certificate_scope(user, certificate)
        return _certificate_response(certificate, repository, include_pem=True)

    def _exportable_certificate(certificate: IssuedCertificate, user: User) -> IssuedCertificate:
        require_certificate_scope(user, certificate)
        return certificate

    def _export_response(result) -> Response:
        return Response(
            content=result.content,
            media_type=result.media_type,
            headers={
                "Content-Disposition": f'attachment; filename="{result.filename}"',
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "X-Content-Type-Options": "nosniff",
            },
        )

    def _export_certificate_download_target(
        certificate: IssuedCertificate, request: Request, format: str = "pem"
    ) -> Response:
        _, user = active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, Role.AUDITOR)
        certificate = _exportable_certificate(certificate, user)
        try:
            fmt = ExportFormat(format)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"Unknown export format: {format}") from exc
        if fmt in KEY_BEARING_FORMATS:
            raise HTTPException(
                status_code=400,
                detail="Key-bearing formats are exported via POST (password in the body)",
            )
        chain = (
            certificate_chain_pems(certificate.certificate_pem)
            if fmt is ExportFormat.PEM_CHAIN
            else ()
        )
        try:
            result = build_export(
                certificate.certificate_pem,
                fmt,
                serial_number=certificate.serial_number,
                chain_pems=chain,
            )
        except ExportError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return _export_response(result)

    @app.get("/internal/certificates/{serial_number}/export")
    def export_certificate_download(
        serial_number: str, request: Request, format: str = "pem"
    ) -> Response:
        active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, Role.AUDITOR)
        return _export_certificate_download_target(
            _serial_certificate(serial_number), request, format
        )

    def _export_certificate_with_key_target(
        certificate: IssuedCertificate,
        payload: CertificateExportRequest,
        request: Request,
    ) -> Response:
        # No AUDITOR here: key-bearing bundles hand out the private key.
        session, user = active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, csrf=True)
        with audit_sensitive_failures(
            request,
            category=AuditCategory.CERTIFICATE,
            action="export",
            object_type="certificate",
            object_id=certificate.certificate_id,
        ):
            auth_status = sensitive_auth_status(
                session,
                method=("totp" if auth_service.totp_required(user.role) else "password"),
            )
            # A just-created password-only session is itself fresh authentication.
            # Privileged/TOTP sessions carry an explicit MFA timestamp instead.
            initial_login_recent = (
                auth_status["method"] == "password"
                and auth_status["verified_at"] is None
                and datetime.now(timezone.utc) - session.created_at
                <= timedelta(seconds=int(auth_status["window_seconds"]))
            )
            if not auth_status["recent"] and not initial_login_recent:
                try:
                    auth_service.require_recent_sensitive_auth(session, user)
                except AuthenticationError as exc:
                    raise HTTPException(status_code=403, detail=str(exc)) from exc
            certificate = _exportable_certificate(certificate, user)
            try:
                fmt = ExportFormat(payload.format)
            except ValueError as exc:
                raise HTTPException(
                    status_code=400, detail=f"Unknown export format: {payload.format}"
                ) from exc
            if fmt not in KEY_BEARING_FORMATS:
                raise HTTPException(status_code=400, detail="Keyless formats are exported via GET")
            try:
                key_pem = key_vault.load_pem(certificate.request_id)
            except ServerKeyError as exc:
                raise HTTPException(status_code=500, detail=str(exc)) from exc
            if key_pem is None:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "No server-held private key for this certificate; it was issued "
                        "from a user-supplied CSR or the key was purged"
                    ),
                )
            chain = (
                certificate_chain_pems(certificate.certificate_pem)
                if fmt is ExportFormat.PKCS12
                else ()
            )
            try:
                result = build_export(
                    certificate.certificate_pem,
                    fmt,
                    serial_number=certificate.serial_number,
                    chain_pems=chain,
                    private_key_pem=key_pem,
                    password=payload.password,
                )
            except ExportError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            audit.record(
                AuditCategory.CERTIFICATE,
                "export",
                actor=audit_actor(request),
                object_type="certificate",
                object_id=certificate.certificate_id or certificate.serial_number,
                details={"format": fmt.value},
            )
        return _export_response(result)

    @app.post("/internal/certificates/{serial_number}/export")
    def export_certificate_with_key(
        serial_number: str, payload: CertificateExportRequest, request: Request
    ) -> Response:
        active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, csrf=True)
        return _export_certificate_with_key_target(
            _serial_certificate(serial_number), payload, request
        )

    def _renew_certificate_target(
        certificate: IssuedCertificate,
        request: Request,
        payload: CertificateRenewalCreate | None = None,
    ) -> dict[str, object]:
        _, user = active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, csrf=True)
        require_certificate_scope(user, certificate)
        if certificate.archived_at is not None:
            raise HTTPException(status_code=409, detail="Archived certificates cannot be renewed")
        anchor_request = repository.get_request(certificate.request_id)
        template = repository.get_template(certificate.template_id)
        server_key_held = key_vault.held(certificate.request_id)
        mode = (
            payload.mode
            if payload is not None
            else (
                "reuse"
                if certificate.source is CertificateSource.ISSUED or server_key_held
                else "rotate"
            )
        )
        new_key = None
        if mode == "reuse":
            if certificate.source is CertificateSource.IMPORTED:
                try:
                    key_pem = key_vault.load_pem(certificate.request_id)
                    if key_pem is None:
                        raise HTTPException(
                            status_code=409,
                            detail="Certificate-only imports cannot reuse the original key",
                        )
                    new_key = serialization.load_pem_private_key(key_pem.encode(), password=None)
                    csr_pem = build_csr_from_certificate(
                        new_key,
                        x509.load_pem_x509_certificate(certificate.certificate_pem.encode()),
                    )
                except (LeafImportError, ValueError, TypeError) as exc:
                    raise HTTPException(status_code=400, detail=str(exc)) from exc
            else:
                csr_pem = anchor_request.csr_pem
        elif mode == "rotate":
            algorithm = payload.algorithm if payload is not None else "ecdsa-p256"
            if algorithm not in template.allowed_key_algorithms:
                raise HTTPException(
                    status_code=400,
                    detail="Key algorithm is not allowed by the certificate template",
                )
            try:
                new_key = keygen.generate_private_key(
                    algorithm, entropy_source=current_entropy_source
                )
                csr_pem = build_rotated_csr_from_certificate(
                    new_key,
                    x509.load_pem_x509_certificate(certificate.certificate_pem.encode()),
                )
            except (keygen.EntropyError, LeafImportError, ValueError) as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        else:
            if payload is None or not (payload.csr_pem or "").strip():
                raise HTTPException(status_code=400, detail="csr mode requires csr_pem")
            csr_pem = payload.csr_pem
        try:
            renewal = service.submit_request(
                template_id=certificate.template_id,
                csr_pem=csr_pem,
                kind=RequestKind.RENEWAL,
                requested_by_user_id=anchor_request.requested_by_user_id,
                renewal_of_serial_number=certificate.serial_number,
                renewal_of_certificate_id=certificate.certificate_id,
            )
        except (RepositoryError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        service.assign_request_holder(
            renewal.id,
            person_id=certificate.holder_person_id,
            device_id=certificate.holder_device_id,
        )
        if mode == "reuse" and server_key_held:
            key_vault.copy(certificate.request_id, renewal.id)
            reuse_request_key_registration(certificate, renewal.id)
        elif mode == "rotate" and new_key is not None:
            algorithm = payload.algorithm if payload is not None else "ecdsa-p256"
            key_vault.store(renewal.id, new_key, algorithm)
            ensure_request_key_registered(renewal.id)
        audit.record(
            AuditCategory.CERTIFICATE,
            "renewal_requested",
            actor=audit_actor(request),
            object_type="request",
            object_id=renewal.id,
            details={
                "renewal_of": certificate.serial_number,
                "renewal_of_certificate_id": certificate.certificate_id,
                "template_id": certificate.template_id,
                "mode": mode,
            },
        )
        return _request_response(renewal, repository, current_user=user)

    @app.post("/internal/certificates/{serial_number}/renew", status_code=201)
    def renew_certificate(
        serial_number: str,
        request: Request,
        payload: CertificateRenewalCreate | None = None,
    ) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, csrf=True)
        return _renew_certificate_target(_serial_certificate(serial_number), request, payload)

    @app.post("/internal/certificate-inventory/{certificate_id}/revoke", status_code=201)
    def revoke_inventory_certificate(
        certificate_id: str,
        payload: RevocationCreate,
        request: Request,
    ) -> dict[str, str]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, csrf=True)
        certificate = _inventory_certificate(certificate_id)
        return _revoke_certificate_target(certificate, payload, request)

    @app.delete("/internal/certificate-inventory/{certificate_id}")
    def archive_inventory_certificate(
        certificate_id: str,
        payload: CertificateArchive,
        request: Request,
    ) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, csrf=True)
        certificate = _inventory_certificate(certificate_id)
        return _archive_certificate_target(certificate, payload, request)

    @app.get("/internal/certificate-inventory/{certificate_id}/export")
    def export_inventory_certificate(
        certificate_id: str,
        request: Request,
        format: str = "pem",
    ) -> Response:
        active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, Role.AUDITOR)
        certificate = _inventory_certificate(certificate_id)
        return _export_certificate_download_target(certificate, request, format)

    @app.post("/internal/certificate-inventory/{certificate_id}/export")
    def export_inventory_certificate_with_key(
        certificate_id: str,
        payload: CertificateExportRequest,
        request: Request,
    ) -> Response:
        active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, csrf=True)
        certificate = _inventory_certificate(certificate_id)
        return _export_certificate_with_key_target(certificate, payload, request)

    @app.post("/internal/certificate-inventory/{certificate_id}/renew", status_code=201)
    def renew_inventory_certificate(
        certificate_id: str,
        request: Request,
        payload: CertificateRenewalCreate | None = None,
    ) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, csrf=True)
        certificate = _inventory_certificate(certificate_id)
        return _renew_certificate_target(certificate, request, payload)

    @app.post("/internal/certificates/{serial_number}/send", status_code=201)
    def send_certificate(
        serial_number: str, payload: CertificateSendRequest, request: Request
    ) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        certificate = _serial_certificate(serial_number)
        recipient = payload.recipient_override
        if not recipient:
            person = _resolve_holder_person(repository, certificate)
            if person is None:
                raise HTTPException(
                    status_code=409,
                    detail="Certificate has no holder; assign one or pass recipient_override",
                )
            if payload.channel is NotificationChannel.SMS:
                recipient = person.phone
            elif payload.channel is NotificationChannel.SLACK:
                recipient = person.slack_handle or person.email
            else:
                recipient = person.email
        if not recipient:
            raise HTTPException(status_code=400, detail="Holder has no contact for this channel")
        body = (
            f"Certificate for {certificate.subject} (serial {certificate.serial_number}), "
            f"expiring {certificate.expires_at.date().isoformat()}.\n\n{certificate.certificate_pem}"
        )
        try:
            result = comms.send(
                payload.channel,
                recipient,
                Message(body=body, subject=f"Your certificate: {certificate.subject}"),
            )
        except CommsError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        audit.record(
            AuditCategory.COMMS,
            "send",
            actor=audit_actor(request),
            object_type="certificate",
            object_id=certificate.certificate_id or certificate.serial_number,
            details={"channel": payload.channel.value, "recipient": recipient},
        )
        return {"recipient": recipient, **result.to_dict()}

    @app.post("/internal/certificates/{serial_number}/send-pkcs12", status_code=201)
    def send_pkcs12_certificate(
        serial_number: str, payload: CertificatePKCS12SendRequest, request: Request
    ) -> dict[str, object]:
        """Deliver a server-held key as an encrypted PKCS#12 bundle.

        The password is intentionally generated and retained only for the two
        outbound delivery calls.  It must never reach persistence, audit, or
        the API response.
        """
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        certificate = _serial_certificate(serial_number)
        if payload.password_channel not in {NotificationChannel.SMS, NotificationChannel.SLACK}:
            raise HTTPException(
                status_code=400,
                detail="PKCS#12 delivery password channel must be SMS or Slack",
            )
        person = _resolve_holder_person(repository, certificate)
        if person is None or not person.email:
            raise HTTPException(
                status_code=409,
                detail="Certificate has no holder with an email address",
            )
        password_recipient = (
            person.phone
            if payload.password_channel is NotificationChannel.SMS
            else person.slack_handle
        )
        if not password_recipient:
            label = "phone number" if payload.password_channel is NotificationChannel.SMS else "Slack handle"
            raise HTTPException(status_code=400, detail=f"Holder has no {label} for password delivery")

        require_recent_sensitive_action(
            request,
            category=AuditCategory.CERTIFICATE,
            action="send_pkcs12",
            object_type="certificate",
            object_id=certificate.certificate_id or certificate.serial_number,
            roles=(Role.ADMIN, Role.SUPERUSER),
        )
        try:
            key_pem = key_vault.load_pem(certificate.request_id)
        except ServerKeyError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        if key_pem is None:
            raise HTTPException(
                status_code=409,
                detail=(
                    "No server-held private key for this certificate; it was issued "
                    "from a user-supplied CSR or the key was purged"
                ),
            )

        ca_attachments = tuple(ca_certificate_attachments())
        password = secrets.token_urlsafe(32)
        try:
            bundle = build_export(
                certificate.certificate_pem,
                ExportFormat.PKCS12,
                serial_number=certificate.serial_number,
                chain_pems=certificate_chain_pems(certificate.certificate_pem),
                private_key_pem=key_pem,
                password=password,
            )
        except ExportError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        filename = bundle.filename.removesuffix(".pfx") + ".p12"
        bundle_message = Message(
            subject=f"Your certificate bundle: {certificate.subject}",
            body=_pkcs12_message_body(
                bool(payload.include_ca_certificates and ca_attachments)
            ),
            attachments=(
                Attachment(
                    content=bundle.content,
                    filename=filename,
                    media_type="application/x-pkcs12",
                ),
                *(ca_attachments if payload.include_ca_certificates else ()),
            ),
        )
        try:
            email_result = comms.send(NotificationChannel.EMAIL, person.email, bundle_message)
            if not email_result.success:
                raise CommsError("Email delivery was rejected")
        except CommsError as exc:
            audit.record(
                AuditCategory.COMMS,
                "send_pkcs12_failed",
                actor=audit_actor(request),
                outcome=AuditOutcome.FAILURE,
                object_type="certificate",
                object_id=certificate.certificate_id or certificate.serial_number,
                details={"stage": "email", "email_recipient": person.email},
            )
            raise HTTPException(status_code=502, detail="Certificate bundle delivery failed") from exc

        password_message = Message(
            subject=f"PKCS#12 password: {certificate.subject}",
            body=f"Password for your PKCS#12 certificate bundle: {password}",
        )
        try:
            password_result = comms.send(
                payload.password_channel, password_recipient, password_message
            )
            if not password_result.success:
                raise CommsError("Password delivery was rejected")
        except CommsError as exc:
            audit.record(
                AuditCategory.COMMS,
                "send_pkcs12_partial",
                actor=audit_actor(request),
                outcome=AuditOutcome.FAILURE,
                object_type="certificate",
                object_id=certificate.certificate_id or certificate.serial_number,
                details={
                    "stage": "password",
                    "email_recipient": person.email,
                    "password_channel": payload.password_channel.value,
                    "password_recipient": password_recipient,
                },
            )
            raise HTTPException(
                status_code=502,
                detail=(
                    "Certificate bundle was emailed, but password delivery failed. "
                    "Retry to generate a new bundle and password."
                ),
            ) from exc

        audit.record(
            AuditCategory.COMMS,
            "send_pkcs12",
            actor=audit_actor(request),
            object_type="certificate",
            object_id=certificate.certificate_id or certificate.serial_number,
            details={
                "email_recipient": person.email,
                "password_channel": payload.password_channel.value,
                "password_recipient": password_recipient,
            },
        )
        return {
            "success": True,
            "email_recipient": person.email,
            "password_channel": payload.password_channel.value,
            "password_recipient": password_recipient,
        }

    @app.post("/internal/crls", status_code=202)
    def create_crl(request: Request) -> dict[str, str | None]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        issuer = current_issuer()
        if issuer is None:
            raise HTTPException(status_code=503, detail="No issuer configured")
        job = crl_worker.enqueue(issuer)
        audit.record(
            AuditCategory.CERTIFICATE,
            "crl_queued",
            actor=audit_actor(request),
            object_type="crl_job",
            object_id=job.job_id,
        )
        return {
            "status": job.status,
            "crl_job_id": job.job_id,
            "distribution_url": issuer_crl_url(issuer),
        }

    @app.get("/internal/crls/status")
    def crl_status(request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, Role.AUDITOR)
        return crl_worker.status()

    @app.get("/internal/crls/latest")
    def latest_crl(request: Request) -> dict[str, str | int]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, Role.AUDITOR)
        issuer = current_issuer()
        if issuer is None:
            raise HTTPException(status_code=503, detail="No issuer configured")
        issuer_subject = issuer.certificate.subject.rfc4514_string()
        issuer_fingerprint = issuer.certificate.fingerprint(hashes.SHA256()).hex()
        crl = repository.get_latest_issuer_crl(
            issuer_subject,
            issuer_fingerprint,
        )
        if crl is None:
            raise HTTPException(status_code=404, detail="No CRL has been generated yet")
        return {
            "number": crl.number,
            "crl_pem": crl.crl_pem,
            "generated_at": crl.generated_at.isoformat(),
            "issuer_subject": crl.issuer_subject,
            "issuer_id": crl.issuer_id,
            "this_update": (crl.this_update.isoformat() if crl.this_update is not None else None),
            "next_update": (crl.next_update.isoformat() if crl.next_update is not None else None),
            "source": crl.source,
            "sha256": crl.sha256,
        }

    @app.get("/crl/{issuer_id}.crl", include_in_schema=False)
    def serve_crl(issuer_id: str) -> Response:
        # Public + unauthenticated by design: a CRL is signed, so relying parties
        # fetch it without a session. Returns DER (application/pkix-crl).
        if not _ISSUER_ID_RE.match(issuer_id):
            raise HTTPException(status_code=404, detail="Unknown issuer")
        subject: str | None = None
        issuer_fingerprint: str | None = None
        if lab_chain is not None and issuer_id == LAB_ISSUER_ID:
            subject = lab_chain.issuer.certificate.subject.rfc4514_string()
            issuer_fingerprint = lab_chain.issuer.certificate.fingerprint(hashes.SHA256()).hex()
        else:
            for sub_ca in repository.list_sub_cas():
                if sub_ca.id == issuer_id:
                    subject = sub_ca.subject
                    issuer_fingerprint = (
                        x509.load_pem_x509_certificate(sub_ca.certificate_pem.encode())
                        .fingerprint(hashes.SHA256())
                        .hex()
                    )
                    break
        if subject is None:
            raise HTTPException(status_code=404, detail="Unknown issuer")
        crl = repository.get_latest_issuer_crl(subject, issuer_fingerprint)
        if crl is None:
            raise HTTPException(status_code=404, detail="No CRL has been generated yet")
        return Response(content=crl_pem_to_der(crl.crl_pem), media_type="application/pkix-crl")

    @app.post("/internal/ca-certificates/send", status_code=201)
    def send_ca_certificates(
        payload: CACertificateSendRequest, request: Request
    ) -> dict[str, object]:
        """Email the CA certificates to a person, with no end-entity material.

        Needed before a device can trust anything this CA issues, and useful on
        its own: a holder whose certificate was delivered earlier, or a machine
        being prepared before any certificate exists for it.
        """

        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        person = _repository_person_or_none(repository, payload.person_id)
        if person is None:
            raise HTTPException(status_code=404, detail="Unknown person")
        if not person.email:
            raise HTTPException(
                status_code=409, detail="This person has no email address"
            )
        attachments = tuple(ca_certificate_attachments())
        if not attachments:
            raise HTTPException(
                status_code=409,
                detail="No issuer is configured, so there are no CA certificates to send",
            )
        message = Message(
            subject="Certificate authority certificates",
            body=(
                "The certificates for this certificate authority are attached: "
                + ", ".join(item.filename for item in attachments)
                + ".\n\nInstall them to trust certificates issued by this CA. "
                "On iOS, install the root and then enable it under Settings > "
                "General > About > Certificate Trust Settings; installing it "
                "alone does not make it trusted."
            ),
            attachments=attachments,
        )
        try:
            result = comms.send(NotificationChannel.EMAIL, person.email, message)
        except CommsError as exc:
            audit.record(
                AuditCategory.CERTIFICATE,
                "send_ca_certificates_failed",
                actor=audit_actor(request),
                outcome=AuditOutcome.FAILURE,
                object_type="person",
                object_id=person.id,
                details={"detail": str(exc)},
            )
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        audit.record(
            AuditCategory.CERTIFICATE,
            "send_ca_certificates",
            actor=audit_actor(request),
            outcome=AuditOutcome.SUCCESS if result.success else AuditOutcome.FAILURE,
            object_type="person",
            object_id=person.id,
            details={
                "files": [item.filename for item in attachments],
                "success": result.success,
            },
        )
        return {
            "person_id": person.id,
            "recipient": person.email,
            "files": [item.filename for item in attachments],
            "success": result.success,
            "detail": result.detail,
        }

    @app.get("/aia/{issuer_id}.cer", include_in_schema=False)
    def serve_aia(issuer_id: str) -> Response:
        # Public + unauthenticated by design: a CA certificate is public. Returns DER
        # (application/pkix-cert) so AIA caIssuers consumers can fetch the issuer.
        if not _ISSUER_ID_RE.match(issuer_id):
            raise HTTPException(status_code=404, detail="Unknown issuer")
        pem: str | None = None
        if lab_chain is not None and issuer_id == LAB_ISSUER_ID:
            pem = certificate_to_pem(lab_chain.issuer.certificate)
        else:
            for sub_ca in repository.list_sub_cas():
                if sub_ca.id == issuer_id:
                    pem = sub_ca.certificate_pem
                    break
        if pem is None:
            raise HTTPException(status_code=404, detail="Unknown issuer")
        return Response(content=cert_pem_to_der(pem), media_type="application/pkix-cert")

    # -- people & devices (certificate holders) -------------------------------

    @app.get("/internal/people")
    def list_people(request: Request) -> list[dict[str, object]]:
        _, user = active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, Role.AUDITOR)
        people = repository.list_people()
        if user.role is Role.USER:
            people = [own_person(user)]
        return [_person_response(person) for person in people]

    @app.post("/internal/people", status_code=201)
    def create_person(payload: PersonCreate, request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        person = Person(
            id=payload.id or str(uuid4()),
            name=payload.name,
            surname=payload.surname,
            email=payload.email,
            created_at=datetime.now(timezone.utc),
            phone=payload.phone,
            slack_handle=payload.slack_handle,
            company=payload.company,
            comments=payload.comments,
        )
        try:
            repository.add_person(person)
        except RepositoryError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return _person_response(person)

    @app.get("/internal/people/{person_id}")
    def get_person(person_id: str, request: Request) -> dict[str, object]:
        _, user = active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, Role.AUDITOR)
        if user.role is Role.USER:
            require_holder_scope(user, person_id=person_id)
        try:
            person = repository.get_person(person_id)
        except RepositoryError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return _person_response(person)

    @app.put("/internal/people/{person_id}")
    def update_person(person_id: str, payload: PersonUpdate, request: Request) -> dict[str, object]:
        _, user = active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, csrf=True)
        if user.role is Role.USER:
            require_holder_scope(user, person_id=person_id)
            if payload.email.casefold() != user.email.casefold():
                raise HTTPException(
                    status_code=400,
                    detail="Your Person email must remain equal to your login email",
                )
        try:
            existing = repository.get_person(person_id)
        except RepositoryError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        person = Person(
            id=person_id,
            name=payload.name,
            surname=payload.surname,
            email=payload.email,
            created_at=existing.created_at,
            phone=payload.phone,
            slack_handle=payload.slack_handle,
            company=payload.company,
            comments=payload.comments,
        )
        try:
            repository.update_person(person)
        except RepositoryError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return _person_response(person)

    @app.delete("/internal/people/{person_id}")
    def delete_person(person_id: str, request: Request) -> dict[str, str]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        try:
            repository.delete_person(person_id)
        except RepositoryError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"id": person_id}

    @app.get("/internal/devices")
    def list_devices(request: Request) -> list[dict[str, object]]:
        _, user = active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, Role.AUDITOR)
        people_by_id = {person.id: person for person in repository.list_people()}
        devices = repository.list_devices()
        if user.role is Role.USER:
            devices = [device for device in devices if device.admin_id == own_person(user).id]
        return [_device_response(device, people_by_id.get(device.admin_id)) for device in devices]

    @app.post("/internal/devices", status_code=201)
    def create_device(payload: DeviceCreate, request: Request) -> dict[str, object]:
        _, user = active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, csrf=True)
        admin_id = payload.admin_id
        if user.role is Role.USER:
            admin_id = own_person(user).id
        device = Device(
            id=payload.id or str(uuid4()),
            device_name=payload.device_name,
            admin_id=admin_id,
            created_at=datetime.now(timezone.utc),
            fqdn=payload.fqdn,
            comments=payload.comments,
        )
        try:
            repository.add_device(device)
        except RepositoryError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return _device_response(device, _repository_person_or_none(repository, device.admin_id))

    @app.get("/internal/devices/{device_id}")
    def get_device(device_id: str, request: Request) -> dict[str, object]:
        _, user = active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, Role.AUDITOR)
        if user.role is Role.USER:
            require_holder_scope(user, device_id=device_id)
        try:
            device = repository.get_device(device_id)
        except RepositoryError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return _device_response(device, _repository_person_or_none(repository, device.admin_id))

    @app.put("/internal/devices/{device_id}")
    def update_device(device_id: str, payload: DeviceUpdate, request: Request) -> dict[str, object]:
        _, user = active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, csrf=True)
        if user.role is Role.USER:
            require_holder_scope(user, device_id=device_id)
        try:
            existing = repository.get_device(device_id)
        except RepositoryError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        device = Device(
            id=device_id,
            device_name=payload.device_name,
            admin_id=(own_person(user).id if user.role is Role.USER else payload.admin_id),
            created_at=existing.created_at,
            fqdn=payload.fqdn,
            comments=payload.comments,
        )
        try:
            repository.update_device(device)
        except RepositoryError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return _device_response(device, _repository_person_or_none(repository, device.admin_id))

    @app.delete("/internal/devices/{device_id}")
    def delete_device(device_id: str, request: Request) -> dict[str, str]:
        _, user = active_user(request, Role.ADMIN, Role.SUPERUSER, Role.USER, csrf=True)
        if user.role is Role.USER:
            require_holder_scope(user, device_id=device_id)
        try:
            repository.delete_device(device_id)
        except RepositoryError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"id": device_id}

    @app.post("/internal/certificate-requests/{request_id}/holder", status_code=201)
    def assign_request_holder(
        request_id: str, payload: RequestHolderAssign, request: Request
    ) -> dict[str, object]:
        _, user = active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        try:
            certificate_request = service.assign_request_holder(
                request_id,
                person_id=payload.person_id,
                device_id=payload.device_id,
            )
        except (RepositoryError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        body = _request_response(certificate_request, repository, current_user=user)
        body.update({"auto_issued": False, "auto_issue_error": None, "issued_certificate": None})

        # If the request was already approved to threshold and only lacked a
        # holder, issuing it is now unblocked — attempt it immediately.
        template = repository.get_template(certificate_request.template_id)
        approvals = repository.list_approvals(request_id)
        needed = required_approvals(certificate_request, template)
        if len({record.superuser_id for record in approvals}) >= needed:
            certificate, auto_issue_error = attempt_issuance(request_id, audit_actor(request))
            if certificate is not None:
                updated = repository.get_request(request_id)
                body = _request_response(updated, repository, current_user=user)
                body.update(
                    {
                        "auto_issued": True,
                        "auto_issue_error": None,
                        "issued_certificate": _certificate_response(
                            certificate, repository, include_pem=True
                        ),
                    }
                )
            else:
                body["auto_issue_error"] = auto_issue_error
        return body

    # -- communication channels -----------------------------------------------

    @app.get("/internal/comms/channels")
    def list_comms_channels(request: Request) -> list[dict[str, object]]:
        active_user(request, Role.ADMIN, Role.SUPERUSER)
        return comms.list_configs_redacted()

    @app.put("/internal/comms/channels/{channel}")
    def update_comms_channel(
        channel: str, payload: CommsChannelConfigUpdate, request: Request
    ) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        try:
            notification_channel = NotificationChannel(channel)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=f"Unknown channel: {channel}") from exc
        return comms.set_config(
            notification_channel,
            enabled=payload.enabled,
            config=payload.config,
            secrets=payload.secrets,
        )

    @app.post("/internal/comms/send")
    def send_comms_message(payload: CommsSendRequest, request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        try:
            result = comms.send(
                payload.channel,
                payload.recipient,
                Message(
                    body=payload.body,
                    subject=payload.subject,
                    metadata=payload.metadata,
                ),
            )
        except CommsError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return result.to_dict()

    @app.post("/internal/comms/test")
    def test_comms_channel(payload: CommsSendRequest, request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        try:
            result = comms.send(
                payload.channel,
                payload.recipient,
                Message(
                    body=payload.body,
                    subject=payload.subject,
                    metadata=payload.metadata,
                ),
            )
        except CommsError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        audit.record(
            AuditCategory.COMMS,
            "channel_test",
            actor=audit_actor(request),
            outcome=AuditOutcome.SUCCESS if result.success else AuditOutcome.FAILURE,
            object_type="comms_channel",
            object_id=payload.channel.value,
            details={"success": result.success},
        )
        return result.to_dict()

    # -- notifications ---------------------------------------------------------

    @app.get("/internal/notifications/schedule")
    def notification_schedule_settings(request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER)
        return app.state.notification_schedule.settings().model_dump()

    @app.put("/internal/notifications/schedule")
    def update_notification_schedule(
        payload: NotificationScheduleSettings, request: Request,
    ) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        previous = app.state.notification_schedule.update(payload)
        if previous != payload:
            audit.record(
                AuditCategory.COMMS, "notification_schedule_updated",
                actor=audit_actor(request), object_type="setting",
                object_id=NotificationSchedule.SETTING_KEY,
                details={"previous": previous.model_dump(), "current": payload.model_dump()},
            )
        return payload.model_dump()

    @app.post("/internal/notifications/run", status_code=201)
    def run_notifications(request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        summary = notifications.run_scheduled(datetime.now(timezone.utc))
        rules = summary["rules"]
        audit.record(
            AuditCategory.COMMS,
            "notifications_run",
            actor=audit_actor(request),
            object_type="notification_rules",
            object_id="scheduled",
            details={
                "rules": len(rules),
                "sent": sum(entry["sent"] for entry in rules),
                "failed": sum(entry["failed"] for entry in rules),
                "skipped": sum(entry["skipped"] for entry in rules),
                "skipped_reason": summary.get("skipped_reason"),
            },
        )
        return summary

    @app.get("/internal/notifications/variables")
    def list_notification_variables(request: Request) -> dict[str, str]:
        active_user(request, Role.ADMIN, Role.SUPERUSER)
        return TEMPLATE_VARIABLES

    @app.get("/internal/notifications/templates")
    def list_notification_templates(request: Request) -> list[dict[str, object]]:
        active_user(request, Role.ADMIN, Role.SUPERUSER)
        return [
            _notification_template_response(template)
            for template in notifications.repository.list_templates()
        ]

    @app.post("/internal/notifications/templates", status_code=201)
    def create_notification_template(
        payload: NotificationTemplateCreate, request: Request
    ) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        template = NotificationTemplate(**payload.model_dump())
        try:
            notifications.repository.add_template(template)
        except RepositoryError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        audit.record(
            AuditCategory.COMMS,
            "notification_template_create",
            actor=audit_actor(request),
            object_type="notification_template",
            object_id=template.name,
            details={"event_type": template.event_type.value},
        )
        return _notification_template_response(notifications.repository.get_template(template.name))

    @app.put("/internal/notifications/templates/{name}")
    def update_notification_template(
        name: str, payload: NotificationTemplateUpdate, request: Request
    ) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        template = NotificationTemplate(name=name, **payload.model_dump())
        try:
            notifications.repository.update_template(template)
        except RepositoryError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        audit.record(
            AuditCategory.COMMS,
            "notification_template_update",
            actor=audit_actor(request),
            object_type="notification_template",
            object_id=name,
            details={"event_type": template.event_type.value},
        )
        return _notification_template_response(notifications.repository.get_template(name))

    @app.delete("/internal/notifications/templates/{name}")
    def delete_notification_template(name: str, request: Request) -> dict[str, str]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        try:
            notifications.repository.delete_template(name)
        except RepositoryError as exc:
            status = 404 if "Unknown" in str(exc) else 409
            raise HTTPException(status_code=status, detail=str(exc)) from exc
        audit.record(
            AuditCategory.COMMS,
            "notification_template_delete",
            actor=audit_actor(request),
            object_type="notification_template",
            object_id=name,
        )
        return {"name": name}

    @app.post("/internal/notifications/templates/{name}/preview")
    def preview_notification_template(
        name: str, payload: NotificationTemplatePreview, request: Request
    ) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        try:
            stored = notifications.repository.get_template(name)
        except RepositoryError:
            stored = None
        if payload.subject is None and payload.body is None:
            if stored is None:
                raise HTTPException(
                    status_code=404, detail=f"Unknown notification template: {name}"
                )
            template = stored
        else:
            template = NotificationTemplate(
                name=name,
                event_type=stored.event_type if stored else NotificationEvent.EXPIRING,
                format=payload.format,
                subject=payload.subject or "",
                body=payload.body or "",
            )
        subject, body = render_notification(template, SAMPLE_CONTEXT)
        return {"subject": subject, "body": body, "format": template.format.value}

    @app.get("/internal/notifications/rules")
    def list_notification_rules(request: Request) -> list[dict[str, object]]:
        active_user(request, Role.ADMIN, Role.SUPERUSER)
        return [_notification_rule_response(rule) for rule in notifications.repository.list_rules()]

    @app.post("/internal/notifications/rules", status_code=201)
    def create_notification_rule(
        payload: NotificationRuleCreate, request: Request
    ) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        body = payload.model_dump()
        rule = NotificationRule(**{**body, "id": body["id"] or str(uuid4())})
        try:
            notifications.repository.add_rule(rule)
        except RepositoryError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        audit.record(
            AuditCategory.COMMS,
            "notification_rule_create",
            actor=audit_actor(request),
            object_type="notification_rule",
            object_id=rule.id,
            details={"event_type": rule.event_type.value, "template": rule.template_name},
        )
        return _notification_rule_response(notifications.repository.get_rule(rule.id))

    @app.put("/internal/notifications/rules/{rule_id}")
    def update_notification_rule(
        rule_id: str, payload: NotificationRuleUpdate, request: Request
    ) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        rule = NotificationRule(id=rule_id, **payload.model_dump())
        try:
            notifications.repository.update_rule(rule)
        except RepositoryError as exc:
            status = 404 if "Unknown notification rule" in str(exc) else 409
            raise HTTPException(status_code=status, detail=str(exc)) from exc
        audit.record(
            AuditCategory.COMMS,
            "notification_rule_update",
            actor=audit_actor(request),
            object_type="notification_rule",
            object_id=rule_id,
            details={"event_type": rule.event_type.value, "template": rule.template_name},
        )
        return _notification_rule_response(notifications.repository.get_rule(rule_id))

    @app.delete("/internal/notifications/rules/{rule_id}")
    def delete_notification_rule(rule_id: str, request: Request) -> dict[str, str]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        try:
            notifications.repository.delete_rule(rule_id)
        except RepositoryError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        audit.record(
            AuditCategory.COMMS,
            "notification_rule_delete",
            actor=audit_actor(request),
            object_type="notification_rule",
            object_id=rule_id,
        )
        return {"id": rule_id}

    @app.get("/internal/notifications/log")
    def list_notification_log(request: Request) -> list[dict[str, object]]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, Role.AUDITOR)
        return [_notification_log_response(entry) for entry in notifications.repository.list_log()]

    # -- audit log ------------------------------------------------------------

    @app.get("/internal/audit/events")
    def list_audit_events(
        request: Request,
        category: str | None = None,
        actor_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, object]]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, Role.AUDITOR)
        return [
            event.to_dict()
            for event in audit.list_events(
                category=category, actor_id=actor_id, limit=limit, offset=offset
            )
        ]

    @app.get("/internal/audit/verify")
    def verify_audit_chain(request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.AUDITOR)
        return audit.verify_chain()

    @app.get("/internal/audit/syslog")
    def get_syslog_config(request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN)
        return audit.get_syslog_config()

    @app.put("/internal/audit/syslog")
    def update_syslog_config(payload: SyslogConfigUpdate, request: Request) -> dict[str, object]:
        _, user = active_user(request, Role.ADMIN, csrf=True)
        try:
            config = audit.set_syslog_config(
                enabled=payload.enabled,
                host=payload.host,
                port=payload.port,
                protocol=payload.protocol,
                facility=payload.facility,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        audit.record(
            AuditCategory.AUDIT,
            "syslog_config_update",
            actor=audit_actor(request),
            object_type="syslog",
            details={
                "enabled": payload.enabled,
                "host": payload.host,
                "protocol": payload.protocol,
            },
        )
        return config

    # -- service certificates (public-facing certs) ---------------------------

    @app.post("/internal/service-certs/{cert_id}/use-as-portal-tls")
    def use_service_cert_as_portal_tls(cert_id: str, request: Request) -> dict[str, object]:
        active_user(request, Role.SUPERUSER, csrf=True)
        try:
            service_certs.get_cert(cert_id)
        except Exception as exc:  # noqa: BLE001 - repository raises a plain RuntimeError
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        try:
            _materialize_portal_tls(cert_id)
        except (ServiceCertError, portal_tls.PortalTlsError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        repository.set_setting("portal_tls_service_cert_id", cert_id)
        audit.record(
            AuditCategory.SERVICE_CERT,
            "portal_tls_set",
            actor=audit_actor(request),
            object_type="service_cert",
            object_id=cert_id,
        )
        return _portal_tls_status()

    @app.get("/internal/portal-tls")
    def get_portal_tls(request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, Role.AUDITOR)
        return _portal_tls_status()

    @app.delete("/internal/portal-tls")
    def clear_portal_tls(request: Request) -> dict[str, object]:
        active_user(request, Role.SUPERUSER, csrf=True)
        portal_tls.clear(resolve_state_dir())
        repository.set_setting("portal_tls_service_cert_id", "")
        audit.record(
            AuditCategory.SERVICE_CERT,
            "portal_tls_cleared",
            actor=audit_actor(request),
            object_type="setting",
            object_id="portal_tls",
        )
        return {"cleared": True}

    @app.get("/internal/service-certs")
    def list_service_certs(request: Request) -> list[dict[str, object]]:
        active_user(request, Role.ADMIN, Role.SUPERUSER)
        return [_service_cert_response(cert) for cert in service_certs.list_certs()]

    @app.get("/internal/service-certs/{cert_id}")
    def get_service_cert(cert_id: str, request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER)
        try:
            cert = service_certs.get_cert(cert_id)
        except Exception as exc:  # noqa: BLE001 - repository raises a plain RuntimeError
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return _service_cert_response(cert, include_pem=True)

    @app.delete("/internal/service-certs/{cert_id}")
    def delete_service_cert(cert_id: str, request: Request) -> dict[str, object]:
        session, user = active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        try:
            auth_service.require_recent_sensitive_auth(session, user)
        except AuthenticationError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        try:
            cert = service_certs.get_cert(cert_id)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        if cert.key_backend in {KeyBackend.AWS_KMS, KeyBackend.AZURE_KEY_VAULT}:
            active_jobs = any(
                signing_jobs.has_active_for_key(key.id)
                for key in cloud_keys.list_all(provider=cert.key_backend.value)
                if _same_cloud_key(key.provider, key.key_ref, cert.key_ref)
            )
            if active_jobs:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "Cancel the active cloud signing job before deleting "
                        "this service certificate"
                    ),
                )
        registered = retire_service_certificate_key(cert)
        archived = replace(
            cert,
            status=ServiceCertStatus.SUPERSEDED,
            updated_at=datetime.now(timezone.utc),
        )
        service_certs.repository.update(archived)
        audit.record(
            AuditCategory.SERVICE_CERT,
            "service_certificate_archived",
            actor=audit_actor(request),
            object_type="service_cert",
            object_id=cert.id,
            details={
                "key_status": registered.status.value,
                "delete_after": registered.delete_after.isoformat()
                if registered.delete_after
                else None,
            },
        )
        return {
            "id": cert_id,
            "status": archived.status.value,
            "key_status": registered.status.value,
            "delete_after": registered.delete_after.isoformat()
            if registered.delete_after
            else None,
        }

    @app.post(
        "/internal/service-certs/csr",
        status_code=201,
        response_model=None,
    )
    def create_service_csr(
        payload: ServiceCsrCreate, request: Request
    ) -> dict[str, object] | JSONResponse:
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        selected_backend = payload.key_backend or default_service_key_backend
        if selected_backend in {KeyBackend.AWS_KMS, KeyBackend.AZURE_KEY_VAULT}:
            cert: ServiceCertificate | None = None
            key: CloudKey | None = None
            cert_id = str(uuid4())
            key_ref: str | None = None
            try:
                key_ref = hsm.generate_key(f"svc-{cert_id.replace('-', '')}", payload.algorithm)
                key = ensure_cloud_key(
                    key_ref=key_ref,
                    algorithm=payload.algorithm,
                    purpose="service_certificate",
                    ownership=CloudKeyOwnership.MANAGED,
                    label=cert_id,
                )
                cert = service_certs.prepare_csr(
                    payload.name,
                    key_backend=selected_backend,
                    algorithm=payload.algorithm,
                    prepared_key_ref=key_ref,
                    certificate_id=cert_id,
                )
                bind_service_certificate_key(cert, ownership=KeyOwnership.MANAGED)
                job = signing_jobs.enqueue(
                    cloud_key_id=key.id,
                    operation="service_csr",
                    resource_type="service_certificate",
                    resource_id=cert.id,
                    payload={
                        "certificate_id": cert.id,
                        "common_name": payload.common_name,
                        "dns_names": payload.dns_names,
                    },
                    deduplication_key=f"service-csr:{cert.id}",
                ).job
            except (CloudRepositoryError, ServiceCertError, RuntimeError, ValueError) as exc:
                if key_ref is not None and _discard_prepared_cloud_service_cert(cert_id):
                    _track_and_compensate_managed_cloud_key(
                        key_ref=key_ref,
                        algorithm=payload.algorithm,
                        purpose="service_certificate",
                        label=cert_id,
                        resource_type="service_certificate",
                        resource_id=cert_id,
                        registered_key=key,
                        request=request,
                    )
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            body = _service_cert_response(cert)
            body.update(
                {
                    "status": "queued",
                    "signing_job_id": job.id,
                    "cloud_key_id": key.id,
                }
            )
            return JSONResponse(status_code=202, content=body)
        cert: ServiceCertificate | None = None
        try:
            cert = service_certs.prepare_csr(
                payload.name,
                key_backend=selected_backend,
                algorithm=payload.algorithm,
            )
            bind_service_certificate_key(cert, ownership=KeyOwnership.MANAGED)
            cert, csr_pem = service_certs.complete_csr(
                cert.id,
                common_name=payload.common_name,
                dns_names=tuple(payload.dns_names),
            )
        except (ServiceCertError, ValueError, RuntimeError) as exc:
            if cert is not None:
                try:
                    service_certs.repository.delete(cert.id)
                    retire_service_certificate_key(cert)
                except Exception:  # noqa: BLE001 - preserve the originating failure
                    logger.exception(
                        "Could not schedule cleanup for failed service CSR %s",
                        cert.id,
                    )
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        body = _service_cert_response(cert)
        body["csr_pem"] = csr_pem
        return body

    @app.post("/internal/service-certs/{cert_id}/import-certificate", status_code=201)
    def import_service_certificate(
        cert_id: str, payload: ServiceCertImportSigned, request: Request
    ) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        try:
            cert = service_certs.import_signed_certificate(
                cert_id, payload.certificate_pem, payload.chain_pem
            )
        except (ServiceCertError, ValueError, RuntimeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        bind_service_certificate_key(cert, ownership=KeyOwnership.MANAGED)
        return _service_cert_response(cert, include_pem=True)

    @app.post("/internal/service-certs/import-pem", status_code=201)
    def import_service_pem(payload: ServiceImportPem, request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        try:
            cert = service_certs.import_pem(
                payload.name,
                certificate_pem=payload.certificate_pem,
                private_key_pem=payload.private_key_pem,
                chain_pem=payload.chain_pem,
                key_passphrase=payload.key_passphrase,
            )
        except (ServiceCertError, ValueError, RuntimeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        bind_service_certificate_key(cert, ownership=KeyOwnership.MANAGED)
        return _service_cert_response(cert, include_pem=True)

    @app.post("/internal/service-certs/import-p12", status_code=201)
    def import_service_p12(payload: ServiceImportP12, request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        try:
            p12_bytes = base64.b64decode(payload.p12_base64, validate=True)
        except (ValueError, BinasciiError) as exc:
            raise HTTPException(status_code=400, detail="p12_base64 is not valid base64") from exc
        try:
            cert = service_certs.import_p12(payload.name, p12_bytes, payload.password)
        except (ServiceCertError, ValueError, RuntimeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        bind_service_certificate_key(cert, ownership=KeyOwnership.MANAGED)
        return _service_cert_response(cert, include_pem=True)

    @app.get("/internal/service-certs/acme/accounts")
    def list_acme_accounts(request: Request) -> list[dict[str, object]]:
        active_user(request, Role.ADMIN, Role.SUPERUSER)
        return [
            _acme_account_response(account, service_certs.account_dependents(account.id))
            for account in service_certs.list_accounts()
        ]

    def _acme_failure(operation: str, target: str, exc: Exception) -> HTTPException:
        """Log the full traceback, record a concise error row, and map to an HTTP status.

        Known/validation failures stay 400; anything unexpected (e.g. a network error from
        the ACME directory) becomes 502. Recording is itself defensive so a logging failure
        never masks the original error.
        """
        logger.exception("ACME %s failed for %s", operation, target)
        try:
            service_certs.repository.record_error(operation, target, str(exc))
        except Exception:  # noqa: BLE001 - recording must not hide the real failure
            logger.exception("failed to record ACME error")
        status = 400 if isinstance(exc, (ServiceCertError, ValueError, RuntimeError)) else 502
        return HTTPException(status_code=status, detail=str(exc) or exc.__class__.__name__)

    @app.post("/internal/service-certs/acme/accounts", status_code=201)
    def create_acme_account(payload: AcmeAccountCreate, request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        try:
            account = service_certs.create_account(payload.directory_url, payload.contact)
        except Exception as exc:  # noqa: BLE001 - surface + log + record every ACME failure
            raise _acme_failure("account_create", payload.directory_url, exc) from exc
        return _acme_account_response(account)

    @app.put("/internal/service-certs/acme/accounts/{account_id}/dns-provider")
    def set_acme_dns_provider(
        account_id: str, payload: AcmeDnsProviderUpdate, request: Request
    ) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        try:
            service_certs.set_account_dns_provider(
                account_id,
                payload.provider,
                {"auth_username": payload.username, "auth_token": payload.token},
            )
            account = service_certs.repository.get_account(account_id)
        except Exception as exc:  # noqa: BLE001 - surface + log + record every ACME failure
            raise _acme_failure("dns_provider", f"account {account_id}", exc) from exc
        return _acme_account_response(account)

    @app.delete("/internal/service-certs/acme/accounts/{account_id}", status_code=204)
    def delete_acme_account(account_id: str, request: Request, force: bool = False) -> Response:
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        try:
            service_certs.delete_account(account_id, force=force)
        except AcmeAccountInUseError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except (ServiceCertError, RuntimeError) as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return Response(status_code=204)

    @app.post(
        "/internal/service-certs/acme/orders",
        status_code=201,
        response_model=None,
    )
    def create_acme_order(
        payload: AcmeOrderCreate, request: Request
    ) -> dict[str, object] | JSONResponse:
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        target = f"{payload.name} ({', '.join(payload.domains)})"
        selected_backend = payload.key_backend or default_service_key_backend
        if selected_backend in {KeyBackend.AWS_KMS, KeyBackend.AZURE_KEY_VAULT}:
            cert: ServiceCertificate | None = None
            key: CloudKey | None = None
            cert_id = str(uuid4())
            key_ref: str | None = None
            try:
                key_ref = hsm.generate_key(f"svc-{cert_id.replace('-', '')}", payload.algorithm)
                key = ensure_cloud_key(
                    key_ref=key_ref,
                    algorithm=payload.algorithm,
                    purpose="service_certificate",
                    ownership=CloudKeyOwnership.MANAGED,
                    label=cert_id,
                )
                cert = service_certs.prepare_acme_certificate(
                    payload.name,
                    account_id=payload.account_id,
                    domains=tuple(payload.domains),
                    challenge_type=payload.challenge_type,
                    key_backend=selected_backend,
                    algorithm=payload.algorithm,
                    renew_before_days=payload.renew_before_days,
                    prepared_key_ref=key_ref,
                    certificate_id=cert_id,
                )
                bind_service_certificate_key(cert, ownership=KeyOwnership.MANAGED)
                job = signing_jobs.enqueue(
                    cloud_key_id=key.id,
                    operation="acme_order",
                    resource_type="service_certificate",
                    resource_id=cert.id,
                    payload={
                        "certificate_id": cert.id,
                        "acme_operation_id": f"acme-issue:{cert.id}",
                    },
                    deduplication_key=f"acme-order:{cert.id}",
                ).job
            except Exception as exc:  # noqa: BLE001 - standard ACME error path
                if key_ref is not None and _discard_prepared_cloud_service_cert(cert_id):
                    _track_and_compensate_managed_cloud_key(
                        key_ref=key_ref,
                        algorithm=payload.algorithm,
                        purpose="service_certificate",
                        label=cert_id,
                        resource_type="service_certificate",
                        resource_id=cert_id,
                        registered_key=key,
                        request=request,
                    )
                raise _acme_failure("order_create", target, exc) from exc
            return JSONResponse(
                status_code=202,
                content={
                    "status": "queued",
                    "certificate_id": cert.id,
                    "signing_job_id": job.id,
                    "cloud_key_id": key.id,
                },
            )
        try:
            result = service_certs.request_certificate(
                payload.name,
                account_id=payload.account_id,
                domains=tuple(payload.domains),
                challenge_type=payload.challenge_type,
                key_backend=selected_backend,
                algorithm=payload.algorithm,
                renew_before_days=payload.renew_before_days,
            )
        except Exception as exc:  # noqa: BLE001 - surface + log + record every ACME failure
            # ACME may fail after the key and pending row were created.  Keep
            # that row retryable, but make the key visible to lifecycle
            # reconciliation instead of deleting it as an error side effect.
            pending = service_certs.repository.get_by_name(payload.name)
            if pending is not None:
                try:
                    bind_service_certificate_key(
                        pending,
                        ownership=KeyOwnership.MANAGED,
                    )
                except KeyLifecycleError:
                    logger.exception(
                        "Could not register the pending ACME service key %s",
                        pending.id,
                    )
            raise _acme_failure("order_create", target, exc) from exc
        issued_service_certificate = service_certs.get_cert(str(result["certificate_id"]))
        bind_service_certificate_key(
            issued_service_certificate,
            ownership=KeyOwnership.MANAGED,
        )
        return result

    @app.get("/internal/service-certs/acme/errors")
    def list_acme_errors(request: Request) -> list[dict[str, object]]:
        active_user(request, Role.ADMIN, Role.SUPERUSER)
        return service_certs.repository.list_recent_errors()

    @app.delete("/internal/service-certs/acme/errors")
    def clear_acme_errors(request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        service_certs.repository.clear_errors()
        return {"cleared": True}

    @app.post(
        "/internal/service-certs/{cert_id}/renew",
        status_code=201,
        response_model=None,
    )
    def renew_service_cert(cert_id: str, request: Request) -> dict[str, object] | JSONResponse:
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        try:
            cert = service_certs.get_cert(cert_id)
        except Exception as exc:  # noqa: BLE001 - repository boundary
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        if cert.key_backend in {KeyBackend.AWS_KMS, KeyBackend.AZURE_KEY_VAULT}:
            try:
                job = enqueue_cloud_acme_renew(cert)
            except (CloudRepositoryError, ServiceCertError, RuntimeError, ValueError) as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            audit.record(
                AuditCategory.SERVICE_CERT,
                "acme_renew_queued",
                actor=audit_actor(request),
                object_type="signing_job",
                object_id=job.id,
                details={"service_certificate_id": cert.id},
            )
            return JSONResponse(
                status_code=202,
                content={
                    "status": "queued",
                    "certificate_id": cert.id,
                    "signing_job_id": job.id,
                },
            )
        try:
            result = service_certs.renew(cert_id)
        except (ServiceCertError, RuntimeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if (repository.get_setting("portal_tls_service_cert_id") or "") == cert_id:
            try:
                _materialize_portal_tls(cert_id)
                audit.record(
                    AuditCategory.SERVICE_CERT,
                    "portal_tls_rematerialized",
                    actor=audit_actor(request),
                    object_type="service_cert",
                    object_id=cert_id,
                )
            except Exception:  # noqa: BLE001 - never fail a renewal on re-materialize
                logger.warning(
                    "portal TLS re-materialize after renewal failed for %s",
                    cert_id,
                    exc_info=True,
                )
        return result

    def _dkek_share_path(filename: str) -> Path:
        # Reject path traversal: the share must resolve directly inside the dir.
        candidate = (settings.pkcs11_dkek_share_dir / filename).resolve()
        share_dir = settings.pkcs11_dkek_share_dir.resolve()
        if candidate.parent != share_dir:
            raise HTTPException(status_code=400, detail="Invalid DKEK share filename")
        return candidate

    def _hsm_error_detail(exc: BaseException, operation: str | None = None) -> str:
        detail = str(exc) or exc.__class__.__name__
        return f"{operation}: {detail}" if operation else detail

    def _cloud_key_response(key) -> dict[str, object]:
        return {
            "id": key.id,
            "provider": key.provider,
            "key_ref": key.key_ref,
            "label": key.label,
            "algorithm": key.algorithm,
            "protection": key.protection,
            "purpose": key.purpose,
            "ownership": key.ownership.value,
            "status": key.status.value,
            "created_at": key.created_at.isoformat(),
            "updated_at": key.updated_at.isoformat(),
        }

    def _signing_job_response(job: SigningJob) -> dict[str, object]:
        # Payloads are intentionally excluded. Even though repository payloads
        # must not contain credentials, operational APIs need only identifiers.
        return {
            "id": job.id,
            "cloud_key_id": job.cloud_key_id,
            "operation": job.operation,
            "resource_type": job.resource_type,
            "resource_id": job.resource_id,
            "status": job.status.value,
            "attempt_count": job.attempt_count,
            "next_attempt_at": job.next_attempt_at.isoformat(),
            "created_at": job.created_at.isoformat(),
            "updated_at": job.updated_at.isoformat(),
            "completed_at": (job.completed_at.isoformat() if job.completed_at else None),
            "last_error_code": job.last_error_code,
            "last_error_message": job.last_error_message,
            "result": dict(job.result) if job.result is not None else None,
            "cancel_requested": job.cancel_requested,
        }

    def _cloud_key_identity(provider: str, key_ref: str) -> str:
        if provider != "azure_key_vault":
            return key_ref
        try:
            parsed = urllib.parse.urlsplit(key_ref)
            parts = [part for part in parsed.path.split("/") if part]
            key_index = parts.index("keys")
            key_name = parts[key_index + 1]
        except (ValueError, IndexError):
            # Invalid refs cannot be safely considered equivalent; provider
            # validation rejects them before registration in normal operation.
            return key_ref
        # Azure delete operates on the key name and therefore affects every
        # version, while signing refs are deliberately version-pinned.
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}/keys/{key_name.lower()}"

    def _same_cloud_key(provider: str, left_ref: str, right_ref: str) -> bool:
        return _cloud_key_identity(provider, left_ref) == _cloud_key_identity(provider, right_ref)

    def _cloud_key_consumers(key) -> list[str]:
        consumers = [
            f"subca:{sub_ca.id}"
            for sub_ca in repository.list_sub_cas()
            if sub_ca.key_backend in (None, key.provider)
            if _same_cloud_key(key.provider, sub_ca.key_ref, key.key_ref)
        ]
        consumers.extend(
            f"pending_subca:{pending.id}"
            for pending in repository.list_pending_sub_cas()
            if pending.key_backend in (None, key.provider)
            if _same_cloud_key(key.provider, pending.key_ref, key.key_ref)
        )
        consumers.extend(
            f"service_certificate:{cert.id}"
            for cert in service_certs.list_certs()
            if (
                cert.status is ServiceCertStatus.PENDING
                or (
                    cert.status is ServiceCertStatus.ACTIVE
                    and (cert.not_after is None or cert.not_after > datetime.now(timezone.utc))
                )
            )
            if _same_cloud_key(key.provider, cert.key_ref, key.key_ref)
        )
        related_keys = [
            candidate
            for candidate in cloud_keys.list_all(provider=key.provider)
            if candidate.id != key.id
            and candidate.status is not CloudKeyStatus.DELETED
            and _same_cloud_key(key.provider, candidate.key_ref, key.key_ref)
        ]
        consumers.extend(f"cloud_key_version:{candidate.id}" for candidate in related_keys)
        for candidate in (key, *related_keys):
            if signing_jobs.has_active_for_key(candidate.id):
                consumers.append("active_signing_job")
                break
        return consumers

    def _hold_cloud_key_for_reactivation(key):
        """Cancel due cleanup before touching a recovered provider key."""

        ownership = (
            KeyOwnership.ATTACHED
            if key.ownership is CloudKeyOwnership.ATTACHED
            else KeyOwnership.MANAGED
        )
        registered = key_lifecycle_repository.find(
            backend=key.provider,
            key_ref=key.key_ref,
        )
        if registered is None:
            registered = key_lifecycle.register_key(
                backend=key.provider,
                key_ref=key.key_ref,
                purpose=key.purpose,
                ownership=ownership,
            )
        bindings = key_lifecycle_repository.list_bindings(registered.id)
        had_binding = any(
            binding.resource_type == "cloud_key" and binding.resource_id == key.id
            for binding in bindings
        )
        orphaned_at = registered.orphaned_at
        registered = key_lifecycle.bind_key(
            registered.id,
            resource_type="cloud_key",
            resource_id=key.id,
        )
        return registered, had_binding, orphaned_at

    def _release_failed_cloud_reactivation(
        registered,
        key,
        *,
        had_binding: bool,
        orphaned_at: datetime | None,
    ) -> None:
        if had_binding:
            return
        try:
            key_lifecycle.unbind_key(
                registered.id,
                resource_type="cloud_key",
                resource_id=key.id,
                now=orphaned_at,
            )
        except KeyLifecycleError:
            logger.exception(
                "Could not restore lifecycle retirement after cloud reactivation failure"
            )

    @app.get("/internal/cloud/keys")
    def list_cloud_keys(request: Request) -> list[dict[str, object]]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, Role.AUDITOR)
        return [_cloud_key_response(key) for key in cloud_keys.list_all()]

    @app.delete("/internal/cloud/keys/{key_id}")
    def delete_cloud_key(
        key_id: str,
        payload: CloudKeyAction,
        request: Request,
    ) -> dict[str, object]:
        active_user(request, Role.ADMIN, csrf=True)
        key = cloud_keys.get(key_id)
        action = "detach" if key.ownership is CloudKeyOwnership.ATTACHED else "delete"
        expected = "DETACH CLOUD KEY" if action == "detach" else "DELETE CLOUD KEY"
        _, _, reason = require_destructive_action(
            request,
            payload,
            expected_confirmation=expected,
            category=AuditCategory.HSM,
            action=f"cloud_key_{action}",
            object_type="cloud_key",
            object_id=key.id,
        )
        consumers = _cloud_key_consumers(key)
        if consumers:
            raise HTTPException(
                status_code=409,
                detail="Cloud key is still in use: " + ", ".join(consumers),
            )
        with audit_destructive_failures(
            request,
            reason=reason,
            category=AuditCategory.HSM,
            action=f"cloud_key_{action}",
            object_type="cloud_key",
            object_id=key.id,
        ):
            lifecycle_key = schedule_unbound_key_retirement(
                backend=key.provider,
                key_ref=key.key_ref,
                purpose=key.purpose,
                ownership=(
                    KeyOwnership.ATTACHED
                    if key.ownership is CloudKeyOwnership.ATTACHED
                    else KeyOwnership.MANAGED
                ),
            )
            updated = cloud_keys.set_status(key.id, CloudKeyStatus.PENDING_DELETION)
        audit.record(
            AuditCategory.HSM,
            f"cloud_key_{action}",
            actor=audit_actor(request),
            object_type="cloud_key",
            object_id=key.id,
            details={"reason": reason, "provider": key.provider},
        )
        body = _cloud_key_response(updated)
        body["action"] = "retirement_scheduled"
        body["key_status"] = lifecycle_key.status.value
        body["delete_after"] = (
            lifecycle_key.delete_after.isoformat() if lifecycle_key.delete_after else None
        )
        return body

    @app.post("/internal/cloud/keys/{key_id}/recover")
    def recover_cloud_key(
        key_id: str,
        payload: CloudKeyAction,
        request: Request,
    ) -> dict[str, object]:
        active_user(request, Role.ADMIN, csrf=True)
        key = cloud_keys.get(key_id)
        if key.ownership is CloudKeyOwnership.ATTACHED:
            raise HTTPException(
                status_code=409,
                detail="Attached keys are recovered by their provider owner",
            )
        _, _, reason = require_destructive_action(
            request,
            payload,
            expected_confirmation="RECOVER CLOUD KEY",
            category=AuditCategory.HSM,
            action="cloud_key_recover",
            object_type="cloud_key",
            object_id=key.id,
        )
        if hsm.active_backend_name() != key.provider:
            raise HTTPException(
                status_code=409,
                detail="The key provider is not the active signing backend",
            )
        try:
            lifecycle_key, had_binding, orphaned_at = _hold_cloud_key_for_reactivation(key)
        except KeyLifecycleError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        try:
            hsm.backend.recover_key(key.key_ref)
        except (CloudBackendError, RuntimeError, ValueError) as exc:
            _release_failed_cloud_reactivation(
                lifecycle_key,
                key,
                had_binding=had_binding,
                orphaned_at=orphaned_at,
            )
            raise HTTPException(status_code=400, detail=_hsm_error_detail(exc)) from exc
        # Keep the lifecycle binding even if this metadata write fails: the
        # provider key is already recovered and must not race a due cleanup.
        updated = cloud_keys.set_status(key.id, CloudKeyStatus.ACTIVE)
        audit.record(
            AuditCategory.HSM,
            "cloud_key_recover",
            actor=audit_actor(request),
            object_type="cloud_key",
            object_id=key.id,
            details={"reason": reason, "provider": key.provider},
        )
        return _cloud_key_response(updated)

    @app.post("/internal/cloud/keys/{key_id}/reattach")
    def reattach_cloud_key(
        key_id: str,
        payload: CloudKeyAction,
        request: Request,
    ) -> dict[str, object]:
        active_user(request, Role.ADMIN, csrf=True)
        key = cloud_keys.get(key_id)
        if key.ownership is not CloudKeyOwnership.ATTACHED:
            raise HTTPException(
                status_code=409,
                detail="Managed keys use the provider recovery operation",
            )
        _, _, reason = require_destructive_action(
            request,
            payload,
            expected_confirmation="REATTACH CLOUD KEY",
            category=AuditCategory.HSM,
            action="cloud_key_reattach",
            object_type="cloud_key",
            object_id=key.id,
        )
        if hsm.active_backend_name() != key.provider:
            raise HTTPException(
                status_code=409,
                detail="The key provider is not the active signing backend",
            )
        try:
            lifecycle_key, had_binding, orphaned_at = _hold_cloud_key_for_reactivation(key)
        except KeyLifecycleError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        try:
            canonical_ref = hsm.backend.attach_key(key.key_ref, expected_algorithm=key.algorithm)
            if canonical_ref != key.key_ref:
                raise ValueError("Provider returned a different versioned key reference")
        except (CloudBackendError, RuntimeError, ValueError) as exc:
            _release_failed_cloud_reactivation(
                lifecycle_key,
                key,
                had_binding=had_binding,
                orphaned_at=orphaned_at,
            )
            raise HTTPException(status_code=400, detail=_hsm_error_detail(exc)) from exc
        updated = cloud_keys.set_status(key.id, CloudKeyStatus.ACTIVE)
        audit.record(
            AuditCategory.HSM,
            "cloud_key_reattach",
            actor=audit_actor(request),
            object_type="cloud_key",
            object_id=key.id,
            details={"reason": reason, "provider": key.provider},
        )
        return _cloud_key_response(updated)

    @app.get("/internal/cloud/signing-jobs")
    def list_cloud_signing_jobs(
        request: Request,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, object]]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, Role.AUDITOR)
        try:
            parsed_status = SigningJobStatus(status) if status else None
            jobs = signing_jobs.list_all(status=parsed_status, limit=limit)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return [_signing_job_response(job) for job in jobs]

    @app.get("/internal/cloud/signing-jobs/{job_id}")
    def get_cloud_signing_job(job_id: str, request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, Role.AUDITOR)
        try:
            return _signing_job_response(signing_jobs.get(job_id))
        except CloudRepositoryError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/internal/cloud/signing-jobs/{job_id}/retry")
    def retry_cloud_signing_job(job_id: str, request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        try:
            job = signing_jobs.retry_failed(job_id)
        except CloudRepositoryError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        audit.record(
            AuditCategory.HSM,
            "cloud_signing_retry",
            actor=audit_actor(request),
            object_type="signing_job",
            object_id=job.id,
        )
        return _signing_job_response(job)

    @app.post("/internal/cloud/signing-jobs/{job_id}/cancel")
    def cancel_cloud_signing_job(job_id: str, request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        try:
            job = signing_jobs.cancel(job_id)
        except CloudRepositoryError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if job.status is SigningJobStatus.CANCELED:
            retire_abandoned_cloud_workflow(job)
        audit.record(
            AuditCategory.HSM,
            "cloud_signing_cancel",
            actor=audit_actor(request),
            object_type="signing_job",
            object_id=job.id,
        )
        return _signing_job_response(job)

    @app.get("/internal/cloud/signing-status")
    def cloud_signing_status(request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN, Role.SUPERUSER, Role.AUDITOR)
        now = datetime.now(timezone.utc)
        counts = signing_jobs.status_counts()
        alerts = signing_jobs.list_alerting(now=now, alert_after=timedelta(minutes=15))
        return {
            "backend": hsm.active_backend_name(),
            "counts": {status.value: counts[status] for status in SigningJobStatus},
            "alert_after_minutes": 15,
            "retry_window_hours": 24,
            "alerts": [_signing_job_response(job) for job in alerts],
        }

    def operator_unlock_allowed() -> bool:
        """Whether Certificate Operators may unlock the token themselves.

        Default on: issuing is the operator's job, so the operator whose
        approval mints the certificate is asked for the PIN and unlocks the
        token to sign with it. An administrator can turn this off to require
        separation of duties, in which case operators are told to ask one.
        """

        stored = repository.get_setting(HSM_OPERATOR_UNLOCK_SETTING)
        if stored is None:
            return True
        return stored.strip() == "true"

    def hsm_unlock_roles() -> tuple[Role, ...]:
        return (Role.ADMIN, Role.SUPERUSER) if operator_unlock_allowed() else (Role.ADMIN,)

    @app.get("/internal/hsm/policy")
    def hsm_policy(request: Request) -> dict[str, bool]:
        active_user(request, Role.ADMIN)
        return {"operator_unlock_allowed": operator_unlock_allowed()}

    @app.put("/internal/hsm/policy")
    def update_hsm_policy(payload: HSMPolicyUpdate, request: Request) -> dict[str, bool]:
        active_user(request, Role.ADMIN, csrf=True)
        repository.set_setting(
            HSM_OPERATOR_UNLOCK_SETTING,
            "true" if payload.operator_unlock_allowed else "false",
        )
        audit.record(
            AuditCategory.SYSTEM,
            "hsm_operator_unlock_policy",
            actor=audit_actor(request),
            object_type="setting",
            object_id=HSM_OPERATOR_UNLOCK_SETTING,
            details={"operator_unlock_allowed": payload.operator_unlock_allowed},
        )
        return {"operator_unlock_allowed": operator_unlock_allowed()}

    @app.get("/internal/hsm/status")
    def hsm_status(request: Request) -> dict[str, object]:
        # Operators need the lock state to know whether issuance can proceed and
        # whether to offer an unlock; token internals stay administrator-only.
        session, user = active_user(request, Role.ADMIN, Role.SUPERUSER)
        backend_name = hsm.active_backend_name()
        may_unlock = user.role in hsm_unlock_roles()
        body: dict[str, object] = {
            "backend": backend_name,
            "pin_required": backend_name == "pkcs11",
            # Preserve the long-standing boolean response contract for local
            # clients; pin_required tells new UIs whether the value is relevant.
            "pin_unlocked": pin_vault.is_unlocked(session.id),
            "any_session_unlocked": pin_vault.active_pin() is not None,
            "may_unlock": may_unlock,
        }
        if user.role is not Role.ADMIN:
            return body
        if backend_name == "pkcs11":
            try:
                body["token"] = hsm.backend.status()
            except (ScHsmError, RuntimeError) as exc:
                body["token_error"] = _hsm_error_detail(exc)
        elif backend_name in cloud_backend_names:
            try:
                body["provider"] = hsm.backend.status()
            except (CloudBackendError, RuntimeError) as exc:
                body["provider_error"] = _hsm_error_detail(exc)
            now = datetime.now(timezone.utc)
            counts = signing_jobs.status_counts()
            alerts = signing_jobs.list_alerting(now=now, alert_after=timedelta(minutes=15))
            body["signing_queue"] = {
                "queued": counts[SigningJobStatus.QUEUED],
                "running": counts[SigningJobStatus.RUNNING],
                "failed": counts[SigningJobStatus.FAILED],
                "alerts": len(alerts),
            }
        return body

    @app.post("/internal/hsm/pin/unlock")
    def hsm_unlock_pin(payload: HSMPinUnlock, request: Request) -> dict[str, bool]:
        session, _ = active_user(request, *hsm_unlock_roles(), csrf=True)
        verifier = getattr(hsm.backend, "verify_pin", None)
        if verifier is not None:
            try:
                verifier(payload.pin)
            except RuntimeError as exc:
                pin_vault.lock(session.id)
                raise HTTPException(
                    status_code=400, detail=_hsm_error_detail(exc, "HSM PIN unlock failed")
                ) from exc
        pin_vault.unlock(
            session.id,
            payload.pin,
            expires_at=session.expires_at,
        )
        active_sub_ca = repository.get_active_sub_ca()
        if active_sub_ca is not None and hsm.active_backend_name() == "pkcs11":
            try:
                issuer_certificate = x509.load_pem_x509_certificate(
                    active_sub_ca.certificate_pem.encode()
                )
                if not public_keys_match(
                    issuer_certificate.public_key(),
                    hsm.public_key(active_sub_ca.key_ref),
                ):
                    raise ValueError("active issuer key mismatch")
            except Exception as exc:  # noqa: BLE001 - fail closed at the HSM boundary
                pin_vault.lock(session.id)
                raise HTTPException(
                    status_code=409,
                    detail=("The unlocked token key does not match the active Sub-CA certificate"),
                ) from exc
        return {"pin_unlocked": True}

    @app.post("/internal/hsm/pin/lock")
    def hsm_lock_pin(request: Request) -> dict[str, bool]:
        # Locking your own session is always permitted: it only drops a PIN you
        # supplied, and must never be gated behind the unlock policy.
        session, _ = active_user(request, Role.ADMIN, Role.SUPERUSER, csrf=True)
        pin_vault.lock(session.id)
        return {"pin_unlocked": False}

    @app.get("/internal/hsm/keys")
    def hsm_list_keys(request: Request) -> list[dict[str, object]]:
        active_user(request, Role.ADMIN)
        backend_name = hsm.active_backend_name()
        if backend_name in cloud_backend_names:
            raise HTTPException(
                status_code=409,
                detail="Use /internal/cloud/keys for cloud key lifecycle operations",
            )
        if backend_name == "software":
            raise HTTPException(
                status_code=400,
                detail="Active backend does not expose key listing",
            )
        try:
            items = hsm.backend.list_keys()
            for item in items:
                registered = key_lifecycle_repository.find(
                    backend=backend_name,
                    key_ref=str(item.get("label") or ""),
                )
                item["key_registry_id"] = registered.id if registered else None
                item["ownership"] = registered.ownership.value if registered else None
                item["public_key_sha256"] = registered.public_key_sha256 if registered else None
            return items
        except AttributeError as exc:
            raise HTTPException(
                status_code=400, detail="Active backend does not expose key listing"
            ) from exc
        except RuntimeError as exc:
            raise HTTPException(
                status_code=400, detail=_hsm_error_detail(exc, "HSM key listing failed")
            ) from exc

    @app.post("/internal/hsm/keys", status_code=201)
    def hsm_create_key(payload: HSMKeyCreate, request: Request) -> dict[str, str]:
        active_user(request, Role.ADMIN, csrf=True)
        if hsm.active_backend_name() in cloud_backend_names:
            raise HTTPException(
                status_code=409,
                detail="Cloud keys must be created through a tracked certificate workflow",
            )
        backend = hsm.active_backend_name()
        if key_lifecycle_repository.find(backend=backend, key_ref=payload.label):
            raise HTTPException(
                status_code=409,
                detail="This HSM key reference is already present in the lifecycle registry",
            )
        try:
            label = hsm.generate_key(payload.label, payload.algorithm)
            registered = key_lifecycle.register_key(
                backend=backend,
                key_ref=label,
                purpose="manual_hsm_key",
                ownership=KeyOwnership.MANAGED,
            )
        except (ValueError, RuntimeError) as exc:
            raise HTTPException(status_code=400, detail=_hsm_error_detail(exc)) from exc
        return {"label": label, "key_registry_id": registered.id}

    @app.post("/internal/hsm/keys/wrapped-backup")
    def hsm_wrapped_key_backup(
        payload: HSMKeyBackup,
        request: Request,
    ) -> Response:
        session, _, reason = require_destructive_action(
            request,
            payload,
            expected_confirmation="BACKUP HSM KEY",
            category=AuditCategory.HSM,
            action="hsm_key_wrapped_backup",
            object_type="hsm_key",
            object_id=payload.key_reference,
        )
        if hsm.active_backend_name() != "pkcs11":
            raise HTTPException(
                status_code=409,
                detail="Wrapped-key backup is available only with the PKCS#11 backend",
            )
        user_pin = pin_vault.pin_for(session.id)
        if not user_pin:
            raise HTTPException(
                status_code=400,
                detail="Unlock the HSM PIN before creating a wrapped-key backup",
            )
        with audit_destructive_failures(
            request,
            reason=reason,
            category=AuditCategory.HSM,
            action="hsm_key_wrapped_backup",
            object_type="hsm_key",
            object_id=payload.key_reference,
        ):
            try:
                backup = hsm_recovery_service().create_wrapped_backup(
                    payload.key_reference,
                    user_pin=user_pin,
                )
            except KeyRecoveryConflictError as exc:
                raise HTTPException(
                    status_code=409,
                    detail=_hsm_error_detail(exc, "HSM wrapped-key backup blocked"),
                ) from exc
            except (ScHsmError, ValueError) as exc:
                raise HTTPException(
                    status_code=400,
                    detail=_hsm_error_detail(exc, "HSM wrapped-key backup failed"),
                ) from exc
        audit.record(
            AuditCategory.HSM,
            "hsm_key_wrapped_backup",
            actor=audit_actor(request),
            object_type="hsm_key",
            object_id=payload.key_reference,
            details={
                "reason": reason,
                "size": len(backup.wrapped_key),
                "persisted": False,
            },
        )
        safe_reference = re.sub(r"[^A-Za-z0-9_-]", "_", payload.key_reference)
        return Response(
            content=backup.wrapped_key,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": (f'attachment; filename="wrapped-key-{safe_reference}.bin"'),
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @app.post("/internal/hsm/token-backup/export-proposals", status_code=201)
    def propose_hsm_raw_backup_export(
        payload: HSMRawBackupExport,
        request: Request,
    ) -> dict[str, object]:
        _, actor, reason = require_destructive_action(
            request,
            payload,
            expected_confirmation="REQUEST EXPORT ENTIRE HSM",
            category=AuditCategory.HSM,
            action="hsm_raw_backup_export_proposal",
            object_type="hsm_token",
            object_id="entire-token",
        )
        if hsm.active_backend_name() != "pkcs11":
            raise HTTPException(
                status_code=409,
                detail="Raw HSM backups are available only with the PKCS#11 backend",
            )
        try:
            proposal = auth_service.create_hsm_backup_proposal(actor, reason=reason)
        except AuthError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        audit.record(
            AuditCategory.HSM,
            "hsm_raw_backup_export_proposed",
            actor=audit_actor(request),
            object_type="admin_change_proposal",
            object_id=proposal.id,
            details={"reason": reason, "status": proposal.status.value},
        )
        return _proposal_response(proposal, auth_repository)

    @app.post("/internal/admin/hsm/token-backup/proposals/{proposal_id}/approve")
    def approve_hsm_raw_backup_export(
        proposal_id: str,
        payload: HSMRawBackupExport,
        request: Request,
    ) -> Response:
        session, actor, reason = require_destructive_action(
            request,
            payload,
            expected_confirmation="APPROVE EXPORT ENTIRE HSM",
            category=AuditCategory.HSM,
            action="hsm_raw_backup_export_approval",
            object_type="admin_change_proposal",
            object_id=proposal_id,
        )
        try:
            pending = auth_repository.get_proposal(proposal_id)
        except RepositoryError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        if pending.change_type is not AdminChangeType.HSM_RAW_BACKUP_EXPORT:
            raise HTTPException(status_code=400, detail="Proposal is not an HSM backup export")
        if hsm.active_backend_name() != "pkcs11":
            raise HTTPException(
                status_code=409,
                detail="Raw HSM backups are available only with the PKCS#11 backend",
            )
        user_pin = pin_vault.pin_for(session.id)
        if not user_pin:
            raise HTTPException(
                status_code=400,
                detail="Unlock the HSM PIN in Admin → HSM & Keys before approving raw HSM backups",
            )
        try:
            approved = auth_service.approve_proposal(proposal_id, actor)
        except (AuthError, RepositoryError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if approved.status is not AdminChangeStatus.APPROVED:
            raise HTTPException(
                status_code=409,
                detail="HSM backup export approval is still pending",
            )
        proposal_payload = decode_payload(pending.payload_json)
        audit.record(
            AuditCategory.HSM,
            "hsm_raw_backup_export_approved",
            actor=audit_actor(request),
            object_type="admin_change_proposal",
            object_id=proposal_id,
            details={
                "reason": reason,
                "proposal_reason": proposal_payload.get("reason"),
                "proposer_id": pending.proposer_id,
            },
        )
        with audit_destructive_failures(
            request,
            reason=reason,
            category=AuditCategory.HSM,
            action="hsm_raw_backup_export",
            object_type="hsm_token",
            object_id="entire-token",
        ):
            try:
                backup = hsm_recovery_service().create_raw_backup_archive(user_pin=user_pin)
            except KeyRecoveryConflictError as exc:
                raise HTTPException(
                    status_code=409,
                    detail=_hsm_error_detail(exc, "Raw HSM backup export blocked"),
                ) from exc
            except (KeyRecoveryError, ScHsmError, ValueError, RuntimeError) as exc:
                raise HTTPException(
                    status_code=400,
                    detail=_hsm_error_detail(exc, "Raw HSM backup export failed"),
                ) from exc
        audit.record(
            AuditCategory.HSM,
            "hsm_raw_backup_export",
            actor=audit_actor(request),
            object_type="hsm_token",
            object_id="entire-token",
            details={
                "reason": reason,
                "size": len(backup),
                "persisted": False,
                "proposal_id": proposal_id,
            },
        )
        return Response(
            content=backup,
            media_type="application/zip",
            headers={
                "Content-Disposition": 'attachment; filename="hsm-raw-key-backups.zip"',
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @app.post("/internal/hsm/token-backup/export")
    def hsm_raw_backup_export(
        payload: HSMRawBackupExport,
        request: Request,
    ) -> None:
        require_destructive_action(
            request,
            payload,
            expected_confirmation="EXPORT ENTIRE HSM",
            category=AuditCategory.HSM,
            action="hsm_raw_backup_export_direct_denied",
            object_type="hsm_token",
            object_id="entire-token",
        )
        raise HTTPException(
            status_code=409,
            detail="Native HSM backup export requires approval by a different administrator",
        )

    @app.delete("/internal/hsm/keys/{label}")
    def hsm_delete_key(
        label: str,
        payload: DestructiveActionConfirmation,
        request: Request,
    ) -> dict[str, object]:
        active_user(request, Role.ADMIN, csrf=True)
        if hsm.active_backend_name() in cloud_backend_names:
            raise HTTPException(
                status_code=409,
                detail="Use /internal/cloud/keys for guarded cloud key deletion",
            )
        _, _, reason = require_destructive_action(
            request,
            payload,
            expected_confirmation=f"DELETE KEY {label}",
            category=AuditCategory.HSM,
            action="hsm_key_delete",
            object_type="hsm_key",
            object_id=label,
        )
        with audit_destructive_failures(
            request,
            reason=reason,
            category=AuditCategory.HSM,
            action="hsm_key_delete",
            object_type="hsm_key",
            object_id=label,
        ):
            try:
                backend = hsm.active_backend_name()
                registered = key_lifecycle_repository.find(
                    backend=backend,
                    key_ref=label,
                )
                if registered is None:
                    raise HTTPException(
                        status_code=409,
                        detail=(
                            "Unmanaged HSM keys cannot be adopted by a delete request; "
                            "register the key through an owning workflow first"
                        ),
                    )
                elif registered.ownership is not KeyOwnership.MANAGED:
                    raise HTTPException(
                        status_code=409,
                        detail=(
                            "Attached keys cannot be scheduled for provider deletion; "
                            "remove their owning resource to schedule a detach"
                        ),
                    )
                bindings = key_lifecycle_repository.list_bindings(registered.id)
                if bindings:
                    raise HTTPException(
                        status_code=409,
                        detail="HSM key is still bound to an active resource",
                    )
                if registered.status is KeyStatus.ACTIVE:
                    registered = key_lifecycle.orphan_key(registered.id)
                elif registered.status not in {KeyStatus.ORPHANED, KeyStatus.ERROR}:
                    raise HTTPException(
                        status_code=409,
                        detail=f"HSM key is already {registered.status.value}",
                    )
            except HTTPException:
                raise
            except (KeyLifecycleError, ValueError, RuntimeError) as exc:
                raise HTTPException(status_code=400, detail=_hsm_error_detail(exc)) from exc
        scheduled = (
            registered.status in {KeyStatus.ORPHANED, KeyStatus.ERROR}
            and registered.delete_after is not None
        )
        audit.record(
            AuditCategory.HSM,
            "hsm_key_delete",
            actor=audit_actor(request),
            object_type="hsm_key",
            object_id=label,
            details={
                "reason": reason,
                "destroyed": 0,
                "scheduled": scheduled,
                "status": registered.status.value,
                "delete_after": (
                    registered.delete_after.isoformat() if registered.delete_after else None
                ),
            },
        )
        return {
            "destroyed": 0,
            "scheduled": scheduled,
            "key_registry_id": registered.id,
            "status": registered.status.value,
            "delete_after": (
                registered.delete_after.isoformat() if registered.delete_after else None
            ),
        }

    @app.post("/internal/hsm/test")
    def hsm_self_test(request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN, csrf=True)
        try:
            return hsm.backend.self_test()
        except AttributeError as exc:
            raise HTTPException(
                status_code=400, detail="Active backend does not support self-test"
            ) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=400, detail=_hsm_error_detail(exc)) from exc

    @app.get("/internal/hsm/dkek/status")
    def hsm_dkek_status(request: Request) -> dict[str, object]:
        active_user(request, Role.ADMIN)
        try:
            status = hsm_ceremony_service().dkek_status()
        except ScHsmError as exc:
            raise HTTPException(status_code=400, detail=_hsm_error_detail(exc)) from exc
        return {
            "shares_total": status.shares_total,
            "shares_imported": status.shares_imported,
            "complete": status.complete,
            "kcv": status.kcv,
        }

    @app.get("/internal/hsm/dkek/shares")
    def hsm_list_dkek_shares(request: Request) -> list[dict[str, object]]:
        active_user(request, Role.ADMIN)
        share_dir = settings.pkcs11_dkek_share_dir
        if not share_dir.exists():
            return []
        return [
            {"filename": path.name, "size": path.stat().st_size}
            for path in sorted(share_dir.glob("*.pbe"))
        ]

    @app.get("/internal/hsm/dkek/shares/{filename}/download")
    def hsm_download_dkek_share(filename: str, request: Request) -> FileResponse:
        require_recent_sensitive_action(
            request,
            category=AuditCategory.HSM,
            action="dkek_share_download",
            object_type="dkek_share",
            object_id=filename,
        )
        share_path = _dkek_share_path(filename)
        if not share_path.exists() or not share_path.is_file():
            raise HTTPException(status_code=404, detail="DKEK share not found")
        audit.record(
            AuditCategory.HSM,
            "dkek_share_download",
            actor=audit_actor(request),
            object_type="dkek_share",
            object_id=filename,
            details={"size": share_path.stat().st_size, "persisted": True},
        )
        return FileResponse(
            share_path,
            media_type="application/octet-stream",
            filename=share_path.name,
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @app.post("/internal/hsm/dkek/shares/{filename}/import", status_code=201)
    def hsm_import_dkek_share(
        filename: str, payload: DKEKShareImport, request: Request
    ) -> dict[str, object]:
        session, _, reason = require_destructive_action(
            request,
            payload,
            expected_confirmation=f"IMPORT DKEK {filename}",
            category=AuditCategory.HSM,
            action="dkek_share_import",
            object_type="dkek_share",
            object_id=filename,
        )
        with audit_destructive_failures(
            request,
            reason=reason,
            category=AuditCategory.HSM,
            action="dkek_share_import",
            object_type="dkek_share",
            object_id=filename,
        ):
            user_pin = pin_vault.pin_for(session.id)
            if not user_pin:
                raise HTTPException(
                    status_code=400,
                    detail="Unlock the HSM PIN before importing a share",
                )
            share_path = _dkek_share_path(filename)
            if not share_path.exists():
                raise HTTPException(status_code=404, detail="DKEK share not found")
            try:
                status = hsm_ceremony_service().import_dkek_shares(
                    [(share_path.read_bytes(), payload.password)],
                    user_pin=user_pin,
                    require_complete=False,
                )
            except (OSError, ScHsmError, ValueError) as exc:
                raise HTTPException(status_code=400, detail=_hsm_error_detail(exc)) from exc
        audit.record(
            AuditCategory.HSM,
            "dkek_share_import",
            actor=audit_actor(request),
            object_type="dkek_share",
            object_id=filename,
            details={
                "reason": reason,
                "shares_total": status.shares_total,
                "shares_imported": status.shares_imported,
                "complete": status.complete,
            },
        )
        return {
            "shares_total": status.shares_total,
            "shares_imported": status.shares_imported,
            "complete": status.complete,
            "kcv": status.kcv,
        }

    @app.delete("/internal/hsm/dkek/shares/{filename}")
    def hsm_delete_dkek_share(
        filename: str,
        payload: DestructiveActionConfirmation,
        request: Request,
    ) -> dict[str, str]:
        _, _, reason = require_destructive_action(
            request,
            payload,
            expected_confirmation=f"DELETE DKEK {filename}",
            category=AuditCategory.HSM,
            action="dkek_share_delete",
            object_type="dkek_share",
            object_id=filename,
        )
        with audit_destructive_failures(
            request,
            reason=reason,
            category=AuditCategory.HSM,
            action="dkek_share_delete",
            object_type="dkek_share",
            object_id=filename,
        ):
            share_path = _dkek_share_path(filename)
            if not share_path.exists():
                raise HTTPException(status_code=404, detail="DKEK share not found")
            share_path.unlink()
        audit.record(
            AuditCategory.HSM,
            "dkek_share_delete",
            actor=audit_actor(request),
            object_type="dkek_share",
            object_id=filename,
            details={"reason": reason},
        )
        return {"filename": share_path.name}

    return app


def _load_or_create_lab_chain(hsm, common_name: str, *, allow_create: bool = True):
    try:
        hsm.public_key("lab-root")
        hsm.public_key("lab-issuer")
    except KeyError:
        if not allow_create:
            raise ValueError("The configured Lab installation is missing its existing keys") from None
        return create_lab_ca_chain(hsm, common_name)

    # Lab certificates are intentionally regenerated around the already-persisted keys.
    # They are only a local fallback issuer; imported real sub-CAs always take precedence.
    return create_lab_ca_chain_from_existing_keys(hsm, common_name)


def _apply_pending_root(repository: PKIRepository) -> None:
    """Import a wizard-captured root cert on first boot (idempotent).

    The standalone setup wizard cannot write to the live DB, so it leaves the
    captured root at <state_dir>/setup/root-ca.pem; the service imports it once,
    only when no root is configured yet.
    """
    from myownca.setup.state import resolve_state_dir

    pending = resolve_state_dir() / "setup" / "root-ca.pem"
    if not pending.exists():
        return
    if repository.get_root_certificate_pem() is not None:
        return
    repository.set_root_certificate_pem(pending.read_text())


def _seed_service_urls(settings: Settings, repository: PKIRepository) -> None:
    """Seed the editable URL settings from install-time config on first boot.

    Idempotent: only writes a key that has no row yet (get_setting is None), so a
    restart never clobbers an admin's later edit — including an explicit clear to "".
    """
    pairs = (
        (settings.admin_base_url, "admin_base_url"),
        (settings.superuser_base_url, "superuser_base_url"),
        (settings.frontend_base_url, "portal_base_url"),
        (settings.crl_url, "crl_base_url"),
        (settings.aia_url, "aia_base_url"),
        (settings.ocsp_url, "ocsp_url"),
    )
    for value, key in pairs:
        if not value:
            continue
        if repository.get_setting(key) is not None:
            continue
        repository.set_setting(key, value.rstrip("/"))


#: The value config.py substitutes when MYOWNCA_AUTH_ENCRYPTION_SECRET is unset.
PLACEHOLDER_ENCRYPTION_SECRET = "change-me-for-local-testing"


def _require_configured_encryption_secret(encryption_secret: str, lab_mode: bool) -> None:
    """Refuse to serve a production install on the placeholder secret.

    Every secret at rest hangs off this value: the Fernet keys for TOTP seeds,
    notification credentials and ACME account keys, plus the audit-chain and
    recovery-code peppers. Booting on the placeholder derives all of them from a
    published constant, so the encryption protects nothing and any re-encryption
    would run against unreadable data. Lab installs are exempt so local work and
    the test suite are unaffected.
    """
    if lab_mode or encryption_secret != PLACEHOLDER_ENCRYPTION_SECRET:
        return
    raise RuntimeError(
        "MYOWNCA_AUTH_ENCRYPTION_SECRET is still the built-in placeholder. Every "
        "secret stored at rest would be encrypted with a published constant. Set a "
        "unique high-entropy value (the setup wizard generates one), or set "
        "MYOWNCA_LAB_MODE=true if this really is a throwaway lab install."
    )


def _reencrypt_stored_secrets(database, encryption_secret: str) -> None:
    """Finish the F-1 migration in the background of a normal boot.

    Deliberately never fatal. The service ciphers read legacy ciphertext through
    their fallback, so an install works whether or not this succeeds — whereas a
    sweep that could abort startup would lock the operator out of the very portal
    needed to fix it. Problems are logged and left for the CLI.
    """
    from myownca.storage.reencrypt import reencrypt_secrets

    try:
        result = reencrypt_secrets(database, encryption_secret)
    except Exception as exc:  # pragma: no cover - defensive; boot must not fail
        logger.warning("Secret re-encryption sweep skipped: %s", exc)
        return
    if result.converted:
        logger.info(
            "Re-encrypted %s stored secret(s) under domain-separated keys: %s",
            result.converted,
            result.per_column,
        )
    if result.failed:
        logger.warning(
            "%s stored secret(s) could not be re-encrypted: %s",
            result.failed,
            "; ".join(result.failures),
        )


def _apply_pending_admins(auth_service: AuthService) -> None:
    """Bootstrap the wizard's captured admins on first boot (idempotent).

    The standalone wizard cannot write to the live DB; it leaves one or two admins
    (with temporary passwords) at <state_dir>/secrets/pending-admins.json. The
    service creates them once, only when the users table is empty, then deletes
    the artifact so the temporary passwords do not linger.
    """
    import json

    from myownca.setup.state import resolve_state_dir

    pending = resolve_state_dir() / "secrets" / "pending-admins.json"
    if not pending.exists():
        return
    if auth_service.repository.has_any_users():
        # Already provisioned; drop the temp-password artifact so it can't linger.
        pending.unlink(missing_ok=True)
        return
    try:
        admins = json.loads(pending.read_text())
        if not isinstance(admins, list) or len(admins) not in {1, 2}:
            raise ValueError("Expected one or two bootstrap administrators")
        second = None
        if len(admins) > 1:
            second = (admins[1]["id"], admins[1]["email"], admins[1]["password"])
        auth_service.bootstrap_initial_admins(
            (admins[0]["id"], admins[0]["email"], admins[0]["password"]),
            second,
        )
    except (ValueError, KeyError, IndexError, TypeError, AuthError) as exc:
        # A corrupt or hand-edited artifact must not brick startup. Leave it in
        # place (so a fix + restart can recover) and boot without admins rather
        # than crash-looping. Transient DB errors are deliberately NOT caught
        # here — they propagate so the next boot retries.
        logger.error("Ignoring unusable pending-admins artifact %s: %s", pending, exc)
        return
    pending.unlink(missing_ok=True)


app = create_app()


def _uvicorn_options(settings: Settings) -> dict[str, object]:
    options: dict[str, object] = {
        "host": settings.bind_host,
        "port": settings.bind_port,
        "reload": False,
    }
    if settings.tls_cert or settings.tls_key:
        # Fail loudly rather than silently serving plain HTTP when an operator
        # set only one half of the TLS pair (a dangerous downgrade for a CA).
        if not (settings.tls_cert and settings.tls_key):
            raise ValueError("MYOWNCA_TLS_CERT and MYOWNCA_TLS_KEY must both be set to serve HTTPS")
        options["ssl_certfile"] = settings.tls_cert
        options["ssl_keyfile"] = settings.tls_key
    return options


def run() -> None:
    settings = Settings.from_env()
    # Gate the serving entry point rather than create_app: this covers both
    # deployment paths (the `myownca` launcher delegates here, as does
    # `myownca-online`) while leaving the app factory usable by tests and
    # embedders that legitimately run without a configured secret.
    _require_configured_encryption_secret(settings.auth_encryption_secret, settings.lab_mode)
    uvicorn.run("myownca.online.app:app", **_uvicorn_options(settings))


def _auth_response(
    session,
    user: User,
    auth_service: AuthService,
) -> dict[str, object]:
    method = "totp" if auth_service.totp_required(user.role) else "password"
    return {
        "user_id": user.id,
        "email": user.email,
        "role": user.role.value,
        "app_version": __version__,
        "stage": session.stage.value,
        "csrf_token": session.csrf_token,
        **auth_service.totp_status(user),
        "sensitive_auth": sensitive_auth_status(session, method=method),
        **recent_mfa_status(session),
    }


def _template_response(template: CertificateTemplate) -> dict[str, object]:
    return {
        "id": template.id,
        "name": template.name,
        "profile": template.profile.value,
        "validity_days": template.validity_days,
        "first_issuance_approvals": template.first_issuance_approvals,
        "renewal_approvals": template.renewal_approvals,
        "key_usages": [usage.value for usage in template.key_usages],
        "extended_key_usages": [usage.value for usage in template.extended_key_usages],
        "key_usage_critical": template.key_usage_critical,
        "extended_key_usage_critical": template.extended_key_usage_critical,
        "allowed_key_algorithms": list(template.allowed_key_algorithms),
    }


def _user_response(user: User, auth_service: AuthService) -> dict[str, object]:
    return {
        "id": user.id,
        "email": user.email,
        "role": user.role.value,
        "is_active": user.is_active,
        **auth_service.totp_status(user),
    }


def _request_response(
    certificate_request: CertificateRequest,
    repository: PKIRepository,
    *,
    current_user: User,
    include_csr: bool = False,
) -> dict[str, object]:
    template = repository.get_template(certificate_request.template_id)
    approvals = repository.list_approvals(certificate_request.id)
    issued_certificate = repository.get_issued_certificate_by_request_id(certificate_request.id)
    requester = _repository_user_or_none(repository, certificate_request.requested_by_user_id)
    needed_approvals = required_approvals(certificate_request, template)
    body: dict[str, object] = {
        "id": certificate_request.id,
        "template_id": template.id,
        "template_name": template.name,
        "profile": template.profile.value,
        "kind": certificate_request.kind.value,
        "status": certificate_request.status.value,
        "created_at": certificate_request.created_at.isoformat(),
        "requested_by_user_id": certificate_request.requested_by_user_id,
        "requester_email": requester.email if requester else None,
        "renewal_of_serial_number": certificate_request.renewal_of_serial_number,
        "renewal_of_certificate_id": certificate_request.renewal_of_certificate_id,
        "required_approvals": needed_approvals,
        "approval_count": len(approvals),
        "approved_by_current_user": any(
            approval.superuser_id == current_user.id for approval in approvals
        ),
        "approvals": [
            {
                "superuser_id": approval.superuser_id,
                "superuser_email": _repository_user_or_none(repository, approval.superuser_id).email
                if _repository_user_or_none(repository, approval.superuser_id)
                else None,
                "approved_at": approval.approved_at.isoformat(),
            }
            for approval in approvals
        ],
        "issued_serial_number": issued_certificate.serial_number if issued_certificate else None,
        "holder": _holder_response(
            repository,
            certificate_request.holder_person_id,
            certificate_request.holder_device_id,
        ),
        "server_key_held": repository.has_request_private_key(certificate_request.id),
        "via_link_auth": certificate_request.via_link_auth,
        "source": certificate_request.source.value,
    }
    if include_csr:
        body["csr_pem"] = certificate_request.csr_pem
    return body


def _certificate_response(
    certificate: IssuedCertificate,
    repository: PKIRepository,
    *,
    include_pem: bool,
) -> dict[str, object]:
    template = repository.get_template(certificate.template_id)
    certificate_request = repository.get_request(certificate.request_id)
    requester = _repository_user_or_none(repository, certificate_request.requested_by_user_id)
    body: dict[str, object] = {
        "certificate_id": certificate.certificate_id or certificate.serial_number,
        "serial_number": certificate.serial_number,
        "request_id": certificate.request_id,
        "template_id": certificate.template_id,
        "template_name": template.name,
        "profile": template.profile.value,
        "subject": certificate.subject,
        "issued_at": certificate.issued_at.isoformat(),
        "expires_at": certificate.expires_at.isoformat(),
        "status": certificate.status.value,
        "source": certificate.source.value,
        "issuer_id": certificate.issuer_id,
        "archived_at": (certificate.archived_at.isoformat() if certificate.archived_at else None),
        "requested_by_user_id": certificate_request.requested_by_user_id,
        "requester_email": requester.email if requester else None,
        "holder": _holder_response(
            repository,
            certificate.holder_person_id,
            certificate.holder_device_id,
        ),
        "server_key_held": repository.has_request_private_key(certificate.request_id),
    }
    if include_pem:
        body["certificate_pem"] = certificate.certificate_pem
        body["chain_pem"] = certificate.chain_pem
    return body


def _signature_verifies(certificate: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        verify_certificate_signature(certificate, issuer)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


HSM_OPERATOR_UNLOCK_SETTING = "hsm_operator_unlock_allowed"

HSM_LOCKED_MESSAGE = (
    "The HSM token is locked, so the certificate was not issued. Your approval "
    "is preserved. Unlock the HSM PIN, then re-assign the holder on this "
    "request to complete issuance."
)


def _auto_issue_error(code: str, message: str) -> dict[str, str]:
    return {"code": code, "message": message}


def _auto_issue_error_from_exception(exc: Exception) -> dict[str, str]:
    message = str(exc)
    if isinstance(exc, IssuerValidityError):
        return _auto_issue_error(exc.code, message)
    if isinstance(exc, ApprovalPolicyError):
        return _auto_issue_error("insufficient_approvals", message)
    if isinstance(exc, RepositoryError):
        if message == "Only pending requests may be issued":
            return _auto_issue_error("request_not_pending", message)
        if "holder" in message.lower():
            return _auto_issue_error("no_holder", message)
        if message.startswith("Issuer is not allowed to issue "):
            return _auto_issue_error("issuer_profile_constraint_mismatch", message)
        if (
            "renewal" in message.lower()
            or "owned by another user" in message
            or "active certificates" in message
        ):
            return _auto_issue_error("invalid_renewal_anchor", message)
        return _auto_issue_error("repository_error", message)
    if isinstance(exc, ValueError):
        if "renewal" in message.lower():
            return _auto_issue_error("invalid_renewal_anchor", message)
        return _auto_issue_error("invalid_csr_template", message)
    return _auto_issue_error("auto_issue_failed", message)


def _proposal_response(
    proposal,
    auth_repository: AuthRepository | None = None,
) -> dict[str, object]:
    is_governance = proposal.change_type is AdminChangeType.GOVERNANCE_MODE_DOWNGRADE
    is_totp_policy = proposal.change_type is AdminChangeType.ROLE_TOTP_POLICY_CHANGE
    is_policy = is_governance or is_totp_policy
    target = None if is_policy else _auth_user_or_none(auth_repository, proposal.target_user_id)
    proposer = _auth_user_or_none(auth_repository, proposal.proposer_id)
    payload = decode_payload(proposal.payload_json)
    approvals = (
        auth_repository.list_proposal_approvals(proposal.id) if auth_repository is not None else []
    )
    required_approvals = int(payload.get("required_approvals", 1))
    body: dict[str, object] = {
        "id": proposal.id,
        "change_type": proposal.change_type.value,
        "proposer_id": proposal.proposer_id,
        "proposer_email": proposer.email if proposer else None,
        "target_user_id": None if is_policy else proposal.target_user_id,
        "target_email": target.email if target else None,
        "target_role": target.role.value if target else None,
        "status": proposal.status.value,
        "created_at": proposal.created_at.isoformat(),
        "expires_at": proposal.expires_at.isoformat(),
        "resolved_at": proposal.resolved_at.isoformat() if proposal.resolved_at else None,
        "governance_mode_at_creation": payload.get(
            "governance_mode_at_creation",
            GovernanceMode.DUAL_CONTROL.value,
        ),
        "required_approvals": required_approvals,
        "approval_count": len({approval.admin_id for approval in approvals}),
        "requires_different_admin": required_approvals > 0,
    }
    if "role" in payload:
        body["requested_role"] = payload["role"]
    if is_governance:
        body["requested_mode"] = payload.get("to_mode")
        body["reason"] = payload.get("reason")
    if is_totp_policy:
        body["previous_required_roles"] = payload.get("previous_required_roles", [])
        body["requested_required_roles"] = payload.get("required_roles", [])
        body["reason"] = payload.get("reason")
    if proposal.change_type is AdminChangeType.HSM_RAW_BACKUP_EXPORT:
        body["reason"] = payload.get("reason")
    return body


def _notification_template_response(template: NotificationTemplate) -> dict[str, object]:
    return {
        "name": template.name,
        "event_type": template.event_type.value,
        "format": template.format.value,
        "subject": template.subject,
        "body": template.body,
        "updated_at": template.updated_at.isoformat() if template.updated_at else None,
    }


def _notification_rule_response(rule: NotificationRule) -> dict[str, object]:
    return {
        "id": rule.id,
        "event_type": rule.event_type.value,
        "template_name": rule.template_name,
        "channel": rule.channel.value,
        "audience": rule.audience.value,
        "enabled": rule.enabled,
        "period_days": rule.period_days,
        "threshold_days": rule.threshold_days,
        "notification_text": rule.notification_text,
        "last_run_at": rule.last_run_at.isoformat() if rule.last_run_at else None,
        "include_renewal_link": rule.include_renewal_link,
    }


def _notification_log_response(entry) -> dict[str, object]:
    return {
        "id": entry.id,
        "rule_id": entry.rule_id,
        "event_type": entry.event_type,
        "template_name": entry.template_name,
        "channel": entry.channel,
        "recipient": entry.recipient,
        "subject": entry.subject,
        "object_ref": entry.object_ref,
        "success": entry.success,
        "detail": entry.detail,
        "sent_at": entry.sent_at.isoformat() if entry.sent_at else None,
    }


def _person_response(person: Person) -> dict[str, object]:
    return {
        "id": person.id,
        "name": person.name,
        "surname": person.surname,
        "full_name": person.full_name,
        "email": person.email,
        "phone": person.phone,
        "slack_handle": person.slack_handle,
        "company": person.company,
        "comments": person.comments,
        "created_at": person.created_at.isoformat(),
    }


def _device_response(device: Device, admin: Person | None) -> dict[str, object]:
    return {
        "id": device.id,
        "device_name": device.device_name,
        "fqdn": device.fqdn,
        "admin_id": device.admin_id,
        "admin_name": admin.full_name if admin else None,
        "admin_email": admin.email if admin else None,
        "comments": device.comments,
        "created_at": device.created_at.isoformat(),
    }


def _holder_response(
    repository: PKIRepository,
    holder_person_id: str | None,
    holder_device_id: str | None,
) -> dict[str, object] | None:
    """Describe a certificate/request holder, resolving the responsible person.

    A device-held certificate always resolves to a person via the device's admin.
    """
    if holder_person_id is not None:
        person = _repository_person_or_none(repository, holder_person_id)
        return {
            "type": "person",
            "id": holder_person_id,
            "label": person.full_name if person else holder_person_id,
            "responsible_person_id": holder_person_id,
            "responsible_person_email": person.email if person else None,
        }
    if holder_device_id is not None:
        device = _repository_device_or_none(repository, holder_device_id)
        admin = _repository_person_or_none(repository, device.admin_id) if device else None
        return {
            "type": "device",
            "id": holder_device_id,
            "label": device.device_name if device else holder_device_id,
            "fqdn": device.fqdn if device else None,
            "responsible_person_id": device.admin_id if device else None,
            "responsible_person_email": admin.email if admin else None,
        }
    return None


def _risk_summary(
    repository: PKIRepository,
    notification_repository: NotificationRepository,
    service_cert_repository: ServiceCertRepository,
    *,
    now: datetime,
) -> dict[str, int]:
    current = now.astimezone(timezone.utc)
    in_7_days = current + timedelta(days=7)
    in_30_days = current + timedelta(days=30)
    in_60_days = current + timedelta(days=60)
    recent_cutoff = current - timedelta(days=30)
    month_start = current.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    active_certificates = [
        certificate
        for certificate in repository.list_issued_certificates()
        if certificate.status is CertificateStatus.ACTIVE
    ]
    non_expired = [
        certificate
        for certificate in active_certificates
        if certificate.expires_at.astimezone(timezone.utc) > current
    ]

    return {
        "expired": sum(
            1
            for certificate in active_certificates
            if certificate.expires_at.astimezone(timezone.utc) <= current
        ),
        "expiring_7_days": sum(
            1
            for certificate in non_expired
            if certificate.expires_at.astimezone(timezone.utc) <= in_7_days
        ),
        "expiring_30_days": sum(
            1
            for certificate in non_expired
            if certificate.expires_at.astimezone(timezone.utc) <= in_30_days
        ),
        "expiring_60_days": sum(
            1
            for certificate in non_expired
            if certificate.expires_at.astimezone(timezone.utc) <= in_60_days
        ),
        "pending_approval": sum(
            1
            for certificate_request in repository.list_requests()
            if certificate_request.status is RequestStatus.PENDING
        ),
        "revoked_this_month": sum(
            1
            for revocation in repository.list_revocations()
            if revocation.revoked_at.astimezone(timezone.utc) >= month_start
        ),
        "failed_notifications_30_days": notification_repository.count_failed_since(recent_cutoff),
        "failed_renewals_30_days": sum(
            1
            for error in service_cert_repository.list_recent_errors()
            if "renew" in str(error.get("operation", "")).lower()
            and datetime.fromisoformat(str(error["created_at"])).astimezone(timezone.utc)
            >= recent_cutoff
        ),
    }


def _service_cert_response(cert, *, include_pem: bool = False) -> dict[str, object]:
    body: dict[str, object] = {
        "id": cert.id,
        "name": cert.name,
        "source": cert.source.value,
        "status": cert.status.value,
        "key_backend": cert.key_backend.value,
        "subject": cert.subject,
        "not_before": cert.not_before.isoformat() if cert.not_before else None,
        "not_after": cert.not_after.isoformat() if cert.not_after else None,
        "created_at": cert.created_at.isoformat(),
        "updated_at": cert.updated_at.isoformat(),
    }
    if include_pem:
        body["csr_pem"] = cert.csr_pem
        body["certificate_pem"] = cert.certificate_pem
        body["chain_pem"] = cert.chain_pem
    return body


def _acme_account_response(account, dependents=()) -> dict[str, object]:
    # The account private key (ciphertext) and DNS credentials are never exposed.
    return {
        "id": account.id,
        "directory_url": account.directory_url,
        "account_url": account.account_url,
        "contact": account.contact,
        "created_at": account.created_at.isoformat(),
        "dns_provider": account.dns_provider,
        "dns_configured": account.dns_credentials_ciphertext is not None,
        "certificates": [
            {"name": c.name, "not_after": c.not_after.isoformat() if c.not_after else None}
            for c in dependents
        ],
    }


def _repository_person_or_none(repository: PKIRepository, person_id: str | None) -> Person | None:
    if person_id is None:
        return None
    try:
        return repository.get_person(person_id)
    except RepositoryError:
        return None


def _repository_device_or_none(repository: PKIRepository, device_id: str | None) -> Device | None:
    if device_id is None:
        return None
    try:
        return repository.get_device(device_id)
    except RepositoryError:
        return None


def _pkcs12_message_body(with_ca_certificates: bool) -> str:
    body = (
        "Your encrypted PKCS#12 certificate bundle is attached. "
        "Its password will be sent through your separately configured channel."
    )
    if with_ca_certificates:
        body += (
            "\n\nThe CA certificates are attached separately as sub-ca.cer and "
            "root-ca.cer. Install them before the bundle. Copies also travel "
            "inside the bundle, but a device will not treat those as trusted: "
            "the root has to be installed in its own right, and on iOS then "
            "enabled under Settings > General > About > Certificate Trust "
            "Settings."
        )
    return body


def _resolve_holder_person(repository: PKIRepository, certificate) -> Person | None:
    """Resolve the responsible person for an issued certificate.

    Person-held certs resolve directly; device-held certs resolve via the
    device's responsible person.
    """
    if certificate.holder_person_id is not None:
        return _repository_person_or_none(repository, certificate.holder_person_id)
    device = _repository_device_or_none(repository, certificate.holder_device_id)
    if device is not None:
        return _repository_person_or_none(repository, device.admin_id)
    return None


def _repository_user_or_none(repository: PKIRepository, user_id: str | None) -> User | None:
    if user_id is None:
        return None
    try:
        return repository.get_user(user_id)
    except RepositoryError:
        return None


def _auth_user_or_none(
    auth_repository: AuthRepository | None,
    user_id: str | None,
) -> User | None:
    if auth_repository is None or user_id is None:
        return None
    try:
        return auth_repository.get_user(user_id)
    except RepositoryError:
        return None
