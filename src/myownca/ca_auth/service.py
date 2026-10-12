from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from myownca.ca_auth.repository import AuthRepository, encode_payload
from myownca.ca_auth.totp import code_for_step, current_step, generate_secret, provisioning_uri
from myownca.domain import (
    AdminChangeProposal,
    AdminChangeStatus,
    AdminChangeType,
    AuthEvent,
    AuthSession,
    GovernanceMode,
    PasswordCredential,
    PRIVILEGED_ROLES,
    RecoveryChallenge,
    Role,
    SessionStage,
    TOTPFactor,
    User,
)
from myownca.secret_keys import (
    CA_AUTH_DOMAIN,
    decrypt_secret,
    derive_fernet_key,
    domain_cipher,
)
from myownca.storage.database import IntegrityError

PASSWORD_MIN_LENGTH = 16
PROPOSAL_TTL = timedelta(hours=24)
FAILURE_WINDOW = timedelta(minutes=5)
MAX_FAILURES = 5
RECOVERY_CODE_COUNT = 10
EMAIL_RECOVERY_TTL = timedelta(minutes=15)
RECENT_MFA_WINDOW = timedelta(minutes=10)
PASSWORD_RECOVERY_PURPOSE = "password"
TOTP_RECOVERY_PURPOSE = "totp"
MAX_RECOVERY_REQUESTS_PER_IP = 20
RECOVERY_IP_WINDOW = timedelta(hours=1)


class AuthError(RuntimeError):
    pass


class AuthenticationError(AuthError):
    pass


class AuthorizationError(AuthError):
    pass


class ThrottledError(AuthError):
    pass


class CSRFError(AuthError):
    pass


@dataclass(frozen=True, slots=True)
class SessionProfile:
    idle_timeout: timedelta
    absolute_timeout: timedelta


SESSION_PROFILES: dict[Role, SessionProfile] = {
    Role.ADMIN: SessionProfile(timedelta(minutes=15), timedelta(hours=8)),
    Role.SUPERUSER: SessionProfile(timedelta(minutes=30), timedelta(hours=12)),
    Role.AUDITOR: SessionProfile(timedelta(minutes=60), timedelta(hours=12)),
    Role.USER: SessionProfile(timedelta(hours=8), timedelta(hours=24)),
}


@dataclass(frozen=True, slots=True)
class CreatedSession:
    token: str
    session: AuthSession
    user: User


class AuthService:
    def __init__(
        self,
        repository: AuthRepository,
        encryption_secret: str,
        *,
        comms=None,
        notifications=None,
        contacts=None,
    ) -> None:
        self.repository = repository
        self.password_hasher = PasswordHasher(
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            salt_len=16,
            type=Type.ID,
        )
        self.cipher = domain_cipher(encryption_secret, CA_AUTH_DOMAIN)
        # Transport for self-service account recovery (a CommsService); optional so
        # the auth module has no hard dependency on the comms module.
        self.comms = comms
        # Optional NotificationService customizes recovery message content via
        # an 'otp' template; the selected enabled channel controls delivery.
        self.notifications = notifications
        # Optional PKIRepository used to resolve phone/Slack contacts mirrored
        # from login accounts. Email/webhook/HTTPS do not require it.
        self.contacts = contacts
        # Server-side pepper so a database leak alone cannot verify recovery codes.
        self._recovery_pepper = hashlib.sha256(f"recovery:{encryption_secret}".encode()).digest()

    def bootstrap_initial_admins(
        self,
        first: tuple[str, str, str],
        second: tuple[str, str, str] | None = None,
        *,
        now: datetime | None = None,
    ) -> tuple[User, ...]:
        mode = self.repository.get_governance_mode()
        if mode is GovernanceMode.DUAL_CONTROL and second is None:
            raise AuthError("Dual-control installations require two initial administrators")
        if second and (first[0] == second[0] or first[1].casefold() == second[1].casefold()):
            raise AuthError("Initial admins must be two distinct accounts")
        current_time = _utc_now(now)
        credentials = (first,) if second is None else (first, second)
        admins = tuple(User(id=item[0], email=item[1], role=Role.ADMIN) for item in credentials)
        password_credentials: list[PasswordCredential] = []
        for user, credential in zip(admins, credentials, strict=True):
            password = credential[2]
            self._validate_password(password)
            password_credentials.append(
                PasswordCredential(
                    user_id=user.id,
                    password_hash=self.password_hasher.hash(password),
                    must_change_password=True,
                    updated_at=current_time,
                )
            )
        result = self.repository.bootstrap_admins(admins, tuple(password_credentials))
        if result == "requires_two":
            raise AuthError("Dual-control installations require two initial administrators")
        if result == "unavailable":
            raise AuthError("Install governance state is unavailable")
        if result != "created":
            raise AuthError("Bootstrap requires an empty users table")
        return admins

    def governance_mode(self) -> GovernanceMode:
        return self.repository.get_governance_mode()

    def totp_policy(self) -> dict[Role, bool]:
        return self.repository.get_totp_policy()

    def totp_required(self, role: Role) -> bool:
        return self.repository.is_totp_required(role)

    def totp_status(self, user: User) -> dict[str, object]:
        factor = self.repository.get_totp_factor(user.id)
        return {
            "totp_required": self.totp_required(user.role),
            "totp_configured": factor is not None and factor.confirmed_at is not None,
        }

    def governance_status(self, *, lab_mode: bool = False) -> dict[str, object]:
        mode = self.governance_mode()
        active_admin_count = self.repository.count_active_users_with_role(Role.ADMIN)
        dual_control_operational = (
            mode is not GovernanceMode.DUAL_CONTROL or active_admin_count >= 2
        )
        return {
            "mode": mode.value,
            "recommended_mode": (
                GovernanceMode.SINGLE_ADMIN.value
                if lab_mode
                else GovernanceMode.DUAL_CONTROL.value
            ),
            "requires_second_admin": mode is GovernanceMode.DUAL_CONTROL,
            "active_admin_count": active_admin_count,
            "can_enable_dual_control": (
                mode is GovernanceMode.SINGLE_ADMIN and active_admin_count >= 2
            ),
            "dual_control_operational": dual_control_operational,
            "warning": (
                None
                if dual_control_operational
                else (
                    "Dual control needs at least two active administrators. "
                    "Reactivate an existing second administrator. If none exists, "
                    "stop and restore a known-good state backup containing at least "
                    "two active administrators."
                )
            ),
        }

    def enable_dual_control(
        self,
        actor: User,
        *,
        now: datetime | None = None,
    ) -> GovernanceMode:
        self._require_admin(actor)
        result = self.repository.enable_dual_control_if_safe(
            updated_at=_utc_now(now),
            updated_by=actor.id,
        )
        if result == "already_dual":
            raise AuthError("Dual control is already enabled")
        if result == "invalid_actor":
            raise AuthorizationError("An active administrator account is required")
        if result == "insufficient_admins":
            raise AuthError("Enable at least two distinct administrator accounts first")
        if result != "enabled":
            raise AuthError("Install governance state is unavailable")
        return GovernanceMode.DUAL_CONTROL

    def create_governance_downgrade_proposal(
        self,
        actor: User,
        *,
        reason: str,
        now: datetime | None = None,
    ) -> AdminChangeProposal:
        self._require_admin(actor)
        cleaned_reason = reason.strip()
        if len(cleaned_reason) < 10 or len(cleaned_reason) > 500:
            raise AuthError("Governance change reason must be 10 to 500 characters")
        current_time = _utc_now(now)
        proposal = AdminChangeProposal(
            id=str(uuid4()),
            change_type=AdminChangeType.GOVERNANCE_MODE_DOWNGRADE,
            proposer_id=actor.id,
            target_user_id=actor.id,
            payload_json=encode_payload({
                "from_mode": GovernanceMode.DUAL_CONTROL.value,
                "to_mode": GovernanceMode.SINGLE_ADMIN.value,
                "reason": cleaned_reason,
                "governance_mode_at_creation": GovernanceMode.DUAL_CONTROL.value,
                "required_approvals": 1,
            }),
            status=AdminChangeStatus.PENDING,
            created_at=current_time,
            expires_at=current_time + PROPOSAL_TTL,
        )
        result = self.repository.add_governance_downgrade_proposal(
            proposal,
            current_time,
        )
        if result == "not_dual":
            raise AuthError("Single-admin governance is already enabled")
        if result == "pending_exists":
            raise AuthError("A single-admin governance proposal is already pending")
        if result == "invalid_proposer":
            raise AuthorizationError("An active administrator account is required")
        if result == "insufficient_admins":
            raise AuthError("Dual control requires two active administrators")
        if result != "created":
            raise AuthError("Install governance state is unavailable")
        return proposal

    def create_ordinary_user(
        self,
        actor: User,
        *,
        user_id: str,
        email: str,
        temporary_password: str,
        now: datetime | None = None,
    ) -> User:
        if actor.role not in {Role.ADMIN, Role.SUPERUSER}:
            raise AuthorizationError(
                "Only administrators and Certificate Operators may create ordinary users"
            )
        self._validate_password(temporary_password)
        current_time = _utc_now(now)
        user = User(id=user_id, email=email, role=Role.USER)
        self.repository.add_user(user)
        self.repository.add_or_update_password_credential(
            PasswordCredential(
                user_id=user.id,
                password_hash=self.password_hasher.hash(temporary_password),
                must_change_password=True,
                updated_at=current_time,
            )
        )
        return user

    def create_privileged_role_grant_proposal(
        self,
        actor: User,
        *,
        user_id: str,
        email: str,
        role: Role,
        temporary_password: str,
        now: datetime | None = None,
    ) -> AdminChangeProposal:
        self._require_admin(actor)
        if role not in PRIVILEGED_ROLES:
            raise AuthError(
                "Privileged role grants require administrator, Certificate Operator, or auditor"
            )
        self._validate_password(temporary_password)
        current_time = _utc_now(now)
        # Pending grants are deliberately ordinary, inactive placeholders with
        # no installed credential. The requested role and password hash are
        # applied together only when the captured governance policy resolves.
        user = User(id=user_id, email=email, role=Role.USER, is_active=False)
        try:
            return self._create_proposal(
                actor,
                change_type=AdminChangeType.PRIVILEGED_ROLE_GRANT,
                target_user_id=user.id,
                payload={
                    "role": role.value,
                    "temporary_password_hash": self.password_hasher.hash(
                        temporary_password
                    ),
                },
                now=current_time,
                new_user=user,
            )
        except IntegrityError as exc:
            raise AuthError("A user with this id or email already exists") from exc

    def create_privileged_password_reset_proposal(
        self,
        actor: User,
        *,
        target_user_id: str,
        temporary_password: str,
        now: datetime | None = None,
    ) -> AdminChangeProposal:
        self._require_admin(actor)
        target = self.repository.get_user(target_user_id)
        if target.role not in PRIVILEGED_ROLES:
            raise AuthError("Use direct reset for ordinary users")
        self._validate_password(temporary_password)
        return self._create_proposal(
            actor,
            change_type=AdminChangeType.PRIVILEGED_PASSWORD_RESET,
            target_user_id=target.id,
            payload={"temporary_password_hash": self.password_hasher.hash(temporary_password)},
            now=_utc_now(now),
        )

    def create_privileged_totp_reset_proposal(
        self,
        actor: User,
        *,
        target_user_id: str,
        now: datetime | None = None,
    ) -> AdminChangeProposal:
        self._require_admin(actor)
        target = self.repository.get_user(target_user_id)
        if target.role not in PRIVILEGED_ROLES:
            raise AuthError("Governed TOTP reset requires a privileged account")
        return self._create_proposal(
            actor,
            change_type=AdminChangeType.PRIVILEGED_TOTP_RESET,
            target_user_id=target.id,
            payload={},
            now=_utc_now(now),
        )

    def reset_ordinary_totp(
        self,
        actor: User,
        *,
        target_user_id: str,
        now: datetime | None = None,
    ) -> None:
        if actor.role not in {Role.ADMIN, Role.SUPERUSER}:
            raise AuthorizationError(
                "Only administrators and Certificate Operators may reset ordinary TOTP"
            )
        target = self.repository.get_user(target_user_id)
        if target.role is not Role.USER:
            raise AuthError("Privileged TOTP resets require the governed workflow")
        if self.repository.get_totp_factor(target.id) is None:
            raise AuthError("No TOTP factor is configured for this account")
        current_time = _utc_now(now)
        self.repository.clear_totp_factor(target.id)
        self.repository.clear_recovery_codes(target.id)
        self.repository.consume_email_recovery_challenges(target.id, current_time)
        self.repository.consume_recovery_challenges(target.id, current_time)
        self.repository.revoke_sessions_for_user(target.id, current_time)

    def create_totp_policy_change(
        self,
        actor: User,
        *,
        required_roles: set[Role],
        reason: str,
        strengthening_only: bool = False,
        now: datetime | None = None,
    ) -> AdminChangeProposal:
        self._require_admin(actor)
        cleaned_reason = reason.strip()
        if len(cleaned_reason) < 10 or len(cleaned_reason) > 500:
            raise AuthError("TOTP policy reason must be 10 to 500 characters")
        current = self.totp_policy()
        previous = {role for role, required in current.items() if required}
        if required_roles == previous:
            raise AuthError("TOTP policy is unchanged")
        if strengthening_only and not previous.issubset(required_roles):
            raise AuthError(
                "TOTP policy changed concurrently; review it before disabling TOTP"
            )
        current_time = _utc_now(now)
        status, proposal = self.repository.create_governed_proposal(
            proposal_id=str(uuid4()),
            change_type=AdminChangeType.ROLE_TOTP_POLICY_CHANGE,
            proposer_id=actor.id,
            # The generic proposal schema requires a user target. Policy
            # proposals follow governance downgrades and anchor this to the actor;
            # the actual target is the role matrix captured in payload_json.
            target_user_id=actor.id,
            payload={
                "previous_required_roles": sorted(role.value for role in previous),
                "required_roles": sorted(role.value for role in required_roles),
                "reason": cleaned_reason,
            },
            created_at=current_time,
            expires_at=current_time + PROPOSAL_TTL,
        )
        if status == "invalid_proposer":
            raise AuthorizationError("An active administrator account is required")
        if status == "insufficient_admins":
            raise AuthError("Dual control requires two active administrators")
        if status == "pending_exists":
            raise AuthError("A TOTP policy change is already pending")
        if status != "created" or proposal is None:
            raise AuthError("Install governance state is unavailable")
        return proposal

    def reset_ordinary_password(
        self,
        actor: User,
        *,
        target_user_id: str,
        temporary_password: str,
        now: datetime | None = None,
    ) -> None:
        if actor.role not in {Role.ADMIN, Role.SUPERUSER}:
            raise AuthorizationError(
                "Only administrators and Certificate Operators may reset ordinary passwords"
            )
        target = self.repository.get_user(target_user_id)
        if target.role is not Role.USER:
            raise AuthError("Privileged password resets require the privileged-change workflow")
        self._validate_password(temporary_password)
        current_time = _utc_now(now)
        result = self.repository.reset_ordinary_password_if_safe(
            PasswordCredential(
                user_id=target.id,
                password_hash=self.password_hasher.hash(temporary_password),
                must_change_password=True,
                updated_at=current_time,
            ),
            actor_id=actor.id,
            revoked_at=current_time,
        )
        if result == "pending_role_grant":
            raise AuthError(
                "Account is awaiting a governed role grant and cannot be reset directly"
            )
        if result == "privileged":
            raise AuthError("Privileged password resets require the privileged-change workflow")
        if result == "invalid_actor":
            raise AuthorizationError("An active authorized account is required")
        if result != "reset":
            raise AuthError("Account changed concurrently; retry the request")

    def set_user_active(
        self,
        actor: User,
        *,
        target_user_id: str,
        active: bool,
        now: datetime | None = None,
    ) -> User:
        """Deactivate or reactivate a login account.

        Deactivation blocks login and revokes the target's live sessions.
        Role and privileged-credential changes use the install governance
        workflow; this method only toggles ``is_active`` and keeps the role.
        """
        if actor.role not in {Role.ADMIN, Role.SUPERUSER}:
            raise AuthorizationError(
                "Only administrators and Certificate Operators may change account status"
            )
        target = self.repository.get_user(target_user_id)
        if actor.id == target.id:
            raise AuthError("You cannot change your own active status")
        if actor.role is not Role.ADMIN and target.role in {Role.ADMIN, Role.SUPERUSER}:
            raise AuthorizationError("Only an admin may change a privileged account's status")
        if target.is_active is active:
            return target
        current_time = _utc_now(now)
        result = self.repository.set_user_active_with_governance_guard(
            target.id,
            actor_id=actor.id,
            active=active,
        )
        if result == "pending_role_grant":
            raise AuthError(
                "Account is awaiting a governed role grant and cannot be activated directly"
            )
        if result != "changed":
            if result == "invalid_actor":
                raise AuthorizationError("An active authorized account is required")
            mode = self.governance_mode()
            if result == "admin_floor" and mode is GovernanceMode.DUAL_CONTROL:
                raise AuthError("Dual control requires at least two active administrators")
            if result == "admin_floor":
                raise AuthError("Cannot deactivate the last active administrator")
            raise AuthError("Account status changed concurrently; retry the request")
        if not active:
            self.repository.revoke_sessions_for_user(target.id, current_time)
        return self.repository.get_user(target.id)

    def approve_proposal(
        self,
        proposal_id: str,
        actor: User,
        *,
        now: datetime | None = None,
    ) -> AdminChangeProposal:
        self._require_admin(actor)
        current_time = _utc_now(now)
        try:
            status, proposal = self.repository.resolve_proposal_approval(
                proposal_id,
                actor.id,
                current_time,
            )
        except IntegrityError as exc:
            raise AuthError("This administrator has already approved the proposal") from exc
        if status == "invalid_approver":
            raise AuthorizationError("An active administrator account is required")
        if status == "self_approval":
            raise AuthorizationError("Proposal approver must be a different admin")
        if status == "not_pending":
            raise AuthError("Only pending proposals may be resolved")
        if status == "expired":
            raise AuthError("Proposal has expired")
        if status == "stale":
            raise AuthError(
                "TOTP policy changed after this proposal was created; the proposal was rejected"
            )
        if status == "unavailable" or proposal is None:
            raise AuthError("Install governance state is unavailable")
        return proposal

    def reject_proposal(
        self,
        proposal_id: str,
        actor: User,
        *,
        now: datetime | None = None,
    ) -> AdminChangeProposal:
        self._require_admin(actor)
        current_time = _utc_now(now)
        status, resolved = self.repository.resolve_proposal_rejection(
            proposal_id,
            actor.id,
            current_time,
        )
        if status == "invalid_actor":
            raise AuthorizationError("An active administrator account is required")
        if status == "not_pending":
            raise AuthError("Only pending proposals may be resolved")
        if status == "unavailable" or resolved is None:
            raise AuthError("Install governance state is unavailable")
        if status == "expired":
            raise AuthError("Proposal has expired")
        return resolved

    def login(
        self,
        email: str,
        password: str,
        *,
        now: datetime | None = None,
    ) -> CreatedSession:
        current_time = _utc_now(now)
        recent_failures = self.repository.count_recent_events(
            "login_failure",
            email=email,
            since=current_time - FAILURE_WINDOW,
        )
        if recent_failures >= MAX_FAILURES:
            raise ThrottledError("Too many recent login failures")

        user = self.repository.get_user_by_email(email)
        credential = self.repository.get_password_credential(user.id) if user else None
        if user is None or credential is None or not user.is_active:
            self._record_event("login_failure", current_time, email=email)
            raise AuthenticationError("Invalid email or password")
        try:
            self.password_hasher.verify(credential.password_hash, password)
        except (VerifyMismatchError, InvalidHashError):
            self._record_event("login_failure", current_time, user=user, email=email)
            raise AuthenticationError("Invalid email or password")

        if self.password_hasher.check_needs_rehash(credential.password_hash):
            self.repository.add_or_update_password_credential(
                PasswordCredential(
                    user_id=user.id,
                    password_hash=self.password_hasher.hash(password),
                    must_change_password=credential.must_change_password,
                    updated_at=current_time,
                )
            )
        stage = self._next_stage_for_login(user, credential)
        created = self._create_session(user, stage, current_time)
        self._record_event("login_success", current_time, user=user, email=user.email)
        return created

    def change_password(
        self,
        token: str,
        new_password: str,
        *,
        now: datetime | None = None,
    ) -> CreatedSession:
        current_time = _utc_now(now)
        session, user = self.require_session(token, allow_incomplete=True, now=current_time)
        if session.stage not in {
            SessionStage.PASSWORD_CHANGE_REQUIRED,
            SessionStage.PASSWORD_RECOVERY_REQUIRED,
        }:
            raise AuthError("Password change is not required for this session")
        self._validate_password(new_password)
        credential = PasswordCredential(
            user_id=user.id,
            password_hash=self.password_hasher.hash(new_password),
            must_change_password=False,
            updated_at=current_time,
        )
        if session.stage is SessionStage.PASSWORD_RECOVERY_REQUIRED:
            profile = SESSION_PROFILES[user.role]
            absolute_expires_at = current_time + profile.absolute_timeout
            next_stage = self.repository.complete_password_recovery(
                session_id=session.id,
                credential=credential,
                completed_at=current_time,
                expires_at=min(
                    current_time + profile.idle_timeout,
                    absolute_expires_at,
                ),
                absolute_expires_at=absolute_expires_at,
            )
            if next_stage is None:
                raise AuthenticationError("Password recovery session is invalid or expired")
            updated = self.repository.get_session_by_token_hash(session.token_hash)
            assert updated is not None
            self._record_event("password_recovery_completed", current_time, user=user)
            return CreatedSession(token=token, session=updated, user=user)
        self.repository.add_or_update_password_credential(
            credential
        )
        self.repository.consume_recovery_challenges(user.id, current_time)
        self.repository.consume_email_recovery_challenges(user.id, current_time)
        next_stage = self._post_password_stage(user)
        self.repository.update_session(session.id, stage=next_stage)
        updated = self.repository.get_session_by_token_hash(session.token_hash)
        assert updated is not None
        self._record_event("password_change", current_time, user=user)
        return CreatedSession(token=token, session=updated, user=user)

    def begin_totp_enrollment(
        self,
        token: str,
        *,
        now: datetime | None = None,
    ) -> dict[str, str]:
        session, user = self.require_session(token, allow_incomplete=True, now=now)
        if session.stage is not SessionStage.TOTP_ENROLLMENT_REQUIRED:
            raise AuthError("TOTP enrollment is not required for this session")
        secret = generate_secret()
        self.repository.add_or_update_totp_factor(
            TOTPFactor(
                user_id=user.id,
                secret_ciphertext=self._encrypt(secret),
                confirmed_at=None,
                last_verified_step=None,
            )
        )
        return {
            "secret": secret,
            "provisioning_uri": provisioning_uri(secret, user.email),
        }

    def confirm_totp_enrollment(
        self,
        token: str,
        code: str,
        *,
        now: datetime | None = None,
    ) -> CreatedSession:
        current_time = _utc_now(now)
        session, user = self.require_session(token, allow_incomplete=True, now=current_time)
        if session.stage is not SessionStage.TOTP_ENROLLMENT_REQUIRED:
            raise AuthError("TOTP enrollment is not required for this session")
        factor = self.repository.get_totp_factor(user.id)
        if factor is None:
            raise AuthError("Start TOTP enrollment before confirming it")
        step = self._verify_totp_code(user, factor, code, current_time)
        self.repository.add_or_update_totp_factor(
            TOTPFactor(
                user_id=user.id,
                secret_ciphertext=factor.secret_ciphertext,
                confirmed_at=current_time,
                last_verified_step=step,
            )
        )
        self.repository.update_session(
            session.id,
            stage=SessionStage.ACTIVE,
            mfa_verified_at=current_time,
        )
        updated = self.repository.get_session_by_token_hash(session.token_hash)
        assert updated is not None
        return CreatedSession(token=token, session=updated, user=user)

    def verify_totp_challenge(
        self,
        token: str,
        code: str,
        *,
        now: datetime | None = None,
    ) -> CreatedSession:
        current_time = _utc_now(now)
        session, user = self.require_session(token, allow_incomplete=True, now=current_time)
        if session.stage is not SessionStage.TOTP_REQUIRED:
            raise AuthError("TOTP challenge is not required for this session")
        factor = self.repository.get_totp_factor(user.id)
        if factor is None or factor.confirmed_at is None:
            raise AuthError("No confirmed TOTP factor is available")
        step = self._verify_totp_code(user, factor, code, current_time)
        self.repository.add_or_update_totp_factor(
            TOTPFactor(
                user_id=user.id,
                secret_ciphertext=factor.secret_ciphertext,
                confirmed_at=factor.confirmed_at,
                last_verified_step=step,
            )
        )
        self.repository.update_session(
            session.id,
            stage=SessionStage.ACTIVE,
            mfa_verified_at=current_time,
        )
        updated = self.repository.get_session_by_token_hash(session.token_hash)
        assert updated is not None
        return CreatedSession(token=token, session=updated, user=user)

    # -- 2FA recovery ---------------------------------------------------------

    def regenerate_recovery_codes(self, token: str, *, now: datetime | None = None) -> list[str]:
        """Issue a fresh set of one-time recovery codes (plaintext shown once)."""
        current_time = _utc_now(now)
        _, user = self.require_session(token, now=current_time)  # ACTIVE required
        factor = self.repository.get_totp_factor(user.id)
        if factor is None or factor.confirmed_at is None:
            raise AuthError("Enroll TOTP before generating recovery codes")
        codes = [_format_recovery_code(secrets.token_hex(5)) for _ in range(RECOVERY_CODE_COUNT)]
        hashes = [self._hash_recovery(self._normalize_code(code)) for code in codes]
        self.repository.replace_recovery_codes(user.id, hashes, current_time)
        self._record_event("recovery_codes_generated", current_time, user=user)
        return codes

    def verify_recovery_code(
        self, token: str, code: str, *, now: datetime | None = None
    ) -> CreatedSession:
        """Consume an offline recovery code as the second factor at login."""
        current_time = _utc_now(now)
        session, user = self.require_session(token, allow_incomplete=True, now=current_time)
        if session.stage is not SessionStage.TOTP_REQUIRED:
            raise AuthError("A recovery code is not expected for this session")
        self._assert_recovery_not_throttled(user, current_time)
        code_hash = self._hash_recovery(self._normalize_code(code))
        if not self.repository.consume_recovery_code(user.id, code_hash, current_time):
            self._record_event("recovery_code_failure", current_time, user=user)
            raise AuthenticationError("Invalid recovery code")
        # A recovery code permits account recovery, but it is not a recent
        # authenticator-app proof for destructive trust operations.
        self.repository.update_session(session.id, stage=SessionStage.ACTIVE)
        updated = self.repository.get_session_by_token_hash(session.token_hash)
        assert updated is not None
        self._record_event("recovery_code_success", current_time, user=user)
        return CreatedSession(token=token, session=updated, user=user)

    def reauthenticate_totp(
        self,
        token: str,
        code: str,
        *,
        now: datetime | None = None,
    ) -> CreatedSession:
        """Refresh recent-MFA state for a live privileged session."""
        current_time = _utc_now(now)
        session, user = self.require_session(token, now=current_time)
        if not self.totp_required(user.role):
            raise AuthorizationError("TOTP is not required for this account role")
        factor = self.repository.get_totp_factor(user.id)
        if factor is None or factor.confirmed_at is None:
            raise AuthError("No confirmed TOTP factor is available")
        step = self._verify_totp_code(user, factor, code, current_time)
        self.repository.add_or_update_totp_factor(
            TOTPFactor(
                user_id=user.id,
                secret_ciphertext=factor.secret_ciphertext,
                confirmed_at=factor.confirmed_at,
                last_verified_step=step,
            )
        )
        self.repository.update_session(session.id, mfa_verified_at=current_time)
        updated = self.repository.get_session_by_token_hash(session.token_hash)
        assert updated is not None
        self._record_event("totp_reauthentication", current_time, user=user)
        return CreatedSession(token=token, session=updated, user=user)

    def reauthenticate_password(
        self,
        token: str,
        password: str,
        *,
        now: datetime | None = None,
    ) -> CreatedSession:
        """Refresh password-based step-up state for a live session."""
        current_time = _utc_now(now)
        session, user = self.require_session(token, now=current_time)
        if self.totp_required(user.role):
            raise AuthorizationError("This account must reauthenticate with TOTP")
        failures = self.repository.count_recent_events(
            "password_reauthentication_failure",
            user_id=user.id,
            since=current_time - FAILURE_WINDOW,
        )
        if failures >= MAX_FAILURES:
            raise ThrottledError("Too many recent password reauthentication failures")
        credential = self.repository.get_password_credential(user.id)
        if credential is None:
            self._record_event(
                "password_reauthentication_failure", current_time, user=user
            )
            raise AuthenticationError("Invalid password")
        try:
            self.password_hasher.verify(credential.password_hash, password)
        except (VerifyMismatchError, InvalidHashError):
            self._record_event(
                "password_reauthentication_failure", current_time, user=user
            )
            raise AuthenticationError("Invalid password")
        self.repository.update_session(
            session.id,
            password_verified_at=current_time,
        )
        updated = self.repository.get_session_by_token_hash(session.token_hash)
        assert updated is not None
        self._record_event("password_reauthentication", current_time, user=user)
        return CreatedSession(token=token, session=updated, user=user)

    def available_recovery_channels(self) -> list[str]:
        """Return globally enabled delivery channels without account-specific data."""
        if self.comms is None or not hasattr(self.comms, "get_config"):
            return []
        from myownca.comms import NotificationChannel  # noqa: PLC0415

        enabled: list[str] = []
        for channel in NotificationChannel:
            try:
                config = self.comms.get_config(channel)
            except Exception:  # noqa: BLE001 - public status must fail closed
                continue
            if config is not None and config.enabled:
                enabled.append(channel.value)
        return enabled

    def request_password_recovery(
        self,
        email: str,
        channel,
        *,
        source_ip: str | None = None,
        now: datetime | None = None,
    ) -> None:
        """Best-effort public recovery request with enumeration-safe behavior."""
        from myownca.comms import NotificationChannel  # noqa: PLC0415

        current_time = _utc_now(now)
        normalized_email = email.strip()
        try:
            selected = NotificationChannel(channel)
        except ValueError:
            selected = None

        email_requests = self.repository.count_recent_events(
            "password_recovery_request",
            email=normalized_email,
            since=current_time - FAILURE_WINDOW,
        )
        ip_requests = (
            self.repository.count_recent_events(
                "password_recovery_request",
                source_ip=source_ip,
                since=current_time - RECOVERY_IP_WINDOW,
            )
            if source_ip
            else 0
        )
        if (
            email_requests >= MAX_FAILURES
            or ip_requests >= MAX_RECOVERY_REQUESTS_PER_IP
        ):
            self._record_event(
                "password_recovery_throttled",
                current_time,
                email=normalized_email,
                source_ip=source_ip,
            )
            return

        user = self.repository.get_user_by_email(normalized_email)
        self._record_event(
            "password_recovery_request",
            current_time,
            user=user,
            email=normalized_email,
            source_ip=source_ip,
            details={"channel": selected.value if selected else str(channel)},
        )
        if user is None or not user.is_active or selected is None:
            return
        try:
            self._issue_recovery_challenge(
                user,
                purpose=PASSWORD_RECOVERY_PURPOSE,
                channel=selected,
                current_time=current_time,
            )
        except Exception:  # noqa: BLE001 - public response must not expose delivery state
            self._record_event(
                "password_recovery_delivery_failure",
                current_time,
                user=user,
                email=normalized_email,
                source_ip=source_ip,
                details={"channel": selected.value},
            )

    def verify_password_recovery(
        self,
        email: str,
        channel,
        code: str,
        *,
        source_ip: str | None = None,
        now: datetime | None = None,
    ) -> CreatedSession:
        from myownca.comms import NotificationChannel  # noqa: PLC0415

        current_time = _utc_now(now)
        normalized_email = email.strip()
        failures = self.repository.count_recent_events(
            "password_recovery_failure",
            email=normalized_email,
            since=current_time - FAILURE_WINDOW,
        )
        if failures >= MAX_FAILURES:
            raise ThrottledError("Too many recent recovery attempts")
        try:
            selected = NotificationChannel(channel)
        except ValueError:
            selected = None
        user = self.repository.get_user_by_email(normalized_email)
        matched = False
        if user is not None and user.is_active and selected is not None:
            matched = self._verify_delivery_code(
                user,
                purpose=PASSWORD_RECOVERY_PURPOSE,
                channel=selected,
                code=code,
                current_time=current_time,
            )
        if not matched or user is None:
            self._record_event(
                "password_recovery_failure",
                current_time,
                user=user,
                email=normalized_email,
                source_ip=source_ip,
                details={"channel": selected.value if selected else str(channel)},
            )
            raise AuthenticationError("Invalid or expired recovery code")
        created = self._create_session(
            user,
            SessionStage.PASSWORD_RECOVERY_REQUIRED,
            current_time,
            idle_timeout=EMAIL_RECOVERY_TTL,
            absolute_timeout=EMAIL_RECOVERY_TTL,
        )
        self._record_event(
            "password_recovery_verified",
            current_time,
            user=user,
            email=user.email,
            source_ip=source_ip,
            details={"channel": selected.value},
        )
        return created

    def request_delivery_recovery(
        self,
        token: str,
        channel,
        *,
        now: datetime | None = None,
    ) -> None:
        """Deliver a lost-TOTP code through any enabled channel."""
        from myownca.comms import NotificationChannel  # noqa: PLC0415

        current_time = _utc_now(now)
        session, user = self.require_session(token, allow_incomplete=True, now=current_time)
        if session.stage is not SessionStage.TOTP_REQUIRED:
            raise AuthError("TOTP recovery is not available for this session")
        requests = self.repository.count_recent_events(
            "delivery_recovery_request",
            user_id=user.id,
            since=current_time - FAILURE_WINDOW,
        )
        if requests >= MAX_FAILURES:
            raise ThrottledError("Too many recent recovery requests")
        try:
            selected = NotificationChannel(channel)
        except ValueError as exc:
            raise AuthError("Unknown recovery channel") from exc
        self._issue_recovery_challenge(
            user,
            purpose=TOTP_RECOVERY_PURPOSE,
            channel=selected,
            current_time=current_time,
        )
        self._record_event(
            "delivery_recovery_request",
            current_time,
            user=user,
            email=user.email,
            details={"channel": selected.value},
        )

    def request_email_recovery(self, token: str, *, now: datetime | None = None) -> None:
        """Compatibility wrapper for emailed lost-TOTP recovery."""
        from myownca.comms import NotificationChannel  # noqa: PLC0415

        self.request_delivery_recovery(token, NotificationChannel.EMAIL, now=now)

    def verify_delivery_recovery(
        self,
        token: str,
        channel,
        code: str,
        *,
        now: datetime | None = None,
    ) -> CreatedSession:
        from myownca.comms import NotificationChannel  # noqa: PLC0415

        current_time = _utc_now(now)
        session, user = self.require_session(token, allow_incomplete=True, now=current_time)
        if session.stage is not SessionStage.TOTP_REQUIRED:
            raise AuthError("TOTP recovery is not available for this session")
        self._assert_recovery_not_throttled(user, current_time)
        try:
            selected = NotificationChannel(channel)
        except ValueError as exc:
            raise AuthenticationError("Invalid or expired recovery code") from exc
        matched = self._verify_delivery_code(
            user,
            purpose=TOTP_RECOVERY_PURPOSE,
            channel=selected,
            code=code,
            current_time=current_time,
        )
        if not matched:
            self._record_event(
                "delivery_recovery_failure",
                current_time,
                user=user,
                details={"channel": selected.value},
            )
            raise AuthenticationError("Invalid or expired recovery code")
        self.repository.consume_recovery_challenges(user.id, current_time)
        self.repository.consume_email_recovery_challenges(user.id, current_time)
        self.repository.clear_totp_factor(user.id)
        self.repository.clear_recovery_codes(user.id)
        self.repository.update_session(
            session.id, stage=SessionStage.TOTP_ENROLLMENT_REQUIRED
        )
        updated = self.repository.get_session_by_token_hash(session.token_hash)
        assert updated is not None
        self._record_event(
            "delivery_recovery_success",
            current_time,
            user=user,
            details={"channel": selected.value},
        )
        return CreatedSession(token=token, session=updated, user=user)

    def verify_email_recovery(
        self, token: str, code: str, *, now: datetime | None = None
    ) -> CreatedSession:
        """Compatibility wrapper for emailed lost-TOTP recovery."""
        from myownca.comms import NotificationChannel  # noqa: PLC0415

        return self.verify_delivery_recovery(
            token, NotificationChannel.EMAIL, code, now=now
        )

    def _assert_recovery_not_throttled(self, user: User, current_time: datetime) -> None:
        since = current_time - FAILURE_WINDOW
        failures = self.repository.count_recent_events(
            "recovery_code_failure", user_id=user.id, since=since
        ) + self.repository.count_recent_events(
            "delivery_recovery_failure", user_id=user.id, since=since
        )
        if failures >= MAX_FAILURES:
            raise ThrottledError("Too many recent recovery attempts")

    def _send_recovery_email(self, user: User, code: str) -> None:
        from myownca.comms import NotificationChannel  # noqa: PLC0415

        self._send_recovery_message(
            user,
            NotificationChannel.EMAIL,
            user.email,
            code,
            purpose=TOTP_RECOVERY_PURPOSE,
        )

    def _issue_recovery_challenge(
        self,
        user: User,
        *,
        purpose: str,
        channel,
        current_time: datetime,
    ) -> None:
        if not self._channel_enabled(channel):
            raise AuthError(f"Recovery channel '{channel.value}' is not configured")
        recipient = self._recovery_recipient(user, channel)
        if not recipient:
            raise AuthError("No account contact is available for this recovery channel")
        code = f"{secrets.randbelow(100_000_000):08d}"
        self._send_recovery_message(
            user,
            channel,
            recipient,
            code,
            purpose=purpose,
        )
        self.repository.replace_recovery_challenge(
            RecoveryChallenge(
                id=str(uuid4()),
                user_id=user.id,
                purpose=purpose,
                channel=channel.value,
                code_hash=self._hash_recovery(self._normalize_code(code)),
                created_at=current_time,
                expires_at=current_time + EMAIL_RECOVERY_TTL,
            ),
            consumed_at=current_time,
        )

    def _verify_delivery_code(
        self,
        user: User,
        *,
        purpose: str,
        channel,
        code: str,
        current_time: datetime,
    ) -> bool:
        challenge = self.repository.get_active_recovery_challenge(
            user_id=user.id,
            purpose=purpose,
            channel=channel.value,
            now=current_time,
        )
        supplied_hash = self._hash_recovery(self._normalize_code(code))
        expected_hash = challenge.code_hash if challenge is not None else "0" * 64
        matches = secrets.compare_digest(expected_hash, supplied_hash)
        if challenge is None or not matches:
            return False
        return self.repository.consume_recovery_challenge(challenge.id, current_time)

    def _channel_enabled(self, channel) -> bool:
        if self.comms is None:
            return False
        if not hasattr(self.comms, "get_config"):
            return True  # compatibility with injected test/embedding transports
        try:
            config = self.comms.get_config(channel)
        except Exception:  # noqa: BLE001 - normalize transport/config failures
            return False
        return config is not None and config.enabled

    def _recovery_recipient(self, user: User, channel) -> str | None:
        from myownca.comms import NotificationChannel  # noqa: PLC0415

        if channel is NotificationChannel.SMS:
            if self.contacts is None:
                return None
            person = self.contacts.get_person_by_email(user.email)
            return person.phone if person and person.phone else None
        if channel is NotificationChannel.SLACK:
            if self.contacts is not None:
                person = self.contacts.get_person_by_email(user.email)
                if person and person.slack_handle:
                    return person.slack_handle
            return user.email
        return user.email

    def _send_recovery_message(
        self,
        user: User,
        channel,
        recipient: str,
        code: str,
        *,
        purpose: str,
    ) -> None:
        from myownca.comms import CommsError, Message  # noqa: PLC0415

        minutes = int(EMAIL_RECOVERY_TTL.total_seconds() // 60)
        subject = "myOwnCA account recovery code"
        next_step = (
            "Entering it will let you choose a new password. If TOTP is required for "
            "your role, you will also set up a new authenticator app."
            if purpose == PASSWORD_RECOVERY_PURPOSE
            else "Entering it will sign you in and require you to set up a new authenticator app."
        )
        body = (
            f"Your myOwnCA account recovery code is: {code}\n\n"
            f"It expires in {minutes} minutes and can be used once. {next_step}\n\n"
            "If you did not request this, ignore this message and consider changing your password."
        )
        if self.notifications is not None:
            try:
                rendered = self.notifications.render_otp(
                    code=code, email=user.email, expires_minutes=minutes
                )
            except Exception:  # noqa: BLE001 - template problems fall back to the default text
                rendered = None
            if rendered is not None:
                subject, body = rendered
        try:
            result = self.comms.send(channel, recipient, Message(body=body, subject=subject))
            if result is not None and not result.success:
                raise AuthError("Recovery message delivery was rejected")
        except CommsError as exc:
            raise AuthError(f"Could not send recovery message: {exc}") from exc

    def _hash_recovery(self, normalized_code: str) -> str:
        return hmac.new(self._recovery_pepper, normalized_code.encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def _normalize_code(code: str) -> str:
        return "".join(ch for ch in code if ch.isalnum()).upper()

    def identify(self, token: str | None) -> User | None:
        """Best-effort, side-effect-free actor lookup for audit logging.

        Returns the user for a live session token, or None. Never raises and
        never mutates the session (no expiry refresh).
        """
        if not token:
            return None
        try:
            session = self.repository.get_session_by_token_hash(_hash_token(token))
            if session is None or session.revoked_at is not None:
                return None
            return self.repository.get_user(session.user_id)
        except Exception:  # noqa: BLE001 - identification is advisory only
            return None

    def require_session(
        self,
        token: str | None,
        *,
        allow_incomplete: bool = False,
        now: datetime | None = None,
    ) -> tuple[AuthSession, User]:
        if not token:
            raise AuthenticationError("Authentication required")
        current_time = _utc_now(now)
        session = self.repository.get_session_by_token_hash(_hash_token(token))
        if session is None or session.revoked_at is not None:
            raise AuthenticationError("Session is invalid")
        if current_time >= session.expires_at or current_time >= session.absolute_expires_at:
            self.repository.update_session(session.id, revoked_at=current_time)
            raise AuthenticationError("Session has expired")
        user = self.repository.get_user(session.user_id)
        if not user.is_active:
            self.repository.update_session(session.id, revoked_at=current_time)
            raise AuthenticationError("Account is inactive")
        if session.stage is not SessionStage.ACTIVE and not allow_incomplete:
            raise AuthenticationError("Session setup is incomplete")
        profile = SESSION_PROFILES[user.role]
        refreshed_expiry = min(
            current_time + profile.idle_timeout,
            session.absolute_expires_at,
        )
        self.repository.update_session(
            session.id,
            last_seen_at=current_time,
            expires_at=refreshed_expiry,
        )
        refreshed = self.repository.get_session_by_token_hash(session.token_hash)
        assert refreshed is not None
        return refreshed, user

    def logout(self, token: str | None, *, now: datetime | None = None) -> None:
        if not token:
            return
        current_time = _utc_now(now)
        session = self.repository.get_session_by_token_hash(_hash_token(token))
        if session is not None and session.revoked_at is None:
            self.repository.update_session(session.id, revoked_at=current_time)

    def require_csrf(self, session: AuthSession, supplied_token: str | None) -> None:
        if not supplied_token or not secrets.compare_digest(session.csrf_token, supplied_token):
            raise CSRFError("CSRF token is missing or invalid")

    def require_recent_mfa(
        self,
        session: AuthSession,
        *,
        now: datetime | None = None,
    ) -> None:
        status = recent_mfa_status(session, now=now)
        if not status["mfa_recent"]:
            raise AuthenticationError(
                "Recent MFA verification required. Re-authenticate with TOTP and try again."
            )

    def require_recent_sensitive_auth(
        self,
        session: AuthSession,
        user: User,
        *,
        now: datetime | None = None,
    ) -> None:
        status = sensitive_auth_status(
            session,
            method="totp" if self.totp_required(user.role) else "password",
            now=now,
        )
        if not status["recent"]:
            if status["method"] == "totp":
                raise AuthenticationError(
                    "Recent MFA verification required. Re-authenticate with TOTP and try again."
                )
            raise AuthenticationError(
                "Recent authentication required. Re-authenticate with your current password and try again."
            )

    def require_role(self, user: User, *roles: Role) -> None:
        if user.role not in roles:
            display_names = {
                Role.ADMIN: "administrator",
                Role.SUPERUSER: "Certificate Operator",
                Role.AUDITOR: "auditor",
                Role.USER: "user",
            }
            allowed = ", ".join(display_names[role] for role in roles)
            raise AuthorizationError(f"Requires one of: {allowed}")

    def list_pending_proposals(self, actor: User) -> list[AdminChangeProposal]:
        self._require_admin(actor)
        return self.repository.list_pending_proposals()

    def create_hsm_backup_proposal(
        self,
        actor: User,
        *,
        reason: str,
        now: datetime | None = None,
    ) -> AdminChangeProposal:
        self._require_admin(actor)
        cleaned_reason = reason.strip()
        if len(cleaned_reason) < 10 or len(cleaned_reason) > 500:
            raise AuthError("HSM backup export reason must be 10 to 500 characters")
        return self._create_proposal(
            actor,
            change_type=AdminChangeType.HSM_RAW_BACKUP_EXPORT,
            target_user_id=actor.id,
            payload={"reason": cleaned_reason},
            now=_utc_now(now),
            force_approval=True,
        )

    def _create_session(
        self,
        user: User,
        stage: SessionStage,
        current_time: datetime,
        *,
        idle_timeout: timedelta | None = None,
        absolute_timeout: timedelta | None = None,
    ) -> CreatedSession:
        token = secrets.token_urlsafe(32)
        profile = SESSION_PROFILES[user.role]
        idle = idle_timeout or profile.idle_timeout
        absolute = absolute_timeout or profile.absolute_timeout
        absolute_expires_at = current_time + absolute
        session = AuthSession(
            id=str(uuid4()),
            token_hash=_hash_token(token),
            user_id=user.id,
            csrf_token=secrets.token_urlsafe(24),
            stage=stage,
            created_at=current_time,
            last_seen_at=current_time,
            expires_at=min(current_time + idle, absolute_expires_at),
            absolute_expires_at=absolute_expires_at,
        )
        self.repository.add_session(session)
        return CreatedSession(token=token, session=session, user=user)

    def _next_stage_for_login(
        self,
        user: User,
        credential: PasswordCredential,
    ) -> SessionStage:
        if credential.must_change_password:
            return SessionStage.PASSWORD_CHANGE_REQUIRED
        return self._post_password_stage(user)

    def _post_password_stage(self, user: User) -> SessionStage:
        if not self.totp_required(user.role):
            return SessionStage.ACTIVE
        factor = self.repository.get_totp_factor(user.id)
        if factor is None or factor.confirmed_at is None:
            return SessionStage.TOTP_ENROLLMENT_REQUIRED
        return SessionStage.TOTP_REQUIRED

    def _verify_totp_code(
        self,
        user: User,
        factor: TOTPFactor,
        code: str,
        current_time: datetime,
    ) -> int:
        recent_failures = self.repository.count_recent_events(
            "totp_failure",
            user_id=user.id,
            since=current_time - FAILURE_WINDOW,
        )
        if recent_failures >= MAX_FAILURES:
            raise ThrottledError("Too many recent TOTP failures")
        secret = self._decrypt(factor.secret_ciphertext)
        base_step = current_step(current_time)
        for step in range(base_step - 1, base_step + 2):
            if factor.last_verified_step is not None and step <= factor.last_verified_step:
                continue
            if secrets.compare_digest(code_for_step(secret, step), code):
                self._record_event("totp_success", current_time, user=user)
                return step
        self._record_event("totp_failure", current_time, user=user)
        raise AuthenticationError("Invalid TOTP code")

    def _create_proposal(
        self,
        actor: User,
        *,
        change_type: AdminChangeType,
        target_user_id: str,
        payload: dict[str, object],
        now: datetime,
        new_user: User | None = None,
        force_approval: bool = False,
    ) -> AdminChangeProposal:
        status, proposal = self.repository.create_governed_proposal(
            proposal_id=str(uuid4()),
            change_type=change_type,
            proposer_id=actor.id,
            target_user_id=target_user_id,
            created_at=now,
            expires_at=now + PROPOSAL_TTL,
            payload=payload,
            new_user=new_user,
            force_approval=force_approval,
        )
        if status == "invalid_proposer":
            raise AuthorizationError("An active administrator account is required")
        if status == "insufficient_admins":
            raise AuthError("Dual control requires two active administrators")
        if status == "pending_exists":
            raise AuthError("An HSM backup export proposal is already pending")
        if status != "created" or proposal is None:
            raise AuthError("Install governance state is unavailable")
        return proposal


    def _require_admin(self, actor: User) -> None:
        if actor.role is not Role.ADMIN:
            raise AuthorizationError("Admin role required")

    def _validate_password(self, password: str) -> None:
        if len(password) < PASSWORD_MIN_LENGTH:
            raise AuthError(f"Passwords must be at least {PASSWORD_MIN_LENGTH} characters long")

    def _encrypt(self, plaintext: str) -> str:
        return self.cipher.encrypt(plaintext.encode()).decode()

    def _decrypt(self, ciphertext: str) -> str:
        return decrypt_secret(self.cipher, ciphertext, what="The stored TOTP secret")

    def _record_event(
        self,
        event_type: str,
        occurred_at: datetime,
        *,
        user: User | None = None,
        email: str | None = None,
        source_ip: str | None = None,
        details: dict[str, object] | None = None,
    ) -> None:
        self.repository.add_event(
            AuthEvent(
                id=str(uuid4()),
                event_type=event_type,
                user_id=user.id if user else None,
                email=email,
                source_ip=source_ip,
                occurred_at=occurred_at,
                details_json=json.dumps(details or {}, sort_keys=True),
            )
        )


def _derive_fernet_key(secret: str) -> bytes:
    """This subsystem's domain-separated Fernet key (see myownca.secret_keys)."""
    return derive_fernet_key(secret, CA_AUTH_DOMAIN)


def _format_recovery_code(raw_hex: str) -> str:
    upper = raw_hex.upper()
    return f"{upper[:5]}-{upper[5:]}"


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def recent_mfa_status(
    session: AuthSession,
    *,
    now: datetime | None = None,
) -> dict[str, object]:
    current_time = _utc_now(now)
    verified = session.mfa_verified_at
    window_seconds = int(RECENT_MFA_WINDOW.total_seconds())
    if verified is None:
        return {
            "mfa_verified_at": None,
            "mfa_recent": False,
            "mfa_valid_for_seconds": 0,
            "mfa_window_seconds": window_seconds,
        }
    verified = _utc_now(verified)
    age = current_time - verified
    recent = timedelta(0) <= age <= RECENT_MFA_WINDOW
    remaining = max(0, int((verified + RECENT_MFA_WINDOW - current_time).total_seconds()))
    return {
        "mfa_verified_at": verified.isoformat(),
        "mfa_recent": recent,
        "mfa_valid_for_seconds": remaining if recent else 0,
        "mfa_window_seconds": window_seconds,
    }


def sensitive_auth_status(
    session: AuthSession,
    *,
    method: str,
    now: datetime | None = None,
) -> dict[str, object]:
    if method not in {"totp", "password"}:
        raise ValueError(f"Unknown sensitive authentication method: {method}")
    current_time = _utc_now(now)
    verified = (
        session.mfa_verified_at if method == "totp" else session.password_verified_at
    )
    window_seconds = int(RECENT_MFA_WINDOW.total_seconds())
    if verified is None:
        return {
            "method": method,
            "verified_at": None,
            "recent": False,
            "valid_for_seconds": 0,
            "window_seconds": window_seconds,
        }
    verified = _utc_now(verified)
    age = current_time - verified
    recent = timedelta(0) <= age <= RECENT_MFA_WINDOW
    remaining = max(
        0,
        int((verified + RECENT_MFA_WINDOW - current_time).total_seconds()),
    )
    return {
        "method": method,
        "verified_at": verified.isoformat(),
        "recent": recent,
        "valid_for_seconds": remaining if recent else 0,
        "window_seconds": window_seconds,
    }


def _utc_now(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        return current.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc)
