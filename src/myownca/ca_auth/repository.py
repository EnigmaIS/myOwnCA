from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timezone
from uuid import uuid4

from myownca.domain import (
    AdminChangeApproval,
    AdminChangeProposal,
    AdminChangeStatus,
    AdminChangeType,
    AuthEvent,
    AuthSession,
    EmailRecoveryChallenge,
    GovernanceMode,
    PasswordCredential,
    PRIVILEGED_ROLES,
    RecoveryChallenge,
    Role,
    SessionStage,
    TOTPFactor,
    TOTP_REQUIRED_ROLES,
    User,
)
from myownca.storage.database import Database
from myownca.storage.repositories import RepositoryError


class AuthRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def has_any_users(self) -> bool:
        with self.database.connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS count FROM users").fetchone()
        return bool(row["count"])

    def get_user(self, user_id: str) -> User:
        with self.database.connect() as connection:
            row = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            raise RepositoryError(f"Unknown user: {user_id}")
        return _user_from_row(row)

    def get_user_by_email(self, email: str) -> User | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE lower(email) = lower(?)",
                (email,),
            ).fetchone()
        return None if row is None else _user_from_row(row)

    def add_user(self, user: User) -> None:
        with self.database.connect() as connection:
            connection.execute(
                "INSERT INTO users(id, email, role, is_active) VALUES (?, ?, ?, ?)",
                (user.id, user.email, user.role.value, int(user.is_active)),
            )

    def get_first_login_guide_outcome(self, user_id: str) -> str | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT outcome FROM first_login_guides WHERE user_id = ?",
                (user_id,),
            ).fetchone()
        return None if row is None else str(row["outcome"])

    def dismiss_first_login_guide(
        self,
        user_id: str,
        *,
        outcome: str,
        dismissed_at: datetime,
    ) -> None:
        if outcome not in {"completed", "skipped"}:
            raise ValueError("First-login guide outcome must be completed or skipped")
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO first_login_guides(user_id, outcome, dismissed_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    outcome = excluded.outcome,
                    dismissed_at = excluded.dismissed_at
                """,
                (user_id, outcome, _dump_dt(dismissed_at)),
            )

    def bootstrap_admins(
        self,
        admins: tuple[User, ...],
        credentials: tuple[PasswordCredential, ...],
    ) -> str:
        """Insert the complete bootstrap set, or no accounts at all.

        The governance singleton is also the bootstrap mutex. This prevents two
        setup/CLI processes from both observing an empty users table and leaving
        a partial or mixed initial administrator set.
        """
        if len(admins) != len(credentials):
            raise ValueError("Each bootstrap administrator requires a credential")
        with self.database.connect() as connection:
            governance = self._lock_governance_row(connection)
            if governance is None:
                return "unavailable"
            if (
                governance["mode"] == GovernanceMode.DUAL_CONTROL.value
                and len(admins) < 2
            ):
                return "requires_two"
            row = connection.execute("SELECT COUNT(*) AS count FROM users").fetchone()
            if row is not None and int(row["count"]) != 0:
                return "not_empty"
            for user, credential in zip(admins, credentials, strict=True):
                connection.execute(
                    "INSERT INTO users(id, email, role, is_active) VALUES (?, ?, ?, ?)",
                    (user.id, user.email, user.role.value, int(user.is_active)),
                )
                connection.execute(
                    """
                    INSERT INTO password_credentials(
                        user_id, password_hash, must_change_password, updated_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        credential.user_id,
                        credential.password_hash,
                        int(credential.must_change_password),
                        _dump_dt(credential.updated_at),
                    ),
                )
        return "created"

    def count_active_users_with_role(self, role: Role) -> int:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM users WHERE role = ? AND is_active = 1",
                (role.value,),
            ).fetchone()
        return int(row["count"])

    def get_governance_mode(self) -> GovernanceMode:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT mode FROM install_governance WHERE singleton_id = 1"
            ).fetchone()
        # Migration 0024 always seeds the row. Keep the fallback fail-safe for
        # hand-built/partially migrated databases: never silently weaken them.
        return GovernanceMode.DUAL_CONTROL if row is None else GovernanceMode(row["mode"])

    def initialize_governance_mode(
        self,
        mode: GovernanceMode,
        updated_at: datetime,
    ) -> None:
        """Apply an explicit install-time mode only over the migration default."""
        with self.database.connect() as connection:
            governance = self._lock_governance_row(connection)
            users = connection.execute(
                "SELECT COUNT(*) AS count FROM users"
            ).fetchone()
            has_users = users is not None and int(users["count"]) > 0
            if mode is GovernanceMode.SINGLE_ADMIN and has_users:
                return
            if governance is None:
                connection.execute(
                    """
                    INSERT INTO install_governance(
                        singleton_id, mode, source, updated_at, updated_by
                    ) VALUES (1, ?, 'install', ?, NULL)
                    """,
                    (mode.value, _dump_dt(updated_at)),
                )
                return
            cursor = connection.execute(
                """
                UPDATE install_governance
                SET mode = ?, source = 'install', updated_at = ?, updated_by = NULL
                WHERE singleton_id = 1 AND source = 'migration_default'
                """,
                (mode.value, _dump_dt(updated_at)),
            )
            if cursor.rowcount == 0:
                return

    def get_totp_policy(self) -> dict[Role, bool]:
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT role, totp_required FROM role_totp_policies ORDER BY role"
            ).fetchall()
        policy = {Role(row["role"]): bool(row["totp_required"]) for row in rows}
        # Migration 0026 always seeds all roles. Fail closed for a hand-built or
        # partially migrated database by retaining the historical requirements.
        for role in Role:
            policy.setdefault(role, role in TOTP_REQUIRED_ROLES)
        return policy

    def is_totp_required(self, role: Role) -> bool:
        return self.get_totp_policy()[role]

    def initialize_totp_policy(
        self,
        required_roles: set[Role],
        updated_at: datetime,
    ) -> None:
        """Apply setup/CLI policy only to a not-yet-used installation."""
        with self.database.connect() as connection:
            users = connection.execute("SELECT COUNT(*) AS count FROM users").fetchone()
            if users is not None and int(users["count"]) > 0:
                return
            for role in Role:
                connection.execute(
                    """
                    UPDATE role_totp_policies
                    SET totp_required = ?, source = 'install', updated_at = ?, updated_by = NULL
                    WHERE role = ? AND source = 'migration_default'
                    """,
                    (int(role in required_roles), _dump_dt(updated_at), role.value),
                )

    def _lock_totp_policy_rows(self, connection) -> dict[Role, bool]:
        suffix = "" if self.database.dialect == "sqlite" else " FOR UPDATE"
        if self.database.dialect == "sqlite":
            connection.execute(
                "UPDATE role_totp_policies SET role = role WHERE role = role"
            )
        rows = connection.execute(
            "SELECT role, totp_required FROM role_totp_policies ORDER BY role" + suffix
        ).fetchall()
        policy = {Role(row["role"]): bool(row["totp_required"]) for row in rows}
        if set(policy) != set(Role):
            raise RepositoryError("Role TOTP policy is incomplete")
        return policy

    def enable_dual_control_if_safe(
        self,
        *,
        updated_at: datetime,
        updated_by: str,
    ) -> str:
        """Enable dual control only in the same transaction that proves its floor.

        The governance singleton serializes this with account deactivation.
        """
        with self.database.connect() as connection:
            governance = self._lock_governance_row(connection)
            if governance is None:
                return "unavailable"
            actor = self._locked_user_row(connection, updated_by)
            if (
                actor is None
                or actor["role"] != Role.ADMIN.value
                or not bool(actor["is_active"])
            ):
                return "invalid_actor"
            if governance["mode"] == GovernanceMode.DUAL_CONTROL.value:
                return "already_dual"
            suffix = "" if self.database.dialect == "sqlite" else " FOR UPDATE"
            admins = connection.execute(
                """
                SELECT id FROM users
                WHERE role = ? AND is_active = 1
                ORDER BY id
                """ + suffix,
                (Role.ADMIN.value,),
            ).fetchall()
            if len(admins) < 2:
                return "insufficient_admins"
            connection.execute(
                """
                UPDATE install_governance
                SET mode = ?, source = 'runtime', updated_at = ?, updated_by = ?
                WHERE singleton_id = 1 AND mode = ?
                """,
                (
                    GovernanceMode.DUAL_CONTROL.value,
                    _dump_dt(updated_at),
                    updated_by,
                    GovernanceMode.SINGLE_ADMIN.value,
                ),
            )
            return "enabled"

    def set_user_active_with_governance_guard(
        self,
        user_id: str,
        *,
        actor_id: str,
        active: bool,
    ) -> str:
        """Set account status without racing the install's active-admin floor."""
        with self.database.connect() as connection:
            governance = self._lock_governance_row(connection)
            if governance is None:
                return "unavailable"
            actor = self._locked_user_row(connection, actor_id)
            if (
                actor is None
                or actor["role"] not in {Role.ADMIN.value, Role.SUPERUSER.value}
                or not bool(actor["is_active"])
            ):
                return "invalid_actor"
            target = self._locked_user_row(connection, user_id)
            if target is None:
                return "not_found"
            if bool(target["is_active"]) is active:
                return "unchanged"
            if active:
                pending_role_grant = connection.execute(
                    """
                    SELECT 1 FROM admin_change_proposals
                    WHERE target_user_id = ? AND change_type = ? AND status = ?
                    LIMIT 1
                    """,
                    (
                        user_id,
                        AdminChangeType.PRIVILEGED_ROLE_GRANT.value,
                        AdminChangeStatus.PENDING.value,
                    ),
                ).fetchone()
                if pending_role_grant is not None:
                    return "pending_role_grant"
                connection.execute(
                    "UPDATE users SET is_active = 1 WHERE id = ?",
                    (user_id,),
                )
                return "changed"

            if target["role"] == Role.ADMIN.value:
                suffix = "" if self.database.dialect == "sqlite" else " FOR UPDATE"
                admins = connection.execute(
                    """
                    SELECT id FROM users
                    WHERE role = ? AND is_active = 1
                    ORDER BY id
                    """ + suffix,
                    (Role.ADMIN.value,),
                ).fetchall()
                minimum = (
                    2
                    if governance["mode"] == GovernanceMode.DUAL_CONTROL.value
                    else 1
                )
                if len(admins) <= minimum:
                    return "admin_floor"
            connection.execute(
                "UPDATE users SET is_active = 0 WHERE id = ?",
                (user_id,),
            )
            return "changed"

    def _lock_governance_row(self, connection):
        """Serialize install-governance and bootstrap mutations."""
        if self.database.dialect == "sqlite":
            connection.execute(
                """
                UPDATE install_governance
                SET singleton_id = singleton_id
                WHERE singleton_id = 1
                """
            )
            return connection.execute(
                "SELECT mode, source FROM install_governance WHERE singleton_id = 1"
            ).fetchone()
        return connection.execute(
            """
            SELECT mode, source FROM install_governance
            WHERE singleton_id = 1 FOR UPDATE
            """
        ).fetchone()

    def _locked_user_row(self, connection, user_id: str):
        suffix = "" if self.database.dialect == "sqlite" else " FOR UPDATE"
        return connection.execute(
            "SELECT id, email, role, is_active FROM users WHERE id = ?" + suffix,
            (user_id,),
        ).fetchone()

    def _locked_proposal_row(self, connection, proposal_id: str):
        suffix = "" if self.database.dialect == "sqlite" else " FOR UPDATE"
        return connection.execute(
            "SELECT * FROM admin_change_proposals WHERE id = ?" + suffix,
            (proposal_id,),
        ).fetchone()

    @staticmethod
    def _proposal_from_connection(connection, proposal_id: str) -> AdminChangeProposal:
        row = connection.execute(
            "SELECT * FROM admin_change_proposals WHERE id = ?",
            (proposal_id,),
        ).fetchone()
        if row is None:
            raise RepositoryError(f"Unknown admin change proposal: {proposal_id}")
        return _proposal_from_row(row)

    @staticmethod
    def _upsert_password_credential(connection, credential: PasswordCredential) -> None:
        connection.execute(
            """
            INSERT INTO password_credentials(
                user_id, password_hash, must_change_password, updated_at
            ) VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                password_hash = excluded.password_hash,
                must_change_password = excluded.must_change_password,
                updated_at = excluded.updated_at
            """,
            (
                credential.user_id,
                credential.password_hash,
                int(credential.must_change_password),
                _dump_dt(credential.updated_at),
            ),
        )

    def _apply_proposal_mutation(
        self,
        connection,
        *,
        change_type: AdminChangeType,
        target_user_id: str,
        payload: dict[str, object],
        resolved_at: datetime,
        resolved_by_user_id: str | None = None,
    ) -> None:
        if change_type is AdminChangeType.ROLE_TOTP_POLICY_CHANGE:
            current = self._lock_totp_policy_rows(connection)
            previous = {Role(value) for value in payload.get("previous_required_roles", [])}
            requested = {Role(value) for value in payload.get("required_roles", [])}
            if {role for role, required in current.items() if required} != previous:
                raise RepositoryError(
                    "TOTP policy changed after this proposal was created"
                )
            changed_roles = [role for role in Role if current[role] != (role in requested)]
            for role in changed_roles:
                required = role in requested
                connection.execute(
                    """
                    UPDATE role_totp_policies
                    SET totp_required = ?, source = 'runtime', updated_at = ?, updated_by = ?
                    WHERE role = ?
                    """,
                    (
                        int(required),
                        _dump_dt(resolved_at),
                        resolved_by_user_id or target_user_id,
                        role.value,
                    ),
                )
                connection.execute(
                    """
                    UPDATE auth_sessions SET revoked_at = ?
                    WHERE revoked_at IS NULL
                      AND user_id IN (SELECT id FROM users WHERE role = ?)
                    """,
                    (_dump_dt(resolved_at), role.value),
                )
                if required:
                    continue
                for table in (
                    "totp_factors",
                    "totp_recovery_codes",
                    "email_recovery_challenges",
                ):
                    connection.execute(
                        f"""
                        DELETE FROM {table}
                        WHERE user_id IN (SELECT id FROM users WHERE role = ?)
                        """,  # noqa: S608 - fixed table list
                        (role.value,),
                    )
                connection.execute(
                    """
                    DELETE FROM account_recovery_challenges
                    WHERE purpose = ?
                      AND user_id IN (SELECT id FROM users WHERE role = ?)
                    """,
                    ("totp", role.value),
                )
            return
        if change_type is AdminChangeType.PRIVILEGED_ROLE_GRANT:
            requested_role = Role(str(payload["role"]))
            target = self._locked_user_row(connection, target_user_id)
            if (
                target is None
                or bool(target["is_active"])
                or target["role"]
                not in {Role.USER.value, requested_role.value}
            ):
                raise RepositoryError(
                    "Role-grant placeholder changed before approval"
                )
            has_session = connection.execute(
                "SELECT 1 FROM auth_sessions WHERE user_id = ? LIMIT 1",
                (target_user_id,),
            ).fetchone()
            if has_session is not None:
                raise RepositoryError(
                    "Role-grant placeholder has login history and cannot be approved"
                )
            password_hash = payload.get("temporary_password_hash")
            if password_hash is not None:
                self._upsert_password_credential(
                    connection,
                    PasswordCredential(
                        user_id=target_user_id,
                        password_hash=str(password_hash),
                        must_change_password=True,
                        updated_at=resolved_at,
                    ),
                )
            elif connection.execute(
                "SELECT 1 FROM password_credentials WHERE user_id = ?",
                (target_user_id,),
            ).fetchone() is None:
                raise RepositoryError("Role-grant credential is unavailable")
            cursor = connection.execute(
                """
                UPDATE users
                SET role = ?, is_active = 1
                WHERE id = ? AND is_active = 0 AND role IN (?, ?)
                """,
                (
                    requested_role.value,
                    target_user_id,
                    Role.USER.value,
                    requested_role.value,
                ),
            )
            if cursor.rowcount != 1:
                raise RepositoryError("Proposal target account is unavailable")
            return
        if change_type is AdminChangeType.PRIVILEGED_PASSWORD_RESET:
            self._upsert_password_credential(
                connection,
                PasswordCredential(
                    user_id=target_user_id,
                    password_hash=str(payload["temporary_password_hash"]),
                    must_change_password=True,
                    updated_at=resolved_at,
                ),
            )
            connection.execute(
                """
                UPDATE account_recovery_challenges SET consumed_at = ?
                WHERE user_id = ? AND consumed_at IS NULL
                """,
                (_dump_dt(resolved_at), target_user_id),
            )
            connection.execute(
                """
                UPDATE auth_sessions
                SET revoked_at = ?
                WHERE user_id = ? AND revoked_at IS NULL
                """,
                (_dump_dt(resolved_at), target_user_id),
            )
            return
        if change_type is AdminChangeType.PRIVILEGED_TOTP_RESET:
            for table in (
                "totp_factors",
                "totp_recovery_codes",
                "email_recovery_challenges",
                "account_recovery_challenges",
            ):
                connection.execute(
                    f"DELETE FROM {table} WHERE user_id = ?",  # noqa: S608
                    (target_user_id,),
                )
            connection.execute(
                """
                UPDATE auth_sessions
                SET revoked_at = ?
                WHERE user_id = ? AND revoked_at IS NULL
                """,
                (_dump_dt(resolved_at), target_user_id),
            )
            return
        if change_type is AdminChangeType.HSM_RAW_BACKUP_EXPORT:
            return
        raise RepositoryError(f"Unsupported governed proposal type: {change_type.value}")

    def _cleanup_role_grant_placeholder(
        self,
        connection,
        proposal: AdminChangeProposal,
    ) -> bool:
        """Delete an untouched failed grant target in the resolver transaction."""
        if proposal.change_type is not AdminChangeType.PRIVILEGED_ROLE_GRANT:
            return False
        target = self._locked_user_row(connection, proposal.target_user_id)
        if target is None or bool(target["is_active"]):
            return False
        requested_role = Role(str(decode_payload(proposal.payload_json)["role"]))
        if target["role"] not in {Role.USER.value, requested_role.value}:
            return False
        if connection.execute(
            "SELECT 1 FROM auth_sessions WHERE user_id = ? LIMIT 1",
            (proposal.target_user_id,),
        ).fetchone() is not None:
            return False
        other = connection.execute(
            """
            SELECT COUNT(*) AS count FROM admin_change_proposals
            WHERE (target_user_id = ? OR proposer_id = ?) AND id != ?
            """,
            (
                proposal.target_user_id,
                proposal.target_user_id,
                proposal.id,
            ),
        ).fetchone()
        if other is not None and int(other["count"]) != 0:
            return False
        resolved_at = proposal.resolved_at or datetime.now(timezone.utc)
        connection.execute(
            """
            INSERT INTO auth_events(
                id, event_type, user_id, email, occurred_at, details_json
            ) VALUES (?, ?, NULL, ?, ?, ?)
            """,
            (
                str(uuid4()),
                "role_grant_placeholder_discarded",
                target["email"],
                _dump_dt(resolved_at),
                encode_payload(
                    {
                        "proposal_id": proposal.id,
                        "target_user_id": proposal.target_user_id,
                        "resolution_status": proposal.status.value,
                        "change_type": proposal.change_type.value,
                    }
                ),
            ),
        )
        connection.execute(
            "DELETE FROM admin_change_approvals WHERE proposal_id = ?",
            (proposal.id,),
        )
        connection.execute(
            "DELETE FROM admin_change_proposals WHERE id = ?",
            (proposal.id,),
        )
        # Authentication failures may already reference the inactive placeholder.
        # Preserve that evidence while releasing the FK before deleting the user.
        connection.execute(
            "UPDATE auth_events SET user_id = NULL WHERE user_id = ?",
            (proposal.target_user_id,),
        )
        for table in (
            "password_credentials",
            "totp_factors",
            "totp_recovery_codes",
            "email_recovery_challenges",
            "account_recovery_challenges",
            "auth_sessions",
        ):
            connection.execute(
                f"DELETE FROM {table} WHERE user_id = ?",  # noqa: S608 - fixed table list
                (proposal.target_user_id,),
            )
        connection.execute(
            "DELETE FROM users WHERE id = ?",
            (proposal.target_user_id,),
        )
        return True

    def _expire_and_list_pending(
        self,
        connection,
        current_time: datetime,
    ) -> list[AdminChangeProposal]:
        rows = connection.execute(
            """
            SELECT * FROM admin_change_proposals
            WHERE status = ?
            ORDER BY created_at
            """,
            (AdminChangeStatus.PENDING.value,),
        ).fetchall()
        live: list[AdminChangeProposal] = []
        for row in rows:
            proposal = _proposal_from_row(row)
            if current_time < proposal.expires_at:
                live.append(proposal)
                continue
            cursor = connection.execute(
                """
                UPDATE admin_change_proposals
                SET status = ?, resolved_at = ?
                WHERE id = ? AND status = ?
                """,
                (
                    AdminChangeStatus.EXPIRED.value,
                    _dump_dt(current_time),
                    proposal.id,
                    AdminChangeStatus.PENDING.value,
                ),
            )
            if cursor.rowcount != 1:
                raise RepositoryError("Proposal was resolved concurrently")
            expired = replace(
                proposal,
                status=AdminChangeStatus.EXPIRED,
                resolved_at=current_time,
            )
            self._cleanup_role_grant_placeholder(connection, expired)
        return live

    def add_or_update_password_credential(self, credential: PasswordCredential) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO password_credentials(user_id, password_hash, must_change_password, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    password_hash = excluded.password_hash,
                    must_change_password = excluded.must_change_password,
                    updated_at = excluded.updated_at
                """,
                (
                    credential.user_id,
                    credential.password_hash,
                    int(credential.must_change_password),
                    _dump_dt(credential.updated_at),
                ),
            )

    def reset_ordinary_password_if_safe(
        self,
        credential: PasswordCredential,
        *,
        actor_id: str,
        revoked_at: datetime,
    ) -> str:
        """Reset an ordinary account unless it is a governed grant placeholder."""
        with self.database.connect() as connection:
            if self._lock_governance_row(connection) is None:
                return "unavailable"
            actor = self._locked_user_row(connection, actor_id)
            if (
                actor is None
                or actor["role"] not in {Role.ADMIN.value, Role.SUPERUSER.value}
                or not bool(actor["is_active"])
            ):
                return "invalid_actor"
            target = self._locked_user_row(connection, credential.user_id)
            if target is None:
                return "not_found"
            if target["role"] != Role.USER.value:
                return "privileged"
            pending_role_grant = connection.execute(
                """
                SELECT 1 FROM admin_change_proposals
                WHERE target_user_id = ? AND change_type = ? AND status = ?
                LIMIT 1
                """,
                (
                    credential.user_id,
                    AdminChangeType.PRIVILEGED_ROLE_GRANT.value,
                    AdminChangeStatus.PENDING.value,
                ),
            ).fetchone()
            if pending_role_grant is not None:
                return "pending_role_grant"
            self._upsert_password_credential(connection, credential)
            connection.execute(
                """
                UPDATE account_recovery_challenges SET consumed_at = ?
                WHERE user_id = ? AND consumed_at IS NULL
                """,
                (_dump_dt(revoked_at), credential.user_id),
            )
            connection.execute(
                """
                UPDATE auth_sessions
                SET revoked_at = ?
                WHERE user_id = ? AND revoked_at IS NULL
                """,
                (_dump_dt(revoked_at), credential.user_id),
            )
        return "reset"

    def get_password_credential(self, user_id: str) -> PasswordCredential | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM password_credentials WHERE user_id = ?",
                (user_id,),
            ).fetchone()
        if row is None:
            return None
        return PasswordCredential(
            user_id=row["user_id"],
            password_hash=row["password_hash"],
            must_change_password=bool(row["must_change_password"]),
            updated_at=_load_dt(row["updated_at"]),
        )

    def add_or_update_totp_factor(self, factor: TOTPFactor) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO totp_factors(
                    user_id, secret_ciphertext, confirmed_at, last_verified_step
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret_ciphertext = excluded.secret_ciphertext,
                    confirmed_at = excluded.confirmed_at,
                    last_verified_step = excluded.last_verified_step
                """,
                (
                    factor.user_id,
                    factor.secret_ciphertext,
                    _dump_dt(factor.confirmed_at) if factor.confirmed_at else None,
                    factor.last_verified_step,
                ),
            )

    def get_totp_factor(self, user_id: str) -> TOTPFactor | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM totp_factors WHERE user_id = ?",
                (user_id,),
            ).fetchone()
        if row is None:
            return None
        return TOTPFactor(
            user_id=row["user_id"],
            secret_ciphertext=row["secret_ciphertext"],
            confirmed_at=_load_dt(row["confirmed_at"]) if row["confirmed_at"] else None,
            last_verified_step=row["last_verified_step"],
        )

    def clear_totp_factor(self, user_id: str) -> None:
        with self.database.connect() as connection:
            connection.execute("DELETE FROM totp_factors WHERE user_id = ?", (user_id,))

    # -- recovery codes -------------------------------------------------------

    def replace_recovery_codes(
        self, user_id: str, code_hashes: list[str], created_at: datetime
    ) -> None:
        with self.database.connect() as connection:
            connection.execute("DELETE FROM totp_recovery_codes WHERE user_id = ?", (user_id,))
            connection.executemany(
                """
                INSERT INTO totp_recovery_codes(user_id, code_hash, created_at, used_at)
                VALUES (?, ?, ?, NULL)
                """,
                [(user_id, code_hash, _dump_dt(created_at)) for code_hash in code_hashes],
            )

    def clear_recovery_codes(self, user_id: str) -> None:
        with self.database.connect() as connection:
            connection.execute("DELETE FROM totp_recovery_codes WHERE user_id = ?", (user_id,))

    def count_unused_recovery_codes(self, user_id: str) -> int:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS n FROM totp_recovery_codes "
                "WHERE user_id = ? AND used_at IS NULL",
                (user_id,),
            ).fetchone()
        return int(row["n"])

    def consume_recovery_code(self, user_id: str, code_hash: str, used_at: datetime) -> bool:
        """Atomically mark a single unused code used; returns True if one matched."""
        with self.database.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE totp_recovery_codes SET used_at = ?
                WHERE user_id = ? AND code_hash = ? AND used_at IS NULL
                """,
                (_dump_dt(used_at), user_id, code_hash),
            )
            return cursor.rowcount > 0

    # -- email recovery challenges --------------------------------------------

    def add_email_recovery_challenge(self, challenge: EmailRecoveryChallenge) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO email_recovery_challenges(
                    id, user_id, code_hash, created_at, expires_at, consumed_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    challenge.id,
                    challenge.user_id,
                    challenge.code_hash,
                    _dump_dt(challenge.created_at),
                    _dump_dt(challenge.expires_at),
                    _dump_dt(challenge.consumed_at) if challenge.consumed_at else None,
                ),
            )

    def get_active_email_recovery_challenge(
        self, user_id: str, now: datetime
    ) -> EmailRecoveryChallenge | None:
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM email_recovery_challenges
                WHERE user_id = ? AND consumed_at IS NULL AND expires_at > ?
                ORDER BY created_at DESC LIMIT 1
                """,
                (user_id, _dump_dt(now)),
            ).fetchone()
        if row is None:
            return None
        return EmailRecoveryChallenge(
            id=row["id"],
            user_id=row["user_id"],
            code_hash=row["code_hash"],
            created_at=_load_dt(row["created_at"]),
            expires_at=_load_dt(row["expires_at"]),
            consumed_at=_load_dt(row["consumed_at"]) if row["consumed_at"] else None,
        )

    def consume_email_recovery_challenges(self, user_id: str, consumed_at: datetime) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                UPDATE email_recovery_challenges SET consumed_at = ?
                WHERE user_id = ? AND consumed_at IS NULL
                """,
                (_dump_dt(consumed_at), user_id),
            )

    # -- channel-neutral account recovery challenges -------------------------

    def replace_recovery_challenge(
        self,
        challenge: RecoveryChallenge,
        *,
        consumed_at: datetime,
    ) -> None:
        """Atomically invalidate older same-purpose proofs and install a new one."""
        with self.database.connect() as connection:
            connection.execute(
                """
                UPDATE account_recovery_challenges SET consumed_at = ?
                WHERE user_id = ? AND purpose = ? AND consumed_at IS NULL
                """,
                (_dump_dt(consumed_at), challenge.user_id, challenge.purpose),
            )
            connection.execute(
                """
                INSERT INTO account_recovery_challenges(
                    id, user_id, purpose, channel, code_hash,
                    created_at, expires_at, consumed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    challenge.id,
                    challenge.user_id,
                    challenge.purpose,
                    challenge.channel,
                    challenge.code_hash,
                    _dump_dt(challenge.created_at),
                    _dump_dt(challenge.expires_at),
                    None,
                ),
            )

    def get_active_recovery_challenge(
        self,
        *,
        user_id: str,
        purpose: str,
        channel: str,
        now: datetime,
    ) -> RecoveryChallenge | None:
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM account_recovery_challenges
                WHERE user_id = ? AND purpose = ? AND channel = ?
                  AND consumed_at IS NULL AND expires_at > ?
                ORDER BY created_at DESC LIMIT 1
                """,
                (user_id, purpose, channel, _dump_dt(now)),
            ).fetchone()
        if row is None:
            return None
        return RecoveryChallenge(
            id=row["id"],
            user_id=row["user_id"],
            purpose=row["purpose"],
            channel=row["channel"],
            code_hash=row["code_hash"],
            created_at=_load_dt(row["created_at"]),
            expires_at=_load_dt(row["expires_at"]),
            consumed_at=_load_dt(row["consumed_at"]) if row["consumed_at"] else None,
        )

    def consume_recovery_challenge(self, challenge_id: str, consumed_at: datetime) -> bool:
        with self.database.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE account_recovery_challenges SET consumed_at = ?
                WHERE id = ? AND consumed_at IS NULL AND expires_at > ?
                """,
                (_dump_dt(consumed_at), challenge_id, _dump_dt(consumed_at)),
            )
        return cursor.rowcount > 0

    def consume_recovery_challenges(
        self,
        user_id: str,
        consumed_at: datetime,
        *,
        purpose: str | None = None,
    ) -> None:
        sql = (
            "UPDATE account_recovery_challenges SET consumed_at = ? "
            "WHERE user_id = ? AND consumed_at IS NULL"
        )
        params: list[object] = [_dump_dt(consumed_at), user_id]
        if purpose is not None:
            sql += " AND purpose = ?"
            params.append(purpose)
        with self.database.connect() as connection:
            connection.execute(sql, params)

    def add_session(self, session: AuthSession) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO auth_sessions(
                    id, token_hash, user_id, csrf_token, stage, created_at, last_seen_at,
                    expires_at, absolute_expires_at, revoked_at, mfa_verified_at,
                    password_verified_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session.id,
                    session.token_hash,
                    session.user_id,
                    session.csrf_token,
                    session.stage.value,
                    _dump_dt(session.created_at),
                    _dump_dt(session.last_seen_at),
                    _dump_dt(session.expires_at),
                    _dump_dt(session.absolute_expires_at),
                    _dump_dt(session.revoked_at) if session.revoked_at else None,
                    _dump_dt(session.mfa_verified_at) if session.mfa_verified_at else None,
                    _dump_dt(session.password_verified_at)
                    if session.password_verified_at else None,
                ),
            )

    def get_session_by_token_hash(self, token_hash: str) -> AuthSession | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM auth_sessions WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
        return None if row is None else _session_from_row(row)

    def update_session(
        self,
        session_id: str,
        *,
        stage: SessionStage | None = None,
        last_seen_at: datetime | None = None,
        expires_at: datetime | None = None,
        revoked_at: datetime | None = None,
        mfa_verified_at: datetime | None = None,
        password_verified_at: datetime | None = None,
    ) -> None:
        updates: list[str] = []
        params: list[object] = []
        if stage is not None:
            updates.append("stage = ?")
            params.append(stage.value)
        if last_seen_at is not None:
            updates.append("last_seen_at = ?")
            params.append(_dump_dt(last_seen_at))
        if expires_at is not None:
            updates.append("expires_at = ?")
            params.append(_dump_dt(expires_at))
        if revoked_at is not None:
            updates.append("revoked_at = ?")
            params.append(_dump_dt(revoked_at))
        if mfa_verified_at is not None:
            updates.append("mfa_verified_at = ?")
            params.append(_dump_dt(mfa_verified_at))
        if password_verified_at is not None:
            updates.append("password_verified_at = ?")
            params.append(_dump_dt(password_verified_at))
        if not updates:
            return
        params.append(session_id)
        with self.database.connect() as connection:
            connection.execute(
                f"UPDATE auth_sessions SET {', '.join(updates)} WHERE id = ?",
                params,
            )

    def complete_password_recovery(
        self,
        *,
        session_id: str,
        credential: PasswordCredential,
        completed_at: datetime,
        expires_at: datetime,
        absolute_expires_at: datetime,
    ) -> SessionStage | None:
        """Atomically install a recovered credential and invalidate old trust."""
        suffix = "" if self.database.dialect == "sqlite" else " FOR UPDATE"
        with self.database.connect() as connection:
            session = connection.execute(
                "SELECT * FROM auth_sessions WHERE id = ?" + suffix,
                (session_id,),
            ).fetchone()
            if (
                session is None
                or session["user_id"] != credential.user_id
                or session["stage"] != SessionStage.PASSWORD_RECOVERY_REQUIRED.value
                or session["revoked_at"] is not None
                or session["expires_at"] <= _dump_dt(completed_at)
                or session["absolute_expires_at"] <= _dump_dt(completed_at)
            ):
                return None

            user = self._locked_user_row(connection, credential.user_id)
            policy = None
            if user is not None:
                policy = connection.execute(
                    "SELECT totp_required FROM role_totp_policies WHERE role = ?" + suffix,
                    (user["role"],),
                ).fetchone()
            # Missing user/policy state fails secure: reset the old factor and
            # require enrollment before granting an active session.
            reset_totp = user is None or policy is None or bool(policy["totp_required"])
            next_stage = (
                SessionStage.TOTP_ENROLLMENT_REQUIRED
                if reset_totp
                else SessionStage.ACTIVE
            )

            self._upsert_password_credential(connection, credential)
            if reset_totp:
                connection.execute(
                    "DELETE FROM totp_factors WHERE user_id = ?",
                    (credential.user_id,),
                )
                connection.execute(
                    "DELETE FROM totp_recovery_codes WHERE user_id = ?",
                    (credential.user_id,),
                )
            connection.execute(
                """
                UPDATE email_recovery_challenges SET consumed_at = ?
                WHERE user_id = ? AND consumed_at IS NULL
                """,
                (_dump_dt(completed_at), credential.user_id),
            )
            connection.execute(
                """
                UPDATE account_recovery_challenges SET consumed_at = ?
                WHERE user_id = ? AND consumed_at IS NULL
                """,
                (_dump_dt(completed_at), credential.user_id),
            )
            connection.execute(
                """
                UPDATE auth_sessions SET revoked_at = ?
                WHERE user_id = ? AND id <> ? AND revoked_at IS NULL
                """,
                (_dump_dt(completed_at), credential.user_id, session_id),
            )
            connection.execute(
                """
                UPDATE auth_sessions
                SET stage = ?, last_seen_at = ?, expires_at = ?, absolute_expires_at = ?,
                    mfa_verified_at = NULL, password_verified_at = NULL
                WHERE id = ?
                """,
                (
                    next_stage.value,
                    _dump_dt(completed_at),
                    _dump_dt(expires_at),
                    _dump_dt(absolute_expires_at),
                    session_id,
                ),
            )
        return next_stage

    def revoke_sessions_for_user(self, user_id: str, revoked_at: datetime) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                UPDATE auth_sessions
                SET revoked_at = ?
                WHERE user_id = ? AND revoked_at IS NULL
                """,
                (_dump_dt(revoked_at), user_id),
            )

    def add_event(self, event: AuthEvent) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO auth_events(
                    id, event_type, user_id, email, occurred_at, source_ip, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.id,
                    event.event_type,
                    event.user_id,
                    event.email,
                    _dump_dt(event.occurred_at),
                    event.source_ip,
                    event.details_json,
                ),
            )

    def count_recent_events(
        self,
        event_type: str,
        *,
        since: datetime,
        email: str | None = None,
        user_id: str | None = None,
        source_ip: str | None = None,
    ) -> int:
        clauses = ["event_type = ?", "occurred_at >= ?"]
        params: list[object] = [event_type, _dump_dt(since)]
        if email is not None:
            clauses.append("lower(email) = lower(?)")
            params.append(email)
        if user_id is not None:
            clauses.append("user_id = ?")
            params.append(user_id)
        if source_ip is not None:
            clauses.append("source_ip = ?")
            params.append(source_ip)
        with self.database.connect() as connection:
            row = connection.execute(
                f"SELECT COUNT(*) AS count FROM auth_events WHERE {' AND '.join(clauses)}",
                params,
            ).fetchone()
        return int(row["count"])

    def create_governed_proposal(
        self,
        *,
        proposal_id: str,
        change_type: AdminChangeType,
        proposer_id: str,
        target_user_id: str,
        payload: dict[str, object],
        created_at: datetime,
        expires_at: datetime,
        new_user: User | None = None,
        force_approval: bool = False,
    ) -> tuple[str, AdminChangeProposal | None]:
        """Capture policy, insert, and (in single mode) apply in one transaction."""
        with self.database.connect() as connection:
            governance = self._lock_governance_row(connection)
            if governance is None:
                return "unavailable", None
            proposer = self._locked_user_row(connection, proposer_id)
            if (
                proposer is None
                or proposer["role"] != Role.ADMIN.value
                or not bool(proposer["is_active"])
            ):
                return "invalid_proposer", None

            mode = GovernanceMode(governance["mode"])
            if force_approval or mode is GovernanceMode.DUAL_CONTROL:
                active_admins = connection.execute(
                    """
                    SELECT COUNT(*) AS count FROM users
                    WHERE role = ? AND is_active = 1
                    """,
                    (Role.ADMIN.value,),
                ).fetchone()
                if active_admins is None or int(active_admins["count"]) < 2:
                    return "insufficient_admins", None
            required_approvals = 1 if force_approval else (
                0 if mode is GovernanceMode.SINGLE_ADMIN else 1
            )
            captured_payload = dict(payload)
            captured_payload["governance_mode_at_creation"] = mode.value
            captured_payload["required_approvals"] = required_approvals
            payload_json = encode_payload(captured_payload)

            if change_type is AdminChangeType.ROLE_TOTP_POLICY_CHANGE:
                if any(
                    pending.change_type is AdminChangeType.ROLE_TOTP_POLICY_CHANGE
                    for pending in self._expire_and_list_pending(connection, created_at)
                ):
                    return "pending_exists", None
            if change_type is AdminChangeType.HSM_RAW_BACKUP_EXPORT:
                if any(
                    pending.change_type is AdminChangeType.HSM_RAW_BACKUP_EXPORT
                    for pending in self._expire_and_list_pending(connection, created_at)
                ):
                    return "pending_exists", None

            if new_user is not None:
                connection.execute(
                    "INSERT INTO users(id, email, role, is_active) VALUES (?, ?, ?, ?)",
                    (
                        new_user.id,
                        new_user.email,
                        new_user.role.value,
                        int(new_user.is_active),
                    ),
                )
            else:
                target = self._locked_user_row(connection, target_user_id)
                if target is None:
                    raise RepositoryError("Proposal target account is unavailable")
                target_role = Role(target["role"])
                if (
                    change_type is AdminChangeType.PRIVILEGED_PASSWORD_RESET
                    and target_role not in PRIVILEGED_ROLES
                ):
                    raise RepositoryError("Use direct reset for ordinary users")
                if (
                    change_type is AdminChangeType.PRIVILEGED_TOTP_RESET
                    and target_role not in PRIVILEGED_ROLES
                ):
                    raise RepositoryError(
                        "Governed TOTP reset requires a privileged account"
                    )

            connection.execute(
                """
                INSERT INTO admin_change_proposals(
                    id, change_type, proposer_id, target_user_id, payload_json,
                    status, created_at, expires_at, resolved_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    proposal_id,
                    change_type.value,
                    proposer_id,
                    target_user_id,
                    payload_json,
                    AdminChangeStatus.PENDING.value,
                    _dump_dt(created_at),
                    _dump_dt(expires_at),
                ),
            )
            if required_approvals == 0:
                self._apply_proposal_mutation(
                    connection,
                    change_type=change_type,
                    target_user_id=target_user_id,
                    payload=captured_payload,
                    resolved_at=created_at,
                    resolved_by_user_id=proposer_id,
                )
                connection.execute(
                    """
                    UPDATE admin_change_proposals
                    SET status = ?, resolved_at = ?
                    WHERE id = ? AND status = ?
                    """,
                    (
                        AdminChangeStatus.APPROVED.value,
                        _dump_dt(created_at),
                        proposal_id,
                        AdminChangeStatus.PENDING.value,
                    ),
                )
            row = connection.execute(
                "SELECT * FROM admin_change_proposals WHERE id = ?",
                (proposal_id,),
            ).fetchone()
        return "created", None if row is None else _proposal_from_row(row)

    def resolve_proposal_approval(
        self,
        proposal_id: str,
        approver_id: str,
        resolved_at: datetime,
    ) -> tuple[str, AdminChangeProposal | None]:
        """Approve and apply a governed proposal as one linearizable mutation."""
        with self.database.connect() as connection:
            governance = self._lock_governance_row(connection)
            if governance is None:
                return "unavailable", None
            approver = self._locked_user_row(connection, approver_id)
            if (
                approver is None
                or approver["role"] != Role.ADMIN.value
                or not bool(approver["is_active"])
            ):
                return "invalid_approver", None
            row = self._locked_proposal_row(connection, proposal_id)
            if row is None:
                raise RepositoryError(f"Unknown admin change proposal: {proposal_id}")
            proposal = _proposal_from_row(row)
            if proposal.status is not AdminChangeStatus.PENDING:
                return "not_pending", proposal
            if resolved_at >= proposal.expires_at:
                cursor = connection.execute(
                    """
                    UPDATE admin_change_proposals
                    SET status = ?, resolved_at = ?
                    WHERE id = ? AND status = ?
                    """,
                    (
                        AdminChangeStatus.EXPIRED.value,
                        _dump_dt(resolved_at),
                        proposal.id,
                        AdminChangeStatus.PENDING.value,
                    ),
                )
                if cursor.rowcount != 1:
                    raise RepositoryError("Proposal was resolved concurrently")
                expired = replace(
                    proposal,
                    status=AdminChangeStatus.EXPIRED,
                    resolved_at=resolved_at,
                )
                self._cleanup_role_grant_placeholder(connection, expired)
                return "expired", expired

            payload = decode_payload(proposal.payload_json)
            required_approvals = int(payload.get("required_approvals", 1))
            if proposal.change_type is AdminChangeType.ROLE_TOTP_POLICY_CHANGE:
                current_policy = self._lock_totp_policy_rows(connection)
                expected_roles = {
                    Role(value) for value in payload.get("previous_required_roles", [])
                }
                if {
                    role for role, required in current_policy.items() if required
                } != expected_roles:
                    connection.execute(
                        """
                        UPDATE admin_change_proposals
                        SET status = ?, resolved_at = ?
                        WHERE id = ? AND status = ?
                        """,
                        (
                            AdminChangeStatus.REJECTED.value,
                            _dump_dt(resolved_at),
                            proposal.id,
                            AdminChangeStatus.PENDING.value,
                        ),
                    )
                    return "stale", replace(
                        proposal,
                        status=AdminChangeStatus.REJECTED,
                        resolved_at=resolved_at,
                    )
            if required_approvals > 0 and proposal.proposer_id == approver_id:
                return "self_approval", proposal
            connection.execute(
                """
                INSERT INTO admin_change_approvals(proposal_id, admin_id, approved_at)
                VALUES (?, ?, ?)
                """,
                (proposal.id, approver_id, _dump_dt(resolved_at)),
            )
            count_row = connection.execute(
                """
                SELECT COUNT(DISTINCT admin_id) AS count
                FROM admin_change_approvals
                WHERE proposal_id = ?
                """,
                (proposal.id,),
            ).fetchone()
            approval_count = 0 if count_row is None else int(count_row["count"])
            if approval_count < required_approvals:
                return "pending", proposal

            if proposal.change_type is AdminChangeType.GOVERNANCE_MODE_DOWNGRADE:
                if governance["mode"] != GovernanceMode.DUAL_CONTROL.value:
                    raise RepositoryError("Governance mode is no longer dual control")
                mode_update = connection.execute(
                    """
                    UPDATE install_governance
                    SET mode = ?, source = 'runtime', updated_at = ?, updated_by = ?
                    WHERE singleton_id = 1 AND mode = ?
                    """,
                    (
                        GovernanceMode.SINGLE_ADMIN.value,
                        _dump_dt(resolved_at),
                        approver_id,
                        GovernanceMode.DUAL_CONTROL.value,
                    ),
                )
                if mode_update.rowcount != 1:
                    raise RepositoryError("Governance mode is no longer dual control")
            else:
                self._apply_proposal_mutation(
                    connection,
                    change_type=proposal.change_type,
                    target_user_id=proposal.target_user_id,
                    payload=payload,
                    resolved_at=resolved_at,
                    resolved_by_user_id=approver_id,
                )
            proposal_update = connection.execute(
                """
                UPDATE admin_change_proposals
                SET status = ?, resolved_at = ?
                WHERE id = ? AND status = ?
                """,
                (
                    AdminChangeStatus.APPROVED.value,
                    _dump_dt(resolved_at),
                    proposal.id,
                    AdminChangeStatus.PENDING.value,
                ),
            )
            if proposal_update.rowcount != 1:
                raise RepositoryError("Proposal was resolved concurrently")
            return "approved", self._proposal_from_connection(
                connection,
                proposal.id,
            )

    def resolve_proposal_rejection(
        self,
        proposal_id: str,
        actor_id: str,
        resolved_at: datetime,
    ) -> tuple[str, AdminChangeProposal | None]:
        """Reject (or expire) a proposal under the common governance lock."""
        with self.database.connect() as connection:
            if self._lock_governance_row(connection) is None:
                return "unavailable", None
            actor = self._locked_user_row(connection, actor_id)
            if (
                actor is None
                or actor["role"] != Role.ADMIN.value
                or not bool(actor["is_active"])
            ):
                return "invalid_actor", None
            row = self._locked_proposal_row(connection, proposal_id)
            if row is None:
                raise RepositoryError(f"Unknown admin change proposal: {proposal_id}")
            proposal = _proposal_from_row(row)
            if proposal.status is not AdminChangeStatus.PENDING:
                return "not_pending", proposal
            status = (
                AdminChangeStatus.EXPIRED
                if resolved_at >= proposal.expires_at
                else AdminChangeStatus.REJECTED
            )
            cursor = connection.execute(
                """
                UPDATE admin_change_proposals
                SET status = ?, resolved_at = ?
                WHERE id = ? AND status = ?
                """,
                (
                    status.value,
                    _dump_dt(resolved_at),
                    proposal.id,
                    AdminChangeStatus.PENDING.value,
                ),
            )
            if cursor.rowcount != 1:
                raise RepositoryError("Proposal was resolved concurrently")
            resolved = replace(
                proposal,
                status=status,
                resolved_at=resolved_at,
            )
            self._cleanup_role_grant_placeholder(connection, resolved)
            return status.value, resolved

    def add_governance_downgrade_proposal(
        self,
        proposal: AdminChangeProposal,
        current_time: datetime,
    ) -> str:
        """Create the sole live downgrade request under the governance lock."""
        with self.database.connect() as connection:
            governance = self._lock_governance_row(connection)
            if governance is None:
                return "unavailable"
            proposer = self._locked_user_row(connection, proposal.proposer_id)
            if (
                proposer is None
                or proposer["role"] != Role.ADMIN.value
                or not bool(proposer["is_active"])
            ):
                return "invalid_proposer"
            if governance["mode"] != GovernanceMode.DUAL_CONTROL.value:
                return "not_dual"
            active_admins = connection.execute(
                """
                SELECT COUNT(*) AS count FROM users
                WHERE role = ? AND is_active = 1
                """,
                (Role.ADMIN.value,),
            ).fetchone()
            if active_admins is None or int(active_admins["count"]) < 2:
                return "insufficient_admins"
            live_pending = self._expire_and_list_pending(connection, current_time)
            if any(
                pending.change_type
                is AdminChangeType.GOVERNANCE_MODE_DOWNGRADE
                for pending in live_pending
            ):
                return "pending_exists"
            connection.execute(
                """
                INSERT INTO admin_change_proposals(
                    id, change_type, proposer_id, target_user_id, payload_json,
                    status, created_at, expires_at, resolved_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    proposal.id,
                    proposal.change_type.value,
                    proposal.proposer_id,
                    proposal.target_user_id,
                    proposal.payload_json,
                    proposal.status.value,
                    _dump_dt(proposal.created_at),
                    _dump_dt(proposal.expires_at),
                    None,
                ),
            )
        return "created"

    def get_proposal(self, proposal_id: str) -> AdminChangeProposal:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM admin_change_proposals WHERE id = ?",
                (proposal_id,),
            ).fetchone()
        if row is None:
            raise RepositoryError(f"Unknown admin change proposal: {proposal_id}")
        return _proposal_from_row(row)

    def list_proposal_approvals(self, proposal_id: str) -> list[AdminChangeApproval]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT proposal_id, admin_id, approved_at
                FROM admin_change_approvals
                WHERE proposal_id = ?
                ORDER BY approved_at, admin_id
                """,
                (proposal_id,),
            ).fetchall()
        return [
            AdminChangeApproval(
                proposal_id=row["proposal_id"],
                admin_id=row["admin_id"],
                approved_at=_load_dt(row["approved_at"]),
            )
            for row in rows
        ]

    def get_pending_governance_downgrade(
        self,
        *,
        now: datetime | None = None,
    ) -> AdminChangeProposal | None:
        current_time = datetime.now(timezone.utc) if now is None else now
        with self.database.connect() as connection:
            if self._lock_governance_row(connection) is None:
                return None
            proposals = self._expire_and_list_pending(connection, current_time)
        for proposal in proposals:
            if proposal.change_type is AdminChangeType.GOVERNANCE_MODE_DOWNGRADE:
                return proposal
        return None

    def list_pending_proposals(
        self,
        *,
        now: datetime | None = None,
    ) -> list[AdminChangeProposal]:
        current_time = datetime.now(timezone.utc) if now is None else now
        with self.database.connect() as connection:
            if self._lock_governance_row(connection) is None:
                return []
            return self._expire_and_list_pending(connection, current_time)


def _user_from_row(row) -> User:
    return User(
        id=row["id"],
        email=row["email"],
        role=Role(row["role"]),
        is_active=bool(row["is_active"]),
    )


def _session_from_row(row) -> AuthSession:
    return AuthSession(
        id=row["id"],
        token_hash=row["token_hash"],
        user_id=row["user_id"],
        csrf_token=row["csrf_token"],
        stage=SessionStage(row["stage"]),
        created_at=_load_dt(row["created_at"]),
        last_seen_at=_load_dt(row["last_seen_at"]),
        expires_at=_load_dt(row["expires_at"]),
        absolute_expires_at=_load_dt(row["absolute_expires_at"]),
        revoked_at=_load_dt(row["revoked_at"]) if row["revoked_at"] else None,
        mfa_verified_at=(
            _load_dt(row["mfa_verified_at"]) if row.get("mfa_verified_at") else None
        ),
        password_verified_at=(
            _load_dt(row["password_verified_at"])
            if row.get("password_verified_at") else None
        ),
    )


def _proposal_from_row(row) -> AdminChangeProposal:
    return AdminChangeProposal(
        id=row["id"],
        change_type=AdminChangeType(row["change_type"]),
        proposer_id=row["proposer_id"],
        target_user_id=row["target_user_id"],
        payload_json=row["payload_json"],
        status=AdminChangeStatus(row["status"]),
        created_at=_load_dt(row["created_at"]),
        expires_at=_load_dt(row["expires_at"]),
        resolved_at=_load_dt(row["resolved_at"]) if row["resolved_at"] else None,
    )


def encode_payload(payload: dict[str, object]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def decode_payload(payload_json: str) -> dict[str, object]:
    return json.loads(payload_json)


def _dump_dt(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _load_dt(value: str) -> datetime:
    return datetime.fromisoformat(value)
