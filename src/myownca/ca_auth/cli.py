from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from myownca.ca_auth.repository import AuthRepository
from myownca.ca_auth.service import AuthService
from myownca.config import Settings
from myownca.domain import GovernanceMode, Role
from myownca.storage.database import Database


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="myownca-auth-bootstrap",
        description="Create the initial myOwnCA administrator account or accounts.",
    )
    parser.add_argument("--database-path", type=Path)
    parser.add_argument(
        "--governance-mode",
        choices=[mode.value for mode in GovernanceMode],
        help=(
            "Install governance mode. Defaults to MYOWNCA_GOVERNANCE_MODE, "
            "or single_admin for an explicitly configured Test/Lab install. "
            "Production requires an explicit choice."
        ),
    )
    parser.add_argument("--admin-1-id", required=True)
    parser.add_argument("--admin-1-email", required=True)
    parser.add_argument("--admin-1-password", required=True)
    parser.add_argument("--admin-2-id")
    parser.add_argument("--admin-2-email")
    parser.add_argument("--admin-2-password")
    parser.add_argument(
        "--totp-required-roles",
        help=(
            "Comma-separated roles that require TOTP: admin,superuser,auditor,user. "
            "An empty value disables TOTP for all roles. Defaults to "
            "MYOWNCA_TOTP_REQUIRED_ROLES or admin,superuser on a fresh database."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    settings = Settings.from_env()
    configured_mode = args.governance_mode or settings.governance_mode
    if configured_mode is None and not settings.lab_mode:
        parser.error(
            "Production bootstrap requires --governance-mode; dual_control is recommended"
        )
    if configured_mode is None:
        configured_mode = GovernanceMode.SINGLE_ADMIN.value
    try:
        governance_mode = GovernanceMode(configured_mode)
    except ValueError:
        parser.error(
            "MYOWNCA_GOVERNANCE_MODE must be single_admin or dual_control"
        )

    second_values = (
        args.admin_2_id,
        args.admin_2_email,
        args.admin_2_password,
    )
    has_any_second_value = any(value is not None for value in second_values)
    has_complete_second_admin = all(value is not None for value in second_values)
    if governance_mode is GovernanceMode.DUAL_CONTROL and not has_complete_second_admin:
        parser.error("dual_control requires all three --admin-2-* options")
    if has_any_second_value and not has_complete_second_admin:
        parser.error("provide all three --admin-2-* options or omit all of them")

    database_target = (
        args.database_path
        if args.database_path is not None
        else settings.database_url or settings.database_path
    )
    database = Database(database_target)
    database.migrate()
    repository = AuthRepository(database)
    repository.initialize_governance_mode(
        governance_mode,
        datetime.now(timezone.utc),
    )
    configured_totp_roles = (
        settings.totp_required_roles
        if args.totp_required_roles is None
        else tuple(
            dict.fromkeys(
                item.strip().lower()
                for item in args.totp_required_roles.split(",")
                if item.strip()
            )
        )
    )
    if configured_totp_roles is not None:
        try:
            required_roles = {Role(value) for value in configured_totp_roles}
        except ValueError:
            parser.error(
                "--totp-required-roles accepts only admin,superuser,auditor,user"
            )
        repository.initialize_totp_policy(
            required_roles,
            datetime.now(timezone.utc),
        )
    service = AuthService(repository, settings.auth_encryption_secret)
    admins = service.bootstrap_initial_admins(
        (args.admin_1_id, args.admin_1_email, args.admin_1_password),
        second_values if has_complete_second_admin else None,
    )
    print(f"created {len(admins)} initial administrator account(s)")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
