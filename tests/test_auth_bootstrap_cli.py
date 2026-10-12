from __future__ import annotations

import os
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from myownca.ca_auth.cli import main
from myownca.ca_auth.repository import AuthRepository
from myownca.config import Settings
from myownca.domain import GovernanceMode, Role
from myownca.storage.database import Database


class AuthBootstrapCliTests(unittest.TestCase):
    def test_lab_defaults_to_single_admin_and_accepts_one_account(self) -> None:
        with TemporaryDirectory() as tempdir:
            database_path = Path(tempdir) / "lab.sqlite3"
            with mock.patch.dict(
                os.environ,
                {
                    "MYOWNCA_LAB_MODE": "true",
                    "MYOWNCA_AUTH_ENCRYPTION_SECRET": "test-secret",
                },
                clear=True,
            ):
                result = main(
                    [
                        "--database-path",
                        str(database_path),
                        "--admin-1-id",
                        "admin-1",
                        "--admin-1-email",
                        "admin1@example.test",
                        "--admin-1-password",
                        "temporary-password-1",
                    ]
                )

            repository = AuthRepository(Database(database_path))
            self.assertEqual(result, 0)
            self.assertEqual(repository.get_governance_mode(), GovernanceMode.SINGLE_ADMIN)
            self.assertEqual(repository.count_active_users_with_role(Role.ADMIN), 1)

    def test_production_requires_an_explicit_governance_choice(self) -> None:
        with TemporaryDirectory() as tempdir, mock.patch.dict(
            os.environ,
            {"MYOWNCA_LAB_MODE": "false"},
            clear=True,
        ), redirect_stderr(StringIO()) as stderr:
            with self.assertRaises(SystemExit) as raised:
                main(
                    [
                        "--database-path",
                        str(Path(tempdir) / "production.sqlite3"),
                        "--admin-1-id",
                        "admin-1",
                        "--admin-1-email",
                        "admin1@example.test",
                        "--admin-1-password",
                        "temporary-password-1",
                    ]
                )

            self.assertEqual(raised.exception.code, 2)
            self.assertIn("Production bootstrap requires --governance-mode", stderr.getvalue())

    def test_cli_initializes_explicit_totp_role_policy(self) -> None:
        with TemporaryDirectory() as tempdir:
            database_path = Path(tempdir) / "totp.sqlite3"
            with mock.patch.dict(
                os.environ,
                {
                    "MYOWNCA_LAB_MODE": "true",
                    "MYOWNCA_AUTH_ENCRYPTION_SECRET": "test-secret",
                },
                clear=True,
            ):
                result = main(
                    [
                        "--database-path",
                        str(database_path),
                        "--totp-required-roles",
                        "admin,auditor,user",
                        "--admin-1-id",
                        "admin-1",
                        "--admin-1-email",
                        "admin1@example.test",
                        "--admin-1-password",
                        "temporary-password-1",
                    ]
                )

            repository = AuthRepository(Database(database_path))
            self.assertEqual(result, 0)
            self.assertEqual(
                {role for role, required in repository.get_totp_policy().items() if required},
                {Role.ADMIN, Role.AUDITOR, Role.USER},
            )

    def test_external_database_url_is_used_when_no_path_override_is_given(self) -> None:
        settings = Settings.from_mapping(
            {
                "MYOWNCA_DATABASE_URL": "mysql+pymysql://ca:test@db.example.test/myownca",
                "MYOWNCA_LAB_MODE": "true",
            }
        )
        database = mock.Mock()
        repository = mock.Mock()
        service = mock.Mock()
        service.bootstrap_initial_admins.return_value = (object(),)

        with mock.patch(
            "myownca.ca_auth.cli.Settings.from_env",
            return_value=settings,
        ), mock.patch(
            "myownca.ca_auth.cli.Database",
            return_value=database,
        ) as database_type, mock.patch(
            "myownca.ca_auth.cli.AuthRepository",
            return_value=repository,
        ), mock.patch(
            "myownca.ca_auth.cli.AuthService",
            return_value=service,
        ):
            result = main(
                [
                    "--governance-mode",
                    "single_admin",
                    "--admin-1-id",
                    "admin-1",
                    "--admin-1-email",
                    "admin1@example.test",
                    "--admin-1-password",
                    "temporary-password-1",
                ]
            )

        self.assertEqual(result, 0)
        database_type.assert_called_once_with(settings.database_url)
        database.migrate.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
