from __future__ import annotations

import unittest
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from myownca.cloud import CloudKeyOwnership, CloudKeyRepository, CloudKeyStatus
from myownca.ca_hsm import SoftwareHSM
from myownca.config import Settings
from myownca.key_lifecycle import (
    ORPHAN_GRACE_PERIOD,
    KeyLifecycleRepository,
    KeyOwnership,
    KeyStatus,
)
from myownca.key_lifecycle.cli import run
from myownca.service_certs import KeyBackend, ServiceKeyStore
from myownca.storage.database import Database
from myownca.storage.dialect import prepare_ddl


NOW = datetime(2026, 7, 22, 12, 0, tzinfo=timezone.utc)
_MIGRATION = (
    Path(__file__).resolve().parents[1]
    / "src/myownca/storage/migrations/0031_key_lifecycle.sql"
)


class KeyCleanupCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.database_path = self.root / "keys.sqlite3"
        self.key_dir = self.root / "online-keys"
        self.service_key_dir = self.root / "service-keys"
        self.settings = Settings.from_mapping(
            {
                "MYOWNCA_DATABASE_PATH": str(self.database_path),
                "MYOWNCA_ONLINE_KEY_DIR": str(self.key_dir),
                "MYOWNCA_ONLINE_KEY_PASSPHRASE": "test-key-passphrase",
                "MYOWNCA_SERVICE_KEY_DIR": str(self.service_key_dir),
                "MYOWNCA_AUTH_ENCRYPTION_SECRET": "test-auth-secret",
                "MYOWNCA_HSM_BACKEND": "software",
            }
        )
        self.database = Database(self.database_path)
        self.database.migrate()
        self.repository = KeyLifecycleRepository(self.database)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def due_key(
        self,
        *,
        key_id: str,
        backend: str,
        key_ref: str,
        ownership: KeyOwnership,
        purpose: str = "leaf_certificate",
    ):
        key = self.repository.register(
            key_id=key_id,
            backend=backend,
            key_ref=key_ref,
            purpose=purpose,
            ownership=ownership,
            now=NOW - ORPHAN_GRACE_PERIOD,
        )
        return self.repository.mark_orphaned(
            key.id,
            now=NOW - ORPHAN_GRACE_PERIOD,
        )

    def test_default_mode_is_a_read_only_preview(self) -> None:
        key = self.due_key(
            key_id="preview",
            backend="software",
            key_ref="preview-key",
            ownership=KeyOwnership.MANAGED,
        )
        output = StringIO()

        result = run(
            [],
            settings=self.settings,
            clock=lambda: NOW,
            stdout=output,
        )

        self.assertEqual(result, 0)
        self.assertIn("read-only preview", output.getvalue())
        self.assertIn("Re-run with --execute", output.getvalue())
        self.assertEqual(self.repository.get(key.id).status, KeyStatus.ORPHANED)
        self.assertEqual(self.repository.get(key.id).cleanup_attempts, 0)

    def test_execute_deletes_software_key_and_second_run_is_a_noop(self) -> None:
        hsm = SoftwareHSM(
            self.key_dir,
            passphrase=self.settings.online_key_passphrase,
        )
        hsm.generate_key("retired-key", "ecdsa-p256")
        key = self.due_key(
            key_id="software-key",
            backend="software",
            key_ref="retired-key",
            ownership=KeyOwnership.MANAGED,
        )
        first_output = StringIO()

        first = run(
            ["--execute"],
            settings=self.settings,
            clock=lambda: NOW,
            stdout=first_output,
        )

        self.assertEqual(first, 0)
        self.assertIn("1 succeeded, 0 failed", first_output.getvalue())
        self.assertEqual(self.repository.get(key.id).status, KeyStatus.DELETED)
        self.assertFalse((self.key_dir / "retired-key.pem").exists())

        second_output = StringIO()
        second = run(
            ["--execute"],
            settings=self.settings,
            clock=lambda: NOW,
            stdout=second_output,
        )
        self.assertEqual(second, 0)
        self.assertIn("No registered keys are due", second_output.getvalue())
        self.assertEqual(self.repository.get(key.id).cleanup_attempts, 1)

    def test_execute_treats_already_absent_software_material_as_success(self) -> None:
        key = self.due_key(
            key_id="already-removed",
            backend="software",
            key_ref="already-removed",
            ownership=KeyOwnership.MANAGED,
        )

        result = run(
            ["--execute"],
            settings=self.settings,
            clock=lambda: NOW,
            stdout=StringIO(),
        )

        self.assertEqual(result, 0)
        self.assertEqual(self.repository.get(key.id).status, KeyStatus.DELETED)

    def test_service_software_cleanup_uses_service_store_not_ca_store(self) -> None:
        ca_hsm = SoftwareHSM(
            self.key_dir,
            passphrase=self.settings.online_key_passphrase,
        )
        ca_hsm.generate_key("shared-label", "ecdsa-p256")
        service_store = ServiceKeyStore(
            self.service_key_dir,
            passphrase=self.settings.online_key_passphrase,
        )
        service_store.generate("shared-label", KeyBackend.SOFTWARE)
        key = self.due_key(
            key_id="service-software",
            backend="software",
            key_ref="shared-label",
            ownership=KeyOwnership.MANAGED,
            purpose="service_certificate",
        )

        result = run(
            ["--execute"],
            settings=self.settings,
            clock=lambda: NOW,
            stdout=StringIO(),
        )

        self.assertEqual(result, 0)
        self.assertEqual(self.repository.get(key.id).status, KeyStatus.DELETED)
        self.assertFalse((self.service_key_dir / "shared-label.pem").exists())
        self.assertTrue((self.key_dir / "shared-label.pem").exists())

    def test_attached_cloud_cleanup_detaches_durable_metadata(self) -> None:
        cloud_repository = CloudKeyRepository(self.database)
        cloud_key = cloud_repository.register(
            provider="aws_kms",
            key_ref="arn:aws:kms:eu-test-1:123456789012:key/external",
            algorithm="ecdsa-p256",
            purpose="sub_ca",
            ownership=CloudKeyOwnership.ATTACHED,
        )
        key = self.due_key(
            key_id="attached-cloud",
            backend=cloud_key.provider,
            key_ref=cloud_key.key_ref,
            ownership=KeyOwnership.ATTACHED,
            purpose="sub_ca",
        )

        result = run(
            ["--execute"],
            settings=self.settings,
            clock=lambda: NOW,
            stdout=StringIO(),
        )

        self.assertEqual(result, 0)
        self.assertEqual(self.repository.get(key.id).status, KeyStatus.DETACHED)
        self.assertIs(cloud_repository.get(cloud_key.id).status, CloudKeyStatus.DELETED)

    def test_execute_detaches_unknown_external_backend_without_contacting_it(self) -> None:
        key = self.due_key(
            key_id="external",
            backend="external_vendor_hsm",
            key_ref="vendor/key/123",
            ownership=KeyOwnership.ATTACHED,
        )

        with mock.patch("myownca.key_lifecycle.cli.create_hsm") as create_hsm:
            result = run(
                ["--execute"],
                settings=self.settings,
                clock=lambda: NOW,
                stdout=StringIO(),
            )

        self.assertEqual(result, 0)
        create_hsm.assert_not_called()
        self.assertEqual(self.repository.get(key.id).status, KeyStatus.DETACHED)

    def test_unavailable_managed_backend_is_recorded_as_retryable_error(self) -> None:
        key = self.due_key(
            key_id="inactive",
            backend="pkcs11",
            key_ref="token-key",
            ownership=KeyOwnership.MANAGED,
        )
        output = StringIO()

        result = run(
            ["--execute"],
            settings=self.settings,
            clock=lambda: NOW,
            stdout=output,
        )

        self.assertEqual(result, 1)
        self.assertIn("failed", output.getvalue())
        stored = self.repository.get(key.id)
        self.assertEqual(stored.status, KeyStatus.ERROR)
        self.assertIn("pkcs11", stored.last_error)

    def test_pkcs11_pin_is_read_securely_and_never_printed_or_persisted(self) -> None:
        settings = Settings.from_mapping(
            {
                "MYOWNCA_DATABASE_PATH": str(self.database_path),
                "MYOWNCA_AUTH_ENCRYPTION_SECRET": "test-auth-secret",
                "MYOWNCA_HSM_BACKEND": "pkcs11",
            }
        )
        key = self.due_key(
            key_id="token",
            backend="pkcs11",
            key_ref="token-key",
            ownership=KeyOwnership.MANAGED,
        )
        observed: dict[str, object] = {}

        class FakeToken:
            def list_keys(self):
                return [{"label": "token-key", "id": "01"}]

            def delete_key(self, key_ref):
                observed["deleted"] = key_ref

        def fake_create_hsm(_settings, *, pin_vault, **_kwargs):
            observed["pin"] = pin_vault.active_pin()
            return FakeToken(), "pkcs11"

        output = StringIO()
        with mock.patch(
            "myownca.key_lifecycle.cli.create_hsm",
            side_effect=fake_create_hsm,
        ):
            result = run(
                ["--execute"],
                settings=settings,
                pin_reader=lambda _prompt: "123456-secret-pin",
                clock=lambda: NOW,
                stdout=output,
            )

        self.assertEqual(result, 0)
        self.assertEqual(observed, {"pin": "123456-secret-pin", "deleted": "token-key"})
        self.assertNotIn("123456-secret-pin", output.getvalue())
        stored = self.repository.get(key.id)
        self.assertEqual(stored.status, KeyStatus.DELETED)
        self.assertNotIn("123456-secret-pin", stored.last_error or "")

    def test_canceled_pin_does_not_claim_any_key(self) -> None:
        settings = Settings.from_mapping(
            {
                "MYOWNCA_DATABASE_PATH": str(self.database_path),
                "MYOWNCA_HSM_BACKEND": "pkcs11",
            }
        )
        key = self.due_key(
            key_id="token",
            backend="pkcs11",
            key_ref="token-key",
            ownership=KeyOwnership.MANAGED,
        )
        errors = StringIO()

        result = run(
            ["--execute"],
            settings=settings,
            pin_reader=lambda _prompt: "",
            clock=lambda: NOW,
            stdout=StringIO(),
            stderr=errors,
        )

        self.assertEqual(result, 2)
        self.assertIn("PIN is required", errors.getvalue())
        stored = self.repository.get(key.id)
        self.assertEqual(stored.status, KeyStatus.ORPHANED)
        self.assertEqual(stored.cleanup_attempts, 0)

    def test_database_url_is_preferred_without_path_override(self) -> None:
        settings = Settings.from_mapping(
            {"MYOWNCA_DATABASE_URL": "mysql+pymysql://ca:test@db.example.test/myownca"}
        )
        database = mock.Mock()
        repository = mock.Mock()
        repository.list_due.return_value = []
        repository.list_all.return_value = []

        with mock.patch(
            "myownca.key_lifecycle.cli.Database", return_value=database
        ) as database_type, mock.patch(
            "myownca.key_lifecycle.cli.KeyLifecycleRepository",
            return_value=repository,
        ):
            result = run([], settings=settings, clock=lambda: NOW, stdout=StringIO())

        self.assertEqual(result, 0)
        database_type.assert_called_once_with(settings.database_url)
        database.migrate.assert_called_once_with()


class KeyLifecycleMigrationPortabilityTests(unittest.TestCase):
    def test_migration_uses_sqlite_and_postgresql_compatible_base_ddl(self) -> None:
        ddl = _MIGRATION.read_text()
        sqlite_statements = prepare_ddl(ddl, "sqlite")
        postgresql_statements = prepare_ddl(ddl, "postgresql")

        self.assertEqual(postgresql_statements, sqlite_statements)
        joined = "\n".join(postgresql_statements).upper()
        self.assertNotIn("AUTOINCREMENT", joined)
        self.assertNotIn("PRAGMA", joined)
        self.assertNotIn("`", joined)
        self.assertIn("ON DELETE CASCADE", joined)
        self.assertIn("CHECK (OWNERSHIP IN", joined)

    def test_mariadb_translation_keeps_locator_unbounded_and_indexes_digests(self) -> None:
        joined = "\n".join(prepare_ddl(_MIGRATION.read_text(), "mysql"))

        self.assertIn("key_ref LONGTEXT NOT NULL", joined)
        self.assertIn("key_ref_digest VARCHAR(191) NOT NULL", joined)
        self.assertIn("UNIQUE (backend, key_ref_digest)", joined)
        self.assertIn(
            "FOREIGN KEY (`key_id`) REFERENCES key_lifecycle_keys(`id`) ON DELETE CASCADE",
            joined,
        )


if __name__ == "__main__":
    unittest.main()
