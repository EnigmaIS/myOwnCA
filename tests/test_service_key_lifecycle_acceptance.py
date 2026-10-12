from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import HTTPException

from myownca.cloud import CloudKeyOwnership, CloudKeyStatus
from myownca.domain import Role
from myownca.key_lifecycle import KeyOwnership, KeyStatus
from myownca.online.app import (
    CloudKeyAction,
    DestructiveActionConfirmation,
    HSMKeyCreate,
    ServiceCsrCreate,
    create_app,
)
from myownca.service_certs import KeyBackend, ServiceCertStatus
from tests.helpers import (
    add_login_ready_user,
    create_active_session,
    create_app_with_hsm,
    request_with_session,
    route_endpoint,
)


_REASON = "Approved lifecycle maintenance for integration testing"


class _LifecycleBackend:
    def __init__(self, provider: str = "aws_kms") -> None:
        self.provider = provider
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.generated: list[str] = []
        self.deleted: list[str] = []
        self.recovered: list[str] = []
        self.attached: list[str] = []
        self.validated_deletions: list[str] = []

    def generate_key(self, label: str, algorithm: str = "ecdsa-p256") -> str:
        if self.provider == "azure_key_vault":
            key_ref = f"https://test.vault.azure.net/keys/{label}/version-1"
        elif self.provider == "pkcs11":
            key_ref = label
        else:
            key_ref = f"arn:aws:kms:eu-test-1:123456789012:key/{label}"
        self.generated.append(key_ref)
        return key_ref

    def public_key(self, _key_ref: str):
        return self.private_key.public_key()

    def delete_key(self, key_ref: str) -> int:
        self.deleted.append(key_ref)
        return 1

    def validate_managed_key_for_deletion(self, key_ref: str) -> str:
        self.validated_deletions.append(key_ref)
        return key_ref

    def recover_key(self, key_ref: str) -> str:
        self.recovered.append(key_ref)
        return key_ref

    def attach_key(self, key_ref: str, expected_algorithm: str | None = None) -> str:
        self.attached.append(key_ref)
        return key_ref


def _admin(app):
    secret = add_login_ready_user(
        app,
        user_id="admin-1",
        email="admin@example.test",
        role=Role.ADMIN,
    )
    token, csrf = create_active_session(
        app,
        email="admin@example.test",
        totp_secret=secret,
    )
    return token, csrf


class ServiceKeyLifecycleAcceptanceTests(unittest.TestCase):
    def test_software_service_key_cleanup_uses_service_keystore(self) -> None:
        with TemporaryDirectory() as tempdir, mock.patch.dict(
            "os.environ",
            {
                "MYOWNCA_STATE_DIR": tempdir,
                "MYOWNCA_SERVICE_KEY_DIR": str(Path(tempdir) / "service-keys"),
            },
        ):
            app = create_app(
                Path(tempdir) / "api.sqlite3",
                online_key_dir=Path(tempdir) / "ca-keys",
            )
            token, csrf = _admin(app)
            created = route_endpoint(app, "/internal/service-certs/csr", "POST")(
                ServiceCsrCreate(
                    name="portal",
                    common_name="portal.example.test",
                ),
                request_with_session(token, csrf, method="POST"),
            )
            cert = app.state.service_certs.get_cert(created["id"])
            service_key_path = Path(tempdir) / "service-keys" / f"{cert.key_ref}.pem"
            self.assertTrue(service_key_path.is_file())

            retired = route_endpoint(
                app, "/internal/service-certs/{cert_id}", "DELETE"
            )(
                cert.id,
                request_with_session(token, csrf, method="DELETE"),
            )
            self.assertEqual(retired["key_status"], KeyStatus.ORPHANED.value)
            registered = app.state.key_lifecycle.repository.find(
                backend="software",
                key_ref=cert.key_ref,
            )
            self.assertIsNotNone(registered)
            outcomes = app.state.key_lifecycle.cleanup_due(
                now=registered.delete_after,
            )
            self.assertEqual(len(outcomes), 1)
            self.assertTrue(outcomes[0].succeeded)
            self.assertFalse(service_key_path.exists())

    def test_restart_retires_superseded_and_expired_service_keys(self) -> None:
        with TemporaryDirectory() as tempdir, mock.patch.dict(
            "os.environ",
            {
                "MYOWNCA_STATE_DIR": tempdir,
                "MYOWNCA_SERVICE_KEY_DIR": str(Path(tempdir) / "service-keys"),
            },
        ):
            database_path = Path(tempdir) / "api.sqlite3"
            app = create_app(database_path)
            token, csrf = _admin(app)
            endpoint = route_endpoint(app, "/internal/service-certs/csr", "POST")
            first = endpoint(
                ServiceCsrCreate(name="old", common_name="old.example.test"),
                request_with_session(token, csrf, method="POST"),
            )
            second = endpoint(
                ServiceCsrCreate(name="expired", common_name="expired.example.test"),
                request_with_session(token, csrf, method="POST"),
            )
            old_time = datetime.now(timezone.utc) - timedelta(days=45)
            superseded = replace(
                app.state.service_certs.get_cert(first["id"]),
                status=ServiceCertStatus.SUPERSEDED,
                updated_at=old_time,
            )
            expired = replace(
                app.state.service_certs.get_cert(second["id"]),
                status=ServiceCertStatus.ACTIVE,
                not_after=old_time,
                updated_at=old_time,
            )
            app.state.service_certs.repository.update(superseded)
            app.state.service_certs.repository.update(expired)

            restarted = create_app(database_path)
            for cert in (superseded, expired):
                registered = restarted.state.key_lifecycle.repository.find(
                    backend="software",
                    key_ref=cert.key_ref,
                )
                self.assertIsNotNone(registered)
                self.assertIs(registered.status, KeyStatus.ORPHANED)
                self.assertEqual(
                    restarted.state.key_lifecycle.repository.list_bindings(
                        registered.id
                    ),
                    [],
                )
                self.assertEqual(
                    registered.delete_after - registered.orphaned_at,
                    timedelta(days=30),
                )
                if cert.status is ServiceCertStatus.ACTIVE:
                    self.assertLessEqual(
                        registered.delete_after,
                        datetime.now(timezone.utc),
                    )

    def test_unknown_hsm_key_cannot_be_adopted_by_delete(self) -> None:
        with TemporaryDirectory() as tempdir:
            backend = _LifecycleBackend("pkcs11")
            app = create_app_with_hsm(
                backend,
                "pkcs11",
                Path(tempdir) / "api.sqlite3",
            )
            token, csrf = _admin(app)
            delete = route_endpoint(app, "/internal/hsm/keys/{label}", "DELETE")
            with self.assertRaises(HTTPException) as caught:
                delete(
                    "unknown-key",
                    DestructiveActionConfirmation(
                        reason=_REASON,
                        confirmation="DELETE KEY unknown-key",
                    ),
                    request_with_session(token, csrf, method="DELETE"),
                )
            self.assertEqual(caught.exception.status_code, 409)
            self.assertIsNone(
                app.state.key_lifecycle.repository.find(
                    backend="pkcs11",
                    key_ref="unknown-key",
                )
            )

            created = route_endpoint(app, "/internal/hsm/keys", "POST")(
                HSMKeyCreate(label="tracked-key"),
                request_with_session(token, csrf, method="POST"),
            )
            tracked = app.state.key_lifecycle.repository.get(
                created["key_registry_id"]
            )
            self.assertIs(tracked.ownership, KeyOwnership.MANAGED)

    def test_cloud_recover_and_reattach_cancel_due_cleanup(self) -> None:
        with TemporaryDirectory() as tempdir:
            backend = _LifecycleBackend()
            app = create_app_with_hsm(
                backend,
                "aws_kms",
                Path(tempdir) / "api.sqlite3",
            )
            token, csrf = _admin(app)
            key_ref = "arn:aws:kms:eu-test-1:123456789012:key/recover-me"
            cloud_key = app.state.cloud_keys.register(
                provider="aws_kms",
                key_ref=key_ref,
                algorithm="ecdsa-p256",
                purpose="service_certificate",
                ownership=CloudKeyOwnership.MANAGED,
                status=CloudKeyStatus.PENDING_DELETION,
            )
            registered = app.state.key_lifecycle.register_key(
                backend="aws_kms",
                key_ref=key_ref,
                purpose="service_certificate",
                ownership=KeyOwnership.MANAGED,
            )
            due_at = datetime.now(timezone.utc) - timedelta(days=31)
            app.state.key_lifecycle.orphan_key(registered.id, now=due_at)

            route_endpoint(app, "/internal/cloud/keys/{key_id}/recover", "POST")(
                cloud_key.id,
                CloudKeyAction(
                    reason=_REASON,
                    confirmation="RECOVER CLOUD KEY",
                ),
                request_with_session(token, csrf, method="POST"),
            )
            active = app.state.key_lifecycle.repository.get(registered.id)
            self.assertIs(active.status, KeyStatus.ACTIVE)
            self.assertIsNone(active.delete_after)
            self.assertEqual(
                [
                    (binding.resource_type, binding.resource_id)
                    for binding in app.state.key_lifecycle.repository.list_bindings(
                        active.id
                    )
                ],
                [("cloud_key", cloud_key.id)],
            )
            self.assertEqual(
                app.state.key_lifecycle.cleanup_due(
                    now=datetime.now(timezone.utc) + timedelta(days=365)
                ),
                [],
            )
            self.assertEqual(backend.recovered, [key_ref])

            attached_ref = (
                "arn:aws:kms:eu-test-1:123456789012:key/reattach-customer-key"
            )
            attached_cloud_key = app.state.cloud_keys.register(
                provider="aws_kms",
                key_ref=attached_ref,
                algorithm="ecdsa-p256",
                purpose="subca",
                ownership=CloudKeyOwnership.ATTACHED,
                status=CloudKeyStatus.PENDING_DELETION,
            )
            attached_registered = app.state.key_lifecycle.register_key(
                backend="aws_kms",
                key_ref=attached_ref,
                purpose="subca",
                ownership=KeyOwnership.ATTACHED,
            )
            app.state.key_lifecycle.orphan_key(
                attached_registered.id,
                now=due_at,
            )
            route_endpoint(app, "/internal/cloud/keys/{key_id}/reattach", "POST")(
                attached_cloud_key.id,
                CloudKeyAction(
                    reason=_REASON,
                    confirmation="REATTACH CLOUD KEY",
                ),
                request_with_session(token, csrf, method="POST"),
            )
            reattached = app.state.key_lifecycle.repository.get(
                attached_registered.id
            )
            self.assertIs(reattached.status, KeyStatus.ACTIVE)
            self.assertIsNone(reattached.delete_after)
            self.assertEqual(backend.attached, [attached_ref])

    def test_canceling_new_cloud_service_workflow_retires_its_key(self) -> None:
        with TemporaryDirectory() as tempdir:
            backend = _LifecycleBackend()
            app = create_app_with_hsm(
                backend,
                "aws_kms",
                Path(tempdir) / "api.sqlite3",
            )
            token, csrf = _admin(app)
            response = route_endpoint(app, "/internal/service-certs/csr", "POST")(
                ServiceCsrCreate(
                    name="abandoned",
                    common_name="abandoned.example.test",
                    key_backend=KeyBackend.AWS_KMS,
                ),
                request_with_session(token, csrf, method="POST"),
            )
            import json

            queued = json.loads(response.body)
            canceled = route_endpoint(
                app, "/internal/cloud/signing-jobs/{job_id}/cancel", "POST"
            )(
                queued["signing_job_id"],
                request_with_session(token, csrf, method="POST"),
            )
            self.assertEqual(canceled["status"], "canceled")
            cert = app.state.service_certs.get_cert(queued["id"])
            self.assertIs(cert.status, ServiceCertStatus.SUPERSEDED)
            registered = app.state.key_lifecycle.repository.find(
                backend="aws_kms",
                key_ref=cert.key_ref,
            )
            self.assertIsNotNone(registered)
            self.assertIs(registered.status, KeyStatus.ORPHANED)
            cloud_key = app.state.cloud_keys.get(queued["cloud_key_id"])
            self.assertIs(cloud_key.status, CloudKeyStatus.PENDING_DELETION)

    def test_cooperative_running_cancel_retires_key_after_worker_returns(self) -> None:
        with TemporaryDirectory() as tempdir:
            backend = _LifecycleBackend()
            app = create_app_with_hsm(
                backend,
                "aws_kms",
                Path(tempdir) / "api.sqlite3",
            )
            token, csrf = _admin(app)
            response = route_endpoint(app, "/internal/service-certs/csr", "POST")(
                ServiceCsrCreate(
                    name="running-cancel",
                    common_name="running-cancel.example.test",
                    key_backend=KeyBackend.AWS_KMS,
                ),
                request_with_session(token, csrf, method="POST"),
            )
            import json

            queued = json.loads(response.body)

            def cancel_from_running_handler(job):
                app.state.signing_jobs.cancel(job.id)
                return {"discarded": True}

            app.state.cloud_signing_worker.handler = cancel_from_running_handler
            completed = app.state.cloud_signing_worker.run_once()
            self.assertIsNotNone(completed)
            self.assertEqual(completed.status.value, "canceled")
            cert = app.state.service_certs.get_cert(queued["id"])
            self.assertIs(cert.status, ServiceCertStatus.SUPERSEDED)
            registered = app.state.key_lifecycle.repository.find(
                backend="aws_kms",
                key_ref=cert.key_ref,
            )
            self.assertIsNotNone(registered)
            self.assertIs(registered.status, KeyStatus.ORPHANED)

    def test_azure_lifecycle_deletes_only_proven_exclusive_managed_name(self) -> None:
        with TemporaryDirectory() as tempdir:
            backend = _LifecycleBackend("azure_key_vault")
            app = create_app_with_hsm(
                backend,
                "azure_key_vault",
                Path(tempdir) / "api.sqlite3",
            )
            key_ref = "https://test.vault.azure.net/keys/shared-name/version-1"
            cloud_key = app.state.cloud_keys.register(
                provider="azure_key_vault",
                key_ref=key_ref,
                algorithm="ecdsa-p256",
                purpose="service_certificate",
                ownership=CloudKeyOwnership.MANAGED,
                status=CloudKeyStatus.PENDING_DELETION,
            )
            registered = app.state.key_lifecycle.register_key(
                backend="azure_key_vault",
                key_ref=key_ref,
                purpose="service_certificate",
                ownership=KeyOwnership.MANAGED,
            )
            orphaned_at = datetime.now(timezone.utc) - timedelta(days=31)
            app.state.key_lifecycle.orphan_key(registered.id, now=orphaned_at)

            outcomes = app.state.key_lifecycle.cleanup_due(
                now=datetime.now(timezone.utc)
            )
            self.assertEqual(len(outcomes), 1)
            self.assertTrue(outcomes[0].succeeded)
            self.assertEqual(backend.validated_deletions, [key_ref])
            self.assertEqual(backend.deleted, [key_ref])
            self.assertIs(
                app.state.cloud_keys.get(cloud_key.id).status,
                CloudKeyStatus.PENDING_DELETION,
            )

    def test_azure_cleanup_refuses_name_with_another_registered_version(self) -> None:
        with TemporaryDirectory() as tempdir:
            backend = _LifecycleBackend("azure_key_vault")
            app = create_app_with_hsm(
                backend,
                "azure_key_vault",
                Path(tempdir) / "api.sqlite3",
            )
            key_ref = "https://test.vault.azure.net/keys/shared-name/version-1"
            app.state.cloud_keys.register(
                provider="azure_key_vault",
                key_ref=key_ref,
                algorithm="ecdsa-p256",
                purpose="service_certificate",
                ownership=CloudKeyOwnership.MANAGED,
                status=CloudKeyStatus.PENDING_DELETION,
            )
            registered = app.state.key_lifecycle.register_key(
                backend="azure_key_vault",
                key_ref=key_ref,
                purpose="service_certificate",
                ownership=KeyOwnership.MANAGED,
            )
            app.state.key_lifecycle.register_key(
                backend="azure_key_vault",
                key_ref="https://test.vault.azure.net/keys/shared-name/version-2",
                purpose="sub_ca",
                ownership=KeyOwnership.ATTACHED,
            )
            app.state.key_lifecycle.orphan_key(
                registered.id,
                now=datetime.now(timezone.utc) - timedelta(days=31),
            )

            outcomes = app.state.key_lifecycle.cleanup_due(
                now=datetime.now(timezone.utc)
            )

            self.assertEqual(len(outcomes), 1)
            self.assertFalse(outcomes[0].succeeded)
            self.assertEqual(backend.validated_deletions, [])
            self.assertEqual(backend.deleted, [])
            self.assertIs(
                app.state.key_lifecycle.repository.get(registered.id).status,
                KeyStatus.ERROR,
            )


if __name__ == "__main__":
    unittest.main()
