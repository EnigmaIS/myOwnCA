from __future__ import annotations

import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi import HTTPException
from cryptography.hazmat.primitives.asymmetric import ec

from myownca.cloud import CloudKeyStatus, CloudRepositoryError
from myownca.domain import Role
from myownca.key_lifecycle import KeyStatus
from myownca.online.app import (
    AcmeOrderCreate,
    ServiceCsrCreate,
    create_app,
)
from myownca.service_certs import AcmeAccount, ChallengeType, KeyBackend
from tests.helpers import (
    add_login_ready_user,
    create_active_session,
    request_with_session,
    route_endpoint,
)


class _FakeCloudHSM:
    def __init__(self) -> None:
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.generated: list[str] = []
        self.attached: list[str] = []
        self.deleted: list[str] = []

    def generate_key(self, label: str, algorithm: str = "rsa-2048") -> str:
        key_ref = f"arn:aws:kms:eu-test-1:123456789012:key/{label}"
        self.generated.append(key_ref)
        return key_ref

    def attach_key(self, key_ref: str, expected_algorithm: str | None = None) -> str:
        self.attached.append(key_ref)
        return key_ref

    def delete_key(self, key_ref: str) -> dict[str, str]:
        self.deleted.append(key_ref)
        return {"key_ref": key_ref, "state": "pending_deletion"}

    def public_key(self, key_ref: str):
        return self.private_key.public_key()


@contextmanager
def _cloud_app(tempdir: str):
    backend = _FakeCloudHSM()
    env = {
        "MYOWNCA_STATE_DIR": tempdir,
        "MYOWNCA_HSM_BACKEND": "aws_kms",
        "MYOWNCA_SERVICE_KEY_BACKEND": "aws_kms",
        "MYOWNCA_LAB_MODE": "false",
    }
    with mock.patch.dict("os.environ", env), mock.patch(
        "myownca.online.app.create_hsm",
        return_value=(backend, "aws_kms"),
    ):
        app = create_app(Path(tempdir) / "api.sqlite3")
        secret = add_login_ready_user(
            app,
            user_id="admin-1",
            email="admin@example.test",
            role=Role.ADMIN,
        )
        token, csrf = create_active_session(
            app, email="admin@example.test", totp_secret=secret
        )
        yield app, backend, request_with_session(token, csrf, method="POST")


def _add_acme_account(app) -> str:
    account_id = "account-1"
    app.state.service_certs.repository.add_account(
        AcmeAccount(
            id=account_id,
            directory_url="https://acme.example.test/directory",
            account_key_ciphertext="not-used-during-prepare",
            created_at=datetime.now(timezone.utc),
            account_url="https://acme.example.test/account/1",
        )
    )
    return account_id


def _assert_delayed_cleanup(app, backend: _FakeCloudHSM) -> None:
    assert backend.deleted == []
    for key_ref in backend.generated:
        registered = app.state.key_lifecycle.repository.find(
            backend="aws_kms", key_ref=key_ref
        )
        assert registered is not None
        assert registered.status is KeyStatus.ORPHANED
        assert registered.orphaned_at is not None
        assert registered.delete_after is not None
        assert registered.delete_after - registered.orphaned_at == timedelta(days=30)


class CloudSagaCompensationTests(unittest.TestCase):
    def test_runtime_exposes_no_subca_provisioning_saga(self) -> None:
        with TemporaryDirectory() as tempdir, _cloud_app(tempdir) as (
            app,
            _backend,
            _request,
        ):
            paths = {route.path for route in app.routes}
        self.assertFalse(any(path.startswith("/internal/setup/") for path in paths))

    def test_service_csr_registration_failure_removes_pending_cert_and_key(self) -> None:
        with TemporaryDirectory() as tempdir, _cloud_app(tempdir) as (app, backend, request):
            with mock.patch.object(
                app.state.cloud_keys,
                "register",
                side_effect=CloudRepositoryError("registry unavailable"),
            ):
                with self.assertRaises(HTTPException):
                    route_endpoint(app, "/internal/service-certs/csr", "POST")(
                        ServiceCsrCreate(
                            name="external-cloud",
                            common_name="external.example.test",
                            key_backend=KeyBackend.AWS_KMS,
                        ),
                        request,
                    )

            self.assertEqual(app.state.service_certs.list_certs(), [])
            _assert_delayed_cleanup(app, backend)
            self.assertEqual(app.state.cloud_keys.list_all(), [])

    def test_service_csr_enqueue_failure_removes_cert_and_tracks_key(self) -> None:
        with TemporaryDirectory() as tempdir, _cloud_app(tempdir) as (app, backend, request):
            with mock.patch.object(
                app.state.signing_jobs,
                "enqueue",
                side_effect=CloudRepositoryError("queue unavailable"),
            ):
                with self.assertRaises(HTTPException):
                    route_endpoint(app, "/internal/service-certs/csr", "POST")(
                        ServiceCsrCreate(
                            name="external-cloud",
                            common_name="external.example.test",
                            key_backend=KeyBackend.AWS_KMS,
                        ),
                        request,
                    )

            self.assertEqual(app.state.service_certs.list_certs(), [])
            _assert_delayed_cleanup(app, backend)
            keys = app.state.cloud_keys.list_all()
            self.assertEqual(len(keys), 1)
            self.assertIs(keys[0].status, CloudKeyStatus.PENDING_DELETION)

    def test_service_csr_row_failure_still_tracks_and_deletes_key(self) -> None:
        with TemporaryDirectory() as tempdir, _cloud_app(tempdir) as (app, backend, request):
            with mock.patch.object(
                app.state.service_certs.repository,
                "add",
                side_effect=RuntimeError("certificate table unavailable"),
            ):
                with self.assertRaises(HTTPException):
                    route_endpoint(app, "/internal/service-certs/csr", "POST")(
                        ServiceCsrCreate(
                            name="external-cloud",
                            common_name="external.example.test",
                            key_backend=KeyBackend.AWS_KMS,
                        ),
                        request,
                    )

            self.assertEqual(app.state.service_certs.list_certs(), [])
            _assert_delayed_cleanup(app, backend)
            keys = app.state.cloud_keys.list_all()
            self.assertEqual(len(keys), 1)
            self.assertIs(keys[0].status, CloudKeyStatus.PENDING_DELETION)

    def test_acme_registration_failure_removes_pending_cert_and_key(self) -> None:
        with TemporaryDirectory() as tempdir, _cloud_app(tempdir) as (app, backend, request):
            account_id = _add_acme_account(app)
            with mock.patch.object(
                app.state.cloud_keys,
                "register",
                side_effect=CloudRepositoryError("registry unavailable"),
            ):
                with self.assertRaises(HTTPException):
                    route_endpoint(app, "/internal/service-certs/acme/orders", "POST")(
                        AcmeOrderCreate(
                            name="acme-cloud",
                            account_id=account_id,
                            domains=["www.example.test"],
                            challenge_type=ChallengeType.HTTP_01,
                            key_backend=KeyBackend.AWS_KMS,
                        ),
                        request,
                    )

            self.assertEqual(app.state.service_certs.list_certs(), [])
            _assert_delayed_cleanup(app, backend)
            self.assertEqual(app.state.cloud_keys.list_all(), [])

    def test_acme_enqueue_failure_removes_cert_and_tracks_key(self) -> None:
        with TemporaryDirectory() as tempdir, _cloud_app(tempdir) as (app, backend, request):
            account_id = _add_acme_account(app)
            with mock.patch.object(
                app.state.signing_jobs,
                "enqueue",
                side_effect=CloudRepositoryError("queue unavailable"),
            ):
                with self.assertRaises(HTTPException):
                    route_endpoint(app, "/internal/service-certs/acme/orders", "POST")(
                        AcmeOrderCreate(
                            name="acme-cloud",
                            account_id=account_id,
                            domains=["www.example.test"],
                            challenge_type=ChallengeType.HTTP_01,
                            key_backend=KeyBackend.AWS_KMS,
                        ),
                        request,
                    )

            self.assertEqual(app.state.service_certs.list_certs(), [])
            _assert_delayed_cleanup(app, backend)
            keys = app.state.cloud_keys.list_all()
            self.assertEqual(len(keys), 1)
            self.assertIs(keys[0].status, CloudKeyStatus.PENDING_DELETION)

    def test_acme_config_failure_removes_partial_row_and_deletes_key(self) -> None:
        with TemporaryDirectory() as tempdir, _cloud_app(tempdir) as (app, backend, request):
            account_id = _add_acme_account(app)
            with mock.patch.object(
                app.state.service_certs.repository,
                "set_cert_config",
                side_effect=RuntimeError("config table unavailable"),
            ):
                with self.assertRaises(HTTPException):
                    route_endpoint(app, "/internal/service-certs/acme/orders", "POST")(
                        AcmeOrderCreate(
                            name="acme-cloud",
                            account_id=account_id,
                            domains=["www.example.test"],
                            challenge_type=ChallengeType.HTTP_01,
                            key_backend=KeyBackend.AWS_KMS,
                        ),
                        request,
                    )

            self.assertEqual(app.state.service_certs.list_certs(), [])
            _assert_delayed_cleanup(app, backend)
            keys = app.state.cloud_keys.list_all()
            self.assertEqual(len(keys), 1)
            self.assertIs(keys[0].status, CloudKeyStatus.PENDING_DELETION)


if __name__ == "__main__":
    unittest.main()
