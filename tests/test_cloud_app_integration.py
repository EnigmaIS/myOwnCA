from __future__ import annotations

import json
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from myownca.ca_hsm import SoftwareHSM
from myownca.ca_hsm.aws_kms import AWSKMSHSM
from myownca.domain import CertificateProfile, Role
from myownca.offline import OfflineRootService, OfflineStateRepository
from myownca.online.app import (
    AcmeOrderCreate,
    RequestCreate,
    ServiceCsrCreate,
    TemplateCreate,
    create_app,
)
from myownca.service_certs import ChallengeType, KeyBackend, ServiceCertStatus
from tests.helpers import (
    add_login_ready_user,
    assign_request_holder,
    create_active_session,
    make_csr,
    request_with_session,
    route_endpoint,
)
from tests.test_cloud_hsm import FakeAWSClient


class _CheckpointAcme:
    def __init__(self, fullchain: str) -> None:
        self.fullchain = fullchain
        self.begin_calls = 0
        self.complete_calls = 0

    @staticmethod
    def generate_account_key_pem() -> str:
        key = ec.generate_private_key(ec.SECP256R1())
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

    @staticmethod
    def register_account(directory_url, account_key_pem, contact) -> str:
        return "https://acme.example.test/account/1"

    def begin_http01(
        self, directory_url, account_key_pem, account_url, csr_pem
    ) -> tuple[str, str]:
        self.begin_calls += 1
        return "https://acme.example.test/order/1", '{"order":"state"}'

    def complete_http01(
        self,
        directory_url,
        account_key_pem,
        account_url,
        order_json,
        publisher,
        cleanup,
    ) -> str:
        self.complete_calls += 1
        return self.fullchain


def _certificate_for(public_key) -> str:
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [x509.NameAttribute(NameOID.COMMON_NAME, "www.example.test")]
            )
        )
        .issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test ACME CA")])
        )
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=90))
        .sign(issuer_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM).decode()


@contextmanager
def _cloud_app(tempdir: str):
    private_key = ec.generate_private_key(ec.SECP384R1())
    client = FakeAWSClient(private_key)
    backend = AWSKMSHSM(region_name="eu-central-1", client=client)
    env = {
        "MYOWNCA_STATE_DIR": tempdir,
        "MYOWNCA_SERVICE_KEY_DIR": str(Path(tempdir) / "service-keys"),
        "MYOWNCA_HSM_BACKEND": "aws_kms",
        "MYOWNCA_SERVICE_KEY_BACKEND": "aws_kms",
    }
    with mock.patch.dict("os.environ", env), mock.patch(
        "myownca.online.app.create_hsm",
        return_value=(backend, "aws_kms"),
    ):
        app = create_app(
            Path(tempdir) / "api.sqlite3",
            lab_mode=True,
            online_key_dir=Path(tempdir) / "online-keys",
        )
        yield app, private_key, client


def _login(app, *, user_id: str, email: str, role: Role):
    secret = add_login_ready_user(app, user_id=user_id, email=email, role=role)
    token, csrf = create_active_session(app, email=email, totp_secret=secret)
    return request_with_session(token, csrf, method="POST")


class CloudAppIntegrationTests(unittest.TestCase):
    def test_preprovisioned_subca_and_leaf_issuance_flow_through_durable_worker(self) -> None:
        with TemporaryDirectory() as tempdir, _cloud_app(tempdir) as (
            app,
            _,
            _,
        ):
            admin_request = _login(
                app,
                user_id="admin-1",
                email="admin@example.test",
                role=Role.ADMIN,
            )
            offline = OfflineRootService(
                OfflineStateRepository(Path(tempdir) / "offline.sqlite3"),
                SoftwareHSM(),
            )
            bootstrap = offline.create_root("Integration Offline Root")

            pending = app.state.ceremony.create_sub_ca_request(
                common_name="Integration Cloud Issuing CA",
                allowed_profiles=(CertificateProfile.HOST_TLS,),
                algorithm="ecdsa-p384",
                key_backend="aws_kms",
            )
            signed = offline.sign_sub_ca_csr(
                pending.csr_pem,
                allowed_profiles=(CertificateProfile.HOST_TLS,),
            )
            app.state.ceremony.import_sub_ca_certificate(
                signed.certificate_pem,
                root_certificate_pem=bootstrap.root_certificate_pem,
                pending_id=pending.id,
            )
            self.assertEqual(app.state.repository.list_pending_sub_cas(), [])
            self.assertEqual(app.state.repository.get_active_sub_ca().id, pending.id)

            su1_request = _login(
                app,
                user_id="su-1",
                email="su1@example.test",
                role=Role.SUPERUSER,
            )
            su2_request = _login(
                app,
                user_id="su-2",
                email="su2@example.test",
                role=Role.SUPERUSER,
            )
            user_request = _login(
                app,
                user_id="user-1",
                email="user@example.test",
                role=Role.USER,
            )
            route_endpoint(app, "/internal/templates", "POST")(
                TemplateCreate(
                    id="host",
                    name="Host TLS",
                    profile=CertificateProfile.HOST_TLS,
                ),
                admin_request,
            )
            request_id = route_endpoint(
                app, "/internal/certificate-requests", "POST"
            )(
                RequestCreate(
                    template_id="host",
                    csr_pem=make_csr(
                        "api.example.test", dns_names=("api.example.test",)
                    ),
                ),
                user_request,
            )["id"]
            assign_request_holder(app, request_id)
            approve = route_endpoint(
                app,
                "/internal/certificate-requests/{request_id}/approvals",
                "POST",
            )
            approve(request_id, su1_request)
            approval = approve(request_id, su2_request)
            self.assertEqual(
                approval["auto_issue_error"]["code"], "cloud_signing_queued"
            )

            issuance_job = app.state.signing_jobs.get(
                approval["auto_issue_error"]["job_id"]
            )
            self.assertEqual(issuance_job.status.value, "queued")
            completed = app.state.cloud_signing_worker.run_once()
            self.assertEqual(completed.id, issuance_job.id)
            self.assertEqual(completed.status.value, "succeeded")
            issued = app.state.repository.get_issued_certificate_by_request_id(
                request_id
            )
            self.assertIsNotNone(issued)
            self.assertTrue(
                x509.load_pem_x509_certificate(
                    issued.certificate_pem.encode()
                ).signature
            )

    def test_service_csr_endpoint_is_completed_by_short_signing_worker(self) -> None:
        with TemporaryDirectory() as tempdir, _cloud_app(tempdir) as (
            app,
            _,
            _,
        ):
            admin_request = _login(
                app,
                user_id="admin-1",
                email="admin@example.test",
                role=Role.ADMIN,
            )
            response = route_endpoint(app, "/internal/service-certs/csr", "POST")(
                ServiceCsrCreate(
                    name="external-cloud",
                    common_name="external.example.test",
                    dns_names=["external.example.test"],
                    key_backend=KeyBackend.AWS_KMS,
                    algorithm="ecdsa-p384",
                ),
                admin_request,
            )
            queued = json.loads(response.body)
            self.assertEqual(response.status_code, 202)

            completed = app.state.cloud_signing_worker.run_once()
            self.assertEqual(completed.id, queued["signing_job_id"])
            self.assertEqual(completed.status.value, "succeeded")
            cert = app.state.service_certs.get_cert(queued["id"])
            csr = x509.load_pem_x509_csr(cert.csr_pem.encode())
            self.assertTrue(csr.is_signature_valid)
            self.assertEqual(cert.key_backend, KeyBackend.AWS_KMS)

    def test_acme_order_uses_dedicated_checkpointed_worker(self) -> None:
        with TemporaryDirectory() as tempdir, _cloud_app(tempdir) as (
            app,
            private_key,
            _,
        ):
            admin_request = _login(
                app,
                user_id="admin-1",
                email="admin@example.test",
                role=Role.ADMIN,
            )
            acme = _CheckpointAcme(_certificate_for(private_key.public_key()))
            app.state.service_certs.acme = acme
            account = app.state.service_certs.create_account(
                "https://acme.example.test/directory",
                "ops@example.test",
            )

            response = route_endpoint(
                app, "/internal/service-certs/acme/orders", "POST"
            )(
                AcmeOrderCreate(
                    name="public-cloud",
                    account_id=account.id,
                    domains=["www.example.test"],
                    challenge_type=ChallengeType.HTTP_01,
                    key_backend=KeyBackend.AWS_KMS,
                    algorithm="ecdsa-p384",
                ),
                admin_request,
            )
            queued = json.loads(response.body)
            self.assertEqual(response.status_code, 202)
            self.assertIsNone(app.state.cloud_signing_worker.run_once())

            completed = app.state.cloud_acme_worker.run_once()
            self.assertEqual(completed.id, queued["signing_job_id"])
            self.assertEqual(completed.status.value, "succeeded")
            cert = app.state.service_certs.get_cert(queued["certificate_id"])
            self.assertEqual(cert.status, ServiceCertStatus.ACTIVE)
            self.assertEqual(acme.begin_calls, 1)
            self.assertEqual(acme.complete_calls, 1)


if __name__ == "__main__":
    unittest.main()
