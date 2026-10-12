from __future__ import annotations

import datetime
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from myownca.service_certs import (
    ChallengeType,
    KeyBackend,
    ServiceCertError,
    ServiceCertRepository,
    ServiceCertService,
    ServiceCertStatus,
    ServiceKeyStore,
)
from myownca.storage.database import Database


def _self_signed(key, common_name: str) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=90))
        .sign(key, hashes.SHA256())
    )


def _cert_for_public_key(public_key, issuer_key, common_name: str) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")]))
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=90))
        .sign(issuer_key, hashes.SHA256())
    )


def _pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _key_pem(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


class _FakeAcme:
    """Stand-in for AcmeClient so tests never touch the network or `acme` lib."""

    def __init__(self, fullchain: str) -> None:
        self.fullchain = fullchain
        self.published: dict[str, str] = {}

    def generate_account_key_pem(self) -> str:
        return _key_pem(ec.generate_private_key(ec.SECP256R1()))

    def register_account(self, directory_url, account_key_pem, contact) -> str:
        return "https://acme.test/acct/1"

    def _bind_fullchain_to_csr(self, csr_pem: str) -> None:
        """Model the ACME invariant that the issued leaf uses the CSR key."""

        csr = x509.load_pem_x509_csr(csr_pem.encode())
        existing_leaf = x509.load_pem_x509_certificate(
            self.fullchain.split("-----END CERTIFICATE-----", 1)[0].encode()
            + b"-----END CERTIFICATE-----\n"
        )
        common_name = existing_leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[
            0
        ].value
        ca_key = ec.generate_private_key(ec.SECP256R1())
        leaf = _cert_for_public_key(csr.public_key(), ca_key, common_name)
        self.fullchain = _pem(leaf) + _pem(_self_signed(ca_key, "Test CA"))

    def order_http01(self, directory_url, account_key_pem, account_url, csr_pem, publisher, cleanup) -> str:
        self._bind_fullchain_to_csr(csr_pem)
        publisher("tok-123", "keyauth-xyz")
        self.published["tok-123"] = "keyauth-xyz"
        cleanup("tok-123")
        return self.fullchain

    def begin_dns01(self, directory_url, account_key_pem, account_url, csr_pem):
        from myownca.service_certs.base import AcmeChallenge

        self._bind_fullchain_to_csr(csr_pem)
        challenge = AcmeChallenge(
            domain="example.test",
            challenge_type=ChallengeType.DNS_01,
            token="tok",
            key_authorization="ka",
            dns_txt_value="txt-value-abc",
        )
        return "https://acme.test/order/1", '{"order": "state"}', [challenge]

    def complete_dns01(self, directory_url, account_key_pem, account_url, order_json) -> str:
        return self.fullchain

    @staticmethod
    def dns_record_name(domain: str) -> str:
        return f"_acme-challenge.{domain}"


class _CheckpointingFakeAcme(_FakeAcme):
    """ACME fake exposing resumable operations and provider call counts."""

    def __init__(self, fullchain: str) -> None:
        super().__init__(fullchain)
        self.http_begin_calls = 0
        self.http_complete_calls = 0
        self.dns_begin_calls = 0
        self.dns_complete_calls = 0
        self.fail_http_begins_after_create = 0
        self.fail_http_completions = 0
        self.fail_dns_completions = 0

    def begin_http01(self, directory_url, account_key_pem, account_url, csr_pem):
        self.http_begin_calls += 1
        self._bind_fullchain_to_csr(csr_pem)
        if self.fail_http_begins_after_create:
            self.fail_http_begins_after_create -= 1
            raise ServiceCertError("ACME order response was lost")
        return (
            f"https://acme.test/order/http-{self.http_begin_calls}",
            f'{{"order": "http-{self.http_begin_calls}"}}',
        )

    def complete_http01(
        self,
        directory_url,
        account_key_pem,
        account_url,
        order_json,
        publisher,
        cleanup,
    ):
        self.http_complete_calls += 1
        if self.fail_http_completions:
            self.fail_http_completions -= 1
            raise ServiceCertError("temporary ACME failure")
        publisher("durable-token", "durable-key-authorization")
        cleanup("durable-token")
        return self.fullchain

    def begin_dns01(self, directory_url, account_key_pem, account_url, csr_pem):
        self.dns_begin_calls += 1
        return super().begin_dns01(
            directory_url, account_key_pem, account_url, csr_pem
        )

    def complete_dns01(
        self, directory_url, account_key_pem, account_url, order_json
    ) -> str:
        self.dns_complete_calls += 1
        if self.fail_dns_completions:
            self.fail_dns_completions -= 1
            raise ServiceCertError("temporary ACME failure")
        return self.fullchain


def _service(tempdir: str, acme=None) -> ServiceCertService:
    db = Database(Path(tempdir) / "svc.sqlite3")
    db.migrate()
    keystore = ServiceKeyStore(Path(tempdir) / "keys")
    return ServiceCertService(
        ServiceCertRepository(db), keystore, "unit-secret", acme_client=acme
    )


class KeyStoreTests(unittest.TestCase):
    def test_generate_build_csr_and_match(self) -> None:
        with TemporaryDirectory() as tempdir:
            ks = ServiceKeyStore(Path(tempdir) / "keys")
            ks.generate("svc-a", KeyBackend.SOFTWARE, "ecdsa-p256")
            csr_pem = ks.build_csr(
                "svc-a", KeyBackend.SOFTWARE, common_name="ocsp.example.test",
                dns_names=("ocsp.example.test",),
            )
            csr = x509.load_pem_x509_csr(csr_pem.encode())
            self.assertTrue(csr.is_signature_valid)
            self.assertEqual(
                csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
                "ocsp.example.test",
            )

    def test_unsafe_label_rejected(self) -> None:
        with TemporaryDirectory() as tempdir:
            ks = ServiceKeyStore(Path(tempdir) / "keys")
            with self.assertRaises(ServiceCertError):
                ks.generate("../escape", KeyBackend.SOFTWARE)


class Capability1Tests(unittest.TestCase):
    def test_generate_csr_then_import_signed(self) -> None:
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir)
            cert, csr_pem = svc.generate_csr("ocsp", common_name="ocsp.example.test")
            self.assertEqual(cert.status, ServiceCertStatus.PENDING)
            self.assertIn("BEGIN CERTIFICATE REQUEST", csr_pem)

            # Build a cert carrying our key's public key, signed by an external CA.
            our_pub = svc.keystore.public_key(cert.key_ref, KeyBackend.SOFTWARE)
            ca_key = ec.generate_private_key(ec.SECP256R1())
            signed = _cert_for_public_key(our_pub, ca_key, "ocsp.example.test")
            updated = svc.import_signed_certificate(cert.id, _pem(signed))
            self.assertEqual(updated.status, ServiceCertStatus.ACTIVE)
            self.assertIsNotNone(updated.not_after)

    def test_import_signed_mismatch_rejected(self) -> None:
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir)
            cert, _ = svc.generate_csr("ocsp", common_name="ocsp.example.test")
            wrong_key = ec.generate_private_key(ec.SECP256R1())
            wrong_cert = _self_signed(wrong_key, "ocsp.example.test")
            with self.assertRaises(ServiceCertError):
                svc.import_signed_certificate(cert.id, _pem(wrong_cert))


class Capability2Tests(unittest.TestCase):
    def test_import_pem(self) -> None:
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir)
            key = ec.generate_private_key(ec.SECP256R1())
            cert = _self_signed(key, "imported.example.test")
            result = svc.import_pem(
                "imported", certificate_pem=_pem(cert), private_key_pem=_key_pem(key)
            )
            self.assertEqual(result.status, ServiceCertStatus.ACTIVE)
            self.assertEqual(svc.get_active_by_name("imported").id, result.id)

    def test_import_pem_key_mismatch(self) -> None:
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir)
            cert = _self_signed(ec.generate_private_key(ec.SECP256R1()), "x.example.test")
            other_key = ec.generate_private_key(ec.SECP256R1())
            with self.assertRaises(ServiceCertError):
                svc.import_pem(
                    "x", certificate_pem=_pem(cert), private_key_pem=_key_pem(other_key)
                )

    def test_import_p12(self) -> None:
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir)
            key = ec.generate_private_key(ec.SECP256R1())
            cert = _self_signed(key, "p12.example.test")
            p12 = pkcs12.serialize_key_and_certificates(
                b"friendly", key, cert, None,
                serialization.BestAvailableEncryption(b"p12pass"),
            )
            result = svc.import_p12("p12cert", p12, "p12pass")
            self.assertEqual(result.status, ServiceCertStatus.ACTIVE)

    def test_import_p12_wrong_password(self) -> None:
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir)
            key = ec.generate_private_key(ec.SECP256R1())
            cert = _self_signed(key, "p12.example.test")
            p12 = pkcs12.serialize_key_and_certificates(
                b"f", key, cert, None, serialization.BestAvailableEncryption(b"right")
            )
            with self.assertRaises(Exception):  # noqa: B017 - cryptography raises ValueError
                svc.import_p12("p12cert", p12, "wrong")


class AcmeFlowTests(unittest.TestCase):
    def _fullchain(self) -> str:
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        ca_key = ec.generate_private_key(ec.SECP256R1())
        return self._leaf_and_chain(leaf_key, ca_key)

    def _leaf_and_chain(self, leaf_key, ca_key) -> str:
        leaf = _cert_for_public_key(leaf_key.public_key(), ca_key, "example.test")
        chain = _self_signed(ca_key, "Test CA")
        return _pem(leaf) + _pem(chain)

    def test_http01_order_installs_certificate(self) -> None:
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir, acme=_FakeAcme(self._fullchain()))
            account = svc.create_account("https://acme.test/dir", "ops@example.test")
            result = svc.request_certificate(
                "web-tls",
                account_id=account.id,
                domains=("example.test",),
                challenge_type=ChallengeType.HTTP_01,
            )
            self.assertEqual(result["status"], "issued")
            installed = svc.get_cert(result["certificate_id"])
            self.assertEqual(installed.status, ServiceCertStatus.ACTIVE)
            self.assertIsNotNone(installed.chain_pem)

    def test_acme_leaf_with_wrong_public_key_is_rejected(self) -> None:
        with TemporaryDirectory() as tempdir:
            wrong_fullchain = self._fullchain()
            acme = _FakeAcme(wrong_fullchain)
            acme.order_http01 = lambda *args, **kwargs: wrong_fullchain  # type: ignore[method-assign]
            svc = _service(tempdir, acme=acme)
            account = svc.create_account("https://acme.test/dir")

            with self.assertRaisesRegex(ServiceCertError, "does not match"):
                svc.request_certificate(
                    "wrong-key",
                    account_id=account.id,
                    domains=("example.test",),
                    challenge_type=ChallengeType.HTTP_01,
                )

    def test_account_key_encrypted_at_rest(self) -> None:
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir, acme=_FakeAcme(self._fullchain()))
            account = svc.create_account("https://acme.test/dir", "ops@example.test")
            stored = svc.repository.get_account(account.id)
            self.assertNotIn("BEGIN", stored.account_key_ciphertext)  # not plaintext PEM

    def test_dns01_requires_provider(self) -> None:
        """DNS-01 without a configured provider raises ServiceCertError immediately."""
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir, acme=_FakeAcme(self._fullchain()))
            account = svc.create_account("https://acme.test/dir")
            with self.assertRaises(ServiceCertError):
                svc.request_certificate(
                    "web-tls",
                    account_id=account.id,
                    domains=("example.test",),
                    challenge_type=ChallengeType.DNS_01,
                )

    def test_http01_challenge_store_serves_and_clears(self) -> None:
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir)
            svc._publish_http01("abc", "keyauth")
            self.assertEqual(svc.http01_keyauth("abc"), "keyauth")
            svc._cleanup_http01("abc")
            self.assertIsNone(svc.http01_keyauth("abc"))


class AcmeIdempotencyTests(unittest.TestCase):
    def _fullchain(self, common_name: str = "example.test") -> str:
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        ca_key = ec.generate_private_key(ec.SECP256R1())
        leaf = _cert_for_public_key(leaf_key.public_key(), ca_key, common_name)
        return _pem(leaf) + _pem(_self_signed(ca_key, "Test CA"))

    def test_retry_resumes_persisted_http_order_after_service_restart(self) -> None:
        with TemporaryDirectory() as tempdir:
            acme = _CheckpointingFakeAcme(self._fullchain())
            acme.fail_http_completions = 1
            svc = _service(tempdir, acme=acme)
            account = svc.create_account("https://acme.test/dir")
            cert = svc.prepare_acme_certificate(
                "durable-http",
                account_id=account.id,
                domains=("example.test",),
                challenge_type=ChallengeType.HTTP_01,
            )

            with self.assertRaises(ServiceCertError):
                svc.complete_acme_certificate(
                    cert.id, idempotency_key="cloud-job-http"
                )
            checkpoint = svc.repository.get_acme_order_checkpoint("cloud-job-http")
            self.assertIsNotNone(checkpoint)
            self.assertEqual(checkpoint.order_url, "https://acme.test/order/http-1")
            self.assertEqual(acme.http_begin_calls, 1)

            # Reconstruct the service to prove the resume state is in the DB,
            # rather than process memory.
            restarted = _service(tempdir, acme=acme)
            result = restarted.complete_acme_certificate(
                cert.id, idempotency_key="cloud-job-http"
            )
            self.assertEqual(result["status"], "issued")
            self.assertEqual(acme.http_begin_calls, 1)
            self.assertEqual(acme.http_complete_calls, 2)

            # A queue acknowledgement failure after the handler returned is
            # also harmless: the active cert is recognized without ACME I/O.
            restarted.complete_acme_certificate(
                cert.id, idempotency_key="cloud-job-http"
            )
            self.assertEqual(acme.http_begin_calls, 1)
            self.assertEqual(acme.http_complete_calls, 2)

    def test_indeterminate_new_order_is_not_repeated_automatically(self) -> None:
        with TemporaryDirectory() as tempdir:
            acme = _CheckpointingFakeAcme(self._fullchain())
            acme.fail_http_begins_after_create = 1
            svc = _service(tempdir, acme=acme)
            account = svc.create_account("https://acme.test/dir")
            cert = svc.prepare_acme_certificate(
                "indeterminate-http",
                account_id=account.id,
                domains=("example.test",),
                challenge_type=ChallengeType.HTTP_01,
            )

            with self.assertRaisesRegex(ServiceCertError, "response was lost"):
                svc.complete_acme_certificate(
                    cert.id, idempotency_key="cloud-job-indeterminate"
                )
            checkpoint = svc.repository.get_acme_order_checkpoint(
                "cloud-job-indeterminate"
            )
            self.assertEqual(checkpoint.state, "creating")

            with self.assertRaisesRegex(ServiceCertError, "indeterminate outcome"):
                svc.complete_acme_certificate(
                    cert.id, idempotency_key="cloud-job-indeterminate"
                )
            self.assertEqual(acme.http_begin_calls, 1)
            self.assertEqual(acme.http_complete_calls, 0)

    def test_retry_installs_checkpointed_renewal_result_without_new_order(self) -> None:
        with TemporaryDirectory() as tempdir:
            acme = _CheckpointingFakeAcme(self._fullchain())
            svc = _service(tempdir, acme=acme)
            account = svc.create_account("https://acme.test/dir")
            initial = svc.request_certificate(
                "durable-renew",
                account_id=account.id,
                domains=("example.test",),
                challenge_type=ChallengeType.HTTP_01,
            )
            cert_id = str(initial["certificate_id"])
            acme.fullchain = self._fullchain("renewed.example.test")

            with mock.patch.object(
                svc.repository,
                "update",
                side_effect=RuntimeError("simulated DB loss after provider result"),
            ):
                with self.assertRaises(RuntimeError):
                    svc.renew(cert_id, idempotency_key="cloud-job-renew")

            checkpoint = svc.repository.get_acme_order_checkpoint("cloud-job-renew")
            self.assertIsNotNone(checkpoint)
            self.assertIsNotNone(checkpoint.fullchain_pem)
            self.assertEqual(acme.http_begin_calls, 1)
            self.assertEqual(acme.http_complete_calls, 1)

            # The provider result was durable before the failed local update.
            # Retry installs that exact result and never touches ACME again.
            result = svc.renew(cert_id, idempotency_key="cloud-job-renew")
            self.assertEqual(result["status"], "renewed")
            self.assertEqual(acme.http_begin_calls, 1)
            self.assertEqual(acme.http_complete_calls, 1)
            installed = svc.get_cert(cert_id)
            self.assertIn("renewed.example.test", installed.subject)

            svc.renew(cert_id, idempotency_key="cloud-job-renew")
            self.assertEqual(acme.http_begin_calls, 1)
            self.assertEqual(acme.http_complete_calls, 1)

    def test_dns_retry_reuses_order_and_checkpointed_challenges(self) -> None:
        with TemporaryDirectory() as tempdir:
            acme = _CheckpointingFakeAcme(self._fullchain())
            acme.fail_dns_completions = 1
            svc = _service(tempdir, acme=acme)
            account = svc.create_account("https://acme.test/dir")

            published: list[tuple[str, str]] = []

            class _Provider:
                def publish_txt(self, name, value):
                    published.append((name, value))

                def remove_txt(self, name, value):
                    pass

            svc._dns_provider = lambda unused_account: _Provider()  # type: ignore[method-assign]
            cert = svc.prepare_acme_certificate(
                "durable-dns",
                account_id=account.id,
                domains=("example.test",),
                challenge_type=ChallengeType.DNS_01,
            )

            with mock.patch(
                "myownca.service_certs.service.wait_for_txt", return_value=True
            ):
                with self.assertRaises(ServiceCertError):
                    svc.complete_acme_certificate(
                        cert.id, idempotency_key="cloud-job-dns"
                    )
                result = svc.complete_acme_certificate(
                    cert.id, idempotency_key="cloud-job-dns"
                )

            self.assertEqual(result["status"], "issued")
            self.assertEqual(acme.dns_begin_calls, 1)
            self.assertEqual(acme.dns_complete_calls, 2)
            self.assertEqual(
                published,
                [
                    ("_acme-challenge.example.test", "txt-value-abc"),
                    ("_acme-challenge.example.test", "txt-value-abc"),
                ],
            )


class ServiceCertAPITests(unittest.TestCase):
    def _admin_app(self, tempdir: str):
        from myownca.domain import Role
        from myownca.online.app import create_app
        from tests.helpers import add_login_ready_user, create_active_session

        app = create_app(Path(tempdir) / "api.sqlite3", online_key_dir=Path(tempdir) / "keys")
        secret = add_login_ready_user(
            app, user_id="admin-1", email="admin1@example.test", role=Role.ADMIN
        )
        add_login_ready_user(app, user_id="user-1", email="user@example.test", role=Role.USER)
        admin = create_active_session(app, email="admin1@example.test", totp_secret=secret)
        user = create_active_session(app, email="user@example.test")
        return app, admin, user

    def test_generate_csr_and_role_gating(self) -> None:
        from fastapi import HTTPException

        from myownca.online.app import ServiceCsrCreate
        from tests.helpers import request_with_session, route_endpoint

        with TemporaryDirectory() as tempdir:
            app, (admin_token, admin_csrf), (user_token, user_csrf) = self._admin_app(tempdir)
            result = route_endpoint(app, "/internal/service-certs/csr", "POST")(
                ServiceCsrCreate(name="ocsp", common_name="ocsp.example.test"),
                request_with_session(admin_token, admin_csrf, method="POST"),
            )
            self.assertEqual(result["status"], "pending")
            self.assertIn("BEGIN CERTIFICATE REQUEST", result["csr_pem"])

            with self.assertRaises(HTTPException) as forbidden:
                route_endpoint(app, "/internal/service-certs", "GET")(
                    request_with_session(user_token)
                )
            self.assertEqual(forbidden.exception.status_code, 403)

    def test_well_known_challenge_route(self) -> None:
        from tests.helpers import route_endpoint

        with TemporaryDirectory() as tempdir:
            app, _, _ = self._admin_app(tempdir)
            app.state.service_certs._publish_http01("token-1", "keyauth-1")
            response = route_endpoint(app, "/.well-known/acme-challenge/{token}", "GET")("token-1")
            self.assertEqual(response.body, b"keyauth-1")

            from fastapi import HTTPException

            with self.assertRaises(HTTPException) as missing:
                route_endpoint(app, "/.well-known/acme-challenge/{token}", "GET")("nope")
            self.assertEqual(missing.exception.status_code, 404)


class PortalTlsMaterialTests(unittest.TestCase):
    def test_material_returns_cert_chain_key_for_software_cert(self) -> None:
        from myownca.online.portal_tls import validate_pair

        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir)
            key = ec.generate_private_key(ec.SECP256R1())
            leaf = _self_signed(key, "portal.example.test")
            cert = svc.import_pem(
                "portal", certificate_pem=_pem(leaf), private_key_pem=_key_pem(key)
            )
            cert_pem, chain_pem, key_pem = svc.portal_tls_material(cert.id)
            self.assertEqual(cert_pem, cert.certificate_pem)
            self.assertEqual(chain_pem, cert.chain_pem or "")
            # The returned key matches the returned cert.
            validate_pair(cert_pem, key_pem)

    def test_material_rejects_hsm_keyed_cert(self) -> None:
        from dataclasses import replace

        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir)
            key = ec.generate_private_key(ec.SECP256R1())
            leaf = _self_signed(key, "portal.example.test")
            cert = svc.import_pem(
                "portal", certificate_pem=_pem(leaf), private_key_pem=_key_pem(key)
            )
            hsm_cert = replace(cert, key_backend=KeyBackend.PKCS11)
            svc.get_cert = lambda _cid: hsm_cert  # type: ignore[method-assign]
            # Pin the rejection reason: the software key file is genuinely on disk, so
            # without the backend gate this would extract it and pass for the wrong reason.
            with self.assertRaises(ServiceCertError) as ctx:
                svc.portal_tls_material(cert.id)
            self.assertIn("non-extractable", str(ctx.exception))

    def test_material_rejects_pending_cert_without_certificate(self) -> None:
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir)
            cert, _csr = svc.generate_csr("pending-svc", common_name="pending.example.test")
            with self.assertRaises(ServiceCertError) as ctx:
                svc.portal_tls_material(cert.id)
            self.assertIn("no issued certificate", str(ctx.exception))

    def test_eligible_for_portal_tls(self) -> None:
        from dataclasses import replace

        from myownca.service_certs.service import eligible_for_portal_tls

        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir)
            key = ec.generate_private_key(ec.SECP256R1())
            leaf = _self_signed(key, "portal.example.test")
            cert = svc.import_pem(
                "portal", certificate_pem=_pem(leaf), private_key_pem=_key_pem(key)
            )
            self.assertTrue(eligible_for_portal_tls(cert))
            self.assertFalse(eligible_for_portal_tls(replace(cert, key_backend=KeyBackend.PKCS11)))


class AcmeDns01AutomatedTests(unittest.TestCase):
    def _svc_with_provider(self, tempdir, events):
        svc = _service(tempdir, acme=_FakeAcme(AcmeFlowTests()._fullchain()))
        account = svc.create_account("https://acme.test/dir")
        svc.set_account_dns_provider(account.id, "fake", {"auth_username": "u", "auth_token": "t"})

        class _FakeProvider:
            def publish_txt(self, name, value):
                events.append(("publish", name, value))
            def remove_txt(self, name, value):
                events.append(("remove", name, value))

        svc._dns_provider = lambda acct: _FakeProvider()  # type: ignore[method-assign]
        import myownca.service_certs.service as svc_mod
        svc_mod.wait_for_txt = lambda *a, **k: True  # type: ignore[attr-defined]
        svc_mod.resolve_cname = lambda name: name  # no CNAME; tests don't hit live DNS
        return svc, account

    def test_dns01_issues_synchronously_and_cleans_up(self) -> None:
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as tempdir:
            events: list = []
            svc, account = self._svc_with_provider(tempdir, events)
            result = svc.request_certificate(
                "web", account_id=account.id, domains=("example.test",),
                challenge_type=ChallengeType.DNS_01,
            )
            self.assertEqual(result["status"], "issued")
            self.assertEqual(svc.get_cert(result["certificate_id"]).status, ServiceCertStatus.ACTIVE)
            self.assertEqual([e[0] for e in events], ["publish", "remove"])

    def test_dns01_propagation_timeout_raises_and_cleans_up(self) -> None:
        from tempfile import TemporaryDirectory

        import myownca.service_certs.service as svc_mod
        from myownca.service_certs.dns_provider import wait_for_txt as _real
        with TemporaryDirectory() as tempdir:
            events: list = []
            svc, account = self._svc_with_provider(tempdir, events)  # sets wait_for_txt -> True
            self.addCleanup(setattr, svc_mod, "wait_for_txt", _real)
            svc_mod.wait_for_txt = lambda *a, **k: False  # the TXT never propagates
            with self.assertRaises(ServiceCertError):
                svc.request_certificate(
                    "web", account_id=account.id, domains=("example.test",),
                    challenge_type=ChallengeType.DNS_01,
                )
            self.assertEqual([e[0] for e in events], ["publish", "remove"])  # cleaned up anyway

    def test_dns01_publishes_at_cname_delegated_target(self) -> None:
        from tempfile import TemporaryDirectory

        import myownca.service_certs.service as svc_mod
        from myownca.service_certs.dns_provider import resolve_cname as _real_cname
        with TemporaryDirectory() as tempdir:
            events: list = []
            svc, account = self._svc_with_provider(tempdir, events)  # also sets wait_for_txt -> True
            self.addCleanup(setattr, svc_mod, "resolve_cname", _real_cname)
            # Simulate `_acme-challenge.athae.net` CNAMEd to the LuaDNS-managed zone.
            svc_mod.resolve_cname = lambda name: "_acme-challenge.trinity.athae.net"
            svc.request_certificate(
                "web", account_id=account.id, domains=("athae.net",),
                challenge_type=ChallengeType.DNS_01,
            )
            published = [e for e in events if e[0] == "publish"]
            removed = [e for e in events if e[0] == "remove"]
            self.assertEqual(published[0][1], "_acme-challenge.trinity.athae.net")
            self.assertEqual(removed[0][1], "_acme-challenge.trinity.athae.net")

    def test_dns01_without_provider_is_rejected(self) -> None:
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir, acme=_FakeAcme(AcmeFlowTests()._fullchain()))
            account = svc.create_account("https://acme.test/dir")  # no provider
            with self.assertRaises(ServiceCertError):
                svc.request_certificate(
                    "web", account_id=account.id, domains=("example.test",),
                    challenge_type=ChallengeType.DNS_01,
                )

    def test_complete_dns_order_is_gone(self) -> None:
        self.assertFalse(hasattr(ServiceCertService, "complete_dns_order"))


class AcmeDnsProviderStorageTests(unittest.TestCase):
    def test_set_and_read_back_dns_provider(self) -> None:
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir, acme=_FakeAcme(AcmeFlowTests()._fullchain()))
            account = svc.create_account("https://acme.test/dir", "ops@example.test")
            self.assertIsNone(account.dns_provider)
            svc.set_account_dns_provider(account.id, "luadns", {"auth_username": "u", "auth_token": "t"})
            stored = svc.repository.get_account(account.id)
            self.assertEqual(stored.dns_provider, "luadns")
            self.assertIsNotNone(stored.dns_credentials_ciphertext)
            self.assertNotIn("auth_token", stored.dns_credentials_ciphertext)  # encrypted
            import json
            self.assertEqual(
                json.loads(svc.cipher.decrypt(stored.dns_credentials_ciphertext.encode()).decode()),
                {"auth_username": "u", "auth_token": "t"},
            )


class AcmeDnsProviderApiTests(unittest.TestCase):
    def test_set_provider_then_account_response_shows_configured_without_secrets(self) -> None:
        from tempfile import TemporaryDirectory
        from myownca.online.app import AcmeDnsProviderUpdate
        from tests.helpers import request_with_session, route_endpoint
        with TemporaryDirectory() as tempdir:
            app, (admin_token, admin_csrf), _ = ServiceCertAPITests()._admin_app(tempdir)
            svc = app.state.service_certs
            svc.acme = _FakeAcme(AcmeFlowTests()._fullchain())
            account = svc.create_account("https://acme.test/dir", "ops@example.test")
            route_endpoint(app, "/internal/service-certs/acme/accounts/{account_id}/dns-provider", "PUT")(
                account.id,
                AcmeDnsProviderUpdate(provider="luadns", username="u", token="t"),
                request_with_session(admin_token, admin_csrf, method="PUT"),
            )
            accounts = route_endpoint(app, "/internal/service-certs/acme/accounts", "GET")(
                request_with_session(admin_token)
            )
            entry = next(a for a in accounts if a["id"] == account.id)
            self.assertEqual(entry["dns_provider"], "luadns")
            self.assertTrue(entry["dns_configured"])
            self.assertNotIn("dns_credentials_ciphertext", entry)
            self.assertNotIn("token", entry)


if __name__ == "__main__":
    unittest.main()
