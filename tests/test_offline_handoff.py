from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from myownca.ca_hsm import SoftwareHSM
from myownca.ca_main.crypto import (
    build_sub_ca_csr,
    verify_certificate_signature,
)
from myownca.ca_main.service import CAMainService
from myownca.domain import CertificateProfile, CertificateTemplate, Person, Role, SubCA, User
from myownca.offline import OfflineRootService, OfflineStateRepository
from myownca.offline.cli import main as offline_main
from myownca.online.ceremony import OnlineCeremonyService
from myownca.storage.database import Database
from myownca.storage.repositories import PKIRepository
from myownca.storage.repositories import RepositoryError
from tests.helpers import make_csr


class OfflineHandoffTests(unittest.TestCase):
    def test_offline_cli_signs_pasted_csr_and_prints_only_certificate_pem(self) -> None:
        with TemporaryDirectory() as tempdir:
            state_dir = Path(tempdir) / "offline"
            offline = OfflineRootService(
                OfflineStateRepository(state_dir / "offline.sqlite3"),
                SoftwareHSM(state_dir / "keys"),
            )
            root = offline.create_root("Offline Root")
            request_hsm = SoftwareHSM()
            request_key = request_hsm.generate_key("subca", "ecdsa-p384")
            csr = build_sub_ca_csr(request_hsm, request_key, "Pasted Issuing CA")
            stdin = io.StringIO(
                csr.public_bytes(serialization.Encoding.PEM).decode()
            )
            stdout = io.StringIO()

            with mock.patch("sys.stdin", stdin), redirect_stdout(stdout):
                result = offline_main(
                    ["subca-sign-csr", "--state-dir", str(state_dir)]
                )

            self.assertEqual(result, 0)
            certificate = x509.load_pem_x509_certificate(stdout.getvalue().encode())
            root_certificate = x509.load_pem_x509_certificate(
                root.root_certificate_pem.encode()
            )
            verify_certificate_signature(certificate, root_certificate)

    def test_plain_certificate_import_rejects_a_different_private_key(self) -> None:
        with TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            offline_hsm = SoftwareHSM()
            offline = OfflineRootService(
                OfflineStateRepository(root / "offline.sqlite3"),
                offline_hsm,
            )
            bootstrap = offline.create_root("Offline Root")
            database = Database(root / "online.sqlite3")
            database.migrate()
            repository = PKIRepository(database)
            online_hsm = SoftwareHSM()
            ceremony = OnlineCeremonyService(repository, online_hsm)
            pending = ceremony.create_sub_ca_request(
                common_name="Expected Issuing CA",
            )
            wrong_key_ref = online_hsm.generate_key("wrong-subca", "ecdsa-p384")
            wrong_csr = build_sub_ca_csr(
                online_hsm,
                wrong_key_ref,
                "Expected Issuing CA",
            )
            wrong_certificate = offline.sign_sub_ca_csr(
                wrong_csr.public_bytes(
                    serialization.Encoding.PEM
                ).decode()
            )

            with self.assertRaisesRegex(
                ValueError,
                "does not match the pending CSR key",
            ):
                ceremony.import_sub_ca_certificate(
                    wrong_certificate.certificate_pem,
                    root_certificate_pem=bootstrap.root_certificate_pem,
                    pending_id=pending.id,
                )

            self.assertEqual(repository.get_pending_sub_ca(pending.id), pending)
            self.assertEqual(repository.list_sub_cas(), [])

    def test_subca_promotion_rolls_back_all_rows_on_late_failure(self) -> None:
        with TemporaryDirectory() as tempdir:
            database = Database(Path(tempdir) / "online.sqlite3")
            database.migrate()
            repository = PKIRepository(database)
            sub_ca = SubCA(
                id="atomic-subca",
                certificate_pem="CERTIFICATE",
                key_ref="issuer-key",
                subject="CN=Atomic Issuer",
                created_at=datetime.now(timezone.utc),
                key_backend="software",
            )

            with self.assertRaises(RepositoryError):
                repository.add_sub_ca(
                    sub_ca,
                    root_certificate_pem="ROOT CERTIFICATE",
                    activate=True,
                    remove_pending_id="missing-pending-request",
                )

            with self.assertRaises(RepositoryError):
                repository.get_sub_ca(sub_ca.id)
            self.assertIsNone(repository.get_root_certificate_pem())
            self.assertIsNone(repository.get_active_sub_ca())

    def test_response_import_cannot_replace_configured_root(self) -> None:
        with TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            signer = OfflineRootService(
                OfflineStateRepository(root / "signer.sqlite3"),
                SoftwareHSM(),
            )
            signer_root = signer.create_root("Signing Root")
            other = OfflineRootService(
                OfflineStateRepository(root / "other.sqlite3"),
                SoftwareHSM(),
            )
            configured_root = other.create_root("Configured Root")

            database = Database(root / "online.sqlite3")
            database.migrate()
            repository = PKIRepository(database)
            ceremony = OnlineCeremonyService(repository, SoftwareHSM())
            pending = ceremony.create_sub_ca_request(
                common_name="Online Issuing CA",
            )
            signed = signer.sign_sub_ca_csr(pending.csr_pem)
            repository.set_root_certificate_pem(configured_root.root_certificate_pem)

            with self.assertRaisesRegex(
                ValueError,
                "does not match the configured Root CA",
            ):
                ceremony.import_sub_ca_certificate(
                    signed.certificate_pem,
                    root_certificate_pem=signer_root.root_certificate_pem,
                    pending_id=pending.id,
                )

            self.assertEqual(
                repository.get_root_certificate_pem(),
                configured_root.root_certificate_pem,
            )
            self.assertEqual(repository.get_pending_sub_ca(pending.id).id, pending.id)
            self.assertEqual(repository.list_sub_cas(), [])

    def test_full_offline_to_online_sub_ca_handoff(self) -> None:
        with TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            offline_state = OfflineStateRepository(root / "offline.sqlite3")
            offline_hsm = SoftwareHSM()
            offline = OfflineRootService(offline_state, offline_hsm)
            bootstrap = offline.create_root("myOwnCA Offline Root CA")

            online_db = Database(root / "online.sqlite3")
            online_db.migrate()
            online_repo = PKIRepository(online_db)
            online_hsm = SoftwareHSM()
            online_ceremony = OnlineCeremonyService(online_repo, online_hsm)
            request = online_ceremony.create_sub_ca_request(
                common_name="myOwnCA Online Issuing CA",
                allowed_profiles=(CertificateProfile.HOST_TLS,),
            )
            signed = offline.sign_sub_ca_csr(
                request.csr_pem,
                permitted_dns_suffixes=("example.test",),
                allowed_profiles=(CertificateProfile.HOST_TLS,),
            )
            sub_ca = online_ceremony.import_sub_ca_certificate(
                signed.certificate_pem,
                root_certificate_pem=bootstrap.root_certificate_pem,
                pending_id=request.id,
            )
            with self.assertRaises(RepositoryError):
                online_repo.get_pending_sub_ca(request.id)
            issuer = online_ceremony.issuer_material(sub_ca.id)
            self.assertEqual(sub_ca.allowed_profiles, (CertificateProfile.HOST_TLS,))

            root_certificate = x509.load_pem_x509_certificate(bootstrap.root_certificate_pem.encode())
            verify_certificate_signature(issuer.certificate, root_certificate)
            constraints = issuer.certificate.extensions.get_extension_for_class(
                x509.NameConstraints
            ).value
            self.assertEqual(
                [name.value for name in constraints.permitted_subtrees],
                ["example.test"],
            )

            online_repo.add_user(User(id="su-1", email="su1@example.test", role=Role.SUPERUSER))
            online_repo.add_user(User(id="su-2", email="su2@example.test", role=Role.SUPERUSER))
            online_repo.add_template(
                CertificateTemplate(id="host", name="Host TLS", profile=CertificateProfile.HOST_TLS)
            )
            main = CAMainService(online_repo, online_hsm)
            request = main.submit_request(
                "host",
                make_csr("api.example.test", dns_names=("api.example.test",)),
            )
            main.approve_request(request.id, "su-1")
            main.approve_request(request.id, "su-2")
            online_repo.add_person(
                Person(
                    id="p1",
                    name="Alice",
                    surname="Example",
                    email="alice@example.test",
                    created_at=datetime.now(timezone.utc),
                )
            )
            main.assign_request_holder(request.id, person_id="p1")
            issued = main.issue_certificate(request.id, issuer)
            end_entity = x509.load_pem_x509_certificate(issued.certificate_pem.encode())
            verify_certificate_signature(end_entity, issuer.certificate)

            online_repo.add_template(
                CertificateTemplate(id="smime", name="S/MIME", profile=CertificateProfile.SMIME)
            )
            smime_request = main.submit_request(
                "smime",
                make_csr("Alice Example", emails=("alice@example.test",)),
            )
            main.approve_request(smime_request.id, "su-1")
            main.approve_request(smime_request.id, "su-2")
            with self.assertRaises(RepositoryError):
                main.issue_certificate(smime_request.id, issuer)

    def test_root_creation_initializes_and_advances_crl_state(self) -> None:
        with TemporaryDirectory() as tempdir:
            state = OfflineStateRepository(Path(tempdir) / "offline.sqlite3")
            offline = OfflineRootService(state, SoftwareHSM())
            bootstrap = offline.create_root("myOwnCA Offline Root CA")
            second_crl = offline.sign_root_crl()
            root_certificate = x509.load_pem_x509_certificate(bootstrap.root_certificate_pem.encode())
            parsed_crl = x509.load_pem_x509_crl(second_crl.crl_pem.encode())

            self.assertIn("BEGIN CERTIFICATE", bootstrap.root_certificate_pem)
            self.assertEqual(bootstrap.initial_root_crl.number, 1)
            self.assertEqual(second_crl.number, 2)
            self.assertTrue(parsed_crl.is_signature_valid(root_certificate.public_key()))
            self.assertEqual([crl.number for crl in state.list_root_crls()], [1, 2])
            self.assertEqual(
                [record.operation_type for record in state.list_ceremony_records()],
                ["root_create", "root_crl_sign", "root_crl_sign"],
            )
