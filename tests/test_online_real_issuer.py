from __future__ import annotations

import unittest
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography import x509

from myownca.ca_hsm import SoftwareHSM
from myownca.ca_main.crypto import certificate_to_pem, verify_certificate_signature
from myownca.domain import CertificateProfile, Role, SubCA
from myownca.offline import OfflineRootService, OfflineStateRepository
from myownca.online.app import RequestCreate, TemplateCreate, create_app
from tests.helpers import (
    add_login_ready_user,
    assign_request_holder,
    create_active_session,
    make_csr,
    request_with_session,
    route_endpoint,
)


class OnlineRealIssuerTests(unittest.TestCase):
    def test_app_imports_real_sub_ca_and_prefers_it_over_lab_chain(self) -> None:
        with TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            db_path = root / "online.sqlite3"
            key_dir = root / "online-keys"
            app = create_app(db_path, lab_mode=True, online_key_dir=key_dir)
            offline = OfflineRootService(
                OfflineStateRepository(root / "offline.sqlite3"),
                SoftwareHSM(),
            )
            bootstrap = offline.create_root("myOwnCA Offline Root CA")
            request = app.state.ceremony.create_sub_ca_request(
                common_name="myOwnCA Imported Issuing CA",
            )
            lab_chain = app.state.lab_chain
            assert lab_chain is not None
            app.state.repository.add_sub_ca(
                SubCA(
                    id="older-issuer-with-same-key-label",
                    certificate_pem=certificate_to_pem(
                        lab_chain.issuer.certificate
                    ),
                    key_ref=request.key_ref,
                    subject=lab_chain.issuer.certificate.subject.rfc4514_string(),
                    created_at=request.created_at - timedelta(days=1),
                    key_backend="pkcs11",
                    token_label="historical-token",
                )
            )
            signed = offline.sign_sub_ca_csr(
                request.csr_pem,
                permitted_dns_suffixes=("example.test",),
            )
            imported = app.state.ceremony.import_sub_ca_certificate(
                signed.certificate_pem,
                root_certificate_pem=bootstrap.root_certificate_pem,
                pending_id=request.id,
            )
            # The verified root is persisted for chain assembly (exports).
            self.assertEqual(
                app.state.repository.get_root_certificate_pem(),
                bootstrap.root_certificate_pem,
            )

            restarted = create_app(db_path, lab_mode=True, online_key_dir=key_dir)
            restarted.state.repository.set_setting(
                "crl_base_url", "https://ca.example.test"
            )
            admin_secret = add_login_ready_user(
                restarted, user_id="admin-1", email="admin1@example.test", role=Role.ADMIN
            )
            su1_secret = add_login_ready_user(
                restarted, user_id="su-1", email="su1@example.test", role=Role.SUPERUSER
            )
            su2_secret = add_login_ready_user(
                restarted, user_id="su-2", email="su2@example.test", role=Role.SUPERUSER
            )
            add_login_ready_user(
                restarted, user_id="user-1", email="user@example.test", role=Role.USER
            )

            admin_token, admin_csrf = create_active_session(
                restarted,
                email="admin1@example.test",
                totp_secret=admin_secret,
            )
            su1_token, su1_csrf = create_active_session(
                restarted,
                email="su1@example.test",
                totp_secret=su1_secret,
            )
            su2_token, su2_csrf = create_active_session(
                restarted,
                email="su2@example.test",
                totp_secret=su2_secret,
            )
            user_token, user_csrf = create_active_session(restarted, email="user@example.test")

            issuer_status = route_endpoint(restarted, "/internal/admin/issuer", "GET")
            create_template = route_endpoint(restarted, "/internal/templates", "POST")
            create_request = route_endpoint(
                restarted,
                "/internal/certificate-requests",
                "POST",
            )
            approve_request = route_endpoint(
                restarted,
                "/internal/certificate-requests/{request_id}/approvals",
                "POST",
            )

            setup_status = issuer_status(request_with_session(admin_token))
            self.assertEqual(setup_status["source"], "imported_sub_ca")
            self.assertEqual(setup_status["sub_ca_id"], imported.id)
            self.assertEqual(
                create_template(
                    TemplateCreate(id="host", name="Host TLS", profile="host_tls"),
                    request_with_session(admin_token, admin_csrf, method="POST"),
                ),
                {"id": "host"},
            )
            request_id = create_request(
                RequestCreate(
                    template_id="host",
                    csr_pem=make_csr("api.example.test", dns_names=("api.example.test",)),
                ),
                request_with_session(user_token, user_csrf, method="POST"),
            )["id"]
            assign_request_holder(restarted, request_id)
            approve_request(
                request_id,
                request_with_session(su1_token, su1_csrf, method="POST"),
            )
            second_approval = approve_request(
                request_id,
                request_with_session(su2_token, su2_csrf, method="POST"),
            )
            self.assertTrue(second_approval["auto_issued"])
            issued = second_approval["issued_certificate"]
            self.assertIsNotNone(issued)

            issued_certificate = x509.load_pem_x509_certificate(issued["certificate_pem"].encode())
            imported_issuer = restarted.state.ceremony.active_issuer_material()
            self.assertIsNotNone(imported_issuer)
            verify_certificate_signature(issued_certificate, imported_issuer.certificate)
            self.assertEqual(
                issued_certificate.issuer.rfc4514_string(),
                imported_issuer.certificate.subject.rfc4514_string(),
            )
            distribution_points = issued_certificate.extensions.get_extension_for_class(
                x509.CRLDistributionPoints
            ).value
            urls = [
                name.value
                for point in distribution_points
                for name in (point.full_name or ())
            ]
            self.assertTrue(
                any(url.endswith(f"/crl/{imported.id}.crl") for url in urls)
            )

    def test_app_without_lab_mode_reports_no_issuer_until_import(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(
                Path(tempdir) / "online.sqlite3",
                lab_mode=False,
                online_key_dir=Path(tempdir) / "online-keys",
            )
            admin_secret = add_login_ready_user(
                app, user_id="admin-1", email="admin1@example.test", role=Role.ADMIN
            )
            su1_secret = add_login_ready_user(
                app, user_id="su-1", email="su1@example.test", role=Role.SUPERUSER
            )
            su2_secret = add_login_ready_user(
                app, user_id="su-2", email="su2@example.test", role=Role.SUPERUSER
            )
            add_login_ready_user(
                app, user_id="user-1", email="user@example.test", role=Role.USER
            )
            admin_token, admin_csrf = create_active_session(
                app,
                email="admin1@example.test",
                totp_secret=admin_secret,
            )
            su1_token, su1_csrf = create_active_session(
                app, email="su1@example.test", totp_secret=su1_secret
            )
            su2_token, su2_csrf = create_active_session(
                app, email="su2@example.test", totp_secret=su2_secret
            )
            user_token, user_csrf = create_active_session(app, email="user@example.test")
            status = route_endpoint(app, "/internal/admin/issuer", "GET")(
                request_with_session(admin_token, admin_csrf)
            )
            self.assertEqual(
                status,
                {
                    "configured": False,
                    "source": None,
                    "sub_ca_id": None,
                    "subject": None,
                    "issuer": None,
                    "not_before": None,
                    "not_after": None,
                    "certificate_sha256": None,
                    "key_backend": None,
                    "token_label": None,
                    "allowed_profiles": None,
                },
            )

            route_endpoint(app, "/internal/templates", "POST")(
                TemplateCreate(id="host", name="Host TLS", profile="host_tls"),
                request_with_session(admin_token, admin_csrf, method="POST"),
            )
            request_id = route_endpoint(app, "/internal/certificate-requests", "POST")(
                RequestCreate(
                    template_id="host",
                    csr_pem=make_csr("api.example.test", dns_names=("api.example.test",)),
                ),
                request_with_session(user_token, user_csrf, method="POST"),
            )["id"]
            approve_request = route_endpoint(
                app, "/internal/certificate-requests/{request_id}/approvals", "POST"
            )
            approve_request(
                request_id, request_with_session(su1_token, su1_csrf, method="POST")
            )
            result = approve_request(
                request_id, request_with_session(su2_token, su2_csrf, method="POST")
            )

            self.assertFalse(result["auto_issued"])
            self.assertEqual(result["auto_issue_error"]["code"], "no_issuer")
            self.assertEqual(result["status"], "pending")
            self.assertEqual(result["approval_count"], 2)

    def test_auto_issue_failure_for_imported_sub_ca_profile_constraint(self) -> None:
        with TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            db_path = root / "online.sqlite3"
            key_dir = root / "online-keys"
            app = create_app(db_path, lab_mode=True, online_key_dir=key_dir)
            offline = OfflineRootService(
                OfflineStateRepository(root / "offline.sqlite3"),
                SoftwareHSM(),
            )
            bootstrap = offline.create_root("myOwnCA Offline Root CA")
            request = app.state.ceremony.create_sub_ca_request(
                common_name="myOwnCA User-Only Issuing CA",
                allowed_profiles=(CertificateProfile.USER_AUTH,),
            )
            signed = offline.sign_sub_ca_csr(
                request.csr_pem,
                allowed_profiles=(CertificateProfile.USER_AUTH,),
            )
            app.state.ceremony.import_sub_ca_certificate(
                signed.certificate_pem,
                root_certificate_pem=bootstrap.root_certificate_pem,
                pending_id=request.id,
            )

            admin_secret = add_login_ready_user(
                app, user_id="admin-1", email="admin1@example.test", role=Role.ADMIN
            )
            su1_secret = add_login_ready_user(
                app, user_id="su-1", email="su1@example.test", role=Role.SUPERUSER
            )
            su2_secret = add_login_ready_user(
                app, user_id="su-2", email="su2@example.test", role=Role.SUPERUSER
            )
            add_login_ready_user(
                app, user_id="user-1", email="user@example.test", role=Role.USER
            )
            admin_token, admin_csrf = create_active_session(
                app, email="admin1@example.test", totp_secret=admin_secret
            )
            su1_token, su1_csrf = create_active_session(
                app, email="su1@example.test", totp_secret=su1_secret
            )
            su2_token, su2_csrf = create_active_session(
                app, email="su2@example.test", totp_secret=su2_secret
            )
            user_token, user_csrf = create_active_session(app, email="user@example.test")

            route_endpoint(app, "/internal/templates", "POST")(
                TemplateCreate(id="host", name="Host TLS", profile="host_tls"),
                request_with_session(admin_token, admin_csrf, method="POST"),
            )
            request_id = route_endpoint(app, "/internal/certificate-requests", "POST")(
                RequestCreate(
                    template_id="host",
                    csr_pem=make_csr("api.example.test", dns_names=("api.example.test",)),
                ),
                request_with_session(user_token, user_csrf, method="POST"),
            )["id"]
            approve_request = route_endpoint(
                app, "/internal/certificate-requests/{request_id}/approvals", "POST"
            )
            approve_request(
                request_id, request_with_session(su1_token, su1_csrf, method="POST")
            )
            result = approve_request(
                request_id, request_with_session(su2_token, su2_csrf, method="POST")
            )

            self.assertFalse(result["auto_issued"])
            self.assertEqual(
                result["auto_issue_error"]["code"],
                "issuer_profile_constraint_mismatch",
            )
            self.assertEqual(result["status"], "pending")
            self.assertEqual(result["approval_count"], 2)
