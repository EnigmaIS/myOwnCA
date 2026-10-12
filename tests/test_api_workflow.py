from __future__ import annotations

import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import HTTPException

from myownca.domain import (
    CertificateRequest,
    RequestKind,
    RequestStatus,
    Role,
)
from myownca.online.app import RequestCreate, RevocationCreate, TemplateCreate, create_app
from tests.helpers import (
    add_login_ready_user,
    assign_request_holder,
    create_active_session,
    make_csr,
    request_with_session,
    route_endpoint,
)


class InternalAPIWorkflowTests(unittest.TestCase):
    def test_full_ui_backed_workflow(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "api.sqlite3")
            repository = app.state.repository
            issuer = app.state.lab_chain.issuer
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
                app,
                email="su1@example.test",
                totp_secret=su1_secret,
            )
            su2_token, su2_csrf = create_active_session(
                app,
                email="su2@example.test",
                totp_secret=su2_secret,
            )
            user_token, user_csrf = create_active_session(app, email="user@example.test")

            create_template = route_endpoint(app, "/internal/templates", "POST")
            list_presets = route_endpoint(app, "/internal/templates/presets", "GET")
            create_request = route_endpoint(app, "/internal/certificate-requests", "POST")
            approve_request = route_endpoint(
                app,
                "/internal/certificate-requests/{request_id}/approvals",
                "POST",
            )
            revoke_certificate = route_endpoint(
                app,
                "/internal/certificates/{serial_number}/revoke",
                "POST",
            )
            reject_request = route_endpoint(
                app,
                "/internal/certificate-requests/{request_id}/reject",
                "POST",
            )
            create_crl = route_endpoint(app, "/internal/crls", "POST")

            self.assertEqual(
                create_template(
                    TemplateCreate(id="host", name="Host TLS", profile="host_tls"),
                    request_with_session(admin_token, admin_csrf, method="POST"),
                ),
                {"id": "host"},
            )
            presets = list_presets(request_with_session(admin_token))
            created = create_request(
                RequestCreate(
                    template_id="host",
                    csr_pem=make_csr("api.example.test", dns_names=("api.example.test",)),
                ),
                request_with_session(user_token, user_csrf, method="POST"),
            )
            request_id = created["id"]
            assign_request_holder(app, request_id)

            first_approval = approve_request(
                request_id,
                request_with_session(su1_token, su1_csrf, method="POST"),
            )
            self.assertFalse(first_approval["auto_issued"])
            self.assertIsNone(first_approval["auto_issue_error"])
            self.assertEqual(first_approval["approval_count"], 1)
            self.assertIsNone(first_approval["issued_certificate"])
            with self.assertRaises(HTTPException) as duplicate:
                approve_request(
                    request_id,
                    request_with_session(su1_token, su1_csrf, method="POST"),
                )
            self.assertEqual(duplicate.exception.status_code, 409)
            second_approval = approve_request(
                request_id,
                request_with_session(su2_token, su2_csrf, method="POST"),
            )
            self.assertTrue(second_approval["auto_issued"])
            self.assertIsNone(second_approval["auto_issue_error"])
            self.assertEqual(second_approval["status"], "issued")
            issued = second_approval["issued_certificate"]
            self.assertIsNotNone(issued)
            with self.assertRaises(HTTPException) as reject_issued:
                reject_request(
                    request_id,
                    request_with_session(user_token, user_csrf, method="POST"),
                )
            self.assertEqual(reject_issued.exception.status_code, 400)
            revoked = revoke_certificate(
                issued["serial_number"],
                RevocationCreate(reason="key_compromise"),
                request_with_session(su2_token, su2_csrf, method="POST"),
            )
            crl_job = create_crl(
                request_with_session(admin_token, admin_csrf, method="POST")
            )
            crl = app.state.crl_worker.run_once()

            stored = repository.get_issued_certificate(issued["serial_number"])
            self.assertEqual(first_approval["superuser_id"], "su-1")
            self.assertEqual(second_approval["superuser_id"], "su-2")
            self.assertEqual(revoked["reason"], "key_compromise")
            self.assertEqual(stored.serial_number, issued["serial_number"])
            self.assertIn("crl_job_id", crl_job)
            self.assertEqual(crl.number, 1)
            self.assertIn("BEGIN X509 CRL", crl.crl_pem)
            self.assertEqual(
                next(preset for preset in presets if preset["profile"] == "host_tls")[
                    "key_usages"
                ],
                ["digital_signature", "key_encipherment"],
            )
            self.assertEqual(repository.get_request(request_id).requested_by_user_id, "user-1")
            self.assertIsNotNone(issuer)
            with self.assertRaises(AssertionError):
                route_endpoint(app, "/internal/certificate-requests/{request_id}/issue", "POST")

    def test_invalid_csr_is_rejected_early_but_legacy_row_fails_issuance_safely(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "api.sqlite3")
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
            create_request = route_endpoint(app, "/internal/certificate-requests", "POST")
            invalid_csr = make_csr("api.example.test")
            with self.assertRaises(HTTPException) as invalid:
                create_request(
                    RequestCreate(template_id="host", csr_pem=invalid_csr),
                    request_with_session(user_token, user_csrf, method="POST"),
                )
            self.assertEqual(invalid.exception.status_code, 400)
            self.assertIn("DNS SAN", invalid.exception.detail)
            self.assertEqual(app.state.repository.list_requests(), [])

            request_id = "legacy-invalid-request"
            app.state.repository.add_request(
                CertificateRequest(
                    id=request_id,
                    template_id="host",
                    csr_pem=invalid_csr,
                    kind=RequestKind.FIRST_ISSUANCE,
                    status=RequestStatus.PENDING,
                    created_at=datetime.now(timezone.utc),
                    requested_by_user_id="user-1",
                )
            )
            assign_request_holder(app, request_id)
            approve_request = route_endpoint(
                app,
                "/internal/certificate-requests/{request_id}/approvals",
                "POST",
            )

            approve_request(
                request_id,
                request_with_session(su1_token, su1_csrf, method="POST"),
            )
            result = approve_request(
                request_id,
                request_with_session(su2_token, su2_csrf, method="POST"),
            )

            self.assertFalse(result["auto_issued"])
            self.assertEqual(result["auto_issue_error"]["code"], "invalid_csr_template")
            self.assertIn("DNS SAN", result["auto_issue_error"]["message"])
            self.assertEqual(result["status"], "pending")
            self.assertEqual(result["approval_count"], 2)
            self.assertIsNone(result["issued_certificate"])
