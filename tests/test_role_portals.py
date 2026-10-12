from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import HTTPException

from myownca.domain import Role
from myownca.online.app import (
    PrivilegedRoleGrantCreate,
    RequestCreate,
    TemplateCreate,
    create_app,
)
from tests.helpers import (
    add_login_ready_user,
    assign_request_holder,
    create_active_session,
    make_csr,
    request_with_session,
    route_endpoint,
)


class RolePortalReadAPITests(unittest.TestCase):
    def test_read_apis_are_role_filtered_and_display_ready(self) -> None:
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
                app, user_id="user-1", email="user1@example.test", role=Role.USER
            )
            add_login_ready_user(
                app, user_id="user-2", email="user2@example.test", role=Role.USER
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
            user1_token, user1_csrf = create_active_session(app, email="user1@example.test")
            user2_token, user2_csrf = create_active_session(app, email="user2@example.test")

            route_endpoint(app, "/internal/templates", "POST")(
                TemplateCreate(id="host", name="Host TLS", profile="host_tls"),
                request_with_session(admin_token, admin_csrf, method="POST"),
            )
            create_request = route_endpoint(app, "/internal/certificate-requests", "POST")
            request_1 = create_request(
                RequestCreate(
                    template_id="host",
                    csr_pem=make_csr("api1.example.test", dns_names=("api1.example.test",)),
                ),
                request_with_session(user1_token, user1_csrf, method="POST"),
            )
            create_request_route = next(
                route
                for route in app.routes
                if getattr(route, "path", None) == "/internal/certificate-requests"
                and "POST" in getattr(route, "methods", set())
            )
            self.assertEqual(create_request_route.response_model, dict[str, object])
            self.assertIsInstance(request_1["required_approvals"], int)
            self.assertIsInstance(request_1["approval_count"], int)
            self.assertIsInstance(request_1["approved_by_current_user"], bool)
            self.assertIsInstance(request_1["approvals"], list)
            self.assertIsNone(request_1["issued_serial_number"])
            request_2 = create_request(
                RequestCreate(
                    template_id="host",
                    csr_pem=make_csr("api2.example.test", dns_names=("api2.example.test",)),
                ),
                request_with_session(user2_token, user2_csrf, method="POST"),
            )

            list_templates = route_endpoint(app, "/internal/templates", "GET")
            list_users = route_endpoint(app, "/internal/users", "GET")
            list_requests = route_endpoint(app, "/internal/certificate-requests", "GET")
            get_request = route_endpoint(app, "/internal/certificate-requests/{request_id}", "GET")
            approve_request = route_endpoint(
                app, "/internal/certificate-requests/{request_id}/approvals", "POST"
            )
            reject_request = route_endpoint(
                app, "/internal/certificate-requests/{request_id}/reject", "POST"
            )
            list_certificates = route_endpoint(app, "/internal/certificates", "GET")
            get_certificate = route_endpoint(app, "/internal/certificates/{serial_number}", "GET")

            templates = list_templates(request_with_session(user1_token))
            host_template = next(row for row in templates if row["id"] == "host")
            self.assertEqual(host_template["key_usages"], ["digital_signature", "key_encipherment"])
            users = list_users(request_with_session(su1_token))
            self.assertIn("user1@example.test", {user["email"] for user in users})

            user1_requests = list_requests(request_with_session(user1_token))
            self.assertEqual([row["id"] for row in user1_requests], [request_1["id"]])
            su_requests = list_requests(request_with_session(su1_token))
            self.assertEqual({row["id"] for row in su_requests}, {request_1["id"], request_2["id"]})
            detail = get_request(request_1["id"], request_with_session(su1_token))
            self.assertEqual(detail["requester_email"], "user1@example.test")
            self.assertIn("csr_pem", detail)

            with self.assertRaises(HTTPException) as denied:
                get_request(request_2["id"], request_with_session(user1_token))
            self.assertEqual(denied.exception.status_code, 403)

            with self.assertRaises(HTTPException) as wrong_owner_reject:
                reject_request(
                    request_2["id"],
                    request_with_session(user1_token, user1_csrf, method="POST"),
                )
            self.assertEqual(wrong_owner_reject.exception.status_code, 403)

            owner_rejected = reject_request(
                request_2["id"],
                request_with_session(user2_token, user2_csrf, method="POST"),
            )
            self.assertEqual(owner_rejected["status"], "rejected")
            with self.assertRaises(HTTPException) as rejected_approval:
                approve_request(
                    request_2["id"],
                    request_with_session(su1_token, su1_csrf, method="POST"),
                )
            self.assertEqual(rejected_approval.exception.status_code, 400)

            resubmitted = create_request(
                RequestCreate(
                    template_id="host",
                    csr_pem=make_csr("api2.example.test", dns_names=("api2.example.test",)),
                ),
                request_with_session(user2_token, user2_csrf, method="POST"),
            )
            self.assertNotEqual(resubmitted["id"], request_2["id"])
            self.assertEqual(resubmitted["status"], "pending")
            superuser_rejected = reject_request(
                resubmitted["id"],
                request_with_session(su1_token, su1_csrf, method="POST"),
            )
            self.assertEqual(superuser_rejected["status"], "rejected")

            with self.assertRaises(HTTPException) as admin_cannot_approve:
                approve_request(
                    request_1["id"],
                    request_with_session(admin_token, admin_csrf, method="POST"),
                )
            self.assertEqual(admin_cannot_approve.exception.status_code, 403)

            owner_person_id = next(
                person.id
                for person in app.state.repository.list_people()
                if person.email == "user1@example.test"
            )
            assign_request_holder(
                app, request_1["id"], person_id=owner_person_id
            )
            approve_request(
                request_1["id"], request_with_session(su1_token, su1_csrf, method="POST")
            )
            second_approval = approve_request(
                request_1["id"], request_with_session(su2_token, su2_csrf, method="POST")
            )
            self.assertTrue(second_approval["auto_issued"])
            issued = second_approval["issued_certificate"]
            self.assertIsNotNone(issued)

            user1_certs = list_certificates(request_with_session(user1_token))
            user2_certs = list_certificates(request_with_session(user2_token))
            self.assertEqual([row["serial_number"] for row in user1_certs], [issued["serial_number"]])
            self.assertEqual(user2_certs, [])
            certificate = get_certificate(
                issued["serial_number"], request_with_session(user1_token)
            )
            self.assertIn("BEGIN CERTIFICATE", certificate["certificate_pem"])
            with self.assertRaises(HTTPException) as denied_certificate:
                get_certificate(issued["serial_number"], request_with_session(user2_token))
            self.assertEqual(denied_certificate.exception.status_code, 403)

            with self.assertRaises(HTTPException) as missing_anchor:
                create_request(
                    RequestCreate(
                        template_id="host",
                        csr_pem=make_csr(
                            "api1.example.test", dns_names=("api1.example.test",)
                        ),
                        kind="renewal",
                    ),
                    request_with_session(user1_token, user1_csrf, method="POST"),
                )
            self.assertEqual(missing_anchor.exception.status_code, 400)

            with self.assertRaises(HTTPException) as wrong_owner:
                create_request(
                    RequestCreate(
                        template_id="host",
                        csr_pem=make_csr(
                            "api1.example.test", dns_names=("api1.example.test",)
                        ),
                        kind="renewal",
                        renewal_of_serial_number=issued["serial_number"],
                    ),
                    request_with_session(user2_token, user2_csrf, method="POST"),
                )
            self.assertEqual(wrong_owner.exception.status_code, 400)

            renewal = create_request(
                RequestCreate(
                    template_id="host",
                    csr_pem=make_csr("api1.example.test", dns_names=("api1.example.test",)),
                    kind="renewal",
                    renewal_of_serial_number=issued["serial_number"],
                ),
                request_with_session(user1_token, user1_csrf, method="POST"),
            )
            self.assertEqual(renewal["kind"], "renewal")
            self.assertEqual(renewal["required_approvals"], 1)
            self.assertEqual(renewal["renewal_of_serial_number"], issued["serial_number"])
            assign_request_holder(
                app, renewal["id"], person_id=owner_person_id
            )
            renewal_approval = approve_request(
                renewal["id"], request_with_session(su1_token, su1_csrf, method="POST")
            )
            self.assertTrue(renewal_approval["auto_issued"])
            self.assertEqual(renewal_approval["status"], "issued")

    def test_admin_proposal_list_contains_display_context(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "api.sqlite3")
            admin1_secret = add_login_ready_user(
                app, user_id="admin-1", email="admin1@example.test", role=Role.ADMIN
            )
            admin2_secret = add_login_ready_user(
                app, user_id="admin-2", email="admin2@example.test", role=Role.ADMIN
            )
            admin1_token, admin1_csrf = create_active_session(
                app, email="admin1@example.test", totp_secret=admin1_secret
            )
            admin2_token, admin2_csrf = create_active_session(
                app, email="admin2@example.test", totp_secret=admin2_secret
            )

            proposal = route_endpoint(
                app, "/internal/admin/proposals/privileged-role-grants", "POST"
            )(
                PrivilegedRoleGrantCreate(
                    id="su-1",
                    email="su1@example.test",
                    role="superuser",
                    temporary_password="temporary-password-1",
                ),
                request_with_session(admin1_token, admin1_csrf, method="POST"),
            )
            proposals = route_endpoint(app, "/internal/admin/proposals", "GET")(
                request_with_session(admin2_token)
            )
            self.assertEqual(proposals[0]["id"], proposal["id"])
            self.assertEqual(proposals[0]["target_email"], "su1@example.test")
            self.assertEqual(proposals[0]["requested_role"], "superuser")
            self.assertEqual(proposals[0]["proposer_email"], "admin1@example.test")

            approved = route_endpoint(
                app, "/internal/admin/proposals/{proposal_id}/approve", "POST"
            )(
                proposal["id"],
                request_with_session(admin2_token, admin2_csrf, method="POST"),
            )
            self.assertEqual(approved["status"], "approved")
