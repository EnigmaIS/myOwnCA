from __future__ import annotations

import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import HTTPException

from myownca.domain import CertificateProfile, Device, Person, Role
from myownca.online.app import (
    DeviceCreate,
    PersonCreate,
    RequestCreate,
    RequestHolderAssign,
    TemplateCreate,
    create_app,
)
from myownca.storage.repositories import RepositoryError
from tests.helpers import (
    TempPKI,
    add_login_ready_user,
    create_active_session,
    make_csr,
    request_with_session,
    route_endpoint,
)


def _person(person_id: str = "p1", email: str = "p1@example.test") -> Person:
    return Person(
        id=person_id,
        name="Alice",
        surname="Example",
        email=email,
        created_at=datetime.now(timezone.utc),
    )


class PeopleDeviceRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pki = TempPKI()

    def tearDown(self) -> None:
        self.pki.close()

    def test_person_crud_and_unique_email(self) -> None:
        self.pki.repository.add_person(_person())
        fetched = self.pki.repository.get_person("p1")
        self.assertEqual(fetched.full_name, "Alice Example")
        self.assertEqual([p.id for p in self.pki.repository.list_people()], ["p1"])
        with self.assertRaises(RepositoryError):
            self.pki.repository.add_person(_person(person_id="p2", email="p1@example.test"))

    def test_device_requires_existing_admin(self) -> None:
        with self.assertRaises(RepositoryError):
            self.pki.repository.add_device(
                Device(
                    id="d1",
                    device_name="box",
                    admin_id="ghost",
                    created_at=datetime.now(timezone.utc),
                )
            )

    def test_cannot_delete_person_linked_to_device(self) -> None:
        self.pki.repository.add_person(_person())
        self.pki.repository.add_device(
            Device(id="d1", device_name="box", admin_id="p1", created_at=datetime.now(timezone.utc))
        )
        with self.assertRaises(RepositoryError):
            self.pki.repository.delete_person("p1")
        # Removing the device first unblocks deletion.
        self.pki.repository.delete_device("d1")
        self.pki.repository.delete_person("p1")


class HolderAssignmentServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pki = TempPKI()
        self.pki.add_default_users()
        self.pki.add_template("user", CertificateProfile.USER_AUTH)
        self.pki.repository.add_person(_person())
        self.pki.repository.add_device(
            Device(id="d1", device_name="box", admin_id="p1", created_at=datetime.now(timezone.utc))
        )

    def tearDown(self) -> None:
        self.pki.close()

    def _approved_request(self):
        request = self.pki.service.submit_request(
            "user", make_csr("Alice", emails=("alice@example.test",))
        )
        self.pki.service.approve_request(request.id, "su-1")
        self.pki.service.approve_request(request.id, "su-2")
        return request

    def test_requires_exactly_one_holder(self) -> None:
        request = self._approved_request()
        with self.assertRaises(ValueError):
            self.pki.service.assign_request_holder(request.id)
        with self.assertRaises(ValueError):
            self.pki.service.assign_request_holder(
                request.id, person_id="p1", device_id="d1"
            )

    def test_unknown_holder_rejected(self) -> None:
        request = self._approved_request()
        with self.assertRaises(RepositoryError):
            self.pki.service.assign_request_holder(request.id, person_id="ghost")

    def test_issuance_blocked_until_holder_assigned(self) -> None:
        request = self._approved_request()
        with self.assertRaises(RepositoryError):
            self.pki.service.issue_certificate(request.id, self.pki.lab_chain.issuer)
        self.pki.service.assign_request_holder(request.id, person_id="p1")
        issued = self.pki.service.issue_certificate(request.id, self.pki.lab_chain.issuer)
        self.assertEqual(issued.holder_person_id, "p1")
        self.assertIsNone(issued.holder_device_id)

    def test_device_holder_is_copied_to_issued_certificate(self) -> None:
        request = self._approved_request()
        self.pki.service.assign_request_holder(request.id, device_id="d1")
        issued = self.pki.service.issue_certificate(request.id, self.pki.lab_chain.issuer)
        self.assertEqual(issued.holder_device_id, "d1")
        self.assertIsNone(issued.holder_person_id)


class HolderAPITests(unittest.TestCase):
    def _admin_app(self, tempdir: str):
        app = create_app(Path(tempdir) / "hd.sqlite3")
        admin_secret = add_login_ready_user(
            app, user_id="admin-1", email="admin1@example.test", role=Role.ADMIN
        )
        su1_secret = add_login_ready_user(
            app, user_id="su-1", email="su1@example.test", role=Role.SUPERUSER
        )
        su2_secret = add_login_ready_user(
            app, user_id="su-2", email="su2@example.test", role=Role.SUPERUSER
        )
        add_login_ready_user(app, user_id="user-1", email="user@example.test", role=Role.USER)
        tokens = {
            "admin": create_active_session(app, email="admin1@example.test", totp_secret=admin_secret),
            "su1": create_active_session(app, email="su1@example.test", totp_secret=su1_secret),
            "su2": create_active_session(app, email="su2@example.test", totp_secret=su2_secret),
            "user": create_active_session(app, email="user@example.test"),
        }
        return app, tokens

    def test_person_and_device_creation_and_role_gating(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, tokens = self._admin_app(tempdir)
            admin_token, admin_csrf = tokens["admin"]
            user_token, user_csrf = tokens["user"]

            person = route_endpoint(app, "/internal/people", "POST")(
                PersonCreate(name="Alice", surname="Example", email="alice@example.test"),
                request_with_session(admin_token, admin_csrf, method="POST"),
            )
            self.assertEqual(person["full_name"], "Alice Example")

            device = route_endpoint(app, "/internal/devices", "POST")(
                DeviceCreate(device_name="box", admin_id=person["id"], fqdn="box.example.test"),
                request_with_session(admin_token, admin_csrf, method="POST"),
            )
            self.assertEqual(device["admin_email"], "alice@example.test")

            # Ordinary users cannot manage holders.
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/people", "POST")(
                    PersonCreate(name="X", surname="Y", email="x@example.test"),
                    request_with_session(user_token, user_csrf, method="POST"),
                )
            self.assertEqual(ctx.exception.status_code, 403)

    def test_unknown_admin_person_rejected(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, tokens = self._admin_app(tempdir)
            admin_token, admin_csrf = tokens["admin"]
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/devices", "POST")(
                    DeviceCreate(device_name="box", admin_id="ghost"),
                    request_with_session(admin_token, admin_csrf, method="POST"),
                )
            self.assertEqual(ctx.exception.status_code, 409)

    def test_assigning_holder_after_full_approval_triggers_issuance(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, tokens = self._admin_app(tempdir)
            admin_token, admin_csrf = tokens["admin"]
            su1_token, su1_csrf = tokens["su1"]
            su2_token, su2_csrf = tokens["su2"]
            user_token, user_csrf = tokens["user"]

            route_endpoint(app, "/internal/templates", "POST")(
                TemplateCreate(id="host", name="Host TLS", profile="host_tls"),
                request_with_session(admin_token, admin_csrf, method="POST"),
            )
            person = route_endpoint(app, "/internal/people", "POST")(
                PersonCreate(name="Alice", surname="Example", email="alice@example.test"),
                request_with_session(admin_token, admin_csrf, method="POST"),
            )
            request_id = route_endpoint(app, "/internal/certificate-requests", "POST")(
                RequestCreate(
                    template_id="host",
                    csr_pem=make_csr("api.example.test", dns_names=("api.example.test",)),
                ),
                request_with_session(user_token, user_csrf, method="POST"),
            )["id"]

            approve = route_endpoint(
                app, "/internal/certificate-requests/{request_id}/approvals", "POST"
            )
            approve(request_id, request_with_session(su1_token, su1_csrf, method="POST"))
            # Reaching threshold without a holder fails issuance with no_holder.
            blocked = approve(request_id, request_with_session(su2_token, su2_csrf, method="POST"))
            self.assertFalse(blocked["auto_issued"])
            self.assertEqual(blocked["auto_issue_error"]["code"], "no_holder")

            # Assigning the holder now unblocks and auto-issues.
            assigned = route_endpoint(
                app, "/internal/certificate-requests/{request_id}/holder", "POST"
            )(
                request_id,
                RequestHolderAssign(person_id=person["id"]),
                request_with_session(su1_token, su1_csrf, method="POST"),
            )
            self.assertTrue(assigned["auto_issued"])
            self.assertIsNotNone(assigned["issued_certificate"])
            self.assertEqual(assigned["issued_certificate"]["holder"]["type"], "person")

    def test_certificate_holder_resolves_responsible_person_for_device(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, tokens = self._admin_app(tempdir)
            admin_token, admin_csrf = tokens["admin"]
            su1_token, su1_csrf = tokens["su1"]
            su2_token, su2_csrf = tokens["su2"]
            user_token, user_csrf = tokens["user"]

            route_endpoint(app, "/internal/templates", "POST")(
                TemplateCreate(id="host", name="Host TLS", profile="host_tls"),
                request_with_session(admin_token, admin_csrf, method="POST"),
            )
            person = route_endpoint(app, "/internal/people", "POST")(
                PersonCreate(name="Bob", surname="Ops", email="bob@example.test"),
                request_with_session(admin_token, admin_csrf, method="POST"),
            )
            device = route_endpoint(app, "/internal/devices", "POST")(
                DeviceCreate(device_name="edge-1", admin_id=person["id"]),
                request_with_session(admin_token, admin_csrf, method="POST"),
            )
            request_id = route_endpoint(app, "/internal/certificate-requests", "POST")(
                RequestCreate(
                    template_id="host",
                    csr_pem=make_csr("edge.example.test", dns_names=("edge.example.test",)),
                ),
                request_with_session(user_token, user_csrf, method="POST"),
            )["id"]
            route_endpoint(app, "/internal/certificate-requests/{request_id}/holder", "POST")(
                request_id,
                RequestHolderAssign(device_id=device["id"]),
                request_with_session(su1_token, su1_csrf, method="POST"),
            )
            approve = route_endpoint(
                app, "/internal/certificate-requests/{request_id}/approvals", "POST"
            )
            approve(request_id, request_with_session(su1_token, su1_csrf, method="POST"))
            result = approve(request_id, request_with_session(su2_token, su2_csrf, method="POST"))
            self.assertTrue(result["auto_issued"])
            holder = result["issued_certificate"]["holder"]
            self.assertEqual(holder["type"], "device")
            self.assertEqual(holder["responsible_person_email"], "bob@example.test")


if __name__ == "__main__":
    unittest.main()
