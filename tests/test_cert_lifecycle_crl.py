from __future__ import annotations

import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi import HTTPException

from myownca.comms import NotificationChannel
from myownca.domain import (
    CertificateProfile,
    CertificateStatus,
    CertificateTemplate,
    Device,
    IssuedCertificate,
    Person,
    Role,
)
from myownca.online.app import CertificateSendRequest, _resolve_holder_person, create_app
from tests.helpers import (
    TempPKI,
    add_login_ready_user,
    create_active_session,
    make_csr,
    request_with_session,
    route_endpoint,
    seed_person,
)


def _app_with_issued_cert(tempdir: str):
    app = create_app(Path(tempdir) / "c.sqlite3", lab_mode=True)
    su1 = add_login_ready_user(app, user_id="su-1", email="su1@example.test", role=Role.SUPERUSER)
    add_login_ready_user(app, user_id="su-2", email="su2@example.test", role=Role.SUPERUSER)
    add_login_ready_user(app, user_id="user-1", email="user@example.test", role=Role.USER)
    app.state.repository.add_template(
        CertificateTemplate(id="host", name="Host", profile=CertificateProfile.HOST_TLS)
    )
    person_id = seed_person(app)  # person-default, holder@example.test
    req = app.state.service.submit_request(
        "host", make_csr("h.example.test", dns_names=("h.example.test",)), requested_by_user_id="user-1"
    )
    app.state.service.approve_request(req.id, "su-1")
    app.state.service.approve_request(req.id, "su-2")
    app.state.service.assign_request_holder(req.id, person_id=person_id)
    cert = app.state.service.issue_certificate(req.id, app.state.lab_chain.issuer)
    token, csrf = create_active_session(app, email="su1@example.test", totp_secret=su1)
    return app, cert, token, csrf


class HolderResolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pki = TempPKI()
        now = datetime.now(timezone.utc)
        self.pki.repository.add_person(
            Person(id="p1", name="Al", surname="Ng", email="al@example.test", created_at=now)
        )
        self.pki.repository.add_device(
            Device(id="d1", device_name="box", admin_id="p1", created_at=now)
        )

    def tearDown(self) -> None:
        self.pki.close()

    def _cert(self, *, person=None, device=None) -> IssuedCertificate:
        now = datetime.now(timezone.utc)
        return IssuedCertificate(
            serial_number="S1",
            request_id="r1",
            template_id="host",
            certificate_pem="x",
            subject="CN=x",
            issued_at=now,
            expires_at=now,
            status=CertificateStatus.ACTIVE,
            holder_person_id=person,
            holder_device_id=device,
        )

    def test_person_holder_resolves_directly(self) -> None:
        person = _resolve_holder_person(self.pki.repository, self._cert(person="p1"))
        self.assertEqual(person.email, "al@example.test")

    def test_device_holder_resolves_via_admin(self) -> None:
        person = _resolve_holder_person(self.pki.repository, self._cert(device="d1"))
        self.assertEqual(person.email, "al@example.test")

    def test_no_holder_returns_none(self) -> None:
        self.assertIsNone(_resolve_holder_person(self.pki.repository, self._cert()))


class CertificateRenewTests(unittest.TestCase):
    def test_renew_creates_renewal_request_reusing_csr(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, token, csrf = _app_with_issued_cert(tempdir)
            response = route_endpoint(app, "/internal/certificates/{serial_number}/renew", "POST")(
                cert.serial_number, request_with_session(token, csrf, method="POST")
            )
            self.assertEqual(response["kind"], "renewal")
            self.assertEqual(response["renewal_of_serial_number"], cert.serial_number)
            self.assertEqual(response["template_id"], "host")

    def test_renew_unknown_certificate_returns_404(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _cert, token, csrf = _app_with_issued_cert(tempdir)
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/certificates/{serial_number}/renew", "POST")(
                    "GHOST", request_with_session(token, csrf, method="POST")
                )
            self.assertEqual(ctx.exception.status_code, 404)


class CertificateSendTests(unittest.TestCase):
    def test_send_to_holder_via_webhook(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, token, csrf = _app_with_issued_cert(tempdir)
            app.state.comms.set_config(
                NotificationChannel.WEBHOOK, enabled=True, config={"url": "https://hook.test/x"}, secrets={}
            )
            captured: dict[str, object] = {}

            def fake_http_send(method, url, *, headers=None, data=None, **kw):
                captured["data"] = data
                return (200, "ok")

            with mock.patch("myownca.comms.webhook.http_send", side_effect=fake_http_send):
                response = route_endpoint(app, "/internal/certificates/{serial_number}/send", "POST")(
                    cert.serial_number,
                    CertificateSendRequest(channel=NotificationChannel.WEBHOOK),
                    request_with_session(token, csrf, method="POST"),
                )
            self.assertEqual(response["recipient"], "holder@example.test")
            self.assertTrue(response["success"])
            self.assertIn("BEGIN CERTIFICATE", str(captured["data"]))

    def test_send_without_holder_returns_409(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _cert, token, csrf = _app_with_issued_cert(tempdir)
            now = datetime.now(timezone.utc)
            req = app.state.service.submit_request(
                "host", make_csr("nh.example.test", dns_names=("nh.example.test",)), requested_by_user_id="user-1"
            )
            app.state.repository.add_issued_certificate(
                IssuedCertificate(
                    serial_number="NOHOLDER",
                    request_id=req.id,
                    template_id="host",
                    certificate_pem="x",
                    subject="CN=nh",
                    issued_at=now,
                    expires_at=now,
                    status=CertificateStatus.ACTIVE,
                )
            )
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/certificates/{serial_number}/send", "POST")(
                    "NOHOLDER",
                    CertificateSendRequest(channel=NotificationChannel.WEBHOOK),
                    request_with_session(token, csrf, method="POST"),
                )
            self.assertEqual(ctx.exception.status_code, 409)

    def test_send_on_unconfigured_channel_returns_400(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, token, csrf = _app_with_issued_cert(tempdir)
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/certificates/{serial_number}/send", "POST")(
                    cert.serial_number,
                    CertificateSendRequest(channel=NotificationChannel.EMAIL),
                    request_with_session(token, csrf, method="POST"),
                )
            self.assertEqual(ctx.exception.status_code, 400)


class CrlAccessTests(unittest.TestCase):
    def test_superuser_generate_and_latest(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "crl.sqlite3", lab_mode=True)
            su = add_login_ready_user(app, user_id="su-1", email="su1@example.test", role=Role.SUPERUSER)
            token, csrf = create_active_session(app, email="su1@example.test", totp_secret=su)

            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/crls/latest", "GET")(request_with_session(token, csrf))
            self.assertEqual(ctx.exception.status_code, 404)

            created = route_endpoint(app, "/internal/crls", "POST")(
                request_with_session(token, csrf, method="POST")
            )
            self.assertIn("crl_job_id", created)
            self.assertEqual(created["status"], "pending")
            app.state.crl_worker.run_once()

            latest = route_endpoint(app, "/internal/crls/latest", "GET")(request_with_session(token, csrf))
            self.assertEqual(latest["number"], 1)
            self.assertIn("BEGIN X509 CRL", latest["crl_pem"])

    def test_get_latest_issuer_crl_returns_highest_number(self) -> None:
        pki = TempPKI()
        try:
            first = pki.service.generate_crl(pki.lab_chain.issuer)
            second = pki.service.generate_crl(pki.lab_chain.issuer)
            latest = pki.repository.get_latest_issuer_crl(first.issuer_subject)
            self.assertEqual(latest.number, second.number)
            self.assertGreater(second.number, first.number)
        finally:
            pki.close()


if __name__ == "__main__":
    unittest.main()
