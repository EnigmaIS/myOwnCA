import re
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi import HTTPException, Request, Response

from myownca.comms import CommsService, DeliveryResult, NotificationChannel
from myownca.domain import CertificateProfile, CertificateTemplate, Role
from myownca.holder import LinkPurpose
from myownca.online.app import (
    ClaimDownload,
    ClaimOtpVerify,
    HolderPortalUpdate,
    LinkCreate,
    RequestGenerate,
    create_app,
)
from tests.helpers import (
    add_login_ready_user,
    create_active_session,
    request_with_session,
    route_endpoint,
    seed_person,
)


def _ok_send(channel, recipient, message):  # noqa: ARG001 - mock signature
    return DeliveryResult(
        channel=NotificationChannel.EMAIL, recipient=recipient, success=True, detail="mocked"
    )


def _claim_request(claim_session: str | None = None, method: str = "GET") -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if claim_session is not None:
        headers.append((b"cookie", f"myownca_claim={claim_session}".encode()))
    return Request(
        {
            "type": "http",
            "method": method,
            "path": "/",
            "headers": headers,
            "client": ("203.0.113.9", 1234),
        }
    )


def _app_with_link(tempdir: str):
    """App + issued server-key cert + a delivery link for it + superuser session."""
    app = create_app(Path(tempdir) / "c.sqlite3", lab_mode=True)
    su = add_login_ready_user(app, user_id="su-1", email="su1@example.test", role=Role.SUPERUSER)
    add_login_ready_user(app, user_id="su-2", email="su2@example.test", role=Role.SUPERUSER)
    app.state.repository.add_template(
        CertificateTemplate(id="host", name="Host", profile=CertificateProfile.HOST_TLS)
    )
    su_session = create_active_session(app, email="su1@example.test", totp_secret=su)
    token, csrf = su_session
    generated = route_endpoint(app, "/internal/certificate-requests/generate", "POST")(
        RequestGenerate(
            template_id="host", common_name="hold.example.test", dns_names=["hold.example.test"]
        ),
        request_with_session(token, csrf, method="POST"),
    )
    request_id = generated["id"]
    app.state.service.approve_request(request_id, "su-1")
    app.state.service.approve_request(request_id, "su-2")
    app.state.service.assign_request_holder(request_id, person_id=seed_person(app))
    certificate = app.state.service.issue_certificate(request_id, app.state.lab_chain.issuer)
    link, link_token = app.state.secure_links.mint(
        LinkPurpose.DELIVERY, created_by="su-1", serial_number=certificate.serial_number
    )
    return app, certificate, link, link_token, su_session


def _state(app, token, claim_session=None):
    return route_endpoint(app, "/internal/claim/{token}/state", "GET")(
        token, _claim_request(claim_session)
    )


def _open_session(app, link, link_token) -> str:
    """OTP-verify directly through the service, return the claim session value."""
    code = app.state.secure_links.start_otp(link)
    response = Response()
    route_endpoint(app, "/internal/claim/{token}/otp/verify", "POST")(
        link_token, ClaimOtpVerify(code=code), _claim_request(method="POST"), response
    )
    cookie = response.headers["set-cookie"]
    return re.search(r"myownca_claim=([^;]+)", cookie).group(1)


class ClaimStateTests(unittest.TestCase):
    def test_unknown_token_404(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _cert, _link, _token, _su = _app_with_link(tempdir)
            with self.assertRaises(HTTPException) as ctx:
                _state(app, "no-such-token")
            self.assertEqual(ctx.exception.status_code, 404)

    def test_pre_otp_state_is_masked(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _cert, _link, token, _su = _app_with_link(tempdir)
            state = _state(app, token)
            self.assertEqual(state["status"], "otp_required")
            self.assertEqual(state["recipient_hint"], "h***@example.test")
            self.assertNotIn("certificate", state)

    def test_revoked_link_reports_unusable(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _cert, link, token, _su = _app_with_link(tempdir)
            app.state.secure_links.revoke(link.id)
            state = _state(app, token)
            self.assertEqual(state, {"status": "unusable", "reason": "revoked", "purpose": "delivery"})


class ClaimOtpTests(unittest.TestCase):
    def test_send_emails_code_and_throttles_resend(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _cert, _link, token, _su = _app_with_link(tempdir)
            send = route_endpoint(app, "/internal/claim/{token}/otp/send", "POST")
            with mock.patch.object(CommsService, "send", side_effect=_ok_send) as sent:
                result = send(token, _claim_request(method="POST"))
            self.assertTrue(result["sent"])
            recipient = sent.call_args.args[1]
            body = sent.call_args.args[2].body
            self.assertEqual(recipient, "holder@example.test")
            self.assertRegex(body, r"\d{6}")
            with self.assertRaises(HTTPException) as ctx:
                send(token, _claim_request(method="POST"))
            self.assertEqual(ctx.exception.status_code, 429)

    def test_verify_wrong_code_then_lockout(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _cert, link, token, _su = _app_with_link(tempdir)
            app.state.secure_links.start_otp(link)
            verify = route_endpoint(app, "/internal/claim/{token}/otp/verify", "POST")
            for attempt in range(5):
                with self.assertRaises(HTTPException) as ctx:
                    verify(
                        token,
                        ClaimOtpVerify(code="000000"),
                        _claim_request(method="POST"),
                        Response(),
                    )
                expected = 423 if attempt == 4 else 400
                self.assertEqual(ctx.exception.status_code, expected)
            self.assertEqual(_state(app, token)["reason"], "locked")

    def test_verify_sets_claim_cookie_and_unlocks_state(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, link, token, _su = _app_with_link(tempdir)
            session = _open_session(app, link, token)
            state = _state(app, token, claim_session=session)
            self.assertEqual(state["status"], "ready")
            self.assertEqual(state["certificate"]["subject"], "CN=hold.example.test")
            self.assertTrue(state["server_key_held"])
            self.assertEqual(state["certificate"]["serial_number"], cert.serial_number)


class ClaimDownloadTests(unittest.TestCase):
    def _download(self, app, token, claim_session, fmt, password=None):
        return route_endpoint(app, "/internal/claim/{token}/download", "POST")(
            token,
            ClaimDownload(format=fmt, password=password),
            _claim_request(claim_session, method="POST"),
        )

    def test_download_requires_session(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _cert, _link, token, _su = _app_with_link(tempdir)
            with self.assertRaises(HTTPException) as ctx:
                self._download(app, token, None, "pem")
            self.assertEqual(ctx.exception.status_code, 401)

    def test_keyless_download_and_no_receipt(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _cert, link, token, _su = _app_with_link(tempdir)
            session = _open_session(app, link, token)
            with mock.patch.object(CommsService, "send", side_effect=_ok_send) as sent:
                response = self._download(app, token, session, "pem")
            self.assertIn(".crt", response.headers["content-disposition"])
            self.assertEqual(sent.call_count, 0)  # public material: no receipt

    def test_key_bearing_download_sends_receipt(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _cert, link, token, _su = _app_with_link(tempdir)
            session = _open_session(app, link, token)
            with mock.patch.object(CommsService, "send", side_effect=_ok_send) as sent:
                response = self._download(app, token, session, "pkcs12", "hunter2-strong")
            self.assertIn(".pfx", response.headers["content-disposition"])
            self.assertEqual(sent.call_count, 1)
            self.assertIn("downloaded", sent.call_args.args[2].subject)

    def test_receipts_can_be_disabled(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _cert, link, token, _su = _app_with_link(tempdir)
            app.state.repository.set_setting("holder_download_receipts", "0")
            session = _open_session(app, link, token)
            with mock.patch.object(CommsService, "send", side_effect=_ok_send) as sent:
                self._download(app, token, session, "pkcs12", "hunter2-strong")
            self.assertEqual(sent.call_count, 0)

    def test_short_password_rejected(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _cert, link, token, _su = _app_with_link(tempdir)
            session = _open_session(app, link, token)
            with self.assertRaises(HTTPException) as ctx:
                self._download(app, token, session, "pkcs12", "short")
            self.assertEqual(ctx.exception.status_code, 400)

    def test_renewal_purpose_link_cannot_download(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, _link, _token, _su = _app_with_link(tempdir)
            renewal_link, renewal_token = app.state.secure_links.mint(
                LinkPurpose.RENEWAL, created_by="su-1", serial_number=cert.serial_number
            )
            session = _open_session(app, renewal_link, renewal_token)
            with self.assertRaises(HTTPException) as ctx:
                self._download(app, renewal_token, session, "pem")
            self.assertEqual(ctx.exception.status_code, 400)


class LinkManagementTests(unittest.TestCase):
    def test_create_without_base_url_returns_path_only(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, _link, _token, (token, csrf) = _app_with_link(tempdir)
            created = route_endpoint(app, "/internal/links", "POST")(
                LinkCreate(serial_number=cert.serial_number, send_email=False),
                request_with_session(token, csrf, method="POST"),
            )
            self.assertIsNone(created["claim_url"])
            self.assertTrue(created["claim_path"].startswith("/claim/"))
            self.assertEqual(created["status"], "active")
            self.assertEqual(created["person_email"], "holder@example.test")

    def test_create_with_send_requires_base_url_then_emails_link(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, _link, _token, (token, csrf) = _app_with_link(tempdir)
            create = route_endpoint(app, "/internal/links", "POST")
            with self.assertRaises(HTTPException) as ctx:
                create(
                    LinkCreate(serial_number=cert.serial_number, send_email=True),
                    request_with_session(token, csrf, method="POST"),
                )
            self.assertEqual(ctx.exception.status_code, 409)

            app.state.repository.set_setting("portal_base_url", "https://ca.example.test")
            with mock.patch.object(CommsService, "send", side_effect=_ok_send) as sent:
                created = create(
                    LinkCreate(serial_number=cert.serial_number, send_email=True),
                    request_with_session(token, csrf, method="POST"),
                )
            self.assertTrue(created["email_sent"])
            self.assertTrue(created["claim_url"].startswith("https://ca.example.test/claim/"))
            self.assertIn(created["claim_url"], sent.call_args.args[2].body)

    def test_unknown_purpose_rejected_but_renewal_allowed(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, _link, _token, (token, csrf) = _app_with_link(tempdir)
            create = route_endpoint(app, "/internal/links", "POST")
            with self.assertRaises(HTTPException) as ctx:
                create(
                    LinkCreate(serial_number=cert.serial_number, purpose="bogus", send_email=False),
                    request_with_session(token, csrf, method="POST"),
                )
            self.assertEqual(ctx.exception.status_code, 400)
            renewal = create(
                LinkCreate(serial_number=cert.serial_number, purpose="renewal", send_email=False),
                request_with_session(token, csrf, method="POST"),
            )
            self.assertEqual(renewal["purpose"], "renewal")

    def test_list_and_revoke(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _cert, link, claim_token, (token, csrf) = _app_with_link(tempdir)
            listing = route_endpoint(app, "/internal/links", "GET")(
                request_with_session(token, csrf)
            )
            self.assertEqual(len(listing), 1)
            revoked = route_endpoint(app, "/internal/links/{link_id}/revoke", "POST")(
                link.id, request_with_session(token, csrf, method="POST")
            )
            self.assertEqual(revoked["status"], "revoked")
            self.assertEqual(_state(app, claim_token)["status"], "unusable")

    def test_user_role_cannot_manage_links(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, _link, _token, _su = _app_with_link(tempdir)
            user_secret = add_login_ready_user(
                app, user_id="user-1", email="user@example.test", role=Role.USER
            )
            user_token, user_csrf = create_active_session(
                app, email="user@example.test", totp_secret=user_secret
            )
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/links", "POST")(
                    LinkCreate(serial_number=cert.serial_number, send_email=False),
                    request_with_session(user_token, user_csrf, method="POST"),
                )
            self.assertEqual(ctx.exception.status_code, 403)


class HolderPortalSettingsTests(unittest.TestCase):
    def test_get_put_roundtrip_and_validation(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "h.sqlite3", lab_mode=True)
            admin_secret = add_login_ready_user(
                app, user_id="admin-1", email="admin@example.test", role=Role.ADMIN
            )
            token, csrf = create_active_session(
                app, email="admin@example.test", totp_secret=admin_secret
            )
            status = route_endpoint(app, "/internal/admin/holder-portal", "GET")(
                request_with_session(token, csrf)
            )
            self.assertEqual(
                status,
                {
                    "portal_base_url": None,
                    "download_receipts": True,
                    "mtls_base_url": None,
                    "mtls_proxy_secret_set": False,
                    "server_key_purge_days": 30,
                },
            )

            updated = route_endpoint(app, "/internal/admin/holder-portal", "PUT")(
                HolderPortalUpdate(
                    portal_base_url="https://ca.example.test/", download_receipts=False
                ),
                request_with_session(token, csrf, method="PUT"),
            )
            self.assertEqual(updated["portal_base_url"], "https://ca.example.test")
            self.assertFalse(updated["download_receipts"])
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/admin/holder-portal", "PUT")(
                    HolderPortalUpdate(portal_base_url="ca.example.test"),
                    request_with_session(token, csrf, method="PUT"),
                )
            self.assertEqual(ctx.exception.status_code, 400)


if __name__ == "__main__":
    unittest.main()
