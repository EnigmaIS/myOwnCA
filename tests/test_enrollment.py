import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from cryptography import x509
from fastapi import HTTPException

from myownca.domain import CertificateProfile, CertificateTemplate, Person, Role
from myownca.holder import LinkPurpose
from myownca.online.app import ClaimEnroll, LinkCreate, LinkQrRequest, create_app
from tests.helpers import (
    add_login_ready_user,
    create_active_session,
    make_csr,
    request_with_session,
    route_endpoint,
)
from tests.test_claim_api import _claim_request, _open_session

NOW = datetime(2026, 6, 12, 12, 0, tzinfo=timezone.utc)


def _app(tempdir: str):
    app = create_app(Path(tempdir) / "e.sqlite3", lab_mode=True)
    su = add_login_ready_user(app, user_id="su-1", email="su1@example.test", role=Role.SUPERUSER)
    add_login_ready_user(app, user_id="su-2", email="su2@example.test", role=Role.SUPERUSER)
    app.state.repository.add_template(
        CertificateTemplate(id="user", name="User", profile=CertificateProfile.USER_AUTH)
    )
    app.state.repository.add_person(
        Person(id="p-carol", name="Carol", surname="Newcomer",
               email="carol@example.test", created_at=NOW)
    )
    su_session = create_active_session(app, email="su1@example.test", totp_secret=su)
    return app, su_session


def _enrollment_link(app):
    return app.state.secure_links.mint(
        LinkPurpose.ENROLLMENT, created_by="su-1", person_id="p-carol"
    )


class EnrollmentClaimTests(unittest.TestCase):
    def test_state_offers_templates_and_algorithms(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _su = _app(tempdir)
            link, token = _enrollment_link(app)
            session = _open_session(app, link, token)
            state = route_endpoint(app, "/internal/claim/{token}/state", "GET")(
                token, _claim_request(session)
            )
            self.assertEqual(state["purpose"], "enrollment")
            self.assertEqual([t["id"] for t in state["templates"]], ["user"])
            self.assertIn("ecdsa-p256", state["algorithms"])
            self.assertEqual(
                state["holder_defaults"],
                {"common_name": "Carol Newcomer", "email_address": "carol@example.test"},
            )

    def test_enroll_with_server_key(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _su = _app(tempdir)
            link, token = _enrollment_link(app)
            session = _open_session(app, link, token)
            result = route_endpoint(app, "/internal/claim/{token}/enroll", "POST")(
                token,
                ClaimEnroll(template_id="user", common_name="carol@example.test"),
                _claim_request(session, method="POST"),
            )
            self.assertTrue(result["server_key"])
            self.assertEqual(result["required_approvals"], 2)
            request = app.state.repository.get_request(result["request_id"])
            self.assertEqual(request.holder_person_id, "p-carol")
            self.assertEqual(request.via_link_auth, "otp")
            self.assertTrue(app.state.key_vault.held(request.id))
            csr = x509.load_pem_x509_csr(request.csr_pem.encode())
            self.assertEqual(csr.subject.rfc4514_string(), "CN=carol@example.test")
            # the link is consumed
            self.assertEqual(
                app.state.secure_links.usability(
                    app.state.secure_links.repository.get_link(link.id)
                ),
                "exhausted",
            )

    def test_enroll_with_pasted_csr(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _su = _app(tempdir)
            link, token = _enrollment_link(app)
            session = _open_session(app, link, token)
            pasted = make_csr("carol@example.test")
            result = route_endpoint(app, "/internal/claim/{token}/enroll", "POST")(
                token,
                ClaimEnroll(template_id="user", csr_pem=pasted),
                _claim_request(session, method="POST"),
            )
            self.assertFalse(result["server_key"])
            request = app.state.repository.get_request(result["request_id"])
            self.assertEqual(request.csr_pem, pasted)
            self.assertFalse(app.state.key_vault.held(request.id))

    def test_smime_server_key_enrollment_uses_email_san(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _su = _app(tempdir)
            app.state.repository.add_template(
                CertificateTemplate(id="smime", name="S/MIME", profile=CertificateProfile.SMIME)
            )
            link, token = _enrollment_link(app)
            session = _open_session(app, link, token)
            result = route_endpoint(app, "/internal/claim/{token}/enroll", "POST")(
                token,
                ClaimEnroll(
                    template_id="smime",
                    common_name="Carol Newcomer",
                    email_addresses=["carol@example.test"],
                ),
                _claim_request(session, method="POST"),
            )
            request = app.state.repository.get_request(result["request_id"])
            csr = x509.load_pem_x509_csr(request.csr_pem.encode())
            sans = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            self.assertEqual(
                sans.get_values_for_type(x509.RFC822Name), ["carol@example.test"]
            )

    def test_invalid_server_key_enrollment_does_not_consume_link_or_store_key(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _su = _app(tempdir)
            app.state.repository.add_template(
                CertificateTemplate(id="host", name="Host", profile=CertificateProfile.HOST_TLS)
            )
            link, token = _enrollment_link(app)
            session = _open_session(app, link, token)
            with mock.patch.object(app.state.key_vault, "store") as store:
                with self.assertRaises(HTTPException) as ctx:
                    route_endpoint(app, "/internal/claim/{token}/enroll", "POST")(
                        token,
                        ClaimEnroll(template_id="host", common_name="host.example.test"),
                        _claim_request(session, method="POST"),
                    )
            self.assertEqual(ctx.exception.status_code, 400)
            self.assertIn("DNS SAN", ctx.exception.detail)
            self.assertEqual(app.state.repository.list_requests(), [])
            self.assertIsNone(app.state.secure_links.usability(link))
            store.assert_not_called()

    def test_enroll_validation(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _su = _app(tempdir)
            link, token = _enrollment_link(app)
            session = _open_session(app, link, token)
            enroll = route_endpoint(app, "/internal/claim/{token}/enroll", "POST")
            with self.assertRaises(HTTPException) as ctx:
                enroll(token, ClaimEnroll(template_id="ghost", common_name="x"),
                       _claim_request(session, method="POST"))
            self.assertEqual(ctx.exception.status_code, 400)
            with self.assertRaises(HTTPException) as ctx:
                enroll(token, ClaimEnroll(template_id="user"),
                       _claim_request(session, method="POST"))
            self.assertEqual(ctx.exception.status_code, 400)  # no CSR, no CN
            with self.assertRaises(HTTPException) as ctx:
                enroll(token, ClaimEnroll(template_id="user", common_name="x", algorithm="rsa-1"),
                       _claim_request(session, method="POST"))
            self.assertEqual(ctx.exception.status_code, 400)

    def test_enroll_requires_session_and_enrollment_purpose(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _su = _app(tempdir)
            _link, token = _enrollment_link(app)
            enroll = route_endpoint(app, "/internal/claim/{token}/enroll", "POST")
            with self.assertRaises(HTTPException) as ctx:
                enroll(token, ClaimEnroll(template_id="user", common_name="x"),
                       _claim_request(method="POST"))
            self.assertEqual(ctx.exception.status_code, 401)


class LinkPurposeMintTests(unittest.TestCase):
    def test_superuser_can_mint_enrollment_links(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, (token, csrf) = _app(tempdir)
            created = route_endpoint(app, "/internal/links", "POST")(
                LinkCreate(purpose="enrollment", person_id="p-carol", send_email=False),
                request_with_session(token, csrf, method="POST"),
            )
            self.assertEqual(created["purpose"], "enrollment")
            self.assertEqual(created["person_email"], "carol@example.test")

    def test_enrollment_requires_person(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, (token, csrf) = _app(tempdir)
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/links", "POST")(
                    LinkCreate(purpose="enrollment", send_email=False),
                    request_with_session(token, csrf, method="POST"),
                )
            self.assertEqual(ctx.exception.status_code, 400)

    def test_qr_endpoint_returns_svg(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, (token, csrf) = _app(tempdir)
            response = route_endpoint(app, "/internal/links/qr", "POST")(
                LinkQrRequest(data="https://ca.example.test/claim/abc"),
                request_with_session(token, csrf, method="POST"),
            )
            self.assertEqual(response.media_type, "image/svg+xml")
            self.assertIn(b"<svg", response.body)


class ServerKeyRetentionTests(unittest.TestCase):
    def test_legacy_age_based_prune_is_not_available(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _ = _app(tempdir)
            self.assertFalse(hasattr(app.state.repository, "prune_request_private_keys"))


if __name__ == "__main__":
    unittest.main()
