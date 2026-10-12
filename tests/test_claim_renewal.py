import unittest
import urllib.parse
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography import x509
from fastapi import HTTPException, Request

from myownca.domain import CertificateProfile, CertificateTemplate, Role
from myownca.holder import LinkPurpose
from myownca.online.app import ClaimRenew, HolderPortalUpdate, RequestGenerate, create_app
from tests.helpers import (
    add_login_ready_user,
    create_active_session,
    make_csr,
    request_with_session,
    route_endpoint,
    seed_person,
)
from tests.test_claim_api import _claim_request, _open_session, _state

_PROXY_SECRET = "proxy-shared-secret"


def _mtls_request(certificate_pem: str, secret: str = _PROXY_SECRET) -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/",
            "headers": [
                (b"x-bb-proxy-auth", secret.encode()),
                (b"x-bb-client-cert", urllib.parse.quote(certificate_pem).encode()),
            ],
            "client": ("203.0.113.9", 1234),
        }
    )


def _app_with_renewal_link(tempdir: str, *, server_key: bool = True):
    """Issued cert (renewal_approvals=0 template) + renewal link + mTLS secret."""
    app = create_app(Path(tempdir) / "r.sqlite3", lab_mode=True)
    su = add_login_ready_user(app, user_id="su-1", email="su1@example.test", role=Role.SUPERUSER)
    add_login_ready_user(app, user_id="su-2", email="su2@example.test", role=Role.SUPERUSER)
    app.state.repository.add_template(
        CertificateTemplate(
            id="host", name="Host", profile=CertificateProfile.HOST_TLS, renewal_approvals=0
        )
    )
    su_session = create_active_session(app, email="su1@example.test", totp_secret=su)
    token, csrf = su_session
    if server_key:
        generated = route_endpoint(app, "/internal/certificate-requests/generate", "POST")(
            RequestGenerate(
                template_id="host",
                common_name="renew.example.test",
                dns_names=["renew.example.test"],
            ),
            request_with_session(token, csrf, method="POST"),
        )
        request_id = generated["id"]
    else:
        request_id = app.state.service.submit_request(
            "host",
            make_csr("renew.example.test", dns_names=("renew.example.test",)),
            requested_by_user_id="su-1",
        ).id
    app.state.service.approve_request(request_id, "su-1")
    app.state.service.approve_request(request_id, "su-2")
    app.state.service.assign_request_holder(request_id, person_id=seed_person(app))
    certificate = app.state.service.issue_certificate(request_id, app.state.lab_chain.issuer)
    app.state.repository.set_setting("mtls_proxy_secret", _PROXY_SECRET)
    link, link_token = app.state.secure_links.mint(
        LinkPurpose.RENEWAL, created_by="su-1", serial_number=certificate.serial_number
    )
    return app, certificate, link, link_token, su_session


def _renew(app, link_token, request, mode=None, csr_pem=None):
    return route_endpoint(app, "/internal/claim/{token}/renew", "POST")(
        link_token, ClaimRenew(mode=mode, csr_pem=csr_pem), request
    )


class MtlsRenewalTests(unittest.TestCase):
    def test_possession_proven_rotation_auto_issues(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, _link, link_token, _su = _app_with_renewal_link(tempdir)
            result = _renew(app, link_token, _mtls_request(cert.certificate_pem))
            self.assertEqual(result["auth"], "mtls")
            self.assertEqual(result["mode"], "rotate")
            self.assertEqual(result["required_approvals"], 0)
            self.assertIsNotNone(result["issued_serial_number"])

            renewed = app.state.repository.get_issued_certificate(
                result["issued_serial_number"]
            )
            old = x509.load_pem_x509_certificate(cert.certificate_pem.encode())
            new = x509.load_pem_x509_certificate(renewed.certificate_pem.encode())
            self.assertNotEqual(  # the key actually rotated
                old.public_key().public_numbers(), new.public_key().public_numbers()
            )
            self.assertEqual(new.subject, old.subject)
            sans = new.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)
            self.assertEqual(sans, ["renew.example.test"])
            # rotated key vaulted under the renewal request
            self.assertTrue(app.state.key_vault.held(renewed.request_id))
            self.assertEqual(
                app.state.repository.get_request(renewed.request_id).via_link_auth, "mtls"
            )

    def test_link_consumed_after_renewal(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, _link, link_token, _su = _app_with_renewal_link(tempdir)
            _renew(app, link_token, _mtls_request(cert.certificate_pem))
            self.assertEqual(_state(app, link_token)["reason"], "exhausted")
            with self.assertRaises(HTTPException) as ctx:
                _renew(app, link_token, _mtls_request(cert.certificate_pem))
            self.assertEqual(ctx.exception.status_code, 410)

    def test_wrong_proxy_secret_or_foreign_cert_rejected(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, _link, link_token, _su = _app_with_renewal_link(tempdir)
            with self.assertRaises(HTTPException) as ctx:
                _renew(app, link_token, _mtls_request(cert.certificate_pem, secret="wrong"))
            self.assertEqual(ctx.exception.status_code, 401)
            # a different (valid-looking) certificate must not authenticate this link
            other = app.state.lab_chain.issuer.certificate.public_bytes
            from cryptography.hazmat.primitives import serialization

            other_pem = other(serialization.Encoding.PEM).decode()
            with self.assertRaises(HTTPException) as ctx:
                _renew(app, link_token, _mtls_request(other_pem))
            self.assertEqual(ctx.exception.status_code, 401)

    def test_revoked_certificate_cannot_renew(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, _link, link_token, _su = _app_with_renewal_link(tempdir)
            app.state.service.revoke_certificate(cert.serial_number)
            with self.assertRaises(HTTPException) as ctx:
                _renew(app, link_token, _mtls_request(cert.certificate_pem))
            self.assertEqual(ctx.exception.status_code, 401)  # possession check excludes revoked


class OtpRenewalTests(unittest.TestCase):
    def test_otp_renewal_forces_superuser_approval(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _cert, link, link_token, _su = _app_with_renewal_link(tempdir)
            session = _open_session(app, link, link_token)
            result = _renew(app, link_token, _claim_request(session, method="POST"))
            self.assertEqual(result["auth"], "otp")
            self.assertEqual(result["required_approvals"], 1)  # max(0, 1) forced
            self.assertTrue(result["requires_approval"])
            self.assertIsNone(result["issued_serial_number"])
            request = app.state.repository.get_request(result["request_id"])
            self.assertEqual(request.via_link_auth, "otp")

    def test_single_approval_then_issues(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _cert, link, link_token, (token, csrf) = _app_with_renewal_link(tempdir)
            session = _open_session(app, link, link_token)
            result = _renew(app, link_token, _claim_request(session, method="POST"))
            approval = route_endpoint(
                app, "/internal/certificate-requests/{request_id}/approvals", "POST"
            )(result["request_id"], request_with_session(token, csrf, method="POST"))
            self.assertTrue(approval["auto_issued"])
            self.assertEqual(approval["via_link_auth"], "otp")

    def test_without_any_auth_renewal_is_401(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _cert, _link, link_token, _su = _app_with_renewal_link(tempdir)
            with self.assertRaises(HTTPException) as ctx:
                _renew(app, link_token, _claim_request(method="POST"))
            self.assertEqual(ctx.exception.status_code, 401)


class RenewalModeTests(unittest.TestCase):
    def test_reuse_keeps_anchor_csr_and_copies_key(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, _link, link_token, _su = _app_with_renewal_link(tempdir)
            result = _renew(
                app, link_token, _mtls_request(cert.certificate_pem), mode="reuse"
            )
            renewal = app.state.repository.get_request(result["request_id"])
            anchor = app.state.repository.get_request(cert.request_id)
            self.assertEqual(renewal.csr_pem, anchor.csr_pem)
            self.assertTrue(app.state.key_vault.held(renewal.id))

    def test_paste_csr_mode(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, _link, link_token, _su = _app_with_renewal_link(tempdir)
            pasted = make_csr("renew.example.test", dns_names=("renew.example.test",))
            result = _renew(
                app, link_token, _mtls_request(cert.certificate_pem), mode="csr", csr_pem=pasted
            )
            renewal = app.state.repository.get_request(result["request_id"])
            self.assertEqual(renewal.csr_pem, pasted)
            self.assertFalse(app.state.key_vault.held(renewal.id))

    def test_csr_mode_requires_csr(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, _link, link_token, _su = _app_with_renewal_link(tempdir)
            with self.assertRaises(HTTPException) as ctx:
                _renew(app, link_token, _mtls_request(cert.certificate_pem), mode="csr")
            self.assertEqual(ctx.exception.status_code, 400)

    def test_rotate_without_server_key_409_and_default_falls_to_reuse(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, _link, link_token, _su = _app_with_renewal_link(
                tempdir, server_key=False
            )
            with self.assertRaises(HTTPException) as ctx:
                _renew(app, link_token, _mtls_request(cert.certificate_pem), mode="rotate")
            self.assertEqual(ctx.exception.status_code, 409)
            result = _renew(app, link_token, _mtls_request(cert.certificate_pem))
            self.assertEqual(result["mode"], "reuse")

    def test_renew_rejected_on_delivery_link(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, _link, _token, _su = _app_with_renewal_link(tempdir)
            _dlink, dtoken = app.state.secure_links.mint(
                LinkPurpose.DELIVERY, created_by="su-1", serial_number=cert.serial_number
            )
            with self.assertRaises(HTTPException) as ctx:
                _renew(app, dtoken, _mtls_request(cert.certificate_pem))
            self.assertEqual(ctx.exception.status_code, 400)


class MtlsSettingsTests(unittest.TestCase):
    def test_secret_is_write_only(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "s.sqlite3", lab_mode=True)
            admin = add_login_ready_user(
                app, user_id="admin-1", email="admin@example.test", role=Role.ADMIN
            )
            token, csrf = create_active_session(
                app, email="admin@example.test", totp_secret=admin
            )
            updated = route_endpoint(app, "/internal/admin/holder-portal", "PUT")(
                HolderPortalUpdate(
                    mtls_base_url="https://renew.example.test:8443",
                    mtls_proxy_secret="super-proxy-secret",
                ),
                request_with_session(token, csrf, method="PUT"),
            )
            self.assertEqual(updated["mtls_base_url"], "https://renew.example.test:8443")
            self.assertTrue(updated["mtls_proxy_secret_set"])
            self.assertNotIn("super-proxy-secret", str(updated))


if __name__ == "__main__":
    unittest.main()
