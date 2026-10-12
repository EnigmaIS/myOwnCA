import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import HTTPException

from myownca.domain import CertificateProfile, CertificateTemplate, Role
from myownca.online.app import RequestGenerate, RequestHolderAssign, create_app
from tests.helpers import (
    add_login_ready_user,
    create_active_session,
    request_with_session,
    route_endpoint,
    seed_person,
)


def _app_with_template(tempdir: str):
    app = create_app(Path(tempdir) / "s.sqlite3", lab_mode=True)
    su1 = add_login_ready_user(app, user_id="su-1", email="su1@example.test", role=Role.SUPERUSER)
    add_login_ready_user(app, user_id="su-2", email="su2@example.test", role=Role.SUPERUSER)
    user_secret = add_login_ready_user(
        app, user_id="user-1", email="user@example.test", role=Role.USER
    )
    add_login_ready_user(app, user_id="user-2", email="other@example.test", role=Role.USER)
    app.state.repository.add_template(
        CertificateTemplate(id="host", name="Host", profile=CertificateProfile.HOST_TLS)
    )
    user_session = create_active_session(app, email="user@example.test", totp_secret=user_secret)
    return app, su1, user_session


def _generate(app, session, **overrides):
    payload = RequestGenerate(
        **{
            "template_id": "host",
            "common_name": "gen.example.test",
            "dns_names": ["gen.example.test", "alt.example.test"],
            "algorithm": "ecdsa-p256",
            **overrides,
        }
    )
    token, csrf = session
    return route_endpoint(app, "/internal/certificate-requests/generate", "POST")(
        payload, request_with_session(token, csrf, method="POST")
    )


class GenerateRequestTests(unittest.TestCase):
    def test_zero_approval_generation_issues_when_holder_is_assigned(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, su_secret, _session = _app_with_template(tempdir)
            app.state.repository.update_template(
                CertificateTemplate(
                    id="host", name="Host", profile=CertificateProfile.HOST_TLS,
                    first_issuance_approvals=0,
                )
            )
            session = create_active_session(
                app, email="su1@example.test", totp_secret=su_secret
            )
            generated = _generate(app, session)
            self.assertEqual(generated["status"], "pending")
            token, csrf = session
            result = route_endpoint(
                app, "/internal/certificate-requests/{request_id}/holder", "POST"
            )(
                generated["id"], RequestHolderAssign(person_id=seed_person(app)),
                request_with_session(token, csrf, method="POST"),
            )
            self.assertEqual(result["status"], "issued")
            self.assertTrue(result["auto_issued"])
            self.assertIsNone(result["auto_issue_error"])
            self.assertEqual(result["issued_certificate"]["request_id"], generated["id"])
            self.assertEqual(app.state.repository.list_approvals(generated["id"]), [])
            self.assertEqual(len(app.state.repository.list_requests()), 1)
            self.assertEqual(len(app.state.repository.list_issued_certificates()), 1)

    def test_generate_creates_pending_request_with_vaulted_key(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _su1, session = _app_with_template(tempdir)
            response = _generate(app, session)
            self.assertEqual(response["status"], "pending")
            self.assertTrue(response["server_key_held"])
            self.assertEqual(response["requested_by_user_id"], "user-1")

            request_id = response["id"]
            csr_pem = app.state.repository.get_request(request_id).csr_pem
            csr = x509.load_pem_x509_csr(csr_pem.encode())
            self.assertEqual(csr.subject.rfc4514_string(), "CN=gen.example.test")
            sans = csr.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)
            self.assertEqual(sans, ["gen.example.test", "alt.example.test"])

            key_pem = app.state.key_vault.load_pem(request_id)
            key = serialization.load_pem_private_key(key_pem.encode(), password=None)
            self.assertEqual(key.public_key(), csr.public_key())

    def test_key_is_encrypted_at_rest(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _su1, session = _app_with_template(tempdir)
            request_id = _generate(app, session)["id"]
            row = app.state.repository.get_request_private_key(request_id)
            self.assertNotIn("PRIVATE KEY", row["key_pem_encrypted"])
            self.assertEqual(row["algorithm"], "ecdsa-p256")

    def test_unsupported_algorithm_rejected(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _su1, session = _app_with_template(tempdir)
            with self.assertRaises(HTTPException) as ctx:
                _generate(app, session, algorithm="rsa-512")
            self.assertEqual(ctx.exception.status_code, 400)

    def test_template_disallowed_algorithm_is_rejected_before_key_generation(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _su1, session = _app_with_template(tempdir)
            app.state.repository.update_template(
                CertificateTemplate(
                    id="host",
                    name="Host",
                    profile=CertificateProfile.HOST_TLS,
                    allowed_key_algorithms=("rsa-2048",),
                )
            )
            with self.assertRaises(HTTPException) as ctx:
                _generate(app, session, algorithm="ecdsa-p256")
            self.assertEqual(ctx.exception.status_code, 400)
            self.assertIn("not allowed", ctx.exception.detail)

    def test_unknown_template_rejected(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _su1, session = _app_with_template(tempdir)
            with self.assertRaises(HTTPException) as ctx:
                _generate(app, session, template_id="ghost")
            self.assertEqual(ctx.exception.status_code, 400)

    def test_blank_common_name_rejected(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _su1, session = _app_with_template(tempdir)
            with self.assertRaises(HTTPException) as ctx:
                _generate(app, session, common_name="   ")
            self.assertEqual(ctx.exception.status_code, 400)

    def test_profile_incompatible_request_is_not_persisted_or_vaulted(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _su1, session = _app_with_template(tempdir)
            with mock.patch.object(app.state.key_vault, "store") as store:
                with self.assertRaises(HTTPException) as ctx:
                    _generate(app, session, dns_names=[])
            self.assertEqual(ctx.exception.status_code, 400)
            self.assertIn("DNS SAN", ctx.exception.detail)
            self.assertEqual(app.state.repository.list_requests(), [])
            store.assert_not_called()

    def test_smime_generation_emits_email_san_and_can_issue(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _su1, session = _app_with_template(tempdir)
            app.state.repository.add_template(
                CertificateTemplate(id="smime", name="S/MIME", profile=CertificateProfile.SMIME)
            )
            generated = _generate(
                app,
                session,
                template_id="smime",
                common_name="Alice Example",
                dns_names=[],
                email_addresses=["alice@example.test"],
            )
            request = app.state.repository.get_request(generated["id"])
            csr = x509.load_pem_x509_csr(request.csr_pem.encode())
            sans = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            self.assertEqual(
                sans.get_values_for_type(x509.RFC822Name), ["alice@example.test"]
            )
            app.state.service.assign_request_holder(request.id, person_id=seed_person(app))
            app.state.service.approve_request(request.id, "su-1")
            app.state.service.approve_request(request.id, "su-2")
            issued = app.state.service.issue_certificate(request.id, app.state.lab_chain.issuer)
            self.assertEqual(issued.template_id, "smime")

    def test_broken_entropy_source_fails_closed_with_503(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _su1, session = _app_with_template(tempdir)
            # Runtime admin-portal setting; resolved per generation.
            app.state.repository.set_setting("entropy_source", "/nonexistent/trng")
            with self.assertRaises(HTTPException) as ctx:
                _generate(app, session)
            self.assertEqual(ctx.exception.status_code, 503)

    def test_csr_submitted_requests_hold_no_server_key(self) -> None:
        with TemporaryDirectory() as tempdir:
            from tests.helpers import make_csr

            app, _su1, _session = _app_with_template(tempdir)
            request = app.state.service.submit_request(
                "host",
                make_csr("manual.example.test", dns_names=("manual.example.test",)),
                requested_by_user_id="user-1",
            )
            self.assertFalse(app.state.repository.has_request_private_key(request.id))


class ServerKeyLifecycleTests(unittest.TestCase):
    def _issued(self, app, session):
        request_id = _generate(app, session)["id"]
        app.state.service.approve_request(request_id, "su-1")
        app.state.service.approve_request(request_id, "su-2")
        app.state.service.assign_request_holder(
            request_id,
            person_id=seed_person(app, email="user@example.test"),
        )
        return app.state.service.issue_certificate(request_id, app.state.lab_chain.issuer)

    def test_issued_certificate_reports_server_key_held(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _su1, session = _app_with_template(tempdir)
            certificate = self._issued(app, session)
            token, csrf = session
            response = route_endpoint(
                app, "/internal/certificates/{serial_number}", "GET"
            )(certificate.serial_number, request_with_session(token, csrf))
            self.assertTrue(response["server_key_held"])

    def test_renewal_carries_server_key_over(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _su1, session = _app_with_template(tempdir)
            certificate = self._issued(app, session)
            su_secret = add_login_ready_user(
                app, user_id="su-3", email="su3@example.test", role=Role.SUPERUSER
            )
            su_token, su_csrf = create_active_session(
                app, email="su3@example.test", totp_secret=su_secret
            )
            renewal = route_endpoint(
                app, "/internal/certificates/{serial_number}/renew", "POST"
            )(certificate.serial_number, request_with_session(su_token, su_csrf, method="POST"))
            self.assertTrue(renewal["server_key_held"])
            self.assertTrue(app.state.key_vault.held(renewal["id"]))

    def test_owner_can_purge_and_purge_is_idempotent_404(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _su1, session = _app_with_template(tempdir)
            request_id = _generate(app, session)["id"]
            token, csrf = session
            purge = route_endpoint(
                app, "/internal/certificate-requests/{request_id}/server-key", "DELETE"
            )
            response = purge(request_id, request_with_session(token, csrf, method="DELETE"))
            self.assertFalse(response["server_key_held"])
            self.assertFalse(app.state.key_vault.held(request_id))
            with self.assertRaises(HTTPException) as ctx:
                purge(request_id, request_with_session(token, csrf, method="DELETE"))
            self.assertEqual(ctx.exception.status_code, 404)

    def test_other_user_cannot_purge(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _su1, session = _app_with_template(tempdir)
            request_id = _generate(app, session)["id"]
            other_secret = add_login_ready_user(
                app, user_id="user-3", email="third@example.test", role=Role.USER
            )
            other_token, other_csrf = create_active_session(
                app, email="third@example.test", totp_secret=other_secret
            )
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(
                    app, "/internal/certificate-requests/{request_id}/server-key", "DELETE"
                )(request_id, request_with_session(other_token, other_csrf, method="DELETE"))
            self.assertEqual(ctx.exception.status_code, 403)
            self.assertTrue(app.state.key_vault.held(request_id))

    def test_rejecting_request_purges_key(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _su1, session = _app_with_template(tempdir)
            request_id = _generate(app, session)["id"]
            token, csrf = session
            route_endpoint(
                app, "/internal/certificate-requests/{request_id}/reject", "POST"
            )(request_id, request_with_session(token, csrf, method="POST"))
            self.assertFalse(app.state.key_vault.held(request_id))


class VaultUnitTests(unittest.TestCase):
    def test_copy_missing_source_returns_false(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _su1, _session = _app_with_template(tempdir)
            self.assertFalse(app.state.key_vault.copy("ghost-src", "ghost-dst"))

    def test_load_missing_returns_none(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _su1, _session = _app_with_template(tempdir)
            self.assertIsNone(app.state.key_vault.load_pem("ghost"))


if __name__ == "__main__":
    unittest.main()
