import json
import os
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
from fastapi import HTTPException

from myownca.comms import NotificationChannel
from myownca.domain import CertificateProfile, CertificateTemplate, Role
from myownca.online.app import (
    CertificateExportRequest,
    CertificatePKCS12SendRequest,
    EntropySourceUpdate,
    RequestGenerate,
    create_app,
)
from tests.helpers import (
    add_login_ready_user,
    create_active_session,
    make_csr,
    request_with_session,
    route_endpoint,
    seed_person,
)


def _app_with_issued_server_key_cert(tempdir: str):
    """App + issued cert whose key the server holds, plus user/admin sessions."""
    app = create_app(Path(tempdir) / "e.sqlite3", lab_mode=True)
    add_login_ready_user(app, user_id="su-1", email="su1@example.test", role=Role.SUPERUSER)
    add_login_ready_user(app, user_id="su-2", email="su2@example.test", role=Role.SUPERUSER)
    user_secret = add_login_ready_user(
        app, user_id="user-1", email="user@example.test", role=Role.USER
    )
    admin_secret = add_login_ready_user(
        app, user_id="admin-1", email="admin@example.test", role=Role.ADMIN
    )
    app.state.repository.add_template(
        CertificateTemplate(id="host", name="Host", profile=CertificateProfile.HOST_TLS)
    )
    user_session = create_active_session(app, email="user@example.test", totp_secret=user_secret)
    admin_session = create_active_session(
        app, email="admin@example.test", totp_secret=admin_secret
    )

    token, csrf = user_session
    generated = route_endpoint(app, "/internal/certificate-requests/generate", "POST")(
        RequestGenerate(
            template_id="host",
            common_name="exp.example.test",
            dns_names=["exp.example.test"],
        ),
        request_with_session(token, csrf, method="POST"),
    )
    request_id = generated["id"]
    app.state.service.approve_request(request_id, "su-1")
    app.state.service.approve_request(request_id, "su-2")
    app.state.service.assign_request_holder(
        request_id,
        person_id=seed_person(app, email="user@example.test"),
    )
    certificate = app.state.service.issue_certificate(request_id, app.state.lab_chain.issuer)
    return app, certificate, user_session, admin_session


def _get_export(app, session, serial, fmt):
    token, csrf = session
    return route_endpoint(app, "/internal/certificates/{serial_number}/export", "GET")(
        serial, request_with_session(token, csrf), fmt
    )


def _post_export(app, session, serial, fmt, password=None):
    token, csrf = session
    return route_endpoint(app, "/internal/certificates/{serial_number}/export", "POST")(
        serial,
        CertificateExportRequest(format=fmt, password=password),
        request_with_session(token, csrf, method="POST"),
    )


def _send_pkcs12(
    app, session, serial, password_channel=NotificationChannel.SMS, **options
):
    token, csrf = session
    return route_endpoint(app, "/internal/certificates/{serial_number}/send-pkcs12", "POST")(
        serial,
        CertificatePKCS12SendRequest(password_channel=password_channel, **options),
        request_with_session(token, csrf, method="POST"),
    )


class KeylessExportTests(unittest.TestCase):
    def test_pem_download(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, user_session, _admin = _app_with_issued_server_key_cert(tempdir)
            response = _get_export(app, user_session, cert.serial_number, "pem")
            self.assertEqual(response.media_type, "application/x-pem-file")
            disposition = response.headers["content-disposition"]
            self.assertIn("attachment", disposition)
            self.assertIn(".crt", disposition)
            loaded = x509.load_pem_x509_certificate(response.body)
            self.assertEqual(loaded.subject.rfc4514_string(), "CN=exp.example.test")

    def test_pem_chain_includes_lab_issuer_and_root(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, user_session, _admin = _app_with_issued_server_key_cert(tempdir)
            response = _get_export(app, user_session, cert.serial_number, "pem-chain")
            certificates = x509.load_pem_x509_certificates(response.body)
            self.assertEqual(len(certificates), 3)
            self.assertEqual(certificates[0].subject.rfc4514_string(), "CN=exp.example.test")
            self.assertEqual(certificates[2].subject, certificates[2].issuer)  # root

    def test_pkcs7_and_der(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, user_session, _admin = _app_with_issued_server_key_cert(tempdir)
            p7b = _get_export(app, user_session, cert.serial_number, "pkcs7")
            self.assertEqual(len(pkcs7.load_der_pkcs7_certificates(p7b.body)), 1)
            der = _get_export(app, user_session, cert.serial_number, "der")
            self.assertEqual(
                x509.load_der_x509_certificate(der.body).serial_number,
                pkcs7.load_der_pkcs7_certificates(p7b.body)[0].serial_number,
            )

    def test_key_bearing_format_rejected_on_get(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, user_session, _admin = _app_with_issued_server_key_cert(tempdir)
            with self.assertRaises(HTTPException) as ctx:
                _get_export(app, user_session, cert.serial_number, "pkcs12")
            self.assertEqual(ctx.exception.status_code, 400)

    def test_unknown_format_rejected(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, user_session, _admin = _app_with_issued_server_key_cert(tempdir)
            with self.assertRaises(HTTPException) as ctx:
                _get_export(app, user_session, cert.serial_number, "zip")
            self.assertEqual(ctx.exception.status_code, 400)

    def test_foreign_user_gets_403(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, _user, _admin = _app_with_issued_server_key_cert(tempdir)
            other_secret = add_login_ready_user(
                app, user_id="user-2", email="other@example.test", role=Role.USER
            )
            other = create_active_session(app, email="other@example.test", totp_secret=other_secret)
            with self.assertRaises(HTTPException) as ctx:
                _get_export(app, other, cert.serial_number, "pem")
            self.assertEqual(ctx.exception.status_code, 403)


class KeyBearingExportTests(unittest.TestCase):
    def test_key_export_requires_recent_authentication_and_audits_denial(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, user_session, _admin = _app_with_issued_server_key_cert(tempdir)
            token, _csrf = user_session
            session, _user = app.state.auth_service.require_session(token)
            app.state.auth_repository.update_session(
                session.id,
                mfa_verified_at=datetime.now(timezone.utc) - timedelta(minutes=11),
                password_verified_at=datetime.now(timezone.utc) - timedelta(minutes=11),
            )

            with self.assertRaises(HTTPException) as caught:
                _post_export(
                    app,
                    user_session,
                    cert.serial_number,
                    "pkcs12",
                    password="hunter2-strong",
                )

            self.assertEqual(caught.exception.status_code, 403)
            failed = next(
                event
                for event in app.state.audit.list_events(limit=100)
                if event.action == "export_failed"
            )
            self.assertEqual(failed.outcome.value, "failure")
            self.assertEqual(failed.details, {})

    def test_pkcs12_round_trip_with_chain(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, user_session, _admin = _app_with_issued_server_key_cert(tempdir)
            response = _post_export(
                app, user_session, cert.serial_number, "pkcs12", password="hunter2-strong"
            )
            self.assertEqual(response.media_type, "application/x-pkcs12")
            self.assertEqual(response.headers["cache-control"], "no-store")
            key, leaf, cas = pkcs12.load_key_and_certificates(response.body, b"hunter2-strong")
            self.assertEqual(leaf.subject.rfc4514_string(), "CN=exp.example.test")
            self.assertEqual(len(cas), 2)  # lab issuer + lab root
            self.assertEqual(
                key.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                ),
                leaf.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                ),
            )

    def test_pem_key_and_pkcs8(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, user_session, _admin = _app_with_issued_server_key_cert(tempdir)
            for fmt in ("pem-key", "pem-pkcs8"):
                with self.subTest(fmt=fmt):
                    encrypted = _post_export(
                        app,
                        user_session,
                        cert.serial_number,
                        fmt,
                        password="hunter2-strong",
                    )
                    self.assertIn(b"BEGIN ENCRYPTED PRIVATE KEY", encrypted.body)
                    serialization.load_pem_private_key(
                        encrypted.body, password=b"hunter2-strong"
                    )

    def test_short_password_rejected(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, user_session, _admin = _app_with_issued_server_key_cert(tempdir)
            for fmt in ("pkcs12", "pem-key", "pem-pkcs8"):
                with self.subTest(fmt=fmt):
                    with self.assertRaises(HTTPException) as ctx:
                        _post_export(
                            app,
                            user_session,
                            cert.serial_number,
                            fmt,
                            password="short",
                        )
                    self.assertEqual(ctx.exception.status_code, 400)

    def test_failed_key_export_audit_does_not_capture_secret_error_text(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, user_session, _admin = _app_with_issued_server_key_cert(tempdir)
            secret = "provider-password=do-not-store"
            with mock.patch(
                "myownca.online.app.build_export",
                side_effect=RuntimeError(secret),
            ):
                with self.assertRaises(RuntimeError):
                    _post_export(
                        app,
                        user_session,
                        cert.serial_number,
                        "pem-key",
                        password="hunter2-strong",
                    )
            failed = next(
                event
                for event in app.state.audit.list_events(limit=100)
                if event.action == "export_failed"
            )
            self.assertEqual(failed.outcome.value, "failure")
            self.assertEqual(failed.details, {})
            self.assertNotIn(secret, str(failed.to_dict()))

    def test_keyless_format_rejected_on_post(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, user_session, _admin = _app_with_issued_server_key_cert(tempdir)
            with self.assertRaises(HTTPException) as ctx:
                _post_export(app, user_session, cert.serial_number, "pem")
            self.assertEqual(ctx.exception.status_code, 400)

    def test_csr_submitted_certificate_409(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _cert, user_session, _admin = _app_with_issued_server_key_cert(tempdir)
            request = app.state.service.submit_request(
                "host",
                make_csr("manual.example.test", dns_names=("manual.example.test",)),
                requested_by_user_id="user-1",
            )
            app.state.service.approve_request(request.id, "su-1")
            app.state.service.approve_request(request.id, "su-2")
            app.state.service.assign_request_holder(
                request.id,
                person_id=seed_person(app, email="user@example.test"),
            )
            manual = app.state.service.issue_certificate(request.id, app.state.lab_chain.issuer)
            with self.assertRaises(HTTPException) as ctx:
                _post_export(
                    app, user_session, manual.serial_number, "pkcs12", password="hunter2-strong"
                )
            self.assertEqual(ctx.exception.status_code, 409)

    def test_purged_key_409(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, user_session, _admin = _app_with_issued_server_key_cert(tempdir)
            app.state.key_vault.purge(cert.request_id)
            with self.assertRaises(HTTPException) as ctx:
                _post_export(
                    app, user_session, cert.serial_number, "pkcs12", password="hunter2-strong"
                )
            self.assertEqual(ctx.exception.status_code, 409)

    def test_auditor_cannot_export_keys(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, _user, _admin = _app_with_issued_server_key_cert(tempdir)
            auditor_secret = add_login_ready_user(
                app, user_id="aud-1", email="aud@example.test", role=Role.AUDITOR
            )
            auditor = create_active_session(app, email="aud@example.test", totp_secret=auditor_secret)
            # Keyless export is fine for auditors...
            self.assertEqual(_get_export(app, auditor, cert.serial_number, "pem").status_code, 200)
            # ...key-bearing is not.
            with self.assertRaises(HTTPException) as ctx:
                _post_export(app, auditor, cert.serial_number, "pem-key")
            self.assertEqual(ctx.exception.status_code, 403)


class PKCS12DeliveryTests(unittest.TestCase):
    def _configure_delivery(self, app) -> None:
        person = app.state.repository.get_person("person-default")
        app.state.repository.update_person(replace(person, phone="+48123123123", slack_handle="holder"))
        app.state.comms.set_config(
            NotificationChannel.EMAIL,
            enabled=True,
            config={"host": "smtp.example.test", "from_address": "ca@example.test"},
            secrets={},
        )
        app.state.comms.set_config(
            NotificationChannel.SMS,
            enabled=True,
            config={"url": "https://sms.example.test/send"},
            secrets={},
        )

    def test_email_attachment_and_separate_sms_password(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, _user_session, admin_session = _app_with_issued_server_key_cert(tempdir)
            self._configure_delivery(app)
            smtp_server = mock.MagicMock()
            smtp_server.__enter__.return_value = smtp_server
            sent_sms: dict[str, object] = {}

            def sms_response(method, url, *, headers=None, data=None, **kwargs):
                sent_sms["body"] = json.loads(data)
                return 202, "accepted"

            with (
                mock.patch("myownca.comms.email.smtplib.SMTP", return_value=smtp_server),
                mock.patch("myownca.comms.sms.http_send", side_effect=sms_response),
            ):
                response = _send_pkcs12(app, admin_session, cert.serial_number)

            sent_email = smtp_server.send_message.call_args.args[0]
            attachment = next(part for part in sent_email.iter_attachments())
            password = sent_sms["body"]["message"].rsplit(": ", 1)[1]
            key, leaf, cas = pkcs12.load_key_and_certificates(
                attachment.get_payload(decode=True), password.encode()
            )
            self.assertEqual(attachment.get_content_type(), "application/x-pkcs12")
            self.assertTrue(attachment.get_filename().endswith(".p12"))
            self.assertEqual(leaf.subject.rfc4514_string(), "CN=exp.example.test")
            self.assertEqual(len(cas), 2)
            self.assertIsNotNone(key)
            self.assertEqual(response["password_channel"], "sms")
            self.assertNotIn(password, json.dumps(response))
            self.assertNotIn(password, sent_email.get_body().get_content())
            events = app.state.audit.list_events(limit=100)
            self.assertNotIn(password, json.dumps([event.to_dict() for event in events]))

    def test_password_delivery_failure_is_partial_and_audited_without_password(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, _user_session, admin_session = _app_with_issued_server_key_cert(tempdir)
            self._configure_delivery(app)
            smtp_server = mock.MagicMock()
            smtp_server.__enter__.return_value = smtp_server
            captured_sms: dict[str, object] = {}

            def rejected_sms(method, url, *, headers=None, data=None, **kwargs):
                captured_sms["body"] = json.loads(data)
                return 500, "rejected"

            with (
                mock.patch("myownca.comms.email.smtplib.SMTP", return_value=smtp_server),
                mock.patch("myownca.comms.sms.http_send", side_effect=rejected_sms),
            ):
                with self.assertRaises(HTTPException) as caught:
                    _send_pkcs12(app, admin_session, cert.serial_number)

            password = captured_sms["body"]["message"].rsplit(": ", 1)[1]
            self.assertEqual(caught.exception.status_code, 502)
            self.assertNotIn(password, caught.exception.detail)
            self.assertTrue(smtp_server.send_message.called)
            partial = next(
                event
                for event in app.state.audit.list_events(limit=100)
                if event.action == "send_pkcs12_partial"
            )
            self.assertEqual(partial.details["stage"], "password")
            self.assertNotIn(password, json.dumps(partial.to_dict()))

    def test_email_failure_does_not_send_password(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, _user_session, admin_session = _app_with_issued_server_key_cert(tempdir)
            self._configure_delivery(app)
            with (
                mock.patch(
                    "myownca.comms.email.smtplib.SMTP",
                    side_effect=OSError("SMTP unavailable"),
                ),
                mock.patch("myownca.comms.sms.http_send") as send_sms,
                self.assertRaises(HTTPException) as caught,
            ):
                _send_pkcs12(app, admin_session, cert.serial_number)
            self.assertEqual(caught.exception.status_code, 502)
            send_sms.assert_not_called()
            failed = next(
                event
                for event in app.state.audit.list_events(limit=100)
                if event.action == "send_pkcs12_failed"
            )
            self.assertEqual(failed.details["stage"], "email")

    def test_rejects_missing_password_contact_and_unsupported_channel_before_delivery(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, _user_session, admin_session = _app_with_issued_server_key_cert(tempdir)
            self._configure_delivery(app)
            person = app.state.repository.get_person("person-default")
            app.state.repository.update_person(replace(person, phone=""))
            with self.assertRaises(HTTPException) as missing_contact:
                _send_pkcs12(app, admin_session, cert.serial_number)
            self.assertEqual(missing_contact.exception.status_code, 400)
            with self.assertRaises(HTTPException) as unsupported:
                _send_pkcs12(
                    app,
                    admin_session,
                    cert.serial_number,
                    password_channel=NotificationChannel.WEBHOOK,
                )
            self.assertEqual(unsupported.exception.status_code, 400)

    def test_requires_recent_authentication_before_delivery(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, cert, _user_session, admin_session = _app_with_issued_server_key_cert(tempdir)
            self._configure_delivery(app)
            token, _csrf = admin_session
            session, _user = app.state.auth_service.require_session(token)
            app.state.auth_repository.update_session(
                session.id,
                mfa_verified_at=datetime.now(timezone.utc) - timedelta(minutes=11),
            )
            with self.assertRaises(HTTPException) as caught:
                _send_pkcs12(app, admin_session, cert.serial_number)
            self.assertEqual(caught.exception.status_code, 403)
            self.assertFalse(
                any(event.action == "send_pkcs12" for event in app.state.audit.list_events(limit=100))
            )


class EntropySourceApiTests(unittest.TestCase):
    def _file_with_random(self) -> str:
        handle = tempfile.NamedTemporaryFile(delete=False)
        self.addCleanup(os.unlink, handle.name)
        handle.write(os.urandom(256))
        handle.close()
        return handle.name

    def test_get_put_and_clear(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _cert, _user, admin = _app_with_issued_server_key_cert(tempdir)
            token, csrf = admin
            status = route_endpoint(app, "/internal/admin/entropy-source", "GET")(
                request_with_session(token, csrf)
            )
            self.assertEqual(status, {"entropy_source": None, "origin": "default"})

            device = self._file_with_random()
            updated = route_endpoint(app, "/internal/admin/entropy-source", "PUT")(
                EntropySourceUpdate(entropy_source=device),
                request_with_session(token, csrf, method="PUT"),
            )
            self.assertEqual(updated, {"entropy_source": device, "origin": "setting"})

            cleared = route_endpoint(app, "/internal/admin/entropy-source", "PUT")(
                EntropySourceUpdate(entropy_source=None),
                request_with_session(token, csrf, method="PUT"),
            )
            self.assertEqual(cleared, {"entropy_source": None, "origin": "setting"})

    def test_put_invalid_device_rejected_and_not_stored(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _cert, _user, admin = _app_with_issued_server_key_cert(tempdir)
            token, csrf = admin
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/admin/entropy-source", "PUT")(
                    EntropySourceUpdate(entropy_source="/nonexistent/trng"),
                    request_with_session(token, csrf, method="PUT"),
                )
            self.assertEqual(ctx.exception.status_code, 400)
            self.assertIsNone(app.state.repository.get_setting("entropy_source"))

    def test_validate_endpoint(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _cert, _user, admin = _app_with_issued_server_key_cert(tempdir)
            token, csrf = admin
            validate = route_endpoint(app, "/internal/admin/entropy-source/validate", "POST")
            ok = validate(
                EntropySourceUpdate(entropy_source=self._file_with_random()),
                request_with_session(token, csrf, method="POST"),
            )
            self.assertTrue(ok["ok"])
            with self.assertRaises(HTTPException) as ctx:
                validate(
                    EntropySourceUpdate(entropy_source=""),
                    request_with_session(token, csrf, method="POST"),
                )
            self.assertEqual(ctx.exception.status_code, 400)


class RootCertificateApiTests(unittest.TestCase):
    def test_lab_root_reported_then_stored_root_wins_read_only(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _cert, _user, admin = _app_with_issued_server_key_cert(tempdir)
            token, csrf = admin
            status = route_endpoint(app, "/internal/admin/root-certificate", "GET")(
                request_with_session(token, csrf)
            )
            self.assertEqual(status["source"], "lab_chain")
            lab_root_pem = status["root_certificate_pem"]

            app.state.repository.set_root_certificate_pem(lab_root_pem)
            updated = route_endpoint(
                app,
                "/internal/admin/root-certificate",
                "GET",
            )(
                request_with_session(token, csrf)
            )
            self.assertEqual(updated["source"], "stored")
            self.assertEqual(
                app.state.repository.get_root_certificate_pem().strip(),
                lab_root_pem.strip(),
            )

    def test_root_certificate_mutation_route_is_removed(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _cert, _user, _admin = _app_with_issued_server_key_cert(tempdir)
        with self.assertRaises(AssertionError):
            route_endpoint(app, "/internal/admin/root-certificate", "PUT")

    def test_legacy_setup_root_route_is_removed(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _cert, _user, _admin = _app_with_issued_server_key_cert(tempdir)
        with self.assertRaises(AssertionError):
            route_endpoint(app, "/internal/setup/root-certificate", "PUT")


if __name__ == "__main__":
    unittest.main()


class Pkcs12ReauthenticationFieldTests(unittest.TestCase):
    """The re-authentication field must not be given an empty pattern.

    `pattern=""` is not "no pattern": it compiles to ^(?:)$, which matches only
    an empty value. Setting it on the password branch made the browser reject
    every typed password with "Please match the requested format", so an
    encrypted PKCS#12 bundle could not be sent at all by a password-authenticated
    operator. The constraints must be removed, as app_shared.js already does.
    """

    def _script(self, name: str) -> str:
        import myownca.online.app as app_module

        return (Path(app_module.__file__).parent / "static" / name).read_text()

    def _sync_format(self) -> str:
        script = self._script("superuser.js")
        return script.split("function syncFormat()", 1)[1].split("\n  }", 1)[0]

    def test_the_password_branch_removes_the_constraints(self) -> None:
        block = self._sync_format()
        self.assertIn('reauth.removeAttribute("pattern")', block)
        self.assertIn('reauth.removeAttribute("maxlength")', block)
        self.assertIn('reauth.removeAttribute("inputmode")', block)

    def test_no_constraint_is_blanked_instead_of_removed(self) -> None:
        """The exact defect: a conditional assigning "" to pattern or maxlength."""
        block = self._sync_format()
        self.assertNotIn('reauth.pattern = authIsTotp ? "[0-9]{6}" : ""', block)
        self.assertNotRegex(block, r'\.pattern\s*=\s*""')
        self.assertNotRegex(block, r'\.pattern\s*=\s*[^;]*:\s*""')

    def test_the_totp_branch_still_constrains_the_code(self) -> None:
        """Removing the empty pattern must not drop the real one."""
        block = self._sync_format()
        self.assertIn('reauth.pattern = "[0-9]{6}"', block)
        self.assertIn("reauth.maxLength = 6", block)

    def test_the_prompt_names_which_credential_is_required(self) -> None:
        """Which credential applies follows the role's TOTP policy, not what the
        operator enrolled. "Fresh authentication required" alone leaves them to
        guess, and guessing wrong is rejected by the field's own format rule."""
        block = self._sync_format()
        self.assertIn("Current TOTP code", block)
        self.assertIn("Current account password", block)
        self.assertIn("6-digit code from your authenticator app", block)
        self.assertIn("not accepted here", block)
        self.assertIn("current portal password", block)

    def test_the_static_hint_does_not_claim_a_password_by_default(self) -> None:
        """The markup shipped 'Enter your current password' unconditionally. On a
        TOTP install that is wrong until the script overwrites it."""
        import myownca.online.app as app_module

        page = (Path(app_module.__file__).parent / "static" / "superuser.html").read_text()
        hint = page.split("data-pkcs12-reauth-hint", 1)[1].split("</p>", 1)[0]
        self.assertNotIn("current password", hint)

    def test_the_sensitive_auth_method_follows_the_role_policy(self) -> None:
        """Pin the rule the prompt describes, so UI copy and backend cannot drift."""
        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "auth.sqlite3")
            auth = app.state.auth_service
            for role in (Role.ADMIN, Role.SUPERUSER):
                self.assertTrue(auth.totp_required(role))
            for role in (Role.USER, Role.AUDITOR):
                self.assertFalse(auth.totp_required(role))

    def test_the_shared_helper_keeps_doing_it_correctly(self) -> None:
        """app_shared.js is the reference implementation this now matches."""
        shared = self._script("app_shared.js")
        self.assertIn('reauthInput.removeAttribute("pattern")', shared)
        self.assertNotRegex(shared, r'reauthInput\.pattern\s*=\s*""')


class Pkcs12CaCertificateAttachmentTests(unittest.TestCase):
    """The bundle already carried the chain inside it, which a device will not
    trust. The installable copies ride alongside it."""

    def _send(self, tempdir, **options):
        app, cert, _user, admin = _app_with_issued_server_key_cert(tempdir)
        PKCS12DeliveryTests._configure_delivery(self, app)
        smtp_server = mock.MagicMock()
        smtp_server.__enter__.return_value = smtp_server
        with (
            mock.patch("myownca.comms.email.smtplib.SMTP", return_value=smtp_server),
            mock.patch("myownca.comms.sms.http_send", return_value=(202, "accepted")),
        ):
            _send_pkcs12(app, admin, cert.serial_number, **options)
        email = smtp_server.send_message.call_args.args[0]
        return {
            part.get_filename(): part.get_payload(decode=True)
            for part in email.iter_attachments()
        }, email

    def test_the_ca_certificates_are_attached_by_default(self) -> None:
        with TemporaryDirectory() as tempdir:
            attachments, email = self._send(tempdir)

            self.assertIn("sub-ca.cer", attachments)
            self.assertIn("root-ca.cer", attachments)
            for name in ("sub-ca.cer", "root-ca.cer"):
                # DER, so a phone or desktop installs it on open.
                self.assertFalse(attachments[name].startswith(b"-----BEGIN"))
                x509.load_der_x509_certificate(attachments[name])
            body = email.get_body().get_content()
            self.assertIn("Certificate Trust Settings", body)

    def test_the_bundle_is_still_the_first_attachment(self) -> None:
        with TemporaryDirectory() as tempdir:
            attachments, _ = self._send(tempdir)
            p12 = [name for name in attachments if name.endswith(".p12")]
            self.assertEqual(len(p12), 1)

    def test_the_option_can_be_turned_off(self) -> None:
        with TemporaryDirectory() as tempdir:
            attachments, email = self._send(tempdir, include_ca_certificates=False)

            self.assertNotIn("sub-ca.cer", attachments)
            self.assertNotIn("root-ca.cer", attachments)
            self.assertTrue(any(name.endswith(".p12") for name in attachments))
            self.assertNotIn("Certificate Trust Settings", email.get_body().get_content())

    def test_the_chain_is_still_inside_the_bundle_too(self) -> None:
        """Turning the attachments off must not strip the chain from the P12."""
        with TemporaryDirectory() as tempdir:
            app, cert, _user, admin = _app_with_issued_server_key_cert(tempdir)
            PKCS12DeliveryTests._configure_delivery(self, app)
            smtp_server = mock.MagicMock()
            smtp_server.__enter__.return_value = smtp_server
            sent_sms: dict[str, object] = {}

            def sms_response(method, url, *, headers=None, data=None, **kwargs):
                sent_sms["body"] = json.loads(data)
                return 202, "accepted"

            with (
                mock.patch("myownca.comms.email.smtplib.SMTP", return_value=smtp_server),
                mock.patch("myownca.comms.sms.http_send", side_effect=sms_response),
            ):
                _send_pkcs12(app, admin, cert.serial_number, include_ca_certificates=False)

            email = smtp_server.send_message.call_args.args[0]
            bundle = next(
                part for part in email.iter_attachments()
                if part.get_filename().endswith(".p12")
            )
            password = sent_sms["body"]["message"].rsplit(": ", 1)[1]
            _key, _leaf, cas = pkcs12.load_key_and_certificates(
                bundle.get_payload(decode=True), password.encode()
            )
            self.assertEqual(len(cas), 2)
