from __future__ import annotations

import base64
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography.x509 import ocsp

from myownca.domain import CertificateProfile, CertificateTemplate, RevocationReason, Role
from myownca.online.app import create_app
from tests.helpers import add_login_ready_user, make_csr, seed_person


def _stored_status(app, serial):
    subject = app.state.lab_chain.issuer.certificate.subject.rfc4514_string()
    row = app.state.repository.get_ocsp_response(subject, serial, "sha1")
    return None if row is None else ocsp.load_der_ocsp_response(base64.b64decode(row.response_b64)).certificate_status


def _issue(app):
    for uid, email, role in [("su-1", "su1@example.test", Role.SUPERUSER),
                             ("su-2", "su2@example.test", Role.SUPERUSER),
                             ("user-1", "user@example.test", Role.USER)]:
        add_login_ready_user(app, user_id=uid, email=email, role=role)
    app.state.repository.add_template(
        CertificateTemplate(id="host", name="Host", profile=CertificateProfile.HOST_TLS))
    pid = seed_person(app)
    req = app.state.service.submit_request(
        "host", make_csr("h.example.test", dns_names=("h.example.test",)), requested_by_user_id="user-1")
    app.state.service.approve_request(req.id, "su-1")
    app.state.service.approve_request(req.id, "su-2")
    app.state.service.assign_request_holder(req.id, person_id=pid)
    return app.state.service.issue_certificate(req.id, app.state.lab_chain.issuer)


class CertHookTests(unittest.TestCase):
    def test_issue_and_revoke_refresh_ocsp_without_manual_generate(self) -> None:
        with TemporaryDirectory() as t:
            app = create_app(Path(t) / "c.sqlite3", lab_mode=True)
            app.state.repository.set_setting("ocsp_enabled", "true")
            app.state.ocsp_service.generate_responses(app.state.lab_chain.issuer)  # mint responder + baseline
            issued = _issue(app)
            self.assertEqual(_stored_status(app, issued.serial_number), ocsp.OCSPCertStatus.GOOD)
            app.state.service.revoke_certificate(issued.serial_number, RevocationReason.KEY_COMPROMISE)
            self.assertEqual(_stored_status(app, issued.serial_number), ocsp.OCSPCertStatus.REVOKED)

    def test_listener_failure_does_not_break_issuance(self) -> None:
        from tests.helpers import TempPKI
        pki = TempPKI()
        try:
            pki.service.cert_change_listener = lambda serial: (_ for _ in ()).throw(RuntimeError("boom"))
            pki.add_default_users()
            pki.add_template("host", CertificateProfile.HOST_TLS)
            req = pki.service.submit_request(
                "host", make_csr("h.example.test", dns_names=("h.example.test",)), requested_by_user_id="user-1")
            pki.service.approve_request(req.id, "su-1")
            pki.service.approve_request(req.id, "su-2")
            pki.assign_holder(req.id)
            issued = pki.service.issue_certificate(req.id, pki.lab_chain.issuer)  # must not raise
            self.assertIsNotNone(issued.serial_number)
            rev = pki.service.revoke_certificate(issued.serial_number)  # must not raise
            self.assertEqual(rev.serial_number, issued.serial_number)
        finally:
            pki.close()
