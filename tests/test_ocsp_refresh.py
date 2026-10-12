from __future__ import annotations

import base64
import unittest

from cryptography.x509 import ocsp

from myownca.domain import CertificateProfile, RevocationReason
from myownca.online.ocsp_service import OcspService
from tests.helpers import TempPKI, make_csr


def _service(pki, enabled=True) -> OcspService:
    return OcspService(
        repository=pki.repository, hsm=pki.hsm, keystore=pki.service_keystore(),
        issuer_provider=lambda: pki.lab_chain.issuer,
        validity_days_provider=lambda: 30, enabled_provider=lambda: enabled,
    )


def _issue(pki):
    pki.add_default_users()
    pki.add_template("host", CertificateProfile.HOST_TLS)
    req = pki.service.submit_request(
        "host", make_csr("h.example.test", dns_names=("h.example.test",)), requested_by_user_id="user-1")
    pki.service.approve_request(req.id, "su-1")
    pki.service.approve_request(req.id, "su-2")
    pki.assign_holder(req.id)
    return pki.service.issue_certificate(req.id, pki.lab_chain.issuer)


def _stored_status(pki, serial):
    subject = pki.lab_chain.issuer.certificate.subject.rfc4514_string()
    row = pki.repository.get_ocsp_response(subject, serial, "sha1")
    return ocsp.load_der_ocsp_response(base64.b64decode(row.response_b64)).certificate_status


class RefreshTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pki = TempPKI()

    def tearDown(self) -> None:
        self.pki.close()

    def test_refresh_single_serial_good(self) -> None:
        svc = _service(self.pki)
        svc.generate_responses(self.pki.lab_chain.issuer)  # mints responder + baseline
        issued = _issue(self.pki)  # a new cert, not yet in OCSP store
        self.assertTrue(svc.refresh_response(issued.serial_number))
        self.assertEqual(_stored_status(self.pki, issued.serial_number), ocsp.OCSPCertStatus.GOOD)

    def test_refresh_after_revoke_is_revoked(self) -> None:
        svc = _service(self.pki)
        issued = _issue(self.pki)
        svc.generate_responses(self.pki.lab_chain.issuer)  # GOOD baseline + responder
        self.pki.service.revoke_certificate(issued.serial_number, RevocationReason.SUPERSEDED)
        self.assertTrue(svc.refresh_response(issued.serial_number))
        self.assertEqual(_stored_status(self.pki, issued.serial_number), ocsp.OCSPCertStatus.REVOKED)

    def test_refresh_noop_when_disabled(self) -> None:
        svc_on = _service(self.pki)
        issued = _issue(self.pki)
        svc_on.generate_responses(self.pki.lab_chain.issuer)
        svc_off = _service(self.pki, enabled=False)
        self.assertFalse(svc_off.refresh_response(issued.serial_number))

    def test_refresh_noop_when_no_responder(self) -> None:
        svc = _service(self.pki)  # enabled, but generate never ran → no responder
        issued = _issue(self.pki)
        self.assertFalse(svc.refresh_response(issued.serial_number))

    def test_refresh_unknown_serial_false(self) -> None:
        svc = _service(self.pki)
        svc.generate_responses(self.pki.lab_chain.issuer)
        self.assertFalse(svc.refresh_response("deadbeef"))
