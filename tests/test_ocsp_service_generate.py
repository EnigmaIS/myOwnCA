from __future__ import annotations

import base64
import unittest

from cryptography.x509 import ocsp

from myownca.domain import CertificateProfile, RevocationReason
from myownca.online.ocsp_service import OcspService
from tests.helpers import TempPKI, make_csr


def _service(pki) -> OcspService:
    return OcspService(
        repository=pki.repository, hsm=pki.hsm, keystore=pki.service_keystore(),
        issuer_provider=lambda: pki.lab_chain.issuer,
        validity_days_provider=lambda: 30, enabled_provider=lambda: True,
    )


def _issue(pki, serial_holder):
    pki.add_default_users()
    pki.add_template("host", CertificateProfile.HOST_TLS)
    req = pki.service.submit_request(
        "host", make_csr("h.example.test", dns_names=("h.example.test",)), requested_by_user_id="user-1")
    pki.service.approve_request(req.id, "su-1")
    pki.service.approve_request(req.id, "su-2")
    pki.assign_holder(req.id)
    issued = pki.service.issue_certificate(req.id, pki.lab_chain.issuer)
    serial_holder.append(issued.serial_number)
    return issued


class GenerateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pki = TempPKI()

    def tearDown(self) -> None:
        self.pki.close()

    def test_two_variants_per_issued_serial(self) -> None:
        serials = []
        _issue(self.pki, serials)
        count = _service(self.pki).generate_responses(self.pki.lab_chain.issuer)
        self.assertEqual(count, 2)  # SHA-1 + SHA-256 for one serial
        subject = self.pki.lab_chain.issuer.certificate.subject.rfc4514_string()
        self.assertIsNotNone(self.pki.repository.get_ocsp_response(subject, serials[0], "sha1"))
        self.assertIsNotNone(self.pki.repository.get_ocsp_response(subject, serials[0], "sha256"))

    def test_revoked_serial_yields_revoked_status(self) -> None:
        serials = []
        _issue(self.pki, serials)
        self.pki.service.revoke_certificate(serials[0], RevocationReason.SUPERSEDED)
        _service(self.pki).generate_responses(self.pki.lab_chain.issuer)
        subject = self.pki.lab_chain.issuer.certificate.subject.rfc4514_string()
        der = base64.b64decode(self.pki.repository.get_ocsp_response(subject, serials[0], "sha1").response_b64)
        self.assertEqual(ocsp.load_der_ocsp_response(der).certificate_status, ocsp.OCSPCertStatus.REVOKED)

    def test_disabled_no_ops(self) -> None:
        serials = []
        _issue(self.pki, serials)
        svc = OcspService(
            repository=self.pki.repository, hsm=self.pki.hsm, keystore=self.pki.service_keystore(),
            issuer_provider=lambda: self.pki.lab_chain.issuer,
            validity_days_provider=lambda: 30, enabled_provider=lambda: False)
        self.assertEqual(svc.generate_responses(self.pki.lab_chain.issuer), 0)
