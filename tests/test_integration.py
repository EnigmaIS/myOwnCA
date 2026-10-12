from __future__ import annotations

import unittest

from cryptography import x509

from myownca.domain import CertificateProfile, RevocationReason
from tests.helpers import TempPKI, make_csr


class PKIIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pki = TempPKI()
        self.pki.add_default_users()
        self.pki.add_template("host", CertificateProfile.HOST_TLS)

    def tearDown(self) -> None:
        self.pki.close()

    def test_issue_revoke_and_generate_crl(self) -> None:
        request = self.pki.service.submit_request(
            "host", make_csr("api.example.test", dns_names=("api.example.test",))
        )
        self.pki.service.approve_request(request.id, "su-1")
        self.pki.service.approve_request(request.id, "su-2")
        self.pki.assign_holder(request.id)
        issued = self.pki.service.issue_certificate(request.id, self.pki.lab_chain.issuer)

        revocation = self.pki.service.revoke_certificate(
            issued.serial_number, RevocationReason.KEY_COMPROMISE
        )
        root_crl = self.pki.service.generate_crl(self.pki.lab_chain.issuer)
        crl = x509.load_pem_x509_crl(root_crl.crl_pem.encode())

        revoked_serials = {format(entry.serial_number, "x") for entry in crl}
        self.assertEqual(revocation.serial_number, issued.serial_number)
        self.assertIn(issued.serial_number, revoked_serials)
        self.assertEqual(root_crl.number, 1)
