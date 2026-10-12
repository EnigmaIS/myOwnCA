from __future__ import annotations

import unittest

from cryptography import x509

from myownca.domain import CertificateProfile
from tests.helpers import TempPKI, make_csr


def _issue(pki, *, resolver=None):
    if resolver is not None:
        pki.service.crl_url_resolver = resolver
    pki.add_default_users()
    pki.add_template("host", CertificateProfile.HOST_TLS)
    req = pki.service.submit_request(
        "host", make_csr("h.example.test", dns_names=("h.example.test",)), requested_by_user_id="user-1"
    )
    pki.service.approve_request(req.id, "su-1")
    pki.service.approve_request(req.id, "su-2")
    pki.assign_holder(req.id)
    issued = pki.service.issue_certificate(req.id, pki.lab_chain.issuer)
    return x509.load_pem_x509_certificate(issued.certificate_pem.encode())


class CrlResolverTests(unittest.TestCase):
    def test_resolver_url_is_embedded(self) -> None:
        pki = TempPKI()
        try:
            cert = _issue(pki, resolver=lambda issuer: "http://ca.test/crl/lab.crl")
            cdp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
            self.assertEqual(cdp[0].full_name[0].value, "http://ca.test/crl/lab.crl")
        finally:
            pki.close()

    def test_default_no_resolver_means_no_cdp(self) -> None:
        pki = TempPKI()
        try:
            cert = _issue(pki)  # crl_url_resolver defaults to None
            with self.assertRaises(x509.ExtensionNotFound):
                cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        finally:
            pki.close()
