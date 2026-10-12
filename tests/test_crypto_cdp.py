from __future__ import annotations

import unittest

from cryptography import x509

from myownca.ca_main.crypto import build_end_entity_certificate, parse_csr
from myownca.domain import CertificateProfile, CertificateTemplate
from tests.helpers import TempPKI, make_csr


def _host_template() -> CertificateTemplate:
    return CertificateTemplate(id="host", name="Host", profile=CertificateProfile.HOST_TLS)


class CdpExtensionTests(unittest.TestCase):
    def test_crl_url_adds_distribution_point(self) -> None:
        pki = TempPKI()
        try:
            csr = parse_csr(make_csr("h.example.test", dns_names=("h.example.test",)))
            cert = build_end_entity_certificate(
                csr=csr,
                template=_host_template(),
                issuer=pki.lab_chain.issuer,
                hsm=pki.hsm,
                crl_url="http://ca.test/crl/myOwnCA_Lab_CA.crl",
            )
            cdp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
            self.assertEqual(cdp[0].full_name[0].value, "http://ca.test/crl/myOwnCA_Lab_CA.crl")
            self.assertFalse(
                cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).critical
            )
        finally:
            pki.close()

    def test_no_crl_url_means_no_extension(self) -> None:
        pki = TempPKI()
        try:
            csr = parse_csr(make_csr("h.example.test", dns_names=("h.example.test",)))
            cert = build_end_entity_certificate(
                csr=csr, template=_host_template(), issuer=pki.lab_chain.issuer, hsm=pki.hsm
            )
            with self.assertRaises(x509.ExtensionNotFound):
                cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        finally:
            pki.close()
