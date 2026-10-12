from __future__ import annotations

import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID

from myownca.ca_main.ocsp import build_ocsp_responder_certificate, issuer_cert_id_hashes
from tests.helpers import TempPKI


class ResponderCertTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pki = TempPKI()
        self.issuer = self.pki.lab_chain.issuer

    def tearDown(self) -> None:
        self.pki.close()

    def test_issuer_cert_id_hashes_match_a_real_request(self) -> None:
        from myownca.ca_main.crypto import build_end_entity_certificate, parse_csr
        from myownca.domain import CertificateProfile, CertificateTemplate
        from tests.helpers import make_csr
        leaf = build_end_entity_certificate(
            csr=parse_csr(make_csr("h.example.test", dns_names=("h.example.test",))),
            template=CertificateTemplate(id="host", name="Host", profile=CertificateProfile.HOST_TLS),
            issuer=self.issuer, hsm=self.pki.hsm,
        )
        for alg in (hashes.SHA1(), hashes.SHA256()):
            real = ocsp.OCSPRequestBuilder().add_certificate(leaf, self.issuer.certificate, alg).build()
            name_hash, key_hash = issuer_cert_id_hashes(self.issuer.certificate, alg)
            self.assertEqual(name_hash, real.issuer_name_hash)
            self.assertEqual(key_hash, real.issuer_key_hash)

    def test_responder_cert_has_ocsp_eku_and_nocheck(self) -> None:
        from cryptography.hazmat.primitives.asymmetric import ec
        responder_key = ec.generate_private_key(ec.SECP256R1())
        cert = build_ocsp_responder_certificate(
            self.issuer, responder_key.public_key(), self.pki.hsm, validity_days=30
        )
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        self.assertIn(ExtendedKeyUsageOID.OCSP_SIGNING, list(eku))
        cert.extensions.get_extension_for_class(x509.OCSPNoCheck)  # present
        self.assertEqual(cert.issuer, self.issuer.certificate.subject)
        # RFC 6960 §4.2.2.2: not a CA, and signs (digital_signature) only.
        self.assertFalse(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertTrue(cert.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature)
