from __future__ import annotations

import unittest

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from myownca.ca_main.crypto import crl_pem_to_der, crl_to_pem
from tests.helpers import TempPKI


class CrlPemToDerTests(unittest.TestCase):
    def test_round_trips_to_der(self) -> None:
        pki = TempPKI()
        try:
            crl_obj = pki.service.generate_crl(pki.lab_chain.issuer)
            der = crl_pem_to_der(crl_obj.crl_pem)
            self.assertIsInstance(der, bytes)
            reloaded = x509.load_der_x509_crl(der)
            from_pem = x509.load_pem_x509_crl(crl_obj.crl_pem.encode())
            self.assertEqual(reloaded.issuer, from_pem.issuer)
            self.assertEqual(der, from_pem.public_bytes(Encoding.DER))
        finally:
            pki.close()

    def test_helper_is_inverse_of_crl_to_pem(self) -> None:
        pki = TempPKI()
        try:
            crl = pki.service.generate_crl(pki.lab_chain.issuer)
            der = crl_pem_to_der(crl_to_pem(x509.load_pem_x509_crl(crl.crl_pem.encode())))
            self.assertEqual(x509.load_der_x509_crl(der).issuer, x509.load_pem_x509_crl(crl.crl_pem.encode()).issuer)
        finally:
            pki.close()
