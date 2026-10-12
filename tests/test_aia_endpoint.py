from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import HTTPException

from myownca.ca_main.crypto import cert_pem_to_der
from myownca.online.app import create_app
from tests.helpers import route_endpoint


class CertPemToDerTests(unittest.TestCase):
    def test_round_trips_a_real_cert(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "c.sqlite3", lab_mode=True)
            issuer_cert = app.state.lab_chain.issuer.certificate
            pem = issuer_cert.public_bytes(serialization.Encoding.PEM).decode()
            der = cert_pem_to_der(pem)
            self.assertEqual(x509.load_der_x509_certificate(der).subject, issuer_cert.subject)


class ServeAiaTests(unittest.TestCase):
    def test_serves_lab_issuer_der(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "c.sqlite3", lab_mode=True)
            resp = route_endpoint(app, "/aia/{issuer_id}.cer", "GET")("myOwnCA_Lab_CA")
            self.assertEqual(resp.media_type, "application/pkix-cert")
            cert = x509.load_der_x509_certificate(resp.body)
            self.assertEqual(cert.subject, app.state.lab_chain.issuer.certificate.subject)

    def test_unknown_issuer_404(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "c.sqlite3", lab_mode=True)
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/aia/{issuer_id}.cer", "GET")("nope")
            self.assertEqual(ctx.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
