from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp

from myownca.ca_main.ocsp import (
    build_ocsp_responder_certificate,
    build_ocsp_response,
    build_ocsp_response_by_hash,
    issuer_cert_id_hashes,
    parse_ocsp_request,
    unsuccessful_response,
)
from myownca.domain import CertificateProfile, CertificateTemplate
from myownca.ca_main.crypto import parse_csr
from tests.helpers import TempPKI, make_csr


class OcspResponseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pki = TempPKI()
        self.issuer = self.pki.lab_chain.issuer
        self.now = datetime.now(timezone.utc)
        self.responder_key = ec.generate_private_key(ec.SECP256R1())
        self.responder_cert = build_ocsp_responder_certificate(
            self.issuer, self.responder_key.public_key(), self.pki.hsm
        )
        from myownca.ca_main.crypto import build_end_entity_certificate
        self.leaf = build_end_entity_certificate(
            csr=parse_csr(make_csr("h.example.test", dns_names=("h.example.test",))),
            template=CertificateTemplate(id="host", name="Host", profile=CertificateProfile.HOST_TLS),
            issuer=self.issuer, hsm=self.pki.hsm,
        )

    def tearDown(self) -> None:
        self.pki.close()

    def test_good_response_round_trips(self) -> None:
        der = build_ocsp_response(
            subject_cert=self.leaf, issuer_cert=self.issuer.certificate,
            responder_cert=self.responder_cert, responder_key=self.responder_key,
            cert_status=ocsp.OCSPCertStatus.GOOD, cert_id_hash=hashes.SHA1(),
            this_update=self.now, next_update=self.now + timedelta(days=1),
        )
        loaded = ocsp.load_der_ocsp_response(der)
        self.assertEqual(loaded.response_status, ocsp.OCSPResponseStatus.SUCCESSFUL)
        self.assertEqual(loaded.certificate_status, ocsp.OCSPCertStatus.GOOD)
        self.assertEqual(loaded.serial_number, self.leaf.serial_number)

    def test_revoked_response_carries_time_and_reason(self) -> None:
        revoked_at = self.now - timedelta(hours=1)
        der = build_ocsp_response(
            subject_cert=self.leaf, issuer_cert=self.issuer.certificate,
            responder_cert=self.responder_cert, responder_key=self.responder_key,
            cert_status=ocsp.OCSPCertStatus.REVOKED, cert_id_hash=hashes.SHA256(),
            this_update=self.now, next_update=self.now + timedelta(days=1),
            revocation_time=revoked_at, revocation_reason=x509.ReasonFlags.key_compromise,
        )
        loaded = ocsp.load_der_ocsp_response(der)
        self.assertEqual(loaded.certificate_status, ocsp.OCSPCertStatus.REVOKED)
        self.assertEqual(loaded.revocation_reason, x509.ReasonFlags.key_compromise)

    def test_unknown_by_hash_needs_no_subject_cert(self) -> None:
        name_hash, key_hash = issuer_cert_id_hashes(self.issuer.certificate, hashes.SHA1())
        der = build_ocsp_response_by_hash(
            issuer_name_hash=name_hash, issuer_key_hash=key_hash, serial_number=0xDEAD,
            responder_cert=self.responder_cert, responder_key=self.responder_key,
            cert_id_hash=hashes.SHA1(), this_update=self.now, next_update=self.now + timedelta(days=1),
        )
        loaded = ocsp.load_der_ocsp_response(der)
        self.assertEqual(loaded.certificate_status, ocsp.OCSPCertStatus.UNKNOWN)

    def test_parse_and_unsuccessful(self) -> None:
        from cryptography.hazmat.primitives.serialization import Encoding
        req = ocsp.OCSPRequestBuilder().add_certificate(
            self.leaf, self.issuer.certificate, hashes.SHA1()
        ).build()
        parsed = parse_ocsp_request(req.public_bytes(Encoding.DER))
        self.assertEqual(parsed.serial_number, self.leaf.serial_number)
        der = unsuccessful_response(ocsp.OCSPResponseStatus.UNAUTHORIZED)
        self.assertEqual(
            ocsp.load_der_ocsp_response(der).response_status, ocsp.OCSPResponseStatus.UNAUTHORIZED
        )
