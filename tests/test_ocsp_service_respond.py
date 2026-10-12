from __future__ import annotations

import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ocsp

from myownca.domain import CertificateProfile
from myownca.online.ocsp_service import OcspService
from tests.helpers import TempPKI, make_csr


class RespondTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pki = TempPKI()
        self.issuer = self.pki.lab_chain.issuer
        self.svc = OcspService(
            repository=self.pki.repository, hsm=self.pki.hsm, keystore=self.pki.service_keystore(),
            issuer_provider=lambda: self.issuer,
            validity_days_provider=lambda: 30, enabled_provider=lambda: True)
        self.pki.add_default_users()
        self.pki.add_template("host", CertificateProfile.HOST_TLS)

    def tearDown(self) -> None:
        self.pki.close()

    def _issue(self):
        req = self.pki.service.submit_request(
            "host", make_csr("h.example.test", dns_names=("h.example.test",)), requested_by_user_id="user-1")
        self.pki.service.approve_request(req.id, "su-1")
        self.pki.service.approve_request(req.id, "su-2")
        self.pki.assign_holder(req.id)
        return self.pki.service.issue_certificate(req.id, self.issuer)

    def _request_der(self, subject_cert, alg=hashes.SHA1()):
        return ocsp.OCSPRequestBuilder().add_certificate(
            subject_cert, self.issuer.certificate, alg).build().public_bytes(Encoding.DER)

    def test_good(self) -> None:
        issued = self._issue()
        self.svc.generate_responses(self.issuer)
        leaf = x509.load_pem_x509_certificate(issued.certificate_pem.encode())
        resp = ocsp.load_der_ocsp_response(self.svc.respond(self._request_der(leaf)))
        self.assertEqual(resp.response_status, ocsp.OCSPResponseStatus.SUCCESSFUL)
        self.assertEqual(resp.certificate_status, ocsp.OCSPCertStatus.GOOD)

    def test_unknown_serial_is_signed_unknown(self) -> None:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        from myownca.ca_main.crypto import generate_serial_number
        from datetime import timedelta, timezone
        self._issue()
        self.svc.generate_responses(self.issuer)  # responder exists
        # Build a synthetic leaf signed (structurally) by our issuer with a fresh
        # serial we never stored a response for — so the issuer-hash check passes
        # but the lookup misses and we get a signed UNKNOWN back.
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = __import__("datetime").datetime.now(timezone.utc)
        ghost_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ghost.example.test")]))
            .issuer_name(self.issuer.certificate.subject)
            .public_key(private_key.public_key())
            .serial_number(generate_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .sign(private_key, hashes.SHA256())
        )
        der = self.svc.respond(self._request_der(ghost_cert))
        resp = ocsp.load_der_ocsp_response(der)
        self.assertEqual(resp.response_status, ocsp.OCSPResponseStatus.SUCCESSFUL)
        self.assertEqual(resp.certificate_status, ocsp.OCSPCertStatus.UNKNOWN)

    def test_unknown_issuer_unauthorized(self) -> None:
        svc = OcspService(
            repository=self.pki.repository, hsm=self.pki.hsm, keystore=self.pki.service_keystore(),
            issuer_provider=lambda: None, validity_days_provider=lambda: 30, enabled_provider=lambda: True)
        issued = self._issue()
        leaf = x509.load_pem_x509_certificate(issued.certificate_pem.encode())
        resp = ocsp.load_der_ocsp_response(svc.respond(self._request_der(leaf)))
        self.assertEqual(resp.response_status, ocsp.OCSPResponseStatus.UNAUTHORIZED)

    def test_malformed(self) -> None:
        resp = ocsp.load_der_ocsp_response(self.svc.respond(b"not-a-request"))
        self.assertEqual(resp.response_status, ocsp.OCSPResponseStatus.MALFORMED_REQUEST)

    def test_wrong_issuer_unauthorized(self) -> None:
        other = TempPKI()
        try:
            other.add_default_users()
            other.add_template("host", CertificateProfile.HOST_TLS)
            oreq = other.service.submit_request(
                "host", make_csr("o.example.test", dns_names=("o.example.test",)),
                requested_by_user_id="user-1")
            other.service.approve_request(oreq.id, "su-1")
            other.service.approve_request(oreq.id, "su-2")
            other.assign_holder(oreq.id)
            other_leaf = x509.load_pem_x509_certificate(
                other.service.issue_certificate(oreq.id, other.lab_chain.issuer).certificate_pem.encode())
            der = ocsp.OCSPRequestBuilder().add_certificate(
                other_leaf, other.lab_chain.issuer.certificate, hashes.SHA1()).build().public_bytes(Encoding.DER)
            resp = ocsp.load_der_ocsp_response(self.svc.respond(der))
            self.assertEqual(resp.response_status, ocsp.OCSPResponseStatus.UNAUTHORIZED)
        finally:
            other.close()

    def test_no_responder_yet_is_unauthorized_without_minting(self) -> None:
        # OCSP "enabled" but generate_responses never ran → no responder cert exists.
        # respond() must NOT mint one on the public path (no anonymous HSM trigger);
        # it returns UNAUTHORIZED and leaves the responder absent.
        subject = self.issuer.certificate.subject.rfc4514_string()
        issued = self._issue()
        leaf = x509.load_pem_x509_certificate(issued.certificate_pem.encode())
        self.assertIsNone(self.pki.repository.get_ocsp_responder(subject))
        resp = ocsp.load_der_ocsp_response(self.svc.respond(self._request_der(leaf)))
        self.assertEqual(resp.response_status, ocsp.OCSPResponseStatus.UNAUTHORIZED)
        self.assertIsNone(self.pki.repository.get_ocsp_responder(subject))
