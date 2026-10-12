from __future__ import annotations

import base64
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ocsp
from fastapi import HTTPException

from myownca.domain import CertificateProfile, CertificateTemplate, Role
from myownca.online.app import create_app
from tests.helpers import add_login_ready_user, make_csr, route_endpoint, seed_person


class _Body:
    def __init__(self, data: bytes):
        self._data = data
    async def body(self) -> bytes:
        return self._data


def _issue(app):
    for uid, email, role in [("su-1", "su1@example.test", Role.SUPERUSER),
                             ("su-2", "su2@example.test", Role.SUPERUSER),
                             ("user-1", "user@example.test", Role.USER)]:
        add_login_ready_user(app, user_id=uid, email=email, role=role)
    app.state.repository.add_template(
        CertificateTemplate(id="host", name="Host", profile=CertificateProfile.HOST_TLS))
    pid = seed_person(app)
    req = app.state.service.submit_request(
        "host", make_csr("h.example.test", dns_names=("h.example.test",)), requested_by_user_id="user-1")
    app.state.service.approve_request(req.id, "su-1")
    app.state.service.approve_request(req.id, "su-2")
    app.state.service.assign_request_holder(req.id, person_id=pid)
    issued = app.state.service.issue_certificate(req.id, app.state.lab_chain.issuer)
    return x509.load_pem_x509_certificate(issued.certificate_pem.encode())


def _ocsp_request(leaf, issuer_cert):
    return ocsp.OCSPRequestBuilder().add_certificate(leaf, issuer_cert, hashes.SHA1()).build().public_bytes(Encoding.DER)


class OcspServeTests(unittest.IsolatedAsyncioTestCase):
    async def test_post_returns_good_when_enabled(self) -> None:
        with TemporaryDirectory() as t:
            app = create_app(Path(t) / "c.sqlite3", lab_mode=True)
            app.state.repository.set_setting("ocsp_enabled", "true")
            leaf = _issue(app)
            app.state.ocsp_service.generate_responses(app.state.lab_chain.issuer)
            der = _ocsp_request(leaf, app.state.lab_chain.issuer.certificate)
            resp = await route_endpoint(app, "/ocsp", "POST")(_Body(der))
            self.assertEqual(resp.media_type, "application/ocsp-response")
            parsed = ocsp.load_der_ocsp_response(resp.body)
            self.assertEqual(parsed.certificate_status, ocsp.OCSPCertStatus.GOOD)

    async def test_post_404_when_disabled(self) -> None:
        with TemporaryDirectory() as t:
            app = create_app(Path(t) / "c.sqlite3", lab_mode=True)
            with self.assertRaises(HTTPException) as ctx:
                await route_endpoint(app, "/ocsp", "POST")(_Body(b"x"))
            self.assertEqual(ctx.exception.status_code, 404)

    async def test_get_form_decodes(self) -> None:
        with TemporaryDirectory() as t:
            app = create_app(Path(t) / "c.sqlite3", lab_mode=True)
            app.state.repository.set_setting("ocsp_enabled", "true")
            leaf = _issue(app)
            app.state.ocsp_service.generate_responses(app.state.lab_chain.issuer)
            der = _ocsp_request(leaf, app.state.lab_chain.issuer.certificate)
            encoded = base64.b64encode(der).decode()
            resp = route_endpoint(app, "/ocsp/{encoded:path}", "GET")(encoded)
            self.assertEqual(ocsp.load_der_ocsp_response(resp.body).certificate_status, ocsp.OCSPCertStatus.GOOD)

    async def test_get_404_when_disabled(self) -> None:
        with TemporaryDirectory() as t:
            app = create_app(Path(t) / "c.sqlite3", lab_mode=True)
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/ocsp/{encoded:path}", "GET")("AAAA")
            self.assertEqual(ctx.exception.status_code, 404)
