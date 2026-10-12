from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID

from myownca.domain import CertificateProfile, CertificateTemplate, Role
from myownca.online.app import create_app
from tests.helpers import add_login_ready_user, make_csr, seed_person


def _issue(app):
    add_login_ready_user(app, user_id="su-1", email="su1@example.test", role=Role.SUPERUSER)
    add_login_ready_user(app, user_id="su-2", email="su2@example.test", role=Role.SUPERUSER)
    add_login_ready_user(app, user_id="user-1", email="user@example.test", role=Role.USER)
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


class AiaTests(unittest.TestCase):
    def test_ocsp_aia_when_enabled_and_url_set(self) -> None:
        with TemporaryDirectory() as t:
            app = create_app(Path(t) / "c.sqlite3", lab_mode=True)
            app.state.repository.set_setting("ocsp_enabled", "true")
            app.state.repository.set_setting("ocsp_url", "http://ca.test/ocsp")
            app.state.repository.set_setting("aia_base_url", "http://ca.test")
            aia = _issue(app).extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
            methods = {(d.access_method, d.access_location.value) for d in aia}
            self.assertIn((AuthorityInformationAccessOID.OCSP, "http://ca.test/ocsp"), methods)
            self.assertIn((AuthorityInformationAccessOID.CA_ISSUERS, "http://ca.test/aia/myOwnCA_Lab_CA.cer"), methods)

    def test_no_ocsp_entry_when_disabled_but_caissuers_independent(self) -> None:
        with TemporaryDirectory() as t:
            app = create_app(Path(t) / "c.sqlite3", lab_mode=True)
            app.state.repository.set_setting("ocsp_enabled", "false")
            app.state.repository.set_setting("ocsp_url", "http://ca.test/ocsp")
            app.state.repository.set_setting("aia_base_url", "http://ca.test")
            aia = _issue(app).extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
            methods = {d.access_method for d in aia}
            self.assertNotIn(AuthorityInformationAccessOID.OCSP, methods)
            self.assertIn(AuthorityInformationAccessOID.CA_ISSUERS, methods)

    def test_no_aia_when_nothing_set(self) -> None:
        with TemporaryDirectory() as t:
            app = create_app(Path(t) / "c.sqlite3", lab_mode=True)
            with self.assertRaises(x509.ExtensionNotFound):
                _issue(app).extensions.get_extension_for_class(x509.AuthorityInformationAccess)
