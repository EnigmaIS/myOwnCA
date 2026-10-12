from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography import x509

from myownca.domain import CertificateProfile, CertificateTemplate, Role
from myownca.online.app import create_app
from tests.helpers import add_login_ready_user, make_csr, seed_person


def _issue_in_lab_app(app) -> x509.Certificate:
    add_login_ready_user(app, user_id="su-1", email="su1@example.test", role=Role.SUPERUSER)
    add_login_ready_user(app, user_id="su-2", email="su2@example.test", role=Role.SUPERUSER)
    add_login_ready_user(app, user_id="user-1", email="user@example.test", role=Role.USER)
    app.state.repository.add_template(
        CertificateTemplate(id="host", name="Host", profile=CertificateProfile.HOST_TLS)
    )
    person_id = seed_person(app)
    req = app.state.service.submit_request(
        "host", make_csr("h.example.test", dns_names=("h.example.test",)), requested_by_user_id="user-1"
    )
    app.state.service.approve_request(req.id, "su-1")
    app.state.service.approve_request(req.id, "su-2")
    app.state.service.assign_request_holder(req.id, person_id=person_id)
    issued = app.state.service.issue_certificate(req.id, app.state.lab_chain.issuer)
    return x509.load_pem_x509_certificate(issued.certificate_pem.encode())


class CrlEmbedAppTests(unittest.TestCase):
    def test_lab_leaf_gets_cdp_when_base_url_set(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "c.sqlite3", lab_mode=True)
            app.state.repository.set_setting("crl_base_url", "http://ca.test")
            cert = _issue_in_lab_app(app)
            cdp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
            self.assertEqual(cdp[0].full_name[0].value, "http://ca.test/crl/myOwnCA_Lab_CA.crl")

    def test_no_cdp_when_base_url_unset(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "c.sqlite3", lab_mode=True)
            cert = _issue_in_lab_app(app)
            with self.assertRaises(x509.ExtensionNotFound):
                cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)

    def test_lab_leaf_gets_aia_caissuers_when_base_url_set(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "c.sqlite3", lab_mode=True)
            app.state.repository.set_setting("aia_base_url", "http://ca.test")
            cert = _issue_in_lab_app(app)
            aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
            ca_issuers = [
                d.access_location.value
                for d in aia
                if d.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS
            ]
            self.assertEqual(ca_issuers, ["http://ca.test/aia/myOwnCA_Lab_CA.cer"])
