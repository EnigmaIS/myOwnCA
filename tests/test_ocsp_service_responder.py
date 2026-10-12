from __future__ import annotations

import unittest
from datetime import timedelta

from myownca.ca_hsm.pkcs11 import PKCS11Error
from myownca.online.ocsp_service import OcspService
from tests.helpers import TempPKI


def _service(pki, hsm=None) -> OcspService:
    return OcspService(
        repository=pki.repository, hsm=hsm or pki.hsm, keystore=pki.service_keystore(),
        issuer_provider=lambda: pki.lab_chain.issuer,
        validity_days_provider=lambda: 30, enabled_provider=lambda: True,
    )


class EnsureResponderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pki = TempPKI()

    def tearDown(self) -> None:
        self.pki.close()

    def test_creates_then_reuses(self) -> None:
        svc = _service(self.pki)
        r1 = svc.ensure_responder(self.pki.lab_chain.issuer)
        self.assertIsNotNone(r1)
        r2 = svc.ensure_responder(self.pki.lab_chain.issuer)
        self.assertEqual(r1.cert_pem, r2.cert_pem)  # not re-minted while fresh

    def test_renews_when_near_expiry(self) -> None:
        svc = _service(self.pki)
        r1 = svc.ensure_responder(self.pki.lab_chain.issuer)
        from myownca.domain import OcspResponder
        from datetime import datetime, timezone
        near = datetime.now(timezone.utc) + timedelta(days=1)
        self.pki.repository.upsert_ocsp_responder(
            OcspResponder(issuer_subject=r1.issuer_subject, cert_pem=r1.cert_pem,
                          key_ref=r1.key_ref, not_after=near, created_at=r1.created_at)
        )
        r3 = svc.ensure_responder(self.pki.lab_chain.issuer)
        self.assertNotEqual(r3.cert_pem, r1.cert_pem)  # re-minted

    def test_locked_hsm_returns_none_and_warns(self) -> None:
        class LockedHsm:
            def sign_certificate(self, builder, key_ref):
                raise PKCS11Error("HSM PIN is locked; unlock the PIN before this operation")
        svc = _service(self.pki, hsm=LockedHsm())
        self.assertIsNone(svc.ensure_responder(self.pki.lab_chain.issuer))
        self.assertTrue(self.pki.repository.get_setting("ocsp_responder_warning"))
