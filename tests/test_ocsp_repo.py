from __future__ import annotations

import unittest
from datetime import datetime, timezone

from myownca.domain import OcspResponder, OcspStoredResponse
from tests.helpers import TempPKI


class OcspRepoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pki = TempPKI()
        self.repo = self.pki.repository

    def tearDown(self) -> None:
        self.pki.close()

    def test_responder_upsert_and_get(self) -> None:
        now = datetime(2026, 6, 18, tzinfo=timezone.utc)
        self.repo.upsert_ocsp_responder(
            OcspResponder(issuer_subject="CN=Sub", cert_pem="PEM1", key_ref="ocsp-responder-abc",
                          not_after=now, created_at=now)
        )
        got = self.repo.get_ocsp_responder("CN=Sub")
        self.assertEqual(got.key_ref, "ocsp-responder-abc")
        self.assertEqual(got.cert_pem, "PEM1")
        self.repo.upsert_ocsp_responder(
            OcspResponder(issuer_subject="CN=Sub", cert_pem="PEM2", key_ref="ocsp-responder-abc",
                          not_after=now, created_at=now)
        )
        self.assertEqual(self.repo.get_ocsp_responder("CN=Sub").cert_pem, "PEM2")
        self.assertIsNone(self.repo.get_ocsp_responder("CN=Missing"))

    def test_response_upsert_and_get(self) -> None:
        now = datetime(2026, 6, 18, tzinfo=timezone.utc)
        self.repo.upsert_ocsp_response(
            OcspStoredResponse(issuer_subject="CN=Sub", serial_number="2a", cert_id_hash="sha1",
                               response_b64="AAAA", this_update=now, next_update=now, produced_at=now)
        )
        got = self.repo.get_ocsp_response("CN=Sub", "2a", "sha1")
        self.assertEqual(got.response_b64, "AAAA")
        self.assertIsNone(self.repo.get_ocsp_response("CN=Sub", "2a", "sha256"))
        self.repo.upsert_ocsp_response(
            OcspStoredResponse(issuer_subject="CN=Sub", serial_number="2a", cert_id_hash="sha1",
                               response_b64="BBBB", this_update=now, next_update=now, produced_at=now)
        )
        self.assertEqual(self.repo.get_ocsp_response("CN=Sub", "2a", "sha1").response_b64, "BBBB")
