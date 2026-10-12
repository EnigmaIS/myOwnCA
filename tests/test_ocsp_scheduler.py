from __future__ import annotations

import unittest

from myownca.config import Settings
from myownca.online.ocsp_service import OcspService
from myownca.online.scheduler import IntervalScheduler
from tests.helpers import TempPKI


class SchedulerConfigTests(unittest.TestCase):
    def test_settings_defaults_and_parse(self) -> None:
        self.assertTrue(Settings.from_mapping({}).ocsp_auto)
        self.assertEqual(Settings.from_mapping({}).ocsp_refresh_interval_seconds, 86400)
        s = Settings.from_mapping(
            {"MYOWNCA_OCSP_AUTO": "false", "MYOWNCA_OCSP_REFRESH_INTERVAL_SECONDS": "3600"})
        self.assertFalse(s.ocsp_auto)
        self.assertEqual(s.ocsp_refresh_interval_seconds, 3600)


class IntervalSchedulerTests(unittest.TestCase):
    def test_run_once_invokes_tick(self) -> None:
        calls = []
        sched = IntervalScheduler(lambda: calls.append(1), interval_seconds=3600, name="t")
        sched.run_once()
        self.assertEqual(calls, [1])

    def test_run_once_swallows_tick_errors(self) -> None:
        sched = IntervalScheduler(lambda: (_ for _ in ()).throw(RuntimeError("x")),
                                  interval_seconds=3600, name="t")
        sched.run_once()  # must not raise


class ScheduledPassTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pki = TempPKI()

    def tearDown(self) -> None:
        self.pki.close()

    def _service(self, enabled=True) -> OcspService:
        return OcspService(
            repository=self.pki.repository, hsm=self.pki.hsm, keystore=self.pki.service_keystore(),
            issuer_provider=lambda: self.pki.lab_chain.issuer,
            validity_days_provider=lambda: 30, enabled_provider=lambda: enabled)

    def test_pass_generates_when_enabled(self) -> None:
        from myownca.domain import CertificateProfile
        from tests.helpers import make_csr
        self.pki.add_default_users()
        self.pki.add_template("host", CertificateProfile.HOST_TLS)
        req = self.pki.service.submit_request(
            "host", make_csr("h.example.test", dns_names=("h.example.test",)), requested_by_user_id="user-1")
        self.pki.service.approve_request(req.id, "su-1")
        self.pki.service.approve_request(req.id, "su-2")
        self.pki.assign_holder(req.id)
        self.pki.service.issue_certificate(req.id, self.pki.lab_chain.issuer)
        self.assertEqual(self._service().run_scheduled_pass(), 2)  # one serial × {sha1, sha256}

    def test_pass_noop_when_disabled(self) -> None:
        self.assertEqual(self._service(enabled=False).run_scheduled_pass(), 0)
