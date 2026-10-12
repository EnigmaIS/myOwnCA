from __future__ import annotations

import unittest

from myownca.config import Settings


class ServiceUrlSettingsTests(unittest.TestCase):
    def test_parses_all_six_install_urls(self) -> None:
        settings = Settings.from_mapping(
            {
                "MYOWNCA_ADMIN_BASE_URL": "https://admin.example",
                "MYOWNCA_SUPERUSER_BASE_URL": "https://su.example",
                "MYOWNCA_FRONTEND_BASE_URL": "https://app.example",
                "MYOWNCA_CRL_URL": "http://ca.example",
                "MYOWNCA_AIA_URL": "http://ca.example/aia.cer",
                "MYOWNCA_OCSP_URL": "http://ca.example/ocsp",
            }
        )
        self.assertEqual(settings.admin_base_url, "https://admin.example")
        self.assertEqual(settings.superuser_base_url, "https://su.example")
        self.assertEqual(settings.frontend_base_url, "https://app.example")
        self.assertEqual(settings.crl_url, "http://ca.example")
        self.assertEqual(settings.aia_url, "http://ca.example/aia.cer")
        self.assertEqual(settings.ocsp_url, "http://ca.example/ocsp")

    def test_defaults_to_none_when_absent(self) -> None:
        settings = Settings.from_mapping({})
        for attr in (
            "admin_base_url",
            "superuser_base_url",
            "frontend_base_url",
            "crl_url",
            "aia_url",
            "ocsp_url",
        ):
            self.assertIsNone(getattr(settings, attr), attr)
