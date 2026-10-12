from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from myownca.online.app import create_app

STATIC = Path(__file__).parents[1] / "src" / "myownca" / "online" / "static"


def _asset(name: str) -> str:
    return (STATIC / name).read_text()


class FreshInstallCertificateTemplateTests(unittest.TestCase):
    def test_fresh_install_has_no_certificate_templates(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "seed.sqlite3")
            self.assertEqual(app.state.repository.list_templates(), [])


class OperatorOnboardingDashboardRemovalTests(unittest.TestCase):
    """Certificate Operator onboarding belongs to Getting started, not the dashboard."""

    def test_admin_dashboard_has_no_operator_onboarding_notice(self) -> None:
        markup = _asset("admin.html")
        self.assertNotIn('id="dashboard-operator-notice"', markup)

    def test_dashboard_does_not_fetch_accounts_for_operator_onboarding(self) -> None:
        source = _asset("admin-dashboard.js")
        self.assertNotIn('BB.api("/internal/users")', source)
        self.assertNotIn("dashboard-operator-notice", source)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
