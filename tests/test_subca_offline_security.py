from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from starlette.requests import Request

from myownca.ca_hsm import SoftwareHSM
from myownca.ca_main.crypto import create_root_ca
from myownca.domain import CertificateProfile
from myownca.setup.app import create_setup_app
from myownca.setup.orchestrator import SetupOrchestrator
from myownca.setup.provisioning import SetupProvisioningService
from myownca.setup.token import SetupAuth
from tests.helpers import route_endpoint


def _request(session: str, csrf: str) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [
                (b"cookie", f"myownca_setup={session}".encode()),
                (b"x-csrf-token", csrf.encode()),
            ],
        }
    )


def _prepared_request(state_dir: str | Path) -> None:
    root = create_root_ca(SoftwareHSM(), "Offline Root")
    orchestrator = SetupOrchestrator(state_dir)
    orchestrator.set_install_type("production")
    orchestrator.set_governance_mode("single_admin")
    orchestrator.set_root_certificate(root.certificate_pem)
    orchestrator.prepare_runtime()
    SetupProvisioningService(state_dir).create_request(
        common_name="Offline Issuing CA",
        allowed_profiles=[CertificateProfile.HOST_TLS],
        algorithm="ecdsa-p384",
    )


def test_setup_status_returns_the_pending_csr_as_text() -> None:
    with TemporaryDirectory() as tempdir:
        _prepared_request(tempdir)
        auth = SetupAuth()
        app = create_setup_app(tempdir, auth)
        session, csrf = auth.open_session()
        response = route_endpoint(app, "/setup/issuer", "GET")(
            _request(session, csrf)
        )
    assert response["pending"][0]["csr_pem"].startswith(
        "-----BEGIN CERTIFICATE REQUEST-----"
    )


def test_setup_exposes_no_subca_transfer_archive_routes() -> None:
    with TemporaryDirectory() as tempdir:
        app = create_setup_app(tempdir, SetupAuth())
    routes = {
        (method, route.path)
        for route in app.routes
        for method in getattr(route, "methods", set())
    }
    assert ("GET", "/setup/issuer/request-bundle") not in routes
    assert ("POST", "/setup/issuer/response-bundle") not in routes
