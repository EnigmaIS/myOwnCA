from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from myownca.online.app import create_app
from myownca.setup.app import create_setup_app
from myownca.setup.orchestrator import SetupOrchestrator
from myownca.setup.provisioning import SetupProvisioningService
from myownca.setup.token import SetupAuth


def _route_methods(app) -> set[tuple[str, str]]:
    return {
        (method, route.path)
        for route in app.routes
        for method in getattr(route, "methods", set())
    }


def test_all_initial_issuer_workflows_live_on_the_setup_app() -> None:
    with TemporaryDirectory() as tempdir:
        routes = _route_methods(create_setup_app(tempdir, SetupAuth()))
    expected = {
        ("GET", "/setup/issuer"),
        ("POST", "/setup/issuer/request"),
        ("POST", "/setup/issuer/response/import"),
        ("POST", "/setup/issuer/existing-key/analyze"),
        ("POST", "/setup/issuer/existing-key/commit"),
        ("POST", "/setup/issuer/file/analyze"),
        ("POST", "/setup/issuer/file/commit"),
        ("POST", "/setup/issuer/dkek/analyze"),
        ("POST", "/setup/issuer/dkek/restore"),
        ("POST", "/setup/issuer/lab"),
        ("POST", "/setup/issuer/reset"),
    }
    assert expected <= routes
    assert ("GET", "/setup/issuer/request-bundle") not in routes
    assert ("POST", "/setup/issuer/response-bundle") not in routes


def test_runtime_keeps_only_read_only_trust_status() -> None:
    with TemporaryDirectory() as tempdir:
        runtime = create_app(
            Path(tempdir) / "runtime.sqlite3",
            lab_mode=False,
            online_key_dir=Path(tempdir) / "keys",
        )
    routes = _route_methods(runtime)
    assert not any(path.startswith("/internal/setup/") for _, path in routes)
    assert ("GET", "/internal/admin/issuer") in routes
    assert ("GET", "/internal/admin/root-certificate") in routes


def test_lab_issuer_is_durable_across_setup_service_restart() -> None:
    with TemporaryDirectory() as tempdir:
        orchestrator = SetupOrchestrator(tempdir)
        orchestrator.set_install_type("lab")
        orchestrator.prepare_runtime()
        created = SetupProvisioningService(tempdir).provision_lab()
        restarted = SetupProvisioningService(tempdir).status()
    assert restarted["configured"] is True
    assert restarted["issuer"]["id"] == created["issuer"]["id"]
