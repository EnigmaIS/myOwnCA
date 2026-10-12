from __future__ import annotations

import builtins
import os
import subprocess
import sys
from contextlib import ExitStack
from unittest import mock

import pytest

from myownca import launcher
from myownca.ca_hsm import SoftwareHSM
from myownca.ca_main.crypto import create_lab_ca_chain
from myownca.online.app import create_app
from myownca.setup.config_writer import write_config
from myownca.setup.orchestrator import SetupOrchestrator
from myownca.setup.provisioning import SetupProvisioningService
from myownca.setup.startup import require_existing_issuer
from myownca.setup.state import load_setup_state, mark_setup_complete, save_setup_state


@pytest.fixture
def lab(tmp_path):
    orchestrator = SetupOrchestrator(tmp_path)
    orchestrator.set_install_type("lab")
    orchestrator.set_listener(topology="proxy")
    orchestrator.prepare_runtime()
    return SetupProvisioningService(tmp_path)


def snapshot_files(path):
    return {p.relative_to(path): p.read_bytes() for p in path.rglob("*") if p.is_file()}


@pytest.mark.parametrize("command", [[], ["serve"]])
@pytest.mark.parametrize("failure", ["missing", "database", "migration", "backend", "status"])
def test_completed_failure_never_reopens_setup(lab, tmp_path, capsys, command, failure):
    if failure != "missing":
        lab.provision_lab()
    mark_setup_complete(tmp_path, {"preserve": "marker"})
    before = snapshot_files(tmp_path)
    targets = {
        "database": "myownca.setup.provisioning.Database",
        "migration": "myownca.setup.provisioning.Database.migrate",
        "backend": "myownca.setup.provisioning.create_hsm",
        "status": "myownca.setup.provisioning.SetupProvisioningService.status",
    }
    with ExitStack() as stack:
        if failure in targets:
            stack.enter_context(mock.patch(targets[failure], side_effect=RuntimeError(
                "mysql://admin:sentinel-secret@host/db PIN=sentinel-pin"
            )))
        setup = stack.enter_context(mock.patch.object(launcher, "run_setup"))
        generate = stack.enter_context(mock.patch.object(SoftwareHSM, "generate_key"))
        assert launcher.main(["--state-dir", str(tmp_path), *command]) == 1
    setup.assert_not_called()
    generate.assert_not_called()
    assert snapshot_files(tmp_path) == before
    output = capsys.readouterr().err
    assert "startup failed" in output
    assert "backup" in output
    for secret in ("sentinel-secret", "sentinel-pin", "mysql://", "Token:", "Traceback"):
        assert secret not in output


@pytest.mark.parametrize("target_kind", ["path", "url", "uri", "memory", "memory_uri"])
def test_completed_missing_database_is_not_created(tmp_path, target_kind, capsys):
    missing = tmp_path / "missing" / "database.sqlite3"
    config = {
        "path": {"MYOWNCA_DATABASE_PATH": str(missing)},
        "url": {"MYOWNCA_DATABASE_URL": f"sqlite:///{missing}"},
        "uri": {"MYOWNCA_DATABASE_URL": f"sqlite:///file:{missing}?uri=true"},
        "memory": {"MYOWNCA_DATABASE_URL": "sqlite:///:memory:"},
        "memory_uri": {"MYOWNCA_DATABASE_URL": "sqlite:///file:memdb?mode=memory&uri=true"},
    }[target_kind]
    write_config(tmp_path, config)
    mark_setup_complete(tmp_path)
    before = snapshot_files(tmp_path)
    with mock.patch.object(launcher, "run_setup") as setup:
        assert launcher.main(["--state-dir", str(tmp_path)]) == 1
    setup.assert_not_called()
    assert not missing.parent.exists()
    assert snapshot_files(tmp_path) == before
    with mock.patch.dict(os.environ, {"MYOWNCA_STATE_DIR": str(tmp_path)}, clear=True):
        with pytest.raises(ValueError, match="existing database"):
            create_app()
    assert snapshot_files(tmp_path) == before


def test_healthy_completed_installation_starts_service(lab, tmp_path):
    lab.provision_lab()
    mark_setup_complete(tmp_path)
    before = snapshot_files(tmp_path)
    with mock.patch.dict(os.environ, {}, clear=True), \
         mock.patch("myownca.online.app.run") as run, \
         mock.patch.object(launcher, "run_setup") as setup:
        assert launcher.main(["--state-dir", str(tmp_path)]) == 0
        assert os.environ["MYOWNCA_STATE_DIR"] == str(tmp_path.resolve())
        runtime = create_app()
    run.assert_called_once()
    setup.assert_not_called()
    assert runtime.state.repository.get_active_sub_ca() == lab.repository.get_active_sub_ca()
    for path, contents in before.items():
        if path.suffix != ".sqlite3":
            assert (tmp_path / path).read_bytes() == contents


@pytest.mark.parametrize("phase", ["config", "import", "run"])
def test_service_startup_exceptions_are_secret_safe(lab, tmp_path, phase, capsys):
    lab.provision_lab()
    marker = mark_setup_complete(tmp_path)
    marker_before = marker.read_bytes()
    original_import = builtins.__import__

    def failing_import(name, *args, **kwargs):
        if name == "myownca.online.app":
            raise RuntimeError("sentinel-secret")
        return original_import(name, *args, **kwargs)

    target = {
        "config": "myownca.launcher._apply_state_dir_config_to_env",
        "import": "builtins.__import__",
        "run": "myownca.online.app.run",
    }[phase]
    with mock.patch.dict(os.environ, {}, clear=True), \
         mock.patch(target, side_effect=failing_import if phase == "import"
                    else RuntimeError("sentinel-secret")), \
         mock.patch.object(launcher, "run_setup") as setup:
        assert launcher.run_service(tmp_path) == 1
    setup.assert_not_called()
    assert marker.read_bytes() == marker_before
    assert "sentinel-secret" not in capsys.readouterr().err


def test_failed_handoff_does_not_start_second_wizard(tmp_path, capsys):
    def finalize(*args):
        mark_setup_complete(tmp_path)

    with mock.patch.object(launcher, "_serve_setup_app", side_effect=finalize) as serve:
        assert launcher.run_setup(tmp_path) == 1
    serve.assert_called_once()
    output = capsys.readouterr().err
    assert output.count("Token:") == 1  # Only the original, legitimate first-run token.
    assert "startup failed" in output
    assert not (tmp_path / "myownca.sqlite3").exists()


def test_incomplete_serve_still_starts_setup(tmp_path):
    with mock.patch.object(launcher, "run_setup", return_value=0) as setup:
        assert launcher.run_service(tmp_path) == 0
    setup.assert_called_once()


@pytest.mark.parametrize("key", ["lab-root", "lab-issuer"])
def test_completed_missing_lab_key_never_generates_replacement(lab, tmp_path, key):
    lab.provision_lab()
    lab.backend.delete_key(key)
    mark_setup_complete(tmp_path)
    before = snapshot_files(tmp_path / "online-keys")
    with mock.patch.dict(os.environ, {"MYOWNCA_STATE_DIR": str(tmp_path)}, clear=True), \
         mock.patch.object(SoftwareHSM, "generate_key") as generate, \
         mock.patch("myownca.online.app.run", side_effect=create_app):
        assert launcher.run_service(tmp_path) == 1
        with pytest.raises((ValueError, KeyError)):
            create_app()
    generate.assert_not_called()
    assert snapshot_files(tmp_path / "online-keys") == before


def test_runtime_override_cannot_create_replacement_database(lab, tmp_path):
    lab.provision_lab()
    mark_setup_complete(tmp_path)
    missing = tmp_path / "override.sqlite3"
    with mock.patch.dict(os.environ, {
        "MYOWNCA_STATE_DIR": str(tmp_path), "MYOWNCA_DATABASE_PATH": str(missing)
    }, clear=True):
        with pytest.raises(ValueError, match="existing database"):
            create_app()
    assert not missing.exists()


def test_legacy_lab_adoption_reuses_keys_and_is_repeatable(lab, tmp_path):
    create_lab_ca_chain(lab.backend)
    mark_setup_complete(tmp_path)
    before = snapshot_files(tmp_path / "online-keys")
    with mock.patch.object(SoftwareHSM, "generate_key") as generate:
        assert launcher._issuer_ready(tmp_path)
        first = lab.repository.get_active_sub_ca()
        assert launcher._issuer_ready(tmp_path)
        assert lab.repository.get_active_sub_ca() == first
    generate.assert_not_called()
    assert snapshot_files(tmp_path / "online-keys") == before


@pytest.mark.parametrize("failure", ["missing-key", "persist", "modern-state", "inactive-row"])
def test_legacy_adoption_failure_never_reprovisions(lab, tmp_path, failure):
    if failure == "inactive-row":
        lab.provision_lab()
        with lab.database.connect() as connection:
            connection.execute("DELETE FROM online_settings WHERE key = 'active_sub_ca_id'")
        state = load_setup_state(tmp_path)
        state.data.clear()
        state.steps.clear()
        save_setup_state(tmp_path, state)
    else:
        create_lab_ca_chain(lab.backend)
    if failure == "missing-key":
        lab.backend.delete_key("lab-issuer")
    if failure == "modern-state":
        state = load_setup_state(tmp_path)
        state.data["issuer_locked"] = True
        save_setup_state(tmp_path, state)
    mark_setup_complete(tmp_path)
    before = snapshot_files(tmp_path)
    with mock.patch("myownca.setup.provisioning.PKIRepository.add_sub_ca",
                    side_effect=RuntimeError("sentinel-secret")) as add, \
         mock.patch.object(SoftwareHSM, "generate_key") as generate, \
         mock.patch.object(launcher, "run_setup") as setup:
        assert launcher.run_service(tmp_path) == 1
    if failure == "persist":
        add.assert_called_once()
    else:
        add.assert_not_called()
    generate.assert_not_called()
    setup.assert_not_called()
    assert snapshot_files(tmp_path) == before


def test_issuer_check_does_not_unlock_hardware(lab):
    lab.provision_lab()
    backend = mock.Mock()
    require_existing_issuer(lab.repository, backend, "pkcs11")
    backend.public_key.assert_not_called()
    backend.sign.assert_not_called()


def test_remote_database_failure_does_not_fall_back_to_sqlite(tmp_path, capsys):
    write_config(tmp_path, {
        "MYOWNCA_DATABASE_URL": "mysql+pymysql://admin:sentinel-secret@database/myownca"
    })
    mark_setup_complete(tmp_path)
    before = snapshot_files(tmp_path)
    with mock.patch("myownca.setup.provisioning.Database.migrate",
                    side_effect=RuntimeError("sentinel-secret")), \
         mock.patch.object(launcher, "run_setup") as setup:
        assert launcher.run_service(tmp_path) == 1
    setup.assert_not_called()
    assert snapshot_files(tmp_path) == before
    assert "sentinel-secret" not in capsys.readouterr().err


@pytest.mark.parametrize("missing", [False, True])
def test_launcher_runtime_import_uses_completed_boundary(lab, tmp_path, missing):
    lab.provision_lab()
    mark_setup_complete(tmp_path)
    before = snapshot_files(tmp_path / "online-keys")
    environ = {k: v for k, v in os.environ.items() if not k.startswith("MYOWNCA_")}
    environ["PYTHONPATH"] = os.pathsep.join(["src", "core"])
    replacement = tmp_path / "replacement.sqlite3"
    if missing:
        environ["MYOWNCA_DATABASE_PATH"] = str(replacement)
    # A new process exercises import-time create_app(), which in-process tests
    # have already cached. Stub only the socket server, after app construction.
    script = """
import sys
from unittest.mock import patch
from myownca.launcher import main
with patch('uvicorn.run') as serve:
    rc = main(['--state-dir', sys.argv[1]])
    assert serve.call_count == (0 if rc else 1)
raise SystemExit(rc)
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)],
        env=environ, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == (1 if missing else 0), result.stderr
    assert not replacement.exists()
    assert "Token:" not in result.stderr
    assert "Traceback" not in result.stderr
    assert snapshot_files(tmp_path / "online-keys") == before
