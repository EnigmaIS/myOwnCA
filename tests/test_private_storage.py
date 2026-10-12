from __future__ import annotations

import io
import os
import stat
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy.exc import OperationalError

from myownca import launcher
from myownca.ca_hsm import SoftwareHSM
from myownca.service_certs.keystore import ServiceKeyStore
from myownca.setup.cleanup import cleanup_completed_setup
from myownca.setup.config_writer import read_secrets, write_config, write_secrets
from myownca.setup.state import (
    SetupState, load_setup_state, mark_setup_complete, save_setup_state,
)
from myownca.storage.database import Database
from myownca.storage.permissions import run_permissions
from myownca_core.private_files import atomic_write


@contextmanager
def permissive_umask():
    previous = os.umask(0)
    try:
        yield
    finally:
        os.umask(previous)


def mode(path):
    return stat.S_IMODE(path.stat().st_mode)


@pytest.fixture
def clean_env(monkeypatch):
    for key in list(os.environ):
        if key.startswith("MYOWNCA_"):
            monkeypatch.delenv(key)


def prepared_state(path):
    save_setup_state(path, SetupState(data={
        "admins": [{"id": "a", "email": "a@example.test", "password": "bootstrap-secret"}],
        "database": {"backend": "mariadb", "password": "db-secret"},
        "hsm": {"backend": "aws_kms", "aws_secret_access_key": "cloud-secret",
                "aws_region": "region"},
    }))
    write_secrets(path, {
        "MYOWNCA_DATABASE_URL": "mysql+pymysql://u:db-secret@db/ca",
        "MYOWNCA_AWS_SECRET_ACCESS_KEY": "cloud-secret",
        "MYOWNCA_AUTH_ENCRYPTION_SECRET": "auth-secret",
    })
    mark_setup_complete(path)
    return mock.Mock(count_active_users_with_role=mock.Mock(return_value=1))


def test_cleanup_removes_only_obsolete_secrets_and_is_idempotent(tmp_path):
    repository = prepared_state(tmp_path)
    secrets_before = read_secrets(tmp_path)
    cleanup_completed_setup(tmp_path, repository)
    state = load_setup_state(tmp_path)
    assert state.data["admins"] == [{"id": "a", "email": "a@example.test"}]
    assert state.data["database"] == {"backend": "mariadb"}
    assert state.data["hsm"] == {"backend": "aws_kms", "aws_region": "region"}
    assert read_secrets(tmp_path) == secrets_before
    path = tmp_path / "setup/state.json"
    first_write = path.stat().st_mtime_ns
    cleanup_completed_setup(tmp_path, repository)
    assert path.stat().st_mtime_ns == first_write


@pytest.mark.parametrize("incomplete", [True, False])
def test_cleanup_preserves_secrets_until_bootstrap_succeeds(tmp_path, incomplete):
    repository = prepared_state(tmp_path)
    if incomplete:
        (tmp_path / "setup/complete").unlink()
    else:
        repository.count_active_users_with_role.return_value = 0
    before = (tmp_path / "setup/state.json").read_bytes()
    cleanup_completed_setup(tmp_path, repository)
    assert (tmp_path / "setup/state.json").read_bytes() == before


def test_cleanup_preserves_unmatched_runtime_credentials_and_warns(tmp_path, caplog):
    repository = prepared_state(tmp_path)
    write_secrets(tmp_path, {"MYOWNCA_DATABASE_URL": "mysql+pymysql://u:other@db/ca"})
    cleanup_completed_setup(tmp_path, repository)
    state = load_setup_state(tmp_path)
    assert "password" not in state.data["admins"][0]
    assert state.data["database"]["password"] == "db-secret"
    assert state.data["hsm"]["aws_secret_access_key"] == "cloud-secret"
    assert "retains credentials" in caplog.text
    assert "db-secret" not in caplog.text
    assert "cloud-secret" not in caplog.text


def test_cleanup_failure_is_redacted_nonfatal_and_retried(tmp_path, caplog):
    repository = prepared_state(tmp_path)
    before = (tmp_path / "setup/state.json").read_bytes()
    with mock.patch("myownca.setup.cleanup.atomic_write",
                    side_effect=PermissionError("do-not-log-this-secret")):
        cleanup_completed_setup(tmp_path, repository)
    assert (tmp_path / "setup/state.json").read_bytes() == before
    assert "PermissionError" in caplog.text
    assert "do-not-log-this-secret" not in caplog.text
    cleanup_completed_setup(tmp_path, repository)
    assert "password" not in load_setup_state(tmp_path).data["admins"][0]


def test_corrupt_setup_cleanup_does_not_break_startup_or_log_contents(tmp_path, caplog):
    repository = prepared_state(tmp_path)
    (tmp_path / "setup/state.json").write_text('{"secret": "do-not-log"')
    cleanup_completed_setup(tmp_path, repository)
    assert "could not finish" in caplog.text
    assert "do-not-log" not in caplog.text


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode assertions")
def test_new_state_and_key_material_are_private_with_permissive_umask(tmp_path):
    state = tmp_path / "new" / "state"
    with permissive_umask():
        write_secrets(state, {"MYOWNCA_AUTH_ENCRYPTION_SECRET": "test"})
        save_setup_state(state, SetupState())
        hsm = SoftwareHSM(state / "online-keys")
        hsm.generate_key("issuer", "ecdsa-p256")
        keys = ServiceKeyStore(state / "service-keys")
        keys.store_software_key("service", ec.generate_private_key(ec.SECP256R1()))
    for directory in (state.parent, state, state / "setup", state / "secrets",
                      state / "online-keys", state / "service-keys"):
        assert mode(directory) == 0o700
    for file in (state / "setup/state.json", state / "secrets/secrets.env",
                 state / "online-keys/issuer.pem", state / "service-keys/service.pem"):
        assert mode(file) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode assertions")
@pytest.mark.parametrize("kind", ["path", "url", "uri"])
def test_sqlite_created_private_for_paths_and_urls(tmp_path, kind):
    path = tmp_path / "new" / "db space.sqlite3"
    target = {"path": path, "url": f"sqlite:///{path}",
              "uri": f"sqlite:///file:{str(path).replace(' ', '%20')}?mode=rwc&uri=true"}[kind]
    with permissive_umask():
        database = Database(target)
        database.migrate()
    assert mode(path) == 0o600
    assert mode(path.parent) == 0o700
    # WAL files inherit the restricted database mode.
    with database.connect() as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("INSERT INTO online_settings(key, value) VALUES ('probe', 'value')")
        assert mode(Path(str(path) + "-wal")) == 0o600
        assert mode(Path(str(path) + "-shm")) == 0o600


@pytest.mark.parametrize("target", ["sqlite://", "sqlite:///:memory:",
                                    "sqlite:///file:probe?mode=memory&cache=shared&uri=true",
                                    "sqlite:///file::memory:?cache=shared&uri=true"])
def test_sqlite_memory_does_not_create_files(tmp_path, monkeypatch, target):
    monkeypatch.chdir(tmp_path)
    database = Database(target)
    with database.connect() as connection:
        assert connection.execute("SELECT 1 AS n").fetchone()["n"] == 1
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("access", ["ro", "rw"])
def test_sqlite_uri_missing_database_is_not_created(tmp_path, access):
    database = Database(f"sqlite:///file:{tmp_path}/missing/db?mode={access}&uri=true")
    with pytest.raises(OperationalError):
        with database.connect():
            pass
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode assertions")
def test_runtime_preserves_existing_group_permissions(tmp_path):
    directories = [tmp_path, tmp_path / "secrets", tmp_path / "online-keys",
                   tmp_path / "service-keys"]
    for directory in directories:
        directory.mkdir(exist_ok=True)
        directory.chmod(0o770)
    path = tmp_path / "existing.sqlite3"
    path.touch(mode=0o660)
    path.chmod(0o660)
    Database(path).migrate()
    write_secrets(tmp_path, {"X": "Y"})
    SoftwareHSM(directories[2])
    ServiceKeyStore(directories[3])
    assert mode(path) == 0o660
    assert all(mode(directory) == 0o770 for directory in directories)


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode assertions")
def test_secret_cleanup_preserves_existing_state_permissions(tmp_path):
    repository = prepared_state(tmp_path)
    path = tmp_path / "setup/state.json"
    path.chmod(0o660)
    before = path.stat()
    cleanup_completed_setup(tmp_path, repository)
    assert mode(path) == 0o660
    assert (path.stat().st_uid, path.stat().st_gid) == (before.st_uid, before.st_gid)
    assert "password" not in load_setup_state(tmp_path).data["admins"][0]


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership")
def test_cleanup_does_not_replace_foreign_owned_state(tmp_path, caplog):
    repository = prepared_state(tmp_path)
    path = tmp_path / "setup/state.json"
    before = path.read_bytes()
    with mock.patch("myownca_core.private_files.os.geteuid", return_value=os.getuid() + 1):
        cleanup_completed_setup(tmp_path, repository)
    assert path.read_bytes() == before
    assert "PermissionError" in caplog.text


def test_atomic_write_failure_preserves_original_and_removes_temporary(tmp_path):
    path = tmp_path / "secret"
    path.write_bytes(b"original")
    with mock.patch("myownca_core.private_files.os.replace", side_effect=OSError("failed")):
        with pytest.raises(OSError):
            atomic_write(path, b"replacement")
    assert path.read_bytes() == b"original"
    assert list(tmp_path.iterdir()) == [path]


def test_key_publication_cannot_overwrite_existing_key(tmp_path):
    path = tmp_path / "secret"
    path.write_bytes(b"original")
    with pytest.raises(FileExistsError):
        atomic_write(path, b"replacement", exclusive=True)
    assert path.read_bytes() == b"original"
    assert list(tmp_path.iterdir()) == [path]


def configure_permissions(state):
    write_config(state, {
        "MYOWNCA_DATABASE_PATH": str(state / "db.sqlite3"),
        "MYOWNCA_ONLINE_KEY_DIR": str(state / "online-keys"),
        "MYOWNCA_SERVICE_KEY_DIR": str(state / "service-keys"),
    })


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission repair")
def test_permission_command_reports_then_repairs_without_database_access(tmp_path, clean_env):
    state = tmp_path.resolve() / "state"
    configure_permissions(state)
    database = state / "db.sqlite3"
    database.write_bytes(b"not opened as SQLite")
    keys = state / "online-keys"
    keys.mkdir()
    key = keys / "issuer.pem"
    key.write_bytes(b"private key content must not be printed")
    for path in (database, key):
        path.chmod(0o660)
    for path in (state, keys):
        path.chmod(0o770)
    output = io.StringIO()
    with mock.patch.object(Database, "__init__", side_effect=AssertionError("DB opened")):
        assert run_permissions(state, stdout=output) == 1
        assert mode(database) == 0o660
        assert mode(state) == 0o770
        assert run_permissions(state, execute=True, stdout=output) == 0
        assert run_permissions(state, stdout=output) == 0
    assert mode(database) == mode(key) == 0o600
    assert mode(state) == mode(keys) == 0o700
    assert "private key content" not in output.getvalue()
    assert database.read_bytes() == b"not opened as SQLite"
    assert not (state / "service-keys").exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission repair")
@pytest.mark.parametrize("link_kind", ["symlink", "hardlink", "parent_symlink"])
def test_permission_command_refuses_linked_targets(tmp_path, clean_env, link_kind):
    state = tmp_path.resolve() / "state"
    configure_permissions(state)
    external = tmp_path.resolve() / "external"
    external.mkdir()
    protected = external / "issuer.pem"
    protected.write_bytes(b"secret")
    protected.chmod(0o660)
    keys = state / "online-keys"
    if link_kind == "parent_symlink":
        keys.symlink_to(external, target_is_directory=True)
    else:
        keys.mkdir()
        if link_kind == "symlink":
            (keys / "issuer.pem").symlink_to(protected)
        else:
            os.link(protected, keys / "issuer.pem")
    assert run_permissions(state, execute=True, stdout=io.StringIO()) == 2
    assert mode(protected) == 0o660


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission repair")
def test_permission_command_refuses_foreign_owner(tmp_path, clean_env):
    state = tmp_path.resolve() / "state"
    configure_permissions(state)
    state.chmod(0o770)
    output = io.StringIO()
    with mock.patch("myownca.storage.permissions.os.geteuid", return_value=os.getuid() + 1):
        assert run_permissions(state, execute=True, stdout=output) == 2
    assert mode(state) == 0o770
    assert "not owned" in output.getvalue()


def test_permission_command_missing_installation_creates_nothing(tmp_path, clean_env):
    state = tmp_path.resolve() / "missing"
    assert run_permissions(state, stdout=io.StringIO()) == 2
    assert not state.exists()


def test_permission_cli_dispatch_does_not_start_application(tmp_path):
    with mock.patch("myownca.storage.permissions.run_permissions", return_value=1) as run:
        assert launcher.main(["--state-dir", str(tmp_path), "security", "permissions"]) == 1
        run.assert_called_once_with(tmp_path, execute=False)


def test_permission_config_errors_do_not_print_secrets(tmp_path, clean_env):
    with mock.patch("myownca.storage.permissions.Settings.load",
                    side_effect=ValueError("secret connection string")):
        output = io.StringIO()
        assert run_permissions(tmp_path, stdout=output) == 2
    assert "secret connection string" not in output.getvalue()


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission repair")
@pytest.mark.parametrize("backend", ["sqlite", "mariadb", "memory"])
def test_permission_command_uses_effective_database_url(tmp_path, clean_env, backend):
    state = tmp_path.resolve() / "state"
    configure_permissions(state)
    unused = state / "db.sqlite3"
    unused.write_bytes(b"unused")
    unused.chmod(0o660)
    selected = tmp_path.resolve() / "actual.sqlite3"
    selected.write_bytes(b"actual")
    selected.chmod(0o660)
    urls = {
        "sqlite": f"sqlite:///file:{selected}?mode=rw&uri=true",
        "mariadb": "mysql+pymysql://user:secret@db/ca",
        "memory": "sqlite:///file:probe?mode=memory&uri=true",
    }
    write_secrets(state, {"MYOWNCA_DATABASE_URL": urls[backend]})
    output = io.StringIO()
    assert run_permissions(state, execute=True, stdout=output) == 0
    assert mode(unused) == 0o660
    assert mode(selected) == (0o600 if backend == "sqlite" else 0o660)
    assert "user:secret" not in output.getvalue()


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission repair")
def test_permission_failure_is_reported_without_changing_target(tmp_path, clean_env):
    state = tmp_path.resolve() / "state"
    configure_permissions(state)
    state.chmod(0o770)
    output = io.StringIO()
    with mock.patch("myownca.storage.permissions.os.fchmod", side_effect=PermissionError):
        assert run_permissions(state, execute=True, stdout=output) == 2
    assert mode(state) == 0o770
    assert "PermissionError" in output.getvalue()
