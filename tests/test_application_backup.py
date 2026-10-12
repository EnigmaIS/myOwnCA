from __future__ import annotations

import os
import asyncio
import io
import re
import struct
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine

from myownca.audit import AuditActor, AuditCategory, AuditRepository, AuditService
from myownca.backup.archive import (
    MAGIC,
    ArchiveAuthenticationError,
    BackupArchiveError,
    validate_zip,
)
from myownca.backup.database import DatabaseBackupError
from myownca.backup.repository import BackupRepositoryError
from myownca.backup.restore import BackupRestoreError, restore_backup, verify_backup
from myownca.domain import Role
from myownca.online.app import (
    ApplicationBackupProposalApprove,
    ApplicationBackupProposalCreate,
    create_app,
)
from myownca.storage.database import Database
from tests.helpers import add_login_ready_user, create_active_session, request_with_session, route_endpoint


REQUESTER_SHARE = "requester-share-is-long"
APPROVER_SHARE = "approver-share-is-long"


def _application(root: Path):
    environment = {
        "MYOWNCA_STATE_DIR": str(root),
        "MYOWNCA_AUTH_ENCRYPTION_SECRET": "auth-secret-for-backup-tests",
        "MYOWNCA_ONLINE_KEY_PASSPHRASE": "online-key-passphrase-for-tests",
        "MYOWNCA_SERVICE_KEY_DIR": str(root / "service-keys"),
        "MYOWNCA_OFFLINE_KEY_PASSPHRASE": "must-not-be-in-archive",
        "MYOWNCA_AWS_ACCESS_KEY_ID": "recoverable-cloud-id",
        "MYOWNCA_AWS_SECRET_ACCESS_KEY": "recoverable-cloud-secret",
    }
    patcher = mock.patch.dict(os.environ, environment, clear=False)
    patcher.start()
    app = create_app(
        root / "myownca.sqlite3",
        lab_mode=False,
        online_key_dir=root / "online-keys",
    )
    first_secret = add_login_ready_user(
        app,
        user_id="admin-1",
        email="admin1@example.test",
        role=Role.ADMIN,
    )
    add_login_ready_user(
        app,
        user_id="admin-2",
        email="admin2@example.test",
        role=Role.ADMIN,
    )
    create_active_session(
        app,
        email="admin1@example.test",
        totp_secret=first_secret,
    )
    _seed_backup_audit(app)
    return app, patcher


def _seed_backup_audit(app):
    app.state.audit.record(
        AuditCategory.SYSTEM, "backup_test_seed",
        actor=AuditActor("a|b", "雪@example.test", "admin", "2001:db8::1"),
        object_type="test", object_id="", details={"text": "雪|", "null": None},
    )


def _audit_rows(database):
    with database.connect() as connection:
        return connection.execute("SELECT * FROM audit_events ORDER BY sequence").fetchall()


def _assert_restored_audit(source, target, secret):
    source_rows = _audit_rows(source)
    restored_rows = _audit_rows(target)
    assert len(restored_rows) > 1
    original_rows = restored_rows[:-1]
    assert original_rows == source_rows[:len(original_rows)]
    assert any(row["action"] == "backup_test_seed" for row in original_rows)
    assert all(row["hash_version"] == 2 for row in restored_rows)
    assert restored_rows[-1]["action"] == "application_backup_restored"
    assert restored_rows[-1]["prev_hash"] == original_rows[-1]["record_hash"]
    restarted = AuditService(AuditRepository(target), secret)
    assert restarted.verify_chain() == {"ok": True, "first_bad_sequence": None}
    appended = restarted.record(AuditCategory.SYSTEM, "after_restore_restart")
    assert appended.hash_version == 2
    assert appended.prev_hash == restored_rows[-1]["record_hash"]
    assert restarted.verify_chain()["ok"]


def _create_archive(root: Path, *, audit_change=None):
    app, patcher = _application(root)
    if audit_change is not None:
        column, value = audit_change
        with app.state.audit.repository.database.connect() as connection:
            connection.execute(
                f"UPDATE audit_events SET {column} = ? WHERE action = 'backup_test_seed'",
                (value,),
            )
    service = app.state.application_backup_service
    proposal = service.request_backup(
        proposer_id="admin-1",
        proposer_email="admin1@example.test",
        reason="create a portable recovery archive",
        requester_passphrase=REQUESTER_SHARE,
    )
    result = service.approve_and_create(
        proposal.id,
        approver_id="admin-2",
        approver_email="admin2@example.test",
        reason="approve the portable recovery archive",
        approver_passphrase=APPROVER_SHARE,
    )
    return app, patcher, result, service.export_path(result["id"])


def test_split_share_is_encrypted_then_consumed_before_snapshot() -> None:
    with TemporaryDirectory() as tempdir:
        root = Path(tempdir)
        app, patcher = _application(root)
        try:
            service = app.state.application_backup_service
            proposal = service.request_backup(
                proposer_id="admin-1",
                proposer_email="admin1@example.test",
                reason="create a portable recovery archive",
                requester_passphrase=REQUESTER_SHARE,
            )
            with service.database.connect() as connection:
                row = connection.execute(
                    "SELECT requester_key_ciphertext FROM application_backup_pending_secrets"
                ).fetchone()
            assert row is not None
            assert REQUESTER_SHARE not in row["requester_key_ciphertext"]

            with pytest.raises(BackupRepositoryError, match="cannot approve"):
                service.approve_and_create(
                    proposal.id,
                    approver_id="admin-1",
                    approver_email="admin1@example.test",
                    reason="invalid self approval attempt",
                    approver_passphrase=APPROVER_SHARE,
                )

            result = service.approve_and_create(
                proposal.id,
                approver_id="admin-2",
                approver_email="admin2@example.test",
                reason="approve the portable recovery archive",
                approver_passphrase=APPROVER_SHARE,
            )
            with service.database.connect() as connection:
                pending = connection.execute(
                    "SELECT COUNT(*) AS count FROM application_backup_pending_secrets"
                ).fetchone()
            assert pending == {"count": 0}
            assert service.export_path(result["id"]).is_file()
        finally:
            patcher.stop()


def test_archive_authentication_tamper_and_secret_boundaries() -> None:
    with TemporaryDirectory() as tempdir:
        app, patcher, result, archive = _create_archive(Path(tempdir))
        try:
            manifest = verify_backup(
                archive,
                requester_passphrase=REQUESTER_SHARE,
                approver_passphrase=APPROVER_SHARE,
            )
            assert manifest["archive_id"] == result["id"]
            assert manifest["issuer_backend"] == "software"
            assert "MYOWNCA_AWS_SECRET_ACCESS_KEY" not in archive.read_bytes().decode(
                "latin1", errors="ignore"
            )
            assert b"must-not-be-in-archive" not in archive.read_bytes()
            with pytest.raises(ArchiveAuthenticationError):
                verify_backup(
                    archive,
                    requester_passphrase="wrong-requester-share",
                    approver_passphrase=APPROVER_SHARE,
                )

            tampered = archive.with_name("tampered.myownca-backup")
            data = bytearray(archive.read_bytes())
            data[-20] ^= 1
            tampered.write_bytes(data)
            with pytest.raises((ArchiveAuthenticationError, BackupArchiveError)):
                verify_backup(
                    tampered,
                    requester_passphrase=REQUESTER_SHARE,
                    approver_passphrase=APPROVER_SHARE,
                )

            truncated = archive.with_name("truncated.myownca-backup")
            truncated.write_bytes(archive.read_bytes()[:-10])
            with pytest.raises(BackupArchiveError):
                verify_backup(
                    truncated,
                    requester_passphrase=REQUESTER_SHARE,
                    approver_passphrase=APPROVER_SHARE,
                )

            reordered = archive.with_name("reordered.myownca-backup")
            reordered_data = bytearray(archive.read_bytes())
            header_length = struct.unpack(">I", reordered_data[len(MAGIC) : len(MAGIC) + 4])[0]
            first_frame = len(MAGIC) + 4 + header_length
            reordered_data[first_frame : first_frame + 4] = struct.pack(">I", 1)
            reordered.write_bytes(reordered_data)
            with pytest.raises(BackupArchiveError, match="ordering"):
                verify_backup(
                    reordered,
                    requester_passphrase=REQUESTER_SHARE,
                    approver_passphrase=APPROVER_SHARE,
                )
        finally:
            patcher.stop()


def test_zip_validation_rejects_unsafe_and_duplicate_members() -> None:
    unsafe = io.BytesIO()
    with zipfile.ZipFile(unsafe, "w") as bundle:
        bundle.writestr("../secret", b"no")
        bundle.writestr("manifest.json", '{"format_version":1,"entries":[]}')
    unsafe.seek(0)
    with zipfile.ZipFile(unsafe) as bundle, pytest.raises(BackupArchiveError, match="unsafe"):
        validate_zip(bundle)

    duplicate = io.BytesIO()
    with pytest.warns(UserWarning, match="Duplicate name"):
        with zipfile.ZipFile(duplicate, "w") as bundle:
            bundle.writestr("same", b"one")
            bundle.writestr("same", b"two")
            bundle.writestr("manifest.json", '{"format_version":1,"entries":[]}')
    duplicate.seek(0)
    with zipfile.ZipFile(duplicate) as bundle, pytest.raises(BackupArchiveError, match="duplicate"):
        validate_zip(bundle)


def test_sqlite_restore_round_trip_requires_empty_target_and_revokes_sessions() -> None:
    with TemporaryDirectory() as tempdir:
        source = Path(tempdir) / "source"
        source.mkdir()
        app, patcher, result, archive = _create_archive(source)
        try:
            target = Path(tempdir) / "target"
            restored = restore_backup(
                archive,
                state_dir=target,
                requester_passphrase=REQUESTER_SHARE,
                approver_passphrase=APPROVER_SHARE,
                force_sqlite=True,
            )
            assert restored["archive_id"] == result["id"]
            assert restored["target_database"] == "sqlite"
            assert (target / "setup" / "complete").is_file()
            assert (target / "config.toml").is_file()
            assert (target / "secrets" / "secrets.env").stat().st_mode & 0o777 == 0o600

            database = Database(target / "myownca.sqlite3")
            with database.connect() as connection:
                users = connection.execute("SELECT COUNT(*) AS count FROM users").fetchone()
                active_sessions = connection.execute(
                    "SELECT COUNT(*) AS count FROM auth_sessions WHERE revoked_at IS NULL"
                ).fetchone()
            assert users == {"count": 2}
            assert active_sessions == {"count": 0}
            _assert_restored_audit(
                app.state.audit.repository.database, database, "auth-secret-for-backup-tests"
            )

            occupied = Path(tempdir) / "occupied"
            occupied.mkdir()
            (occupied / "existing").write_text("do not overwrite")
            with pytest.raises(BackupRestoreError, match="must be empty"):
                restore_backup(
                    archive,
                    state_dir=occupied,
                    requester_passphrase=REQUESTER_SHARE,
                    approver_passphrase=APPROVER_SHARE,
                    force_sqlite=True,
                )
            assert (occupied / "existing").read_text() == "do not overwrite"
        finally:
            patcher.stop()


def test_delivery_drives_readiness_and_removes_staged_archive() -> None:
    with TemporaryDirectory() as tempdir:
        app, patcher, result, archive = _create_archive(Path(tempdir))
        try:
            readiness = app.state.operations.readiness()
            backup = next(item for item in readiness["items"] if item["id"] == "backup.application")
            assert backup["status"] == "fail"
            app.state.application_backup_repository.mark_delivered(result["id"])
            archive.unlink()
            readiness = app.state.operations.readiness()
            backup = next(item for item in readiness["items"] if item["id"] == "backup.application")
            assert backup["status"] == "pass"
            assert "Off-host storage" in backup["summary"]
        finally:
            patcher.stop()


def test_admin_backup_ui_replaces_attestations_without_touching_hsm_or_setup_ui() -> None:
    static = Path(__file__).parents[1] / "src" / "myownca" / "online" / "static"
    admin = (static / "admin.html").read_text()
    dashboard = (static / "admin-dashboard.js").read_text()
    backup = (static / "admin-backup.js").read_text()
    css = (static / "app.css").read_text()
    setup = (Path(__file__).parents[1] / "src" / "myownca" / "setup" / "static" / "setup.html").read_text()

    assert 'data-view="backups"' in admin
    assert 'id="view-backups"' in admin
    assert "REQUEST APPLICATION BACKUP" in backup
    assert "APPROVE APPLICATION BACKUP" in backup
    assert "recovery-attestations" not in dashboard
    assert "Record backup attestation" not in admin
    assert "Request native HSM backup export" in admin
    assert "Restore Sub CA key from wrapped backup" in setup
    spacing = re.search(
        r'\.view > :where\(([^)]*)\) \+ :where\(([^)]*)\) \{\s*margin-top: 18px;',
        css,
    )
    assert spacing is not None
    assert ".dashboard-summary-grid" not in spacing.group(1)
    assert ".dashboard-summary-grid" in spacing.group(2)


def test_admin_api_enforces_distinct_approver_and_marks_completed_delivery() -> None:
    with TemporaryDirectory() as tempdir:
        root = Path(tempdir)
        environment = {
            "MYOWNCA_STATE_DIR": str(root),
            "MYOWNCA_AUTH_ENCRYPTION_SECRET": "auth-secret-for-backup-api-tests",
            "MYOWNCA_ONLINE_KEY_PASSPHRASE": "online-key-passphrase-for-api-tests",
            "MYOWNCA_SERVICE_KEY_DIR": str(root / "service-keys"),
        }
        with mock.patch.dict(os.environ, environment, clear=False):
            app = create_app(
                root / "myownca.sqlite3",
                lab_mode=False,
                online_key_dir=root / "online-keys",
            )
            first_secret = add_login_ready_user(
                app,
                user_id="admin-1",
                email="admin1@example.test",
                role=Role.ADMIN,
            )
            second_secret = add_login_ready_user(
                app,
                user_id="admin-2",
                email="admin2@example.test",
                role=Role.ADMIN,
            )
            first_token, first_csrf = create_active_session(
                app,
                email="admin1@example.test",
                totp_secret=first_secret,
            )
            second_token, second_csrf = create_active_session(
                app,
                email="admin2@example.test",
                totp_secret=second_secret,
            )
            proposal = route_endpoint(app, "/internal/admin/backups/proposals", "POST")(
                ApplicationBackupProposalCreate(
                    reason="create a portable recovery archive",
                    confirmation="REQUEST APPLICATION BACKUP",
                    requester_passphrase=REQUESTER_SHARE,
                    requester_passphrase_confirmation=REQUESTER_SHARE,
                ),
                request_with_session(first_token, first_csrf, method="POST"),
            )

            approve = route_endpoint(
                app,
                "/internal/admin/backups/proposals/{proposal_id}/approve",
                "POST",
            )
            payload = ApplicationBackupProposalApprove(
                reason="approve the portable recovery archive",
                confirmation="APPROVE APPLICATION BACKUP",
                approver_passphrase=APPROVER_SHARE,
                approver_passphrase_confirmation=APPROVER_SHARE,
            )
            with pytest.raises(HTTPException) as self_approval:
                approve(
                    proposal["id"],
                    payload,
                    request_with_session(first_token, first_csrf, method="POST"),
                )
            assert getattr(self_approval.value, "status_code", None) == 409

            exported = approve(
                proposal["id"],
                payload,
                request_with_session(second_token, second_csrf, method="POST"),
            )
            download = route_endpoint(
                app,
                "/internal/admin/backups/exports/{export_id}/download",
                "GET",
            )(
                exported["id"],
                request_with_session(second_token),
            )

            async def consume() -> bytes:
                chunks = []
                async for chunk in download.body_iterator:
                    chunks.append(chunk)
                return b"".join(chunks)

            archive_bytes = asyncio.run(consume())
            assert len(archive_bytes) == exported["size_bytes"]
            status = route_endpoint(app, "/internal/admin/backups", "GET")(
                request_with_session(second_token)
            )
            assert status["latest_delivered"]["id"] == exported["id"]
            assert status["latest_delivered"]["status"] == "delivered"


@pytest.mark.skipif(
    not os.environ.get("MYOWNCA_TEST_MARIADB_ADMIN_URL"),
    reason="set MYOWNCA_TEST_MARIADB_ADMIN_URL for the real MariaDB backup matrix",
)
def test_real_mariadb_portable_restore_matrix() -> None:
    admin_url = os.environ["MYOWNCA_TEST_MARIADB_ADMIN_URL"]
    database_names = (
        "myownca_backup_source",
        "myownca_backup_target",
        "myownca_backup_from_sqlite",
    )
    admin_engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with admin_engine.connect() as connection:
        for name in database_names:
            connection.exec_driver_sql(f"DROP DATABASE IF EXISTS `{name}`")
            connection.exec_driver_sql(f"CREATE DATABASE `{name}` CHARACTER SET utf8mb4")
    base_url = admin_url.rsplit("/", 1)[0]
    try:
        with TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            maria_state = root / "maria-source"
            maria_state.mkdir()
            maria_env = {
                "MYOWNCA_STATE_DIR": str(maria_state),
                "MYOWNCA_DATABASE_URL": f"{base_url}/{database_names[0]}",
                "MYOWNCA_AUTH_ENCRYPTION_SECRET": "maria-auth-secret-for-backups",
                "MYOWNCA_ONLINE_KEY_PASSPHRASE": "maria-online-key-passphrase",
                "MYOWNCA_SERVICE_KEY_DIR": str(maria_state / "service-keys"),
            }
            with mock.patch.dict(os.environ, maria_env, clear=False):
                app = create_app(lab_mode=False, online_key_dir=maria_state / "online-keys")
                add_login_ready_user(
                    app,
                    user_id="admin-1",
                    email="admin1@example.test",
                    role=Role.ADMIN,
                )
                add_login_ready_user(
                    app,
                    user_id="admin-2",
                    email="admin2@example.test",
                    role=Role.ADMIN,
                )
                _seed_backup_audit(app)
                service = app.state.application_backup_service
                proposal = service.request_backup(
                    proposer_id="admin-1",
                    proposer_email="admin1@example.test",
                    reason="mariadb portable backup matrix",
                    requester_passphrase=REQUESTER_SHARE,
                )
                exported = service.approve_and_create(
                    proposal.id,
                    approver_id="admin-2",
                    approver_email="admin2@example.test",
                    reason="approve mariadb portable matrix",
                    approver_passphrase=APPROVER_SHARE,
                )
                archive = service.export_path(exported["id"])

                restore_backup(
                    archive,
                    state_dir=root / "maria-target-state",
                    requester_passphrase=REQUESTER_SHARE,
                    approver_passphrase=APPROVER_SHARE,
                    database_url=f"{base_url}/{database_names[1]}",
                )
                _assert_restored_audit(
                    app.state.audit.repository.database,
                    Database(f"{base_url}/{database_names[1]}"),
                    "maria-auth-secret-for-backups",
                )
                restore_backup(
                    archive,
                    state_dir=root / "sqlite-target-state",
                    requester_passphrase=REQUESTER_SHARE,
                    approver_passphrase=APPROVER_SHARE,
                    force_sqlite=True,
                )
                _assert_restored_audit(
                    app.state.audit.repository.database,
                    Database(root / "sqlite-target-state" / "myownca.sqlite3"),
                    "maria-auth-secret-for-backups",
                )

            sqlite_source = root / "sqlite-source"
            sqlite_source.mkdir()
            sqlite_app, sqlite_patcher, _result, sqlite_archive = _create_archive(sqlite_source)
            try:
                restore_backup(
                    sqlite_archive,
                    state_dir=root / "sqlite-to-maria-state",
                    requester_passphrase=REQUESTER_SHARE,
                    approver_passphrase=APPROVER_SHARE,
                    database_url=f"{base_url}/{database_names[2]}",
                )
                _assert_restored_audit(
                    sqlite_app.state.audit.repository.database,
                    Database(f"{base_url}/{database_names[2]}"),
                    "auth-secret-for-backup-tests",
                )
            finally:
                sqlite_patcher.stop()
                del sqlite_app
    finally:
        with admin_engine.connect() as connection:
            for name in database_names:
                connection.exec_driver_sql(f"DROP DATABASE IF EXISTS `{name}`")
        admin_engine.dispose()


@pytest.mark.parametrize(("column", "value"), [
    ("actor_email", "tampered@example.test"),
    ("actor_role", "auditor"),
    ("source_ip", "192.0.2.99"),
    ("hash_version", 1),
    ("hash_version", 99),
])
def test_restore_rejects_invalid_audit_before_publishing_state(tmp_path, column, value):
    source = tmp_path / "source"
    source.mkdir()
    _app, patcher, _result, archive = _create_archive(source, audit_change=(column, value))
    try:
        target = tmp_path / "target"
        with pytest.raises(BackupRestoreError, match="audit chain integrity check failed"):
            restore_backup(
                archive, state_dir=target, requester_passphrase=REQUESTER_SHARE,
                approver_passphrase=APPROVER_SHARE, force_sqlite=True,
            )
        assert list(target.iterdir()) == []
    finally:
        patcher.stop()


def test_restore_retains_exact_release_and_migration_requirements(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    _app, patcher, _result, archive = _create_archive(source)
    try:
        with (
            mock.patch("myownca.backup.restore.__version__", "different-release"),
            pytest.raises(BackupRestoreError, match="Backup requires myOwnCA"),
        ):
            restore_backup(
                archive, state_dir=tmp_path / "version-target",
                requester_passphrase=REQUESTER_SHARE, approver_passphrase=APPROVER_SHARE,
                force_sqlite=True,
            )
        with (
            mock.patch("myownca.backup.database.migration_fingerprint", return_value=("old", [])),
            pytest.raises(DatabaseBackupError, match="migrations do not match"),
        ):
            restore_backup(
                archive, state_dir=tmp_path / "schema-target",
                requester_passphrase=REQUESTER_SHARE, approver_passphrase=APPROVER_SHARE,
                force_sqlite=True,
            )
        assert list((tmp_path / "version-target").iterdir()) == []
        assert list((tmp_path / "schema-target").iterdir()) == []
    finally:
        patcher.stop()
