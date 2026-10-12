from __future__ import annotations

import json
import os
import shutil
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from sqlalchemy import inspect

from myownca import __version__
from myownca.audit import AuditActor, AuditCategory, AuditRepository, AuditService
from myownca.backup.archive import decrypt_archive_to_zip, validate_zip
from myownca.backup.database import restore_logical_database
from myownca.config import Settings
from myownca.setup.config_writer import write_config, write_secrets
from myownca.setup.state import mark_setup_complete
from myownca.storage.database import Database
from myownca.storage.repositories import PKIRepository

_MAX_RUNTIME_JSON_BYTES = 1024 * 1024
_MAX_LOCAL_FILE_BYTES = 64 * 1024 * 1024


class BackupRestoreError(RuntimeError):
    pass


def verify_backup(
    archive: str | Path,
    *,
    requester_passphrase: str,
    approver_passphrase: str,
) -> dict[str, object]:
    with _decrypted_bundle(
        archive,
        requester_passphrase=requester_passphrase,
        approver_passphrase=approver_passphrase,
    ) as bundle:
        manifest = validate_zip(bundle)
        _require_matching_release(manifest)
        return manifest


def restore_backup(
    archive: str | Path,
    *,
    state_dir: str | Path,
    requester_passphrase: str,
    approver_passphrase: str,
    database_url: str | None = None,
    force_sqlite: bool = False,
) -> dict[str, object]:
    target_state = Path(state_dir)
    if target_state.exists() and any(target_state.iterdir()):
        raise BackupRestoreError("Restore state directory must be empty")
    target_state.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(target_state, 0o700)
    staging = Path(tempfile.mkdtemp(prefix=".restore-staging-", dir=target_state))
    try:
        with _decrypted_bundle(
            archive,
            requester_passphrase=requester_passphrase,
            approver_passphrase=approver_passphrase,
        ) as bundle:
            manifest = validate_zip(bundle)
            _require_matching_release(manifest)
            config = _read_json_member(bundle, "runtime/config.json")
            secrets = _read_json_member(bundle, "runtime/secrets.json")
            if not isinstance(config, dict) or not all(
                isinstance(key, str) and isinstance(value, str) for key, value in config.items()
            ):
                raise BackupRestoreError("Backup runtime configuration is invalid")
            if not isinstance(secrets, dict) or not all(
                isinstance(key, str) and isinstance(value, str) for key, value in secrets.items()
            ):
                raise BackupRestoreError("Backup runtime secrets are invalid")

            _stage_files(bundle, manifest, staging)
            effective_database_url = None if force_sqlite else (database_url or secrets.get("MYOWNCA_DATABASE_URL"))
            if effective_database_url:
                target_database = Database(effective_database_url)
                if inspect(target_database._engine).get_table_names():
                    raise BackupRestoreError("Restore database schema must be empty")
                secrets["MYOWNCA_DATABASE_URL"] = effective_database_url
            else:
                database_path = staging / "myownca.sqlite3"
                target_database = Database(database_path)
                secrets.pop("MYOWNCA_DATABASE_URL", None)

            final_config = {str(key): str(value) for key, value in config.items()}
            final_secrets = {str(key): str(value) for key, value in secrets.items()}
            final_config.update(
                {
                    "MYOWNCA_DATABASE_PATH": str(target_state / "myownca.sqlite3"),
                    "MYOWNCA_ONLINE_KEY_DIR": str(target_state / "online-keys"),
                    "MYOWNCA_SERVICE_KEY_DIR": str(target_state / "service-keys"),
                    "MYOWNCA_PKCS11_DKEK_SHARE_DIR": str(target_state / "dkek-shares"),
                }
            )
            write_config(staging, final_config)
            write_secrets(staging, final_secrets)

            restore_logical_database(
                bundle,
                manifest,
                target_database,
                restored_at=datetime.now(timezone.utc),
            )
            _verify_restored_database_and_keys(
                target_database,
                staging,
                final_config,
                final_secrets,
                manifest,
            )
            preflight_audit = AuditService(
                AuditRepository(target_database),
                final_secrets["MYOWNCA_AUTH_ENCRYPTION_SECRET"],
            )
            verification = preflight_audit.verify_chain()
            if not verification["ok"]:
                raise BackupRestoreError("Restored audit chain integrity check failed")
            _move_staged_state(staging, target_state, include_database=not effective_database_url)
            marker_payload = _archived_completion_payload(bundle)
            mark_setup_complete(target_state, marker_payload)

            audit_database = (
                target_database
                if effective_database_url
                else Database(target_state / "myownca.sqlite3")
            )
            audit = AuditService(
                AuditRepository(audit_database),
                final_secrets["MYOWNCA_AUTH_ENCRYPTION_SECRET"],
            )
            audit.record(
                AuditCategory.SYSTEM,
                "application_backup_restored",
                actor=AuditActor.system(),
                object_type="application_backup",
                object_id=str(manifest.get("archive_id") or "unknown"),
                details={
                    "source_version": manifest.get("application_version"),
                    "source_database": manifest.get("database", {}).get("source_dialect"),
                    "target_database": target_database.dialect,
                    "sessions_revoked": True,
                },
            )
            return {
                "archive_id": manifest.get("archive_id"),
                "application_version": manifest.get("application_version"),
                "target_database": target_database.dialect,
                "state_dir": str(target_state),
                "sessions_revoked": True,
                "pending_proposals_preserved": True,
            }
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


class _decrypted_bundle:
    def __init__(self, archive, *, requester_passphrase: str, approver_passphrase: str):
        self.archive = archive
        self.requester_passphrase = requester_passphrase
        self.approver_passphrase = approver_passphrase
        self.path: Path | None = None
        self.bundle: zipfile.ZipFile | None = None

    def __enter__(self) -> zipfile.ZipFile:
        descriptor, name = tempfile.mkstemp(prefix="myownca-restore-", suffix=".zip")
        self.path = Path(name)
        os.chmod(self.path, 0o600)
        try:
            with os.fdopen(descriptor, "w+b") as destination:
                decrypt_archive_to_zip(
                    self.archive,
                    requester_passphrase=self.requester_passphrase,
                    approver_passphrase=self.approver_passphrase,
                    destination=destination,
                )
            self.bundle = zipfile.ZipFile(self.path)
            return self.bundle
        except Exception:
            self.path.unlink(missing_ok=True)
            raise

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self.bundle is not None:
            self.bundle.close()
        if self.path is not None:
            self.path.unlink(missing_ok=True)


def _require_matching_release(manifest: dict[str, object]) -> None:
    if manifest.get("application_version") != __version__:
        raise BackupRestoreError(
            f"Backup requires myOwnCA {manifest.get('application_version')}; running {__version__}"
        )


def _read_json_member(bundle: zipfile.ZipFile, path: str) -> object:
    try:
        info = bundle.getinfo(path)
    except KeyError as exc:
        raise BackupRestoreError(f"Backup member is missing: {path}") from exc
    if info.file_size > _MAX_RUNTIME_JSON_BYTES:
        raise BackupRestoreError(f"Backup member exceeds the safety limit: {path}")
    try:
        return json.loads(bundle.read(path))
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupRestoreError(f"Backup member is invalid: {path}") from exc


def _stage_files(
    bundle: zipfile.ZipFile,
    manifest: dict[str, object],
    staging: Path,
) -> None:
    entries = manifest.get("entries")
    assert isinstance(entries, list)
    seen: set[Path] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        path = str(entry.get("path") or "")
        if not path.startswith("files/"):
            continue
        relative = _restore_relative_path(path)
        if relative == Path("setup/complete"):
            continue
        if relative in seen:
            raise BackupRestoreError("Backup contains duplicate restored file paths")
        seen.add(relative)
        target = staging / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = bundle.getinfo(path)
        if info.file_size > _MAX_LOCAL_FILE_BYTES:
            raise BackupRestoreError(f"Backup local material exceeds the safety limit: {path}")
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _mode_for(relative))
        try:
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                with bundle.open(path) as source:
                    shutil.copyfileobj(source, handle, length=1024 * 1024)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(target, _mode_for(relative))
        finally:
            if descriptor >= 0:
                os.close(descriptor)


def _restore_relative_path(member: str) -> Path:
    if member.startswith("files/online-keys/"):
        return Path("online-keys") / member.removeprefix("files/online-keys/")
    if member.startswith("files/service-keys/"):
        return Path("service-keys") / member.removeprefix("files/service-keys/")
    if member.startswith("files/state/"):
        return Path(member.removeprefix("files/state/"))
    raise BackupRestoreError("Backup contains an unsupported local-material path")


def _mode_for(path: Path) -> int:
    return 0o644 if path.suffix in {".crt", ".json"} and path.name != "state.json" else 0o600


def _archived_completion_payload(bundle: zipfile.ZipFile) -> dict:
    try:
        raw = bundle.read("files/state/setup/complete")
    except KeyError:
        return {"restored": True}
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"restored": True}
    return value if isinstance(value, dict) else {"restored": True}


def _move_staged_state(staging: Path, target: Path, *, include_database: bool) -> None:
    for source in sorted(staging.iterdir(), key=lambda item: item.name):
        if source.name.startswith(".restore-"):
            continue
        if source.name == "myownca.sqlite3" and not include_database:
            continue
        destination = target / source.name
        if destination.exists():
            raise BackupRestoreError(f"Restore target became non-empty: {destination}")
        os.replace(source, destination)
    staging.rmdir()


def _verify_restored_database_and_keys(
    database: Database,
    staging: Path,
    config: dict[str, str],
    secrets: dict[str, str],
    manifest: dict[str, object],
) -> None:
    settings = Settings.from_mapping({**config, **secrets})
    repository = PKIRepository(database)
    root = repository.get_root_certificate_pem()
    active = repository.get_active_sub_ca()
    if root and _fingerprint(root) != manifest.get("root_sha256"):
        raise BackupRestoreError("Restored Root certificate fingerprint does not match")
    if active and _fingerprint(active.certificate_pem) != manifest.get("sub_ca_sha256"):
        raise BackupRestoreError("Restored Issuing Sub CA fingerprint does not match")
    backend = (active.key_backend if active else None) or manifest.get("issuer_backend")
    if active is not None and backend == "software":
        key_path = staging / "online-keys" / f"{active.key_ref}.pem"
        if not key_path.exists():
            raise BackupRestoreError("Restored software Issuing Sub CA key is missing")
        key = serialization.load_pem_private_key(
            key_path.read_bytes(),
            password=(settings.online_key_passphrase or "").encode() or None,
        )
        certificate = x509.load_pem_x509_certificate(active.certificate_pem.encode())
        key_der = key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        cert_der = certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if key_der != cert_der:
            raise BackupRestoreError("Restored software Issuing Sub CA key does not match")


def _fingerprint(pem: str) -> str:
    from cryptography.hazmat.primitives import hashes

    return x509.load_pem_x509_certificate(pem.encode()).fingerprint(hashes.SHA256()).hex().upper()
