from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import InvalidToken

from myownca import __version__
from myownca.backup.archive import (
    SALT_BYTES,
    ChunkEncryptingWriter,
    combine_share_keys,
    create_header,
    derive_share_key,
)
from myownca.backup.database import write_logical_database
from myownca.backup.repository import (
    ApplicationBackupRepository,
    BackupExportStatus,
    BackupProposal,
    proposal_dict,
)
from myownca.config import Settings
from myownca.secret_keys import domain_cipher
from myownca.setup.config_writer import read_config_env, read_secrets
from myownca.storage.database import Database

_PROPOSAL_KEY_DOMAIN = "application-backup-proposals"
_PRIVATE_FILE_MODE = 0o600
_MAX_LOCAL_MATERIAL_BYTES = 64 * 1024 * 1024

_SECRET_SETTINGS = {
    "MYOWNCA_AUTH_ENCRYPTION_SECRET",
    "MYOWNCA_ONLINE_KEY_PASSPHRASE",
    "MYOWNCA_DATABASE_URL",
    "MYOWNCA_AWS_ACCESS_KEY_ID",
    "MYOWNCA_AWS_SECRET_ACCESS_KEY",
    "MYOWNCA_AWS_SESSION_TOKEN",
    "MYOWNCA_AZURE_TENANT_ID",
    "MYOWNCA_AZURE_CLIENT_ID",
    "MYOWNCA_AZURE_CLIENT_SECRET",
}
_EXCLUDED_SECRET_SETTINGS = {
    "MYOWNCA_OFFLINE_KEY_PASSPHRASE",
    "MYOWNCA_SETUP_TOKEN",
    "MYOWNCA_SC_HSM_SHARE_PASSWORD",
    "MYOWNCA_SC_HSM_SO_PIN",
    "MYOWNCA_SC_HSM_USER_PIN",
}
_PATH_SETTINGS = {
    "MYOWNCA_DATABASE_PATH",
    "MYOWNCA_ONLINE_KEY_DIR",
    "MYOWNCA_SERVICE_KEY_DIR",
    "MYOWNCA_PKCS11_DKEK_SHARE_DIR",
}
_PUBLIC_SETTINGS = {
    "MYOWNCA_ACME_AUTORENEW",
    "MYOWNCA_ACME_RENEW_INTERVAL_SECONDS",
    "MYOWNCA_ADMIN_BASE_URL",
    "MYOWNCA_AIA_URL",
    "MYOWNCA_AWS_REGION",
    "MYOWNCA_AZURE_KEY_PROTECTION",
    "MYOWNCA_AZURE_VAULT_URL",
    "MYOWNCA_BIND_HOST",
    "MYOWNCA_BIND_PORT",
    "MYOWNCA_CRL_URL",
    "MYOWNCA_ENTROPY_SOURCE",
    "MYOWNCA_FRONTEND_BASE_URL",
    "MYOWNCA_GOVERNANCE_MODE",
    "MYOWNCA_HSM_BACKEND",
    "MYOWNCA_LAB_COMMON_NAME",
    "MYOWNCA_LAB_MODE",
    "MYOWNCA_OCSP_AUTO",
    "MYOWNCA_OCSP_REFRESH_INTERVAL_SECONDS",
    "MYOWNCA_OCSP_URL",
    "MYOWNCA_PKCS11_LIB",
    "MYOWNCA_PKCS11_TOKEN_LABEL",
    "MYOWNCA_SC_HSM_READER",
    "MYOWNCA_SC_HSM_TOOL",
    "MYOWNCA_SERVICE_KEY_BACKEND",
    "MYOWNCA_SESSION_COOKIE_SECURE",
    "MYOWNCA_SUPERUSER_BASE_URL",
    "MYOWNCA_TLS_CERT",
    "MYOWNCA_TLS_KEY",
    "MYOWNCA_TOTP_REQUIRED_ROLES",
    *_PATH_SETTINGS,
}


class BackupServiceError(RuntimeError):
    pass


class ApplicationBackupService:
    def __init__(
        self,
        *,
        database: Database,
        state_dir: str | Path,
        settings: Settings,
        repository: ApplicationBackupRepository,
        pki_repository,
        backend_name: str,
        online_key_dir: str | Path | None = None,
        service_key_dir: str | Path | None = None,
    ) -> None:
        self.database = database
        self.state_dir = Path(state_dir)
        self.settings = settings
        self.repository = repository
        self.pki_repository = pki_repository
        self.backend_name = backend_name
        self.online_key_dir = Path(online_key_dir or settings.online_key_dir)
        self.service_key_dir = Path(service_key_dir or settings.service_key_dir)
        self.staging_dir = self.state_dir / "backup-exports"
        self._proposal_cipher = domain_cipher(
            settings.auth_encryption_secret, _PROPOSAL_KEY_DOMAIN
        )

    def request_backup(
        self,
        *,
        proposer_id: str,
        proposer_email: str,
        reason: str,
        requester_passphrase: str,
    ) -> BackupProposal:
        salt = os.urandom(SALT_BYTES)
        derived = derive_share_key(requester_passphrase, salt)
        encrypted = self._proposal_cipher.encrypt(derived).decode("ascii")
        return self.repository.create_proposal(
            proposer_id=proposer_id,
            proposer_email=proposer_email,
            reason=reason,
            requester_salt_b64=base64.urlsafe_b64encode(salt).decode("ascii"),
            requester_key_ciphertext=encrypted,
        )

    def approve_and_create(
        self,
        proposal_id: str,
        *,
        approver_id: str,
        approver_email: str,
        reason: str,
        approver_passphrase: str,
    ) -> dict[str, object]:
        proposal = self.repository.get_proposal(proposal_id)
        try:
            requester_key = self._proposal_cipher.decrypt(
                self.repository.requester_key_ciphertext(proposal_id).encode("ascii")
            )
        except (InvalidToken, ValueError) as exc:
            raise BackupServiceError("Stored application backup requester share is invalid") from exc
        try:
            requester_salt = base64.b64decode(
                proposal.requester_salt_b64.encode("ascii"), altchars=b"-_", validate=True
            )
        except Exception as exc:
            raise BackupServiceError("Stored application backup salt is invalid") from exc
        approver_salt = os.urandom(SALT_BYTES)
        approver_key = derive_share_key(approver_passphrase, approver_salt)
        content_key = combine_share_keys(requester_key, approver_key)
        approved = self.repository.approve_and_consume(
            proposal_id,
            approver_id=approver_id,
            approver_email=approver_email,
            reason=reason,
        )
        export_id = str(uuid4())
        filename = (
            "myownca-application-backup-"
            + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            + f"-{export_id[:8]}.myownca-backup"
        )
        self._prepare_staging()
        output_path = self.export_path(export_id)
        try:
            manifest = self._create_archive(
                output_path,
                export_id=export_id,
                proposal=approved,
                requester_salt=requester_salt,
                approver_salt=approver_salt,
                content_key=content_key,
            )
            size = output_path.stat().st_size
            digest = _file_sha256(output_path)
            result = self.repository.add_export(
                export_id=export_id,
                proposal=approved,
                filename=filename,
                database_dialect=self.database.dialect,
                size=size,
                sha256=digest,
            )
            result["download_href"] = f"/internal/admin/backups/exports/{export_id}/download"
            result["manifest_summary"] = {
                "application_version": manifest["application_version"],
                "tables": len(manifest["database"]["tables"]),
                "files": len([entry for entry in manifest["entries"] if entry["path"].startswith("files/")]),
            }
            return result
        except Exception as exc:
            output_path.unlink(missing_ok=True)
            public_error = (
                str(exc)
                if isinstance(exc, BackupServiceError)
                else "Application backup generation failed"
            )
            self.repository.add_failed_export(
                export_id=export_id,
                proposal=approved,
                database_dialect=self.database.dialect,
                error=public_error,
            )
            if isinstance(exc, BackupServiceError):
                raise
            raise BackupServiceError("Application backup generation failed") from exc

    def reject(self, proposal_id: str, *, actor_id: str) -> BackupProposal:
        return self.repository.reject(proposal_id, actor_id=actor_id)

    def status(self, *, current_user_id: str) -> dict[str, object]:
        self.cleanup_expired()
        proposals = self.repository.list_proposals()
        exports = self.repository.list_exports()
        for item in exports:
            item["download_href"] = (
                f"/internal/admin/backups/exports/{item['id']}/download"
                if item["status"] == BackupExportStatus.READY.value
                and item["approver_id"] == current_user_id
                else None
            )
        latest = self.repository.latest_delivered()
        return {
            "database_dialect": self.database.dialect,
            "issuer_backend": self.backend_name,
            "pending": next(
                (proposal_dict(item) for item in proposals if item.status.value == "pending"),
                None,
            ),
            "proposals": [proposal_dict(item) for item in proposals],
            "exports": exports,
            "latest_delivered": latest,
            "active_admin_count": self.repository.active_admin_count(),
            "included": _included_descriptions(self.backend_name),
            "excluded": _excluded_descriptions(),
            "fresh_days": 7,
            "stale_days": 30,
        }

    def export_path(self, export_id: str) -> Path:
        return self.staging_dir / f"{export_id}.myownca-backup"

    def cleanup_expired(self) -> None:
        self._prepare_staging()
        # Listing proposals performs the transactional 24-hour expiry and
        # destroys any pending encrypted requester contribution.
        self.repository.list_proposals()
        for export_id in self.repository.expire_ready():
            self.export_path(export_id).unlink(missing_ok=True)
        known = {str(item["id"]) for item in self.repository.list_exports(limit=200)}
        for path in self.staging_dir.glob("*.myownca-backup"):
            if path.stem not in known:
                path.unlink(missing_ok=True)
        cutoff = datetime.now(timezone.utc).timestamp() - 24 * 60 * 60
        for path in self.staging_dir.glob("database-snapshot-*.sqlite3"):
            if path.stat().st_mtime < cutoff:
                path.unlink(missing_ok=True)

    def _create_archive(
        self,
        output_path: Path,
        *,
        export_id: str,
        proposal: BackupProposal,
        requester_salt: bytes,
        approver_salt: bytes,
        content_key: bytes,
    ) -> dict[str, object]:
        header = create_header(
            requester_salt=requester_salt,
            approver_salt=approver_salt,
        )
        entries: list[dict[str, object]] = []
        files = self._capture_local_files()
        self._validate_software_material(files)
        runtime_config, runtime_secrets = self._runtime_configuration()
        created_at = datetime.now(timezone.utc)
        with output_path.open("xb") as raw_output:
            os.chmod(output_path, _PRIVATE_FILE_MODE)
            encrypted = ChunkEncryptingWriter(raw_output, key=content_key, header=header)
            try:
                with zipfile.ZipFile(
                    encrypted,
                    mode="w",
                    compression=zipfile.ZIP_DEFLATED,
                    compresslevel=9,
                    allowZip64=True,
                ) as bundle:
                    entries.append(_write_json(bundle, "runtime/config.json", runtime_config))
                    entries.append(_write_json(bundle, "runtime/secrets.json", runtime_secrets))
                    for logical_path, data, mode in files:
                        entries.append(_write_bytes(bundle, logical_path, data, mode=mode))
                    database_document, database_entries = write_logical_database(
                        bundle,
                        self.database,
                        staging_dir=self.staging_dir,
                    )
                    entries.extend(database_entries)
                    # Detect any software-key/database binding created while the
                    # logical snapshot was being written. Existing files are
                    # immutable; a missing new binding makes the whole export fail.
                    self._validate_software_material(files)
                    root = self.pki_repository.get_root_certificate_pem()
                    active = self.pki_repository.get_active_sub_ca()
                    manifest: dict[str, object] = {
                        "format_version": 1,
                        "archive_id": export_id,
                        "application_version": __version__,
                        "created_at": created_at.isoformat(),
                        "proposal_id": proposal.id,
                        "requester_id": proposal.proposer_id,
                        "approver_id": proposal.approver_id,
                        "database": database_document,
                        "issuer_backend": self.backend_name,
                        "root_sha256": _certificate_sha256(root) if root else None,
                        "sub_ca_sha256": (
                            _certificate_sha256(active.certificate_pem) if active else None
                        ),
                        "entries": entries,
                        "included": _included_descriptions(self.backend_name),
                        "excluded": _excluded_descriptions(),
                    }
                    bundle.writestr(
                        "manifest.json",
                        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
                    )
            finally:
                encrypted.finish()
                raw_output.flush()
                os.fsync(raw_output.fileno())
        return manifest

    def _capture_local_files(self) -> list[tuple[str, bytes, int]]:
        captured: list[tuple[str, bytes, int]] = []
        if self.backend_name == "software":
            captured.extend(
                _capture_directory(
                    self.online_key_dir,
                    "files/online-keys",
                    suffixes={".pem", ".crt"},
                    validate_private_keys=True,
                    passphrase=self.settings.online_key_passphrase,
                )
            )
        captured.extend(
            _capture_directory(
                self.service_key_dir,
                "files/service-keys",
                suffixes={".pem"},
                validate_private_keys=True,
                passphrase=self.settings.online_key_passphrase,
            )
        )
        for relative in (
            Path("setup/complete"),
            Path("setup/state.json"),
            Path("tls/portal.crt"),
            Path("tls/portal.key"),
            Path("portal.crt"),
            Path("portal.key"),
        ):
            source = self.state_dir / relative
            if source.exists():
                data = _read_stable_regular_file(source)
                mode = 0o600 if source.suffix == ".key" or relative.parts[0] == "setup" else 0o644
                captured.append((f"files/state/{relative.as_posix()}", data, mode))
        return captured

    def _runtime_configuration(self) -> tuple[dict[str, str], dict[str, str]]:
        merged: dict[str, str] = {}
        merged.update(read_config_env(self.state_dir))
        merged.update(read_secrets(self.state_dir))
        merged.update(
            {key: value for key, value in os.environ.items() if key.startswith("MYOWNCA_")}
        )
        config = {key: merged[key] for key in sorted(_PUBLIC_SETTINGS) if key in merged}
        secrets = {key: merged[key] for key in sorted(_SECRET_SETTINGS) if key in merged}
        for excluded in _EXCLUDED_SECRET_SETTINGS:
            secrets.pop(excluded, None)
        configured_backends = {self.backend_name, self.settings.service_key_backend}
        if "aws_kms" not in configured_backends:
            for key in tuple(config):
                if key.startswith("MYOWNCA_AWS_"):
                    config.pop(key)
            for key in tuple(secrets):
                if key.startswith("MYOWNCA_AWS_"):
                    secrets.pop(key)
        if "azure_key_vault" not in configured_backends:
            for key in tuple(config):
                if key.startswith("MYOWNCA_AZURE_"):
                    config.pop(key)
            for key in tuple(secrets):
                if key.startswith("MYOWNCA_AZURE_"):
                    secrets.pop(key)
        return config, secrets

    def _validate_software_material(
        self, captured: list[tuple[str, bytes, int]]
    ) -> None:
        by_path = {path: data for path, data, _mode in captured}
        password = (
            self.settings.online_key_passphrase.encode("utf-8")
            if self.settings.online_key_passphrase
            else None
        )
        active = self.pki_repository.get_active_sub_ca()
        active_backend = (active.key_backend if active is not None else None) or self.backend_name
        if active is not None and active_backend == "software":
            key_path = f"files/online-keys/{active.key_ref}.pem"
            data = by_path.get(key_path)
            if data is None:
                raise BackupServiceError("Active software Issuing Sub CA key is missing")
            _require_key_matches_certificate(data, password, active.certificate_pem, active.key_ref)

        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT key_ref, certificate_pem FROM service_certificates
                WHERE key_backend = 'software' AND status IN ('pending', 'active')
                """
            ).fetchall()
        for row in rows:
            key_ref = str(row["key_ref"])
            data = by_path.get(f"files/service-keys/{key_ref}.pem")
            if data is None:
                raise BackupServiceError(
                    f"Active software service-certificate key is missing: {key_ref}"
                )
            if row["certificate_pem"]:
                _require_key_matches_certificate(
                    data,
                    password,
                    str(row["certificate_pem"]),
                    key_ref,
                )

    def _prepare_staging(self) -> None:
        self.staging_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.staging_dir, 0o700)


def _capture_directory(
    source_dir: Path,
    logical_root: str,
    *,
    suffixes: set[str],
    validate_private_keys: bool,
    passphrase: str | None,
) -> list[tuple[str, bytes, int]]:
    if not source_dir.exists():
        return []
    if not source_dir.is_dir():
        raise BackupServiceError(f"Backup key location is not a directory: {source_dir}")
    captured: list[tuple[str, bytes, int]] = []
    for path in sorted(source_dir.iterdir(), key=lambda item: item.name):
        if path.suffix not in suffixes:
            continue
        data = _read_stable_regular_file(path)
        if validate_private_keys and path.suffix == ".pem":
            try:
                serialization.load_pem_private_key(
                    data,
                    password=passphrase.encode("utf-8") if passphrase else None,
                )
            except Exception as exc:
                raise BackupServiceError(f"Software private key is unreadable: {path.name}") from exc
        mode = 0o600 if path.suffix == ".pem" else 0o644
        captured.append((f"{logical_root}/{path.name}", data, mode))
    return captured


def _read_stable_regular_file(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BackupServiceError(
            f"Backup material must be a readable non-symlink file: {path}"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise BackupServiceError(f"Backup material must be a regular file: {path}")
        if before.st_size > _MAX_LOCAL_MATERIAL_BYTES:
            raise BackupServiceError(f"Backup material exceeds the safety limit: {path}")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            data = handle.read()
            after = os.fstat(handle.fileno())
        current = path.lstat()
        if (
            before.st_ino != after.st_ino
            or before.st_ino != current.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or len(data) != before.st_size
        ):
            raise BackupServiceError(f"Backup material changed during capture: {path}")
        return data
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _write_json(bundle: zipfile.ZipFile, path: str, value: object) -> dict[str, object]:
    return _write_bytes(
        bundle,
        path,
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        mode=0o600,
    )


def _write_bytes(
    bundle: zipfile.ZipFile, path: str, data: bytes, *, mode: int
) -> dict[str, object]:
    info = zipfile.ZipInfo(path)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (mode & 0xFFFF) << 16
    bundle.writestr(info, data)
    return {"path": path, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _certificate_sha256(pem: str) -> str:
    certificate = x509.load_pem_x509_certificate(pem.encode("utf-8"))
    return certificate.fingerprint(hashlib_to_cryptography_sha256()).hex().upper()


def _require_key_matches_certificate(
    private_key_pem: bytes,
    password: bytes | None,
    certificate_pem: str,
    label: str,
) -> None:
    try:
        key = serialization.load_pem_private_key(private_key_pem, password=password)
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))
    except Exception as exc:
        raise BackupServiceError(f"Could not validate software key material: {label}") from exc
    encoding = serialization.Encoding.DER
    public_format = serialization.PublicFormat.SubjectPublicKeyInfo
    if key.public_key().public_bytes(encoding, public_format) != certificate.public_key().public_bytes(
        encoding, public_format
    ):
        raise BackupServiceError(f"Software key does not match its certificate: {label}")


def hashlib_to_cryptography_sha256():
    from cryptography.hazmat.primitives import hashes

    return hashes.SHA256()


def _included_descriptions(backend_name: str) -> list[str]:
    included = [
        "Every application database table and row",
        "Portable runtime configuration and required local encryption secrets",
        "Local software service-certificate keys and managed portal TLS material",
        "Cloud provider configuration and credentials when configured",
    ]
    if backend_name == "software":
        included.append("Software Issuing Sub CA private-key material")
    return included


def _excluded_descriptions() -> list[str]:
    return [
        "SmartCard-HSM private keys, DKEK shares, wrapped-key exports, PINs, and passwords",
        "AWS KMS and Azure Key Vault private-key material",
        "Offline Root private material and offline-key passphrases",
        "Setup tokens and operator-managed TLS files outside the state directory",
    ]
