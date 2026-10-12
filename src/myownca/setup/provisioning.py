from __future__ import annotations

import base64
import binascii
import re
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from myownca.audit import AuditActor, AuditCategory, AuditRepository, AuditService
from myownca.ca_hsm import HSMPinVault, create_hsm
from myownca.ca_hsm.base import (
    ImportableKeyBackend,
    KeyImportError,
    imported_key_algorithm,
    public_keys_match,
    validate_imported_key,
    verify_backend_key,
)
from myownca.ca_hsm.recovery import (
    HSMKeyRecoveryService,
    KeyRecoveryRollbackError,
)
from myownca.ca_hsm.scctl import MAX_WRAPPED_KEY_BYTES, ScHsmCtl
from myownca.ca_main.crypto import (
    certificate_to_pem,
    create_lab_ca_chain,
    create_lab_ca_chain_from_existing_keys,
)
from myownca.ca_main.crl_import import (
    CRLImportAnalysis,
    CRLImportError,
    analyze_crl_migration,
)
from myownca.ca_main.imports import parse_bundle
from myownca.ca_main.service import CAMainService
from myownca.cloud import (
    CloudKeyOwnership,
    CloudKeyRepository,
    CloudKeyStatus,
)
from myownca.config import Settings
from myownca.domain import CertificateProfile, IssuerCRL, SubCA
from myownca.key_lifecycle import (
    KeyLifecycleRepository,
    KeyLifecycleService,
    KeyOwnership,
    KeyStatus,
)
from myownca.online.ceremony import OnlineCeremonyService, _validate_sub_ca_chain
from myownca.setup.state import is_setup_complete, load_setup_state, save_setup_state
from myownca.setup.startup import require_existing_database
from myownca.storage.database import Database
from myownca.storage.repositories import PKIRepository, RepositoryError

MAX_IMPORT_BYTES = 5 * 1024 * 1024
_ALGORITHMS = {
    "ecdsa-p256",
    "ecdsa-p384",
    "ecdsa-p521",
    "rsa-2048",
    "rsa-3072",
    "rsa-4096",
}
_SETUP_ACTOR = AuditActor(id="bootstrap/setup", role="setup")
_LEGACY_PATH_LENGTH_WARNING = (
    "Legacy compatibility: BasicConstraints pathLength is absent. This existing Sub CA is "
    "accepted, but its certificate does not enforce a zero CA path length."
)


def _legacy_path_length_missing(certificate: x509.Certificate) -> bool:
    try:
        constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except x509.ExtensionNotFound:
        return False
    return bool(constraints.ca and constraints.path_length is None)


def _legacy_path_length_audit_detail(certificate: x509.Certificate) -> dict[str, bool]:
    return {"legacy_path_length_missing": True} if _legacy_path_length_missing(certificate) else {}


class SetupProvisioningError(ValueError):
    """Safe, user-presentable failure during first-issuer provisioning."""


class SetupProvisioningService:
    """Provision the one immutable online issuer before the service starts."""

    def __init__(
        self,
        state_dir: str | Path,
        *,
        user_pin: str | None = None,
        scctl: ScHsmCtl | None = None,
    ) -> None:
        self.state_dir = Path(state_dir)
        # Provisioning must always target the files just materialized by this
        # setup session.  Inherited MYOWNCA_* values may describe an older
        # service instance and must not redirect bootstrap keys or the DB.
        settings = Settings.load(self.state_dir, environ={})
        self.settings = replace(
            settings,
            database_path=(
                self.state_dir / "myownca.sqlite3"
                if settings.database_path == Path("var/myownca.sqlite3")
                else settings.database_path
            ),
            online_key_dir=(
                self.state_dir / "online-keys"
                if settings.online_key_dir == Path("var/online-keys")
                else settings.online_key_dir
            ),
            pkcs11_dkek_share_dir=(
                self.state_dir / "dkek-shares"
                if settings.pkcs11_dkek_share_dir == Path("var/dkek-shares")
                else settings.pkcs11_dkek_share_dir
            ),
        )
        target: str | Path = (
            self.settings.database_url
            or self.settings.database_path
            or self.state_dir / "myownca.sqlite3"
        )
        if is_setup_complete(self.state_dir):
            require_existing_database(target)
        self.database = Database(target)
        self.database.migrate()
        self.repository = PKIRepository(self.database)
        self.pin_vault = HSMPinVault()
        self.backend, self.backend_name = create_hsm(
            self.settings,
            pin_vault=self.pin_vault,
            key_dir=self.settings.online_key_dir,
            pkcs11_pin_provider=((lambda pin=user_pin: pin) if user_pin is not None else None),
        )
        self.ceremony = OnlineCeremonyService(
            self.repository,
            self.backend,
        )
        self.audit = AuditService(
            AuditRepository(self.database),
            self.settings.auth_encryption_secret,
        )
        self.cloud_keys = CloudKeyRepository(self.database)
        self.key_lifecycle_repository = KeyLifecycleRepository(self.database)
        self.key_lifecycle = KeyLifecycleService(self.key_lifecycle_repository)
        self.scctl = scctl or ScHsmCtl(
            self.settings.sc_hsm_tool_path,
            self.settings.sc_hsm_reader,
        )
        self.hsm_recovery = HSMKeyRecoveryService(self.backend, self.scctl)
        self.user_pin = user_pin

    # -- status and shared validation -------------------------------------

    def status(self) -> dict[str, object]:
        active = self.repository.get_active_sub_ca()
        pending = self.repository.list_pending_sub_cas()
        state = load_setup_state(self.state_dir)
        result: dict[str, object] = {
            "configured": active is not None,
            "locked": bool(state.data.get("issuer_locked")),
            "backend": self.backend_name,
            "pending": [
                {
                    "id": item.id,
                    "subject": item.subject,
                    "csr_pem": item.csr_pem,
                    "created_at": item.created_at.isoformat(),
                    "algorithm": self._algorithm_for_key(item.key_ref),
                    "allowed_profiles": [profile.value for profile in item.allowed_profiles],
                }
                for item in pending
            ],
        }
        if active is not None:
            certificate = x509.load_pem_x509_certificate(active.certificate_pem.encode())
            issuer_fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
            latest_crl = self.repository.get_latest_issuer_crl(
                active.subject,
                issuer_fingerprint,
            )
            result["issuer"] = {
                "id": active.id,
                "subject": active.subject,
                "issuer": certificate.issuer.rfc4514_string(),
                "not_before": certificate.not_valid_before_utc.isoformat(),
                "not_after": certificate.not_valid_after_utc.isoformat(),
                "certificate_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
                "key_ref": active.key_ref,
                "key_backend": active.key_backend,
                "token_label": active.token_label,
                "allowed_profiles": [profile.value for profile in active.allowed_profiles],
                "crl": (
                    {
                        "number": latest_crl.number,
                        "source": latest_crl.source,
                        "this_update": (
                            latest_crl.this_update.isoformat() if latest_crl.this_update else None
                        ),
                        "next_update": (
                            latest_crl.next_update.isoformat() if latest_crl.next_update else None
                        ),
                    }
                    if latest_crl is not None
                    else None
                ),
            }
        return result

    def assert_finalizable(self) -> dict[str, object]:
        """Verify the trust chain and live access to its private key."""

        active = self.repository.get_active_sub_ca()
        if active is None:
            raise SetupProvisioningError(
                "Provision and activate the issuing Sub CA before finalizing"
            )
        if len(self.repository.list_sub_cas()) != 1:
            raise SetupProvisioningError("First-run setup requires exactly one persisted Sub CA")
        if self.repository.list_pending_sub_cas():
            raise SetupProvisioningError(
                "Complete or reset the pending Sub CA request before finalizing"
            )
        if active.key_backend and active.key_backend != self.backend_name:
            raise SetupProvisioningError(
                "The active Sub CA key backend does not match setup configuration"
            )
        profiles = self._profiles(active.allowed_profiles)
        certificate, _ = self._validate_material(
            active.certificate_pem,
            profiles,
            allow_legacy_missing_path_length=True,
        )
        try:
            verify_backend_key(self.backend, active.key_ref, certificate)
        except Exception as exc:  # noqa: BLE001
            raise SetupProvisioningError(
                "The active Sub CA private key is not accessible or does not match its certificate"
            ) from exc
        state = load_setup_state(self.state_dir)
        if state.data.get("crl_migration_required"):
            issuer_id = certificate.fingerprint(hashes.SHA256()).hex()
            latest_crl = self.repository.get_latest_issuer_crl(
                active.subject,
                issuer_id,
            )
            if latest_crl is None or latest_crl.source != "local":
                raise SetupProvisioningError(
                    "The imported Sub CA requires a signed and persisted local CRL"
                )
        return self.status()

    def _algorithm_for_key(self, key_ref: str) -> str | None:
        try:
            from myownca.ca_hsm.base import imported_key_algorithm

            return imported_key_algorithm(self.backend.public_key(key_ref))
        except Exception:  # noqa: BLE001 - status must remain readable while HSM is locked
            return None

    def _root_pem(self) -> str:
        state = load_setup_state(self.state_dir)
        value = state.data.get("root_certificate")
        if not isinstance(value, str) or not value.strip():
            value = self.repository.get_root_certificate_pem()
        if not isinstance(value, str) or not value.strip():
            raise SetupProvisioningError(
                "Import the Root CA certificate before provisioning the issuer"
            )
        return value.strip() + "\n"

    def _require_empty(self, *, allow_pending: bool = False) -> None:
        if self.repository.get_active_sub_ca() is not None:
            raise SetupProvisioningError(
                "An active Sub CA is already configured; first-run setup permits exactly one"
            )
        issuer_status = load_setup_state(self.state_dir).data.get("issuer_status")
        if isinstance(issuer_status, dict) and issuer_status.get("status") == "cleanup_required":
            raise SetupProvisioningError(
                "Issuer cleanup is incomplete; use Reset issuer step before continuing"
            )
        if not allow_pending and self.repository.list_pending_sub_cas():
            raise SetupProvisioningError(
                "A Sub CA request is already pending; reset the issuer step first"
            )

    @staticmethod
    def _profiles(values: list[CertificateProfile] | tuple[CertificateProfile, ...]):
        profiles = tuple(CertificateProfile(value) for value in values)
        if not profiles:
            raise SetupProvisioningError(
                "An issuing Sub CA must allow at least one certificate profile"
            )
        if len(set(profiles)) != len(profiles):
            raise SetupProvisioningError("Certificate profiles must not contain duplicates")
        return profiles

    def _validate_material(
        self,
        certificate_pem: str,
        profiles: tuple[CertificateProfile, ...],
        *,
        allow_legacy_missing_path_length: bool = False,
    ) -> tuple[x509.Certificate, x509.Certificate]:
        if not profiles:
            raise SetupProvisioningError(
                "An issuing Sub CA must allow at least one certificate profile"
            )
        try:
            certificate = x509.load_pem_x509_certificate(certificate_pem.encode())
            root = x509.load_pem_x509_certificate(self._root_pem().encode())
            from datetime import datetime, timezone

            _validate_sub_ca_chain(
                certificate,
                root,
                now=datetime.now(timezone.utc),
                allow_legacy_missing_path_length=allow_legacy_missing_path_length,
            )
        except ValueError as exc:
            raise SetupProvisioningError(str(exc)) from exc
        return certificate, root

    @staticmethod
    def _analysis(
        *,
        method: str,
        certificate: x509.Certificate,
        root: x509.Certificate,
        algorithm: str,
        key_ref: str,
        backend: str,
        profiles: tuple[CertificateProfile, ...],
        source_format: str | None = None,
        crl_analysis: CRLImportAnalysis | None = None,
    ) -> dict[str, object]:
        result: dict[str, object] = {
            "method": method,
            "subject": certificate.subject.rfc4514_string(),
            "issuer": certificate.issuer.rfc4514_string(),
            "root_subject": root.subject.rfc4514_string(),
            "algorithm": algorithm,
            "key_ref": key_ref,
            "backend": backend,
            "not_before": certificate.not_valid_before_utc.isoformat(),
            "not_after": certificate.not_valid_after_utc.isoformat(),
            "certificate_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
            "root_sha256": root.fingerprint(hashes.SHA256()).hex(),
            "allowed_profiles": [profile.value for profile in profiles],
        }
        if _legacy_path_length_missing(certificate):
            result["legacy_path_length_missing"] = True
            result["warnings"] = [_LEGACY_PATH_LENGTH_WARNING]
        if source_format:
            result["source_format"] = source_format
        if crl_analysis is not None:
            result["crl_migration"] = crl_analysis.to_dict()
        return result

    @staticmethod
    def _analyze_crl(
        certificate: x509.Certificate,
        *,
        prior_crl_state: str,
        crl_b64: str | None,
    ) -> CRLImportAnalysis:
        try:
            return analyze_crl_migration(
                certificate,
                prior_crl_state=prior_crl_state,
                crl_b64=crl_b64,
            )
        except CRLImportError as exc:
            raise SetupProvisioningError(str(exc)) from exc

    def _adopt_crl_migration(
        self,
        sub_ca: SubCA,
        certificate: x509.Certificate,
        analysis: CRLImportAnalysis,
    ) -> IssuerCRL:
        issuer_id = certificate.fingerprint(hashes.SHA256()).hex()
        if analysis.crl is not None:
            assert analysis.crl_pem is not None
            assert analysis.sha256 is not None
            self.repository.import_issuer_crl(
                IssuerCRL(
                    issuer_subject=sub_ca.subject,
                    number=analysis.number,
                    crl_pem=analysis.crl_pem,
                    generated_at=analysis.this_update or datetime.now(timezone.utc),
                    issuer_id=issuer_id,
                    this_update=analysis.this_update,
                    next_update=analysis.next_update,
                    source="imported",
                    sha256=analysis.sha256,
                ),
                analysis.revocations,
            )
        issuer = self.ceremony.issuer_material(sub_ca.id)
        local_crl = CAMainService(self.repository, self.backend).generate_crl(
            issuer,
            crl_number=analysis.number + 1,
        )
        if local_crl.source != "local":
            raise SetupProvisioningError("The first local CRL was not persisted")
        return local_crl

    def _mark_crl_migration_required(self) -> None:
        state = load_setup_state(self.state_dir)
        state.data["crl_migration_required"] = True
        save_setup_state(self.state_dir, state)

    def _clear_crl_migration_requirement(self) -> None:
        state = load_setup_state(self.state_dir)
        state.data.pop("crl_migration_required", None)
        save_setup_state(self.state_dir, state)

    def _remember(
        self,
        *,
        status: str,
        keys: list[dict[str, str]],
        sub_ca_id: str | None = None,
        pending_id: str | None = None,
        subject: str | None = None,
    ) -> None:
        state = load_setup_state(self.state_dir)
        state.data["issuer_locked"] = True
        state.data["issuer_keys"] = keys
        state.data["issuer_status"] = {
            "status": status,
            "sub_ca_id": sub_ca_id,
            "pending_id": pending_id,
            "subject": subject,
            "backend": self.backend_name,
        }
        state.steps["issuer"] = "done" if status == "active" else "pending"
        save_setup_state(self.state_dir, state)

    def _register_key(
        self,
        *,
        key_ref: str,
        ownership: KeyOwnership,
        resource_type: str,
        resource_id: str,
        purpose: str = "sub_ca",
    ) -> str:
        registered = self.key_lifecycle_repository.find(
            backend=self.backend_name,
            key_ref=key_ref,
        )
        if registered is None:
            registered = self.key_lifecycle.register_key(
                backend=self.backend_name,
                key_ref=key_ref,
                purpose=purpose,
                ownership=ownership,
            )
        elif registered.terminal:
            registered = self.key_lifecycle.reactivate_initial_setup_key(
                registered.id,
                purpose=purpose,
                ownership=ownership,
            )
        elif registered.ownership is not ownership:
            raise SetupProvisioningError(
                "The selected key is already registered with different ownership"
            )
        self.key_lifecycle.bind_key(
            registered.id,
            resource_type=resource_type,
            resource_id=resource_id,
        )
        return registered.id

    def _promote_key_binding(
        self,
        *,
        key_ref: str,
        pending_id: str,
        sub_ca_id: str,
    ) -> KeyOwnership:
        registered = self.key_lifecycle_repository.find(
            backend=self.backend_name,
            key_ref=key_ref,
        )
        if registered is None:
            self._register_key(
                key_ref=key_ref,
                ownership=KeyOwnership.MANAGED,
                resource_type="sub_ca",
                resource_id=sub_ca_id,
            )
            return KeyOwnership.MANAGED
        self.key_lifecycle.bind_key(
            registered.id,
            resource_type="sub_ca",
            resource_id=sub_ca_id,
        )
        self.key_lifecycle.unbind_key(
            registered.id,
            resource_type="pending_sub_ca",
            resource_id=pending_id,
        )
        return registered.ownership

    def _register_cloud_key(
        self,
        *,
        key_ref: str,
        algorithm: str,
        ownership: KeyOwnership,
        label: str,
    ) -> None:
        if self.backend_name not in {"aws_kms", "azure_key_vault"}:
            return
        cloud_ownership = (
            CloudKeyOwnership.MANAGED
            if ownership is KeyOwnership.MANAGED
            else CloudKeyOwnership.ATTACHED
        )
        existing = self.cloud_keys.find(
            provider=self.backend_name,
            key_ref=key_ref,
        )
        if existing is not None:
            if existing.algorithm != algorithm:
                raise SetupProvisioningError(
                    "Registered cloud key algorithm does not match the issuer key"
                )
            if existing.ownership is not cloud_ownership:
                raise SetupProvisioningError(
                    "Registered cloud key ownership does not match this setup operation"
                )
            if existing.status is not CloudKeyStatus.ACTIVE:
                self.cloud_keys.set_status(existing.id, CloudKeyStatus.ACTIVE)
            return
        self.cloud_keys.register(
            provider=self.backend_name,
            key_ref=key_ref,
            algorithm=algorithm,
            purpose="subca",
            ownership=cloud_ownership,
            label=label,
            protection=(
                self.settings.azure_key_protection
                if self.backend_name == "azure_key_vault"
                else None
            ),
        )

    def _mark_cloud_key_reset(
        self,
        *,
        key_ref: str,
        ownership: KeyOwnership,
    ) -> None:
        if self.backend_name not in {"aws_kms", "azure_key_vault"}:
            return
        registered = self.cloud_keys.find(
            provider=self.backend_name,
            key_ref=key_ref,
        )
        if registered is None:
            return
        status = (
            CloudKeyStatus.PENDING_DELETION
            if ownership is KeyOwnership.MANAGED
            else CloudKeyStatus.DELETED
        )
        self.cloud_keys.set_status(registered.id, status)

    def _audit(self, action: str, *, object_id: str, details: dict[str, object]) -> None:
        self.audit.record(
            AuditCategory.ISSUER,
            action,
            actor=_SETUP_ACTOR,
            object_type="issuer",
            object_id=object_id,
            details=details,
        )

    def _rollback_failed_provisioning(
        self,
        keys: list[dict[str, str]],
        *,
        delete_managed_keys: bool = True,
    ) -> bool:
        """Synchronously clean a failed pre-launch operation when it is safe.

        Returning ``False`` means that at least one managed key could not be
        proven deleted.  In that case the issuer step stays locked and retains
        only the unresolved key metadata so an explicit reset can retry safely.
        Attached provider keys are never deleted.
        """

        unresolved: list[dict[str, str]] = []
        for item in keys:
            key_ref = item["key_ref"]
            ownership = KeyOwnership(item["ownership"])
            registered = self.key_lifecycle_repository.find(
                backend=item["backend"],
                key_ref=key_ref,
            )
            if ownership is KeyOwnership.MANAGED and delete_managed_keys:
                deleter = getattr(self.backend, "delete_key", None)
                if not callable(deleter):
                    unresolved.append(item)
                    continue
                try:
                    deleter(key_ref)
                except Exception:  # noqa: BLE001 - retry must use explicit reset
                    unresolved.append(item)
                    continue
            if registered is not None and not registered.terminal:
                try:
                    self.key_lifecycle.complete_initial_setup_reset(registered.id)
                except Exception:  # noqa: BLE001 - retain metadata for safe retry
                    unresolved.append(item)
                    continue
            try:
                self._mark_cloud_key_reset(
                    key_ref=key_ref,
                    ownership=ownership,
                )
            except Exception:  # noqa: BLE001 - keep provider metadata retryable
                unresolved.append(item)

        if unresolved:
            if not delete_managed_keys:
                unresolved = [{**item, "hsm_deleted": "true"} for item in unresolved]
            self._remember(status="cleanup_required", keys=unresolved)
            return False
        try:
            self.repository.reset_initial_ca_provisioning()
        except RepositoryError:
            retained = (
                keys if delete_managed_keys else [{**item, "hsm_deleted": "true"} for item in keys]
            )
            self._remember(status="cleanup_required", keys=retained)
            return False
        self._clear_crl_migration_requirement()
        return True

    # -- new issuer / offline ceremony ------------------------------------

    def create_request(
        self,
        *,
        common_name: str,
        allowed_profiles: list[CertificateProfile],
        algorithm: str,
        existing_key_ref: str | None = None,
        reason: str = "",
    ) -> dict[str, object]:
        self._require_empty()
        profiles = self._profiles(allowed_profiles)
        request_mode = self._pkcs11_request_mode()
        if existing_key_ref is not None:
            if request_mode != "existing":
                raise SetupProvisioningError(
                    "An existing key may only be selected for an adopted prepared HSM"
                )
            key_ref, algorithm = self._existing_request_key(existing_key_ref)
            ownership = KeyOwnership.ATTACHED
        else:
            if algorithm not in _ALGORITHMS:
                raise SetupProvisioningError("Unsupported Sub CA key algorithm")
            key_ref = None
            ownership = KeyOwnership.MANAGED
        pending_id = str(uuid4())
        key_metadata: list[dict[str, str]] = []
        try:
            if ownership is KeyOwnership.MANAGED:
                key_ref = self.backend.generate_key(
                    f"subca-{pending_id.replace('-', '')}",
                    algorithm,
                )
            assert key_ref is not None
            key_metadata = [
                {
                    "backend": self.backend_name,
                    "key_ref": key_ref,
                    "ownership": ownership.value,
                }
            ]
            self._register_key(
                key_ref=key_ref,
                ownership=ownership,
                resource_type="pending_sub_ca",
                resource_id=pending_id,
            )
            self._register_cloud_key(
                key_ref=key_ref,
                algorithm=algorithm,
                ownership=ownership,
                label=pending_id,
            )
            pending = self.ceremony.create_sub_ca_request(
                common_name=common_name.strip(),
                allowed_profiles=profiles,
                algorithm=algorithm,
                prepared_key_ref=(
                    key_ref if ownership is KeyOwnership.MANAGED else None
                ),
                existing_key_ref=(
                    key_ref if ownership is KeyOwnership.ATTACHED else None
                ),
                key_backend=self.backend_name,
                token_label=(
                    self.settings.pkcs11_token_label if self.backend_name == "pkcs11" else None
                ),
                pending_id=pending_id,
            )
        except Exception as exc:  # noqa: BLE001 - normalize provider/backend errors
            cleanup_complete = (
                self._rollback_failed_provisioning(key_metadata) if key_metadata else True
            )
            if not cleanup_complete:
                raise SetupProvisioningError(
                    "Sub CA request creation failed and key cleanup "
                    "requires Reset issuer step"
                ) from exc
            raise SetupProvisioningError(str(exc)) from exc
        self._remember(
            status="pending",
            pending_id=pending.id,
            subject=pending.subject,
            keys=[
                {
                    "backend": self.backend_name,
                    "key_ref": pending.key_ref,
                    "ownership": ownership.value,
                }
            ],
        )
        self._audit(
            "setup_subca_request_create",
            object_id=pending.id,
            details={
                "subject": pending.subject,
                "backend": self.backend_name,
                "algorithm": algorithm,
                "ownership": ownership.value,
                "reason": reason,
            },
        )
        return {
            "pending_id": pending.id,
            "subject": pending.subject,
            "csr_pem": pending.csr_pem,
            "backend": self.backend_name,
            "key_ref": pending.key_ref,
            "ownership": ownership.value,
            "algorithm": algorithm,
            "allowed_profiles": [profile.value for profile in pending.allowed_profiles],
        }

    def _pkcs11_request_mode(self) -> str:
        if self.backend_name != "pkcs11":
            return "initialized"
        state = load_setup_state(self.state_dir)
        marker = state.data.get("pkcs11_hsm_ready")
        mode = marker.get("mode") if isinstance(marker, dict) else None
        if mode not in {"existing", "initialized"}:
            raise SetupProvisioningError(
                "Initialize or adopt the current HSM before creating the Sub CA request"
            )
        return str(mode)

    def _existing_request_key(self, key_ref: str | None) -> tuple[str, str]:
        normalized_ref = str(key_ref or "").strip()
        if not normalized_ref:
            raise SetupProvisioningError(
                "Select an existing key from the adopted prepared HSM"
            )
        try:
            inventory = self.backend.list_keys()
            matches = [
                item
                for item in inventory
                if str(item.get("key_ref") or item.get("label") or "") == normalized_ref
            ]
            if not matches:
                raise SetupProvisioningError(
                    "The selected key is no longer present on the adopted HSM"
                )
            if len(matches) != 1:
                raise SetupProvisioningError(
                    "The selected HSM key label is ambiguous"
                )
            algorithm = imported_key_algorithm(self.backend.public_key(normalized_ref))
        except SetupProvisioningError:
            raise
        except (KeyError, RuntimeError, ValueError) as exc:
            raise SetupProvisioningError(str(exc)) from exc
        if algorithm not in _ALGORITHMS:
            raise SetupProvisioningError(
                "The selected HSM key uses an unsupported Sub CA algorithm"
            )
        return normalized_ref, algorithm

    def import_response(
        self,
        *,
        certificate_pem: str,
        reason: str = "",
    ) -> dict[str, object]:
        self._require_empty(allow_pending=True)
        pending = self.repository.list_pending_sub_cas()
        if len(pending) != 1:
            raise SetupProvisioningError("Exactly one pending Sub CA request is required")
        try:
            sub_ca = self.ceremony.import_sub_ca_certificate(
                certificate_pem.strip(),
                root_certificate_pem=self._root_pem(),
                pending_id=pending[0].id,
                activate=True,
            )
            ownership = self._promote_key_binding(
                key_ref=sub_ca.key_ref,
                pending_id=pending[0].id,
                sub_ca_id=sub_ca.id,
            )
        except Exception as exc:  # noqa: BLE001 - safe ceremony messages
            raise SetupProvisioningError(str(exc)) from exc
        self._remember(
            status="active",
            sub_ca_id=sub_ca.id,
            subject=sub_ca.subject,
            keys=[
                {
                    "backend": self.backend_name,
                    "key_ref": sub_ca.key_ref,
                    "ownership": ownership.value,
                }
            ],
        )
        self._audit(
            "setup_subca_response_import",
            object_id=sub_ca.id,
            details={
                "subject": sub_ca.subject,
                "backend": self.backend_name,
                "ownership": ownership.value,
                "reason": reason,
            },
        )
        return self.status()

    # -- existing key ------------------------------------------------------

    def analyze_existing_key(
        self,
        *,
        key_ref: str,
        certificate_pem: str,
        allowed_profiles: list[CertificateProfile],
        algorithm: str,
        prior_crl_state: str,
        crl_b64: str | None,
    ) -> dict[str, object]:
        self._require_empty()
        profiles = self._profiles(allowed_profiles)
        certificate, root = self._validate_material(
            certificate_pem,
            profiles,
            allow_legacy_missing_path_length=True,
        )
        normalized_ref = key_ref.strip()
        if not normalized_ref:
            raise SetupProvisioningError("Provide the existing key reference")
        try:
            attach = getattr(self.backend, "attach_key", None)
            if self.backend_name in {"aws_kms", "azure_key_vault"}:
                if not callable(attach):
                    raise SetupProvisioningError(
                        "The selected cloud backend cannot attach an existing key"
                    )
                normalized_ref = attach(
                    normalized_ref,
                    expected_algorithm=algorithm,
                )
            verification = verify_backend_key(
                self.backend,
                normalized_ref,
                certificate,
            )
        except KeyError as exc:
            raise SetupProvisioningError(
                "The selected key reference does not exist"
            ) from exc
        except (KeyImportError, RuntimeError, ValueError) as exc:
            raise SetupProvisioningError(str(exc)) from exc
        if verification.algorithm != algorithm:
            raise SetupProvisioningError(
                "Selected key algorithm does not match the requested algorithm"
            )
        crl_analysis = self._analyze_crl(
            certificate,
            prior_crl_state=prior_crl_state,
            crl_b64=crl_b64,
        )
        return self._analysis(
            method="existing_key",
            certificate=certificate,
            root=root,
            algorithm=verification.algorithm,
            key_ref=normalized_ref,
            backend=self.backend_name,
            profiles=profiles,
            crl_analysis=crl_analysis,
        )

    def commit_existing_key(
        self,
        *,
        key_ref: str,
        certificate_pem: str,
        allowed_profiles: list[CertificateProfile],
        algorithm: str,
        prior_crl_state: str,
        crl_b64: str | None,
        reason: str = "",
    ) -> dict[str, object]:
        analysis = self.analyze_existing_key(
            key_ref=key_ref,
            certificate_pem=certificate_pem,
            allowed_profiles=allowed_profiles,
            algorithm=algorithm,
            prior_crl_state=prior_crl_state,
            crl_b64=crl_b64,
        )
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode())
        crl_analysis = self._analyze_crl(
            certificate,
            prior_crl_state=prior_crl_state,
            crl_b64=crl_b64,
        )
        profiles = self._profiles(allowed_profiles)
        sub_ca_id = str(uuid4())
        key_metadata = [
            {
                "backend": self.backend_name,
                "key_ref": str(analysis["key_ref"]),
                "ownership": KeyOwnership.ATTACHED.value,
            }
        ]
        try:
            self._register_key(
                key_ref=str(analysis["key_ref"]),
                ownership=KeyOwnership.ATTACHED,
                resource_type="sub_ca",
                resource_id=sub_ca_id,
            )
            self._register_cloud_key(
                key_ref=str(analysis["key_ref"]),
                algorithm=str(analysis["algorithm"]),
                ownership=KeyOwnership.ATTACHED,
                label=sub_ca_id,
            )
            sub_ca = self.ceremony.import_existing_sub_ca(
                certificate_pem=certificate_pem,
                root_certificate_pem=self._root_pem(),
                key_ref=str(analysis["key_ref"]),
                allowed_profiles=profiles,
                activate=True,
                backend=self.backend,
                key_backend=self.backend_name,
                token_label=(
                    self.settings.pkcs11_token_label if self.backend_name == "pkcs11" else None
                ),
                sub_ca_id=sub_ca_id,
            )
            self._mark_crl_migration_required()
            local_crl = self._adopt_crl_migration(
                sub_ca,
                certificate,
                crl_analysis,
            )
        except Exception as exc:  # noqa: BLE001
            cleanup_complete = self._rollback_failed_provisioning(key_metadata)
            if not cleanup_complete:
                raise SetupProvisioningError(
                    "Existing-key attachment failed and its setup binding "
                    "requires Reset issuer step"
                ) from exc
            raise SetupProvisioningError(str(exc)) from exc
        self._remember(
            status="active",
            sub_ca_id=sub_ca.id,
            subject=sub_ca.subject,
            keys=[
                {
                    "backend": self.backend_name,
                    "key_ref": sub_ca.key_ref,
                    "ownership": KeyOwnership.ATTACHED.value,
                }
            ],
        )
        self._audit(
            "setup_subca_existing_key_import",
            object_id=sub_ca.id,
            details={
                "subject": sub_ca.subject,
                "backend": self.backend_name,
                "ownership": KeyOwnership.ATTACHED.value,
                "imported_crl_number": (
                    crl_analysis.number if crl_analysis.crl is not None else None
                ),
                "local_crl_number": local_crl.number,
                "migrated_revocations": len(crl_analysis.revocations),
                **_legacy_path_length_audit_detail(certificate),
                "reason": reason,
            },
        )
        return self.status()

    # -- P12 / PEM ---------------------------------------------------------

    def _parse_file_material(
        self,
        *,
        bundle_b64: str,
        private_key_b64: str | None,
        password: str | None,
        certificate_profiles: list[CertificateProfile],
    ):
        if self.backend_name not in {"software", "pkcs11"}:
            raise SetupProvisioningError(
                "P12/PEM private-key import is available only for Software HSM or PKCS#11"
            )
        bundle = _decode(bundle_b64, "Sub CA bundle", MAX_IMPORT_BYTES)
        private_key = (
            _decode(private_key_b64, "Sub CA private key", MAX_IMPORT_BYTES)
            if private_key_b64
            else None
        )
        try:
            parsed = parse_bundle(
                bundle,
                private_key_data=private_key,
                password=password,
            )
        except ValueError as exc:
            raise SetupProvisioningError(str(exc)) from exc
        if parsed.private_key is None:
            raise SetupProvisioningError("Sub CA P12/PEM import requires a private key")
        matches = [
            item
            for item in parsed.certificates
            if public_keys_match(
                item.public_key(),
                parsed.private_key.public_key(),
            )
        ]
        if len(matches) != 1:
            raise SetupProvisioningError(
                "Sub CA bundle must contain exactly one certificate matching its private key"
            )
        certificate = matches[0]
        try:
            algorithm = validate_imported_key(parsed.private_key, certificate)
        except KeyImportError as exc:
            raise SetupProvisioningError(str(exc)) from exc
        profiles = self._profiles(certificate_profiles)
        certificate, root = self._validate_material(
            certificate_to_pem(certificate),
            profiles,
            allow_legacy_missing_path_length=True,
        )
        root_der = root.public_bytes(serialization.Encoding.DER)
        for candidate in parsed.certificates:
            if candidate.subject == candidate.issuer and (
                candidate.public_bytes(serialization.Encoding.DER) != root_der
            ):
                raise SetupProvisioningError(
                    "The bundle contains a Root CA different from the configured trust anchor"
                )
        return parsed, certificate, root, algorithm, profiles

    def analyze_file(
        self,
        *,
        bundle_b64: str,
        private_key_b64: str | None,
        password: str | None,
        key_label: str,
        allowed_profiles: list[CertificateProfile],
        prior_crl_state: str,
        crl_b64: str | None,
    ) -> dict[str, object]:
        self._require_empty()
        parsed, certificate, root, algorithm, profiles = self._parse_file_material(
            bundle_b64=bundle_b64,
            private_key_b64=private_key_b64,
            password=password,
            certificate_profiles=allowed_profiles,
        )
        _validate_key_label(key_label, self.backend_name)
        crl_analysis = self._analyze_crl(
            certificate,
            prior_crl_state=prior_crl_state,
            crl_b64=crl_b64,
        )
        return self._analysis(
            method="file",
            certificate=certificate,
            root=root,
            algorithm=algorithm,
            key_ref=key_label,
            backend=self.backend_name,
            profiles=profiles,
            source_format=parsed.source_format.value,
            crl_analysis=crl_analysis,
        )

    def commit_file(
        self,
        *,
        bundle_b64: str,
        private_key_b64: str | None,
        password: str | None,
        key_label: str,
        allowed_profiles: list[CertificateProfile],
        prior_crl_state: str,
        crl_b64: str | None,
        reason: str = "",
    ) -> dict[str, object]:
        self._require_empty()
        parsed, certificate, _, _, profiles = self._parse_file_material(
            bundle_b64=bundle_b64,
            private_key_b64=private_key_b64,
            password=password,
            certificate_profiles=allowed_profiles,
        )
        _validate_key_label(key_label, self.backend_name)
        crl_analysis = self._analyze_crl(
            certificate,
            prior_crl_state=prior_crl_state,
            crl_b64=crl_b64,
        )
        if not isinstance(self.backend, ImportableKeyBackend):
            raise SetupProvisioningError(
                "The configured key backend does not support private-key import"
            )
        assert parsed.private_key is not None
        imported_ref: str | None = None
        sub_ca_id = str(uuid4())
        key_metadata: list[dict[str, str]] = []
        try:
            imported_ref = self.backend.import_key(
                key_label,
                parsed.private_key,
                certificate,
            )
            key_metadata = [
                {
                    "backend": self.backend_name,
                    "key_ref": imported_ref,
                    "ownership": KeyOwnership.MANAGED.value,
                }
            ]
            verify_backend_key(self.backend, imported_ref, certificate)
            self._register_key(
                key_ref=imported_ref,
                ownership=KeyOwnership.MANAGED,
                resource_type="sub_ca",
                resource_id=sub_ca_id,
            )
            sub_ca = self.ceremony.import_existing_sub_ca(
                certificate_pem=certificate_to_pem(certificate),
                root_certificate_pem=self._root_pem(),
                key_ref=imported_ref,
                allowed_profiles=profiles,
                activate=True,
                backend=self.backend,
                key_backend=self.backend_name,
                token_label=(
                    self.settings.pkcs11_token_label if self.backend_name == "pkcs11" else None
                ),
                sub_ca_id=sub_ca_id,
            )
            self._mark_crl_migration_required()
            local_crl = self._adopt_crl_migration(
                sub_ca,
                certificate,
                crl_analysis,
            )
        except Exception as exc:  # noqa: BLE001
            cleanup_complete = (
                self._rollback_failed_provisioning(key_metadata) if key_metadata else True
            )
            if not cleanup_complete:
                raise SetupProvisioningError(
                    "Sub CA key import failed and managed key cleanup requires Reset issuer step"
                ) from exc
            raise SetupProvisioningError(str(exc)) from exc
        self._remember(
            status="active",
            sub_ca_id=sub_ca.id,
            subject=sub_ca.subject,
            keys=[
                {
                    "backend": self.backend_name,
                    "key_ref": sub_ca.key_ref,
                    "ownership": KeyOwnership.MANAGED.value,
                }
            ],
        )
        self._audit(
            "setup_subca_file_import",
            object_id=sub_ca.id,
            details={
                "subject": sub_ca.subject,
                "backend": self.backend_name,
                "source_format": parsed.source_format.value,
                "imported_crl_number": (
                    crl_analysis.number if crl_analysis.crl is not None else None
                ),
                "local_crl_number": local_crl.number,
                "migrated_revocations": len(crl_analysis.revocations),
                **_legacy_path_length_audit_detail(certificate),
                "reason": reason,
            },
        )
        return self.status()

    # -- Test/Lab ----------------------------------------------------------

    def provision_lab(self, *, reason: str = "") -> dict[str, object]:
        self._require_empty()
        if not self.settings.lab_mode:
            raise SetupProvisioningError(
                "Automatic Lab CA generation is available only for Test/Lab installs"
            )
        if self.backend_name != "software":
            raise SetupProvisioningError(
                "Automatic Lab CA generation requires the Software HSM backend"
            )
        if load_setup_state(self.state_dir).data.get("root_certificate"):
            raise SetupProvisioningError(
                "Remove the imported Root CA or use a Production issuer flow"
            )
        key_metadata: list[dict[str, str]] = []
        try:
            chain = create_lab_ca_chain(
                self.backend,
                self.settings.lab_common_name,
            )
            key_metadata = [
                {
                    "backend": "software",
                    "key_ref": chain.root.key_ref,
                    "ownership": KeyOwnership.MANAGED.value,
                },
                {
                    "backend": "software",
                    "key_ref": chain.issuer.key_ref,
                    "ownership": KeyOwnership.MANAGED.value,
                },
            ]
            sub_ca = SubCA(
                id=str(uuid4()),
                certificate_pem=certificate_to_pem(chain.issuer.certificate),
                key_ref=chain.issuer.key_ref,
                subject=chain.issuer.certificate.subject.rfc4514_string(),
                created_at=chain.issuer.certificate.not_valid_before_utc,
                allowed_profiles=tuple(CertificateProfile),
                key_backend="software",
                token_label=None,
            )
            self.repository.add_sub_ca(
                sub_ca,
                root_certificate_pem=certificate_to_pem(chain.root.certificate),
                activate=True,
            )
            self._register_key(
                key_ref=chain.root.key_ref,
                ownership=KeyOwnership.MANAGED,
                resource_type="root_ca",
                resource_id="lab-root",
                purpose="root_ca",
            )
            self._register_key(
                key_ref=chain.issuer.key_ref,
                ownership=KeyOwnership.MANAGED,
                resource_type="sub_ca",
                resource_id=sub_ca.id,
            )
        except Exception as exc:  # noqa: BLE001
            cleanup_complete = (
                self._rollback_failed_provisioning(key_metadata) if key_metadata else True
            )
            if not cleanup_complete:
                raise SetupProvisioningError(
                    "Lab CA creation failed and managed key cleanup requires Reset issuer step"
                ) from exc
            raise SetupProvisioningError(str(exc)) from exc
        keys = [
            {
                "backend": "software",
                "key_ref": "lab-root",
                "ownership": KeyOwnership.MANAGED.value,
            },
            {
                "backend": "software",
                "key_ref": sub_ca.key_ref,
                "ownership": KeyOwnership.MANAGED.value,
            },
        ]
        self._remember(
            status="active",
            sub_ca_id=sub_ca.id,
            subject=sub_ca.subject,
            keys=keys,
        )
        self._audit(
            "setup_lab_issuer_create",
            object_id=sub_ca.id,
            details={
                "subject": sub_ca.subject,
                "backend": "software",
                "reason": reason,
            },
        )
        return self.status()

    def adopt_legacy_lab(self) -> dict[str, object] | None:
        """Persist the effective issuer used by pre-provisioning Lab installs."""

        if self.repository.get_active_sub_ca() is not None:
            return self.status()
        if not self.settings.lab_mode or self.backend_name != "software":
            return None
        state = load_setup_state(self.state_dir)
        if (
            self.repository.list_sub_cas()
            or self.repository.list_pending_sub_cas()
            or any(key in state.data for key in ("issuer_locked", "issuer_status", "issuer_keys"))
            or "issuer" in state.steps
        ):
            # Lost modern issuer state is not evidence of a pre-provisioning Lab.
            return None
        try:
            self.backend.public_key("lab-root")
            self.backend.public_key("lab-issuer")
        except KeyError:
            return None
        try:
            chain = create_lab_ca_chain_from_existing_keys(
                self.backend,
                self.settings.lab_common_name,
            )
            sub_ca = SubCA(
                id=str(uuid4()),
                certificate_pem=certificate_to_pem(chain.issuer.certificate),
                key_ref=chain.issuer.key_ref,
                subject=chain.issuer.certificate.subject.rfc4514_string(),
                created_at=chain.issuer.certificate.not_valid_before_utc,
                allowed_profiles=tuple(CertificateProfile),
                key_backend="software",
                token_label=None,
            )
            self.repository.add_sub_ca(
                sub_ca,
                root_certificate_pem=certificate_to_pem(chain.root.certificate),
                activate=True,
            )
            self._register_key(
                key_ref=chain.root.key_ref,
                ownership=KeyOwnership.MANAGED,
                resource_type="root_ca",
                resource_id="lab-root",
                purpose="root_ca",
            )
            self._register_key(
                key_ref=sub_ca.key_ref,
                ownership=KeyOwnership.MANAGED,
                resource_type="sub_ca",
                resource_id=sub_ca.id,
            )
        except Exception as exc:  # noqa: BLE001
            raise SetupProvisioningError("Could not persist the legacy Test/Lab issuer") from exc
        self._remember(
            status="active",
            sub_ca_id=sub_ca.id,
            subject=sub_ca.subject,
            keys=[
                {
                    "backend": "software",
                    "key_ref": "lab-root",
                    "ownership": KeyOwnership.MANAGED.value,
                },
                {
                    "backend": "software",
                    "key_ref": sub_ca.key_ref,
                    "ownership": KeyOwnership.MANAGED.value,
                },
            ],
        )
        self._audit(
            "legacy_lab_issuer_adopt",
            object_id=sub_ca.id,
            details={"subject": sub_ca.subject, "backend": "software"},
        )
        return self.status()

    # -- SmartCard-HSM DKEK -----------------------------------------------

    def analyze_dkek(
        self,
        *,
        wrapped_key_b64: str,
        key_reference: str,
        certificate_pem: str,
        allowed_profiles: list[CertificateProfile],
        prior_crl_state: str,
        crl_b64: str | None,
    ) -> dict[str, object]:
        self._require_empty()
        if self.backend_name != "pkcs11":
            raise SetupProvisioningError("DKEK restore is available only with the PKCS#11 backend")
        profiles = self._profiles(allowed_profiles)
        certificate, root = self._validate_material(
            certificate_pem,
            profiles,
            allow_legacy_missing_path_length=True,
        )
        wrapped_key = _decode(
            wrapped_key_b64,
            "Wrapped-key bundle",
            MAX_WRAPPED_KEY_BYTES,
        )
        try:
            reference, status = self.hsm_recovery.inspect_restore_target(
                key_reference,
                wrapped_key=wrapped_key,
            )
        except Exception as exc:  # noqa: BLE001
            raise SetupProvisioningError(str(exc)) from exc

        result = self._analysis(
            method="dkek_restore",
            certificate=certificate,
            root=root,
            algorithm=imported_key_algorithm(certificate.public_key()),
            key_ref=str(reference),
            backend="pkcs11",
            profiles=profiles,
            source_format="wrapped_key",
            crl_analysis=self._analyze_crl(
                certificate,
                prior_crl_state=prior_crl_state,
                crl_b64=crl_b64,
            ),
        )
        result.update(
            {
                "wrapped_key_size": len(wrapped_key),
                "dkek_shares_total": status.shares_total,
                "dkek_shares_imported": status.shares_imported,
                "dkek_kcv": status.kcv,
            }
        )
        return result

    def restore_dkek(
        self,
        *,
        wrapped_key_b64: str,
        key_reference: str,
        certificate_pem: str,
        allowed_profiles: list[CertificateProfile],
        prior_crl_state: str,
        crl_b64: str | None,
        reason: str = "",
    ) -> dict[str, object]:
        self.analyze_dkek(
            wrapped_key_b64=wrapped_key_b64,
            key_reference=key_reference,
            certificate_pem=certificate_pem,
            allowed_profiles=allowed_profiles,
            prior_crl_state=prior_crl_state,
            crl_b64=crl_b64,
        )
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode())
        crl_analysis = self._analyze_crl(
            certificate,
            prior_crl_state=prior_crl_state,
            crl_b64=crl_b64,
        )
        if not self.user_pin:
            raise SetupProvisioningError("Provide the PKCS#11 User PIN for DKEK restore")
        wrapped_key = _decode(
            wrapped_key_b64,
            "Wrapped-key bundle",
            MAX_WRAPPED_KEY_BYTES,
        )
        restored_ref: str | None = None
        status_kcv: str | None = None
        sub_ca_id = str(uuid4())
        key_metadata: list[dict[str, str]] = []
        try:
            with self.hsm_recovery.restore_key(
                wrapped_key,
                user_pin=self.user_pin,
                key_reference=key_reference,
                expected_public_key=certificate.public_key(),
            ) as restored:
                restored_ref = restored.label
                status_kcv = restored.dkek_kcv
                key_metadata = [
                    {
                        "backend": "pkcs11",
                        "key_ref": restored_ref,
                        "ownership": KeyOwnership.MANAGED.value,
                    }
                ]
                self._register_key(
                    key_ref=restored_ref,
                    ownership=KeyOwnership.MANAGED,
                    resource_type="sub_ca",
                    resource_id=sub_ca_id,
                )
                sub_ca = self.ceremony.import_existing_sub_ca(
                    certificate_pem=certificate_pem,
                    root_certificate_pem=self._root_pem(),
                    key_ref=restored_ref,
                    allowed_profiles=self._profiles(allowed_profiles),
                    activate=True,
                    backend=self.backend,
                    key_backend="pkcs11",
                    token_label=self.settings.pkcs11_token_label,
                    sub_ca_id=sub_ca_id,
                )
                self._mark_crl_migration_required()
                local_crl = self._adopt_crl_migration(
                    sub_ca,
                    certificate,
                    crl_analysis,
                )
        except KeyRecoveryRollbackError as exc:
            if not key_metadata:
                key_metadata = [
                    {
                        "backend": "pkcs11",
                        "key_ref": label,
                        "ownership": KeyOwnership.MANAGED.value,
                    }
                    for label in exc.created_labels
                ]
            cleanup_complete = (
                self._rollback_failed_provisioning(key_metadata) if key_metadata else True
            )
            if not cleanup_complete:
                raise SetupProvisioningError(
                    "DKEK restore failed and managed key cleanup requires Reset issuer step"
                ) from exc
            raise SetupProvisioningError(str(exc)) from exc
        except Exception as exc:  # noqa: BLE001
            cleanup_complete = (
                self._rollback_failed_provisioning(
                    key_metadata,
                    delete_managed_keys=False,
                )
                if key_metadata
                else True
            )
            if not cleanup_complete:
                raise SetupProvisioningError(
                    "DKEK restore failed and issuer metadata cleanup requires Reset issuer step"
                ) from exc
            if isinstance(exc, SetupProvisioningError):
                raise
            raise SetupProvisioningError(str(exc)) from exc
        self._remember(
            status="active",
            sub_ca_id=sub_ca.id,
            subject=sub_ca.subject,
            keys=[
                {
                    "backend": "pkcs11",
                    "key_ref": restored_ref,
                    "ownership": KeyOwnership.MANAGED.value,
                }
            ],
        )
        self._audit(
            "setup_subca_dkek_restore",
            object_id=sub_ca.id,
            details={
                "subject": sub_ca.subject,
                "backend": "pkcs11",
                "kcv": status_kcv,
                "imported_crl_number": (
                    crl_analysis.number if crl_analysis.crl is not None else None
                ),
                "local_crl_number": local_crl.number,
                "migrated_revocations": len(crl_analysis.revocations),
                **_legacy_path_length_audit_detail(certificate),
                "reason": reason,
            },
        )
        return self.status()

    # -- reset --------------------------------------------------------------

    def reset(self, *, reason: str = "") -> dict[str, object]:
        if is_setup_complete(self.state_dir) and self.repository.get_active_sub_ca() is not None:
            raise SetupProvisioningError(
                "Root and Sub CA trust material is immutable after setup completion"
            )
        state = load_setup_state(self.state_dir)
        keys = state.data.get("issuer_keys")
        if not isinstance(keys, list):
            keys = []
        try:
            self.repository.assert_initial_ca_resettable()
        except RepositoryError as exc:
            raise SetupProvisioningError(str(exc)) from exc
        for item in keys:
            if not isinstance(item, dict):
                continue
            ownership = item.get("ownership")
            hsm_deleted = item.get("hsm_deleted") == "true"
            backend = str(item.get("backend") or "")
            key_ref = str(item.get("key_ref") or "")
            if ownership not in {
                KeyOwnership.MANAGED.value,
                KeyOwnership.ATTACHED.value,
            }:
                raise SetupProvisioningError(
                    "Issuer key ownership metadata is invalid; reset was blocked"
                )
            if backend != self.backend_name:
                raise SetupProvisioningError(
                    "Cannot safely reset issuer keys with a different active backend"
                )
            if not key_ref:
                raise SetupProvisioningError(
                    "Issuer key reference metadata is invalid; reset was blocked"
                )
            registered = self.key_lifecycle_repository.find(
                backend=backend,
                key_ref=key_ref,
            )
            if (
                ownership == KeyOwnership.MANAGED.value
                and not hsm_deleted
                and (registered is None or registered.status is not KeyStatus.DELETED)
            ):
                deleter = getattr(self.backend, "delete_key", None)
                if not callable(deleter):
                    raise SetupProvisioningError(
                        f"The {self.backend_name} backend cannot safely delete managed key {key_ref}"
                    )
                try:
                    deleter(key_ref)
                except Exception as exc:  # noqa: BLE001
                    raise SetupProvisioningError(
                        "Managed issuer key cleanup failed; the setup state was preserved"
                    ) from exc
            if registered is not None and not registered.terminal:
                self.key_lifecycle.complete_initial_setup_reset(registered.id)
            try:
                self._mark_cloud_key_reset(
                    key_ref=key_ref,
                    ownership=KeyOwnership(ownership),
                )
            except Exception as exc:  # noqa: BLE001
                raise SetupProvisioningError(
                    "Cloud issuer metadata cleanup failed; the setup state was preserved"
                ) from exc
        try:
            self.repository.reset_initial_ca_provisioning()
        except RepositoryError as exc:
            raise SetupProvisioningError(str(exc)) from exc
        state = load_setup_state(self.state_dir)
        state.data.pop("issuer_locked", None)
        state.data.pop("issuer_keys", None)
        state.data.pop("issuer_status", None)
        state.data.pop("crl_migration_required", None)
        state.steps.pop("issuer", None)
        save_setup_state(self.state_dir, state)
        self._audit(
            "setup_issuer_reset",
            object_id="initial",
            details={"key_count": len(keys), "reason": reason},
        )
        return self.status()


def _decode(value: str | None, label: str, maximum: int) -> bytes:
    try:
        data = base64.b64decode(value or "", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SetupProvisioningError(f"{label} is not valid Base64") from exc
    if not data:
        raise SetupProvisioningError(f"{label} is empty")
    if len(data) > maximum:
        raise SetupProvisioningError(f"{label} exceeds the upload limit")
    return data


def _validate_key_label(value: str, backend: str) -> None:
    pattern = (
        r"[A-Za-z0-9][A-Za-z0-9_-]*"
        if backend == "software"
        else r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}"
    )
    if re.fullmatch(pattern, value) is None:
        raise SetupProvisioningError("Unsafe key label for the configured backend")
