from __future__ import annotations

import hashlib
import importlib.util
import ipaddress
import json
import secrets
import urllib.parse
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from myownca.setup.config_writer import (
    read_secrets,
    write_config,
    write_secret_artifact,
    write_secrets,
)
from myownca.setup.state import (
    SetupState,
    is_setup_complete,
    load_setup_state,
    mark_setup_complete,
    save_setup_state,
)

INSTALL_TYPES = ("production", "lab")
GOVERNANCE_MODES = ("single_admin", "dual_control")
DATABASE_KINDS = ("sqlite", "mariadb")
LISTENER_TOPOLOGIES = ("direct", "proxy")
HSM_BACKENDS = ("software", "pkcs11", "aws_kms", "azure_key_vault")
CLOUD_HSM_BACKENDS = ("aws_kms", "azure_key_vault")
AZURE_KEY_PROTECTIONS = ("standard", "hsm")
AUTH_ROLES = ("admin", "superuser", "auditor", "user")
DEFAULT_TOTP_REQUIRED_ROLES = ("admin", "superuser")
_EMAIL_ERROR = "Admin email must be a valid address like admin@example.com"
_CLOUD_HSM_TEST_KEY = "cloud_hsm_test"
_PKCS11_HSM_READY_KEY = "pkcs11_hsm_ready"


class SetupError(ValueError):
    """A setup step was given invalid input or called out of order."""


def _normalize_bind_host(value: object) -> str:
    """Accept only deterministic local bind targets the wizard can describe."""

    host = str(value or "").strip()
    if host == "localhost":
        return host
    try:
        ipaddress.ip_address(host)
    except ValueError as exc:
        raise SetupError(
            "Bind address must be localhost or a valid IPv4 or IPv6 address"
        ) from exc
    return host


def _normalize_direct_tls_paths(
    certificate_value: object,
    key_value: object,
) -> tuple[str, str]:
    """Validate externally managed PEM files before direct HTTPS is enabled."""

    certificate_path = Path(str(certificate_value or "").strip())
    key_path = Path(str(key_value or "").strip())
    for label, path in (("TLS certificate", certificate_path), ("TLS private key", key_path)):
        if not path.is_absolute():
            raise SetupError(f"{label} path must be absolute")
        if not path.is_file():
            raise SetupError(f"{label} file does not exist or is not a regular file")
    try:
        certificate_pem = certificate_path.read_text(encoding="utf-8")
        key_pem = key_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SetupError("TLS certificate and private key files must be readable") from exc

    from myownca.online.portal_tls import PortalTlsError, validate_pair

    try:
        validate_pair(certificate_pem, key_pem)
    except PortalTlsError as exc:
        raise SetupError(f"Direct HTTPS certificate/key validation failed: {exc}") from exc
    return str(certificate_path), str(key_path)


def _normalize_listener(listener: object) -> dict[str, object]:
    """Validate the setup listener choice before it is persisted or finalized."""

    if not isinstance(listener, dict):
        raise SetupError("Choose a deployment topology before finalizing")
    topology = str(listener.get("topology") or "").strip().lower()
    if topology not in LISTENER_TOPOLOGIES:
        raise SetupError("Choose Direct service or Reverse proxy / container")
    if topology == "proxy":
        return {"topology": topology}

    host = _normalize_bind_host(listener.get("bind_host"))
    try:
        port = int(listener.get("bind_port"))
    except (TypeError, ValueError) as exc:
        raise SetupError("Bind port must be a number from 1 to 65535") from exc
    if not 1 <= port <= 65535:
        raise SetupError("Bind port must be a number from 1 to 65535")
    normalized: dict[str, object] = {
        "topology": topology,
        "bind_host": host,
        "bind_port": port,
    }
    if bool(listener.get("tls_enabled")):
        certificate_path, key_path = _normalize_direct_tls_paths(
            listener.get("tls_cert"), listener.get("tls_key")
        )
        normalized.update(
            {
                "tls_enabled": True,
                "tls_cert": certificate_path,
                "tls_key": key_path,
            }
        )
    return normalized


def _validate_root_certificate(pem: str) -> dict[str, object]:
    """Validate and summarize a production Root CA certificate without saving it."""

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    from myownca.ca_main.crypto import verify_certificate_signature

    normalized = pem.strip() + "\n"
    try:
        root = x509.load_pem_x509_certificate(normalized.encode())
    except ValueError as exc:
        raise SetupError(f"Invalid certificate PEM: {exc}") from exc
    if root.subject != root.issuer:
        raise SetupError("Root certificate must be self-issued (subject == issuer)")
    try:
        verify_certificate_signature(root, root)
    except Exception as exc:  # noqa: BLE001 - normalize crypto backend errors
        raise SetupError("Root certificate signature does not verify") from exc
    now = datetime.now(timezone.utc)
    if not (root.not_valid_before_utc <= now < root.not_valid_after_utc):
        raise SetupError("Root certificate is not currently valid")
    try:
        constraints = root.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except x509.ExtensionNotFound as exc:
        raise SetupError("Root certificate is missing BasicConstraints") from exc
    if not constraints.ca:
        raise SetupError("Root certificate requires CA=true")
    try:
        usage = root.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise SetupError("Root certificate is missing KeyUsage") from exc
    if not usage.key_cert_sign:
        raise SetupError("Root certificate requires keyCertSign")

    return {
        "verified": True,
        "subject": root.subject.rfc4514_string(),
        "issuer": root.issuer.rfc4514_string(),
        "fingerprint_sha256": root.fingerprint(hashes.SHA256()).hex(),
        "not_valid_before": root.not_valid_before_utc.isoformat(),
        "not_valid_after": root.not_valid_after_utc.isoformat(),
        "basic_constraints": {
            "ca": constraints.ca,
            "path_length": constraints.path_length,
        },
        "key_usage": {
            "key_cert_sign": usage.key_cert_sign,
            "crl_sign": usage.crl_sign,
            "digital_signature": usage.digital_signature,
            "content_commitment": usage.content_commitment,
            "key_encipherment": usage.key_encipherment,
            "data_encipherment": usage.data_encipherment,
            "key_agreement": usage.key_agreement,
        },
    }


def _redact_database(database: "dict | None") -> "dict | None":
    """Drop the DB password so snapshots / /setup/state never echo it."""
    if not database or "password" not in database:
        return database
    return {key: value for key, value in database.items() if key != "password"}


def _redact_admins(admins: "list | None") -> "list | None":
    """Drop admin passwords so snapshots / /setup/state never echo them."""
    if not admins:
        return admins
    return [{"id": a["id"], "email": a["email"]} for a in admins]


def _redact_hsm(hsm: "dict | None") -> dict[str, object]:
    """Return setup state without echoing any cloud credential material."""
    # Finalization replaces the draft (which contains credentials in its 0600
    # state file) with this already-redacted shape.  Keep snapshots readable
    # after that scrub without trying to revalidate credentials that now live
    # only in secrets.env.
    backend = str((hsm or {}).get("backend") or "software").strip().lower()
    if backend == "aws_kms" and "aws_secret_access_key" not in (hsm or {}):
        return {
            "backend": backend,
            "aws_region": str((hsm or {}).get("aws_region") or ""),
            "service_key_backend": str(
                (hsm or {}).get("service_key_backend") or "software"
            ),
            "credentials_configured": bool(
                (hsm or {}).get("credentials_configured")
            ),
        }
    if backend == "azure_key_vault" and "azure_client_secret" not in (hsm or {}):
        return {
            "backend": backend,
            "azure_vault_url": str((hsm or {}).get("azure_vault_url") or ""),
            "azure_key_protection": str(
                (hsm or {}).get("azure_key_protection") or "hsm"
            ),
            "service_key_backend": str(
                (hsm or {}).get("service_key_backend") or "software"
            ),
            "credentials_configured": bool(
                (hsm or {}).get("credentials_configured")
            ),
        }
    normalized = _normalize_hsm(hsm, validate_pkcs11_path=False)
    if normalized["backend"] == "aws_kms":
        return {
            "backend": "aws_kms",
            "aws_region": normalized["aws_region"],
            "service_key_backend": normalized["service_key_backend"],
            "credentials_configured": bool(
                normalized["aws_access_key_id"]
                and normalized["aws_secret_access_key"]
            ),
        }
    if normalized["backend"] == "azure_key_vault":
        return {
            "backend": "azure_key_vault",
            "azure_vault_url": normalized["azure_vault_url"],
            "azure_key_protection": normalized["azure_key_protection"],
            "service_key_backend": normalized["service_key_backend"],
            "credentials_configured": bool(
                normalized["azure_tenant_id"]
                and normalized["azure_client_id"]
                and normalized["azure_client_secret"]
            ),
        }
    return normalized


def _cloud_hsm_test_digest(hsm: dict[str, str]) -> str:
    encoded = json.dumps(
        hsm,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _cloud_hsm_test_is_current(state: SetupState, hsm: dict[str, str]) -> bool:
    marker = state.data.get(_CLOUD_HSM_TEST_KEY)
    return bool(
        hsm.get("backend") in CLOUD_HSM_BACKENDS
        and isinstance(marker, dict)
        and marker.get("backend") == hsm["backend"]
        and secrets.compare_digest(
            str(marker.get("digest") or ""),
            _cloud_hsm_test_digest(hsm),
        )
    )


def _pkcs11_hsm_digest(hsm: dict[str, str]) -> str:
    identity = {
        "backend": hsm.get("backend"),
        "pkcs11_lib": hsm.get("pkcs11_lib"),
        "token_label": hsm.get("token_label"),
        "reader": hsm.get("reader", ""),
    }
    encoded = json.dumps(
        identity,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _pkcs11_hsm_is_ready(state: SetupState, hsm: dict[str, str]) -> bool:
    marker = state.data.get(_PKCS11_HSM_READY_KEY)
    dkek_mode = marker.get("dkek_mode") if isinstance(marker, dict) else None
    kcv = str(marker.get("kcv") or "") if isinstance(marker, dict) else ""
    valid_dkek_state = (dkek_mode == "shares" and bool(kcv)) or (
        dkek_mode == "disabled" and not kcv
    )
    return bool(
        hsm.get("backend") == "pkcs11"
        and isinstance(marker, dict)
        and marker.get("mode") in {"existing", "initialized"}
        and str(marker.get("token_serial") or "")
        and valid_dkek_state
        and secrets.compare_digest(
            str(marker.get("digest") or ""),
            _pkcs11_hsm_digest(hsm),
        )
    )


def _normalize_hsm(
    hsm: "dict | None",
    *,
    validate_pkcs11_path: bool,
) -> dict[str, str]:
    hsm = hsm or {}
    backend = str(hsm.get("backend") or "software").strip().lower()
    if backend not in HSM_BACKENDS:
        raise SetupError(f"Unknown HSM backend: {backend}")
    token_label = str(hsm.get("token_label") or "myOwnCA").strip() or "myOwnCA"
    pkcs11_lib = str(hsm.get("pkcs11_lib") or "").strip()
    reader = str(hsm.get("reader") or "").strip()
    if backend in ("software", "pkcs11"):
        normalized = {
            "backend": backend,
            "token_label": token_label,
            "pkcs11_lib": pkcs11_lib,
        }
        if backend != "pkcs11":
            normalized["pkcs11_lib"] = ""
            return normalized
        normalized["reader"] = reader
        if not pkcs11_lib:
            raise SetupError("PKCS#11 module path is required for smartcard HSM setup")
        if validate_pkcs11_path and not Path(pkcs11_lib).exists():
            raise SetupError(f"PKCS#11 module was not found: {pkcs11_lib}")
        return normalized

    service_key_backend = str(
        hsm.get("service_key_backend") or "software"
    ).strip().lower()
    if service_key_backend not in ("software", backend):
        raise SetupError(
            "Service certificate keys must use software storage or the selected "
            "cloud provider"
        )

    if backend == "aws_kms":
        normalized = {
            "backend": backend,
            "aws_region": str(hsm.get("aws_region") or "").strip(),
            "aws_access_key_id": str(hsm.get("aws_access_key_id") or "").strip(),
            "aws_secret_access_key": str(
                hsm.get("aws_secret_access_key") or ""
            ).strip(),
            "aws_session_token": str(hsm.get("aws_session_token") or "").strip(),
            "service_key_backend": service_key_backend,
        }
        missing = [
            label
            for label, value in (
                ("AWS region", normalized["aws_region"]),
                ("AWS access key ID", normalized["aws_access_key_id"]),
                ("AWS secret access key", normalized["aws_secret_access_key"]),
            )
            if not value
        ]
        if missing:
            raise SetupError(f"AWS KMS requires: {', '.join(missing)}")
        return normalized

    protection = str(hsm.get("azure_key_protection") or "hsm").strip().lower()
    if protection not in AZURE_KEY_PROTECTIONS:
        raise SetupError(f"Unknown Azure key protection: {protection}")
    normalized = {
        "backend": backend,
        "azure_vault_url": str(hsm.get("azure_vault_url") or "").strip(),
        "azure_tenant_id": str(hsm.get("azure_tenant_id") or "").strip(),
        "azure_client_id": str(hsm.get("azure_client_id") or "").strip(),
        "azure_client_secret": str(hsm.get("azure_client_secret") or "").strip(),
        "azure_key_protection": protection,
        "service_key_backend": service_key_backend,
    }
    missing = [
        label
        for label, value in (
            ("Azure vault URL", normalized["azure_vault_url"]),
            ("Azure tenant ID", normalized["azure_tenant_id"]),
            ("Azure client ID", normalized["azure_client_id"]),
            ("Azure client secret", normalized["azure_client_secret"]),
        )
        if not value
    ]
    if missing:
        raise SetupError(f"Azure Key Vault requires: {', '.join(missing)}")
    parsed_vault_url = urllib.parse.urlsplit(normalized["azure_vault_url"])
    if (
        parsed_vault_url.scheme.lower() != "https"
        or not parsed_vault_url.netloc
        or parsed_vault_url.path not in {"", "/"}
        or parsed_vault_url.query
        or parsed_vault_url.fragment
        or parsed_vault_url.username
        or parsed_vault_url.password
    ):
        raise SetupError(
            "Azure vault URL must be an HTTPS origin without a path or credentials"
        )
    normalized["azure_vault_url"] = f"https://{parsed_vault_url.netloc.lower()}"
    return normalized


def _cloud_sdk_available(backend: str) -> bool:
    modules = {
        "aws_kms": ("boto3",),
        "azure_key_vault": ("azure.identity", "azure.keyvault.keys"),
    }[backend]
    try:
        return all(importlib.util.find_spec(module) is not None for module in modules)
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


def _require_cloud_sdk(backend: str) -> None:
    if backend not in CLOUD_HSM_BACKENDS or _cloud_sdk_available(backend):
        return
    provider = "AWS KMS" if backend == "aws_kms" else "Azure Key Vault"
    raise SetupError(
        f"{provider} dependencies are bundled with myownca but could not be imported; "
        "reinstall the complete distribution"
    )


def _test_cloud_provider_connection(data: dict[str, str]) -> None:
    """Build the selected adapter lazily and perform its real provider probe."""
    from myownca.ca_hsm.remote import CloudBackendError  # noqa: PLC0415

    backend = data["backend"]
    try:
        if backend == "aws_kms":
            from myownca.ca_hsm.aws_kms import AWSKMSHSM  # noqa: PLC0415

            provider = AWSKMSHSM(
                region_name=data["aws_region"],
                aws_access_key_id=data["aws_access_key_id"] or None,
                aws_secret_access_key=data["aws_secret_access_key"] or None,
                aws_session_token=data["aws_session_token"] or None,
            )
        elif backend == "azure_key_vault":
            from myownca.ca_hsm.azure_key_vault import (  # noqa: PLC0415
                AzureKeyVaultHSM,
            )

            provider = AzureKeyVaultHSM(
                vault_url=data["azure_vault_url"],
                tenant_id=data["azure_tenant_id"] or None,
                client_id=data["azure_client_id"] or None,
                client_secret=data["azure_client_secret"] or None,
                key_protection=data["azure_key_protection"],
            )
        else:  # Defensive: callers already gate this to cloud backends.
            return
        result = provider.test_connection()
    except CloudBackendError as exc:
        # CloudBackendError text is deliberately normalized by the adapter and
        # contains no credential values or raw provider response body.
        raise SetupError(str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - provider SDK types are optional
        provider_name = "AWS KMS" if backend == "aws_kms" else "Azure Key Vault"
        raise SetupError(
            f"{provider_name} connection test failed ({type(exc).__name__})"
        ) from exc
    if result is False or (
        isinstance(result, dict) and result.get("reachable") is False
    ):
        provider_name = "AWS KMS" if backend == "aws_kms" else "Azure Key Vault"
        raise SetupError(f"{provider_name} connection test failed")


def _normalize_admin_email(value: object) -> str:
    email = str(value or "").strip().lower()
    if email.count("@") != 1:
        raise SetupError(_EMAIL_ERROR)
    local, domain = email.split("@", 1)
    if not local or not domain or "." not in domain:
        raise SetupError(_EMAIL_ERROR)
    if any(char.isspace() or ord(char) < 32 for char in email):
        raise SetupError(_EMAIL_ERROR)
    return email


class SetupOrchestrator:
    """Drives the wizard's persisted state and the final write-out.

    Stateless across calls: it reads and writes the on-disk setup state each
    time, so progress survives process restarts (the wizard is resumable). It
    wraps the setup state file, the config/secrets writers, and the completion
    latch.
    """

    def __init__(self, state_dir: str | Path) -> None:
        self.state_dir = Path(state_dir)

    def _ensure_not_complete(self) -> None:
        if is_setup_complete(self.state_dir):
            raise SetupError("Setup is already finalized")

    def _ensure_foundation_unlocked(self) -> None:
        self._ensure_not_complete()
        state = load_setup_state(self.state_dir)
        if state.data.get("issuer_locked"):
            raise SetupError(
                "The database, key backend, install type, and Root CA are locked "
                "after issuer provisioning starts; reset the issuer step first"
            )

    def snapshot(self) -> dict[str, object]:
        state = load_setup_state(self.state_dir)
        hsm_state = (
            state.data.get("hsm") if isinstance(state.data.get("hsm"), dict) else None
        )
        redacted_hsm = _redact_hsm(hsm_state)
        if redacted_hsm["backend"] in CLOUD_HSM_BACKENDS:
            try:
                normalized_hsm = _normalize_hsm(
                    hsm_state,
                    validate_pkcs11_path=False,
                )
            except SetupError:
                connection_tested = False
            else:
                connection_tested = _cloud_hsm_test_is_current(
                    state, normalized_hsm
                )
            redacted_hsm["connection_tested"] = connection_tested
        elif redacted_hsm["backend"] == "pkcs11":
            try:
                normalized_hsm = _normalize_hsm(
                    hsm_state,
                    validate_pkcs11_path=False,
                )
            except SetupError:
                ready = False
            else:
                ready = _pkcs11_hsm_is_ready(state, normalized_hsm)
            redacted_hsm["ready"] = ready
            marker = state.data.get(_PKCS11_HSM_READY_KEY)
            if ready and isinstance(marker, dict):
                redacted_hsm["readiness"] = {
                    "mode": marker["mode"],
                    "token_serial": marker["token_serial"],
                    "dkek_mode": marker["dkek_mode"],
                    "kcv": marker.get("kcv"),
                }
        return {
            "complete": is_setup_complete(self.state_dir),
            "steps": state.steps,
            "install_type": state.data.get("install_type"),
            "governance_mode": state.data.get("governance_mode"),
            "totp_required_roles": state.data.get(
                "totp_required_roles", list(DEFAULT_TOTP_REQUIRED_ROLES)
            ),
            "database": _redact_database(state.data.get("database")),
            "hsm": redacted_hsm,
            "listener": state.data.get("listener"),
            "service_urls": state.data.get("service_urls"),
            "issuance_endpoints": state.data.get("issuance_endpoints"),
            "root_captured": "root_certificate" in state.data,
            "admins": _redact_admins(state.data.get("admins")),
            "issuer_locked": bool(state.data.get("issuer_locked")),
            "issuer": state.data.get("issuer_status"),
        }

    def set_install_type(self, value: str) -> None:
        self._ensure_foundation_unlocked()
        if value not in INSTALL_TYPES:
            raise SetupError(f"Unknown install type: {value}")
        state = load_setup_state(self.state_dir)
        previous = state.data.get("install_type")
        state.data["install_type"] = value
        state.steps["install_type"] = "done"
        if "totp_required_roles" not in state.data:
            state.data["totp_required_roles"] = list(DEFAULT_TOTP_REQUIRED_ROLES)
            state.steps["totp_policy"] = "done"
        if value == "lab":
            # A Lab issuer owns its generated Root CA. Never carry an imported
            # Production Root CA into the Lab flow, even when the operator
            # changes mode before provisioning the issuer.
            state.data.pop("root_certificate", None)
            state.steps.pop("root_certificate", None)
            (self.state_dir / "setup" / "root-ca.pem").unlink(missing_ok=True)
            state.data["governance_mode"] = "single_admin"
            state.steps["governance_mode"] = "done"
        elif value == "production" and previous != "production":
            state.data.pop("governance_mode", None)
            state.steps.pop("governance_mode", None)
        save_setup_state(self.state_dir, state)

    def set_governance_mode(self, value: str) -> None:
        self._ensure_not_complete()
        if value not in GOVERNANCE_MODES:
            raise SetupError(f"Unknown governance mode: {value}")
        state = load_setup_state(self.state_dir)
        if state.data.get("install_type") not in INSTALL_TYPES:
            raise SetupError("Choose an install type before governance mode")
        state.data["governance_mode"] = value
        state.steps["governance_mode"] = "done"
        save_setup_state(self.state_dir, state)

    def set_totp_policy(self, required_roles: list[str]) -> None:
        self._ensure_not_complete()
        normalized = list(dict.fromkeys(str(role).strip().lower() for role in required_roles))
        invalid = sorted(set(normalized) - set(AUTH_ROLES))
        if invalid:
            raise SetupError(f"Unknown TOTP policy roles: {', '.join(invalid)}")
        state = load_setup_state(self.state_dir)
        state.data["totp_required_roles"] = [
            role for role in AUTH_ROLES if role in normalized
        ]
        state.steps["totp_policy"] = "done"
        save_setup_state(self.state_dir, state)

    def set_database(
        self,
        kind: str,
        *,
        host: str = "",
        port: int = 3306,
        name: str = "",
        user: str = "",
        password: str = "",
    ) -> None:
        self._ensure_foundation_unlocked()
        if kind not in DATABASE_KINDS:
            raise SetupError(f"Unknown database kind: {kind}")
        if kind == "mariadb":
            missing = [
                field
                for field, value in (
                    ("host", host), ("name", name), ("user", user), ("password", password)
                )
                if not value
            ]
            if missing:
                raise SetupError(f"MariaDB requires: {', '.join(missing)}")
            data: dict[str, object] = {
                "kind": "mariadb",
                "host": host,
                "port": int(port),
                "name": name,
                "user": user,
                "password": password,
            }
        else:
            data = {"kind": "sqlite"}
        state = load_setup_state(self.state_dir)
        state.data["database"] = data
        state.steps["database"] = "done"
        save_setup_state(self.state_dir, state)

    def set_hsm(
        self,
        backend: str,
        *,
        pkcs11_lib: str = "",
        token_label: str = "myOwnCA",
        reader: str = "",
        aws_region: str = "",
        aws_access_key_id: str = "",
        aws_secret_access_key: str = "",
        aws_session_token: str = "",
        azure_vault_url: str = "",
        azure_tenant_id: str = "",
        azure_client_id: str = "",
        azure_client_secret: str = "",
        azure_key_protection: str = "hsm",
        service_key_backend: str = "software",
    ) -> None:
        self._ensure_foundation_unlocked()
        state = load_setup_state(self.state_dir)
        data = self._normalize_hsm_choice(
            state,
            backend=backend,
            pkcs11_lib=pkcs11_lib,
            token_label=token_label,
            reader=reader,
            aws_region=aws_region,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
            azure_vault_url=azure_vault_url,
            azure_tenant_id=azure_tenant_id,
            azure_client_id=azure_client_id,
            azure_client_secret=azure_client_secret,
            azure_key_protection=azure_key_protection,
            service_key_backend=service_key_backend,
        )
        if not _cloud_hsm_test_is_current(state, data):
            state.data.pop(_CLOUD_HSM_TEST_KEY, None)
        if not _pkcs11_hsm_is_ready(state, data):
            state.data.pop(_PKCS11_HSM_READY_KEY, None)
        state.data["hsm"] = data
        state.steps["hsm"] = "done"
        save_setup_state(self.state_dir, state)

    def _normalize_hsm_choice(
        self,
        state: SetupState,
        *,
        backend: str,
        pkcs11_lib: str,
        token_label: str,
        reader: str,
        aws_region: str,
        aws_access_key_id: str,
        aws_secret_access_key: str,
        aws_session_token: str,
        azure_vault_url: str,
        azure_tenant_id: str,
        azure_client_id: str,
        azure_client_secret: str,
        azure_key_protection: str,
        service_key_backend: str,
    ) -> dict[str, str]:
        raw = {
            "backend": backend,
            "pkcs11_lib": pkcs11_lib,
            "token_label": token_label,
            "reader": reader,
            "aws_region": aws_region,
            "aws_access_key_id": aws_access_key_id,
            "aws_secret_access_key": aws_secret_access_key,
            "aws_session_token": aws_session_token,
            "azure_vault_url": azure_vault_url,
            "azure_tenant_id": azure_tenant_id,
            "azure_client_id": azure_client_id,
            "azure_client_secret": azure_client_secret,
            "azure_key_protection": azure_key_protection,
            "service_key_backend": service_key_backend,
        }
        existing = state.data.get("hsm")
        if isinstance(existing, dict) and existing.get("backend") == backend:
            secret_env = read_secrets(self.state_dir)
            stored_secrets = {
                "aws_access_key_id": existing.get("aws_access_key_id")
                or secret_env.get("MYOWNCA_AWS_ACCESS_KEY_ID"),
                "aws_secret_access_key": existing.get("aws_secret_access_key")
                or secret_env.get("MYOWNCA_AWS_SECRET_ACCESS_KEY"),
                "aws_session_token": existing.get("aws_session_token")
                or secret_env.get("MYOWNCA_AWS_SESSION_TOKEN"),
                "azure_tenant_id": existing.get("azure_tenant_id")
                or secret_env.get("MYOWNCA_AZURE_TENANT_ID"),
                "azure_client_id": existing.get("azure_client_id")
                or secret_env.get("MYOWNCA_AZURE_CLIENT_ID"),
                "azure_client_secret": existing.get("azure_client_secret")
                or secret_env.get("MYOWNCA_AZURE_CLIENT_SECRET"),
            }
            secret_fields: tuple[str, ...] = ()
            if backend == "aws_kms" and not (
                raw["aws_access_key_id"] or raw["aws_secret_access_key"]
            ):
                secret_fields = (
                    "aws_access_key_id",
                    "aws_secret_access_key",
                    "aws_session_token",
                )
            elif backend == "azure_key_vault" and not (
                raw["azure_tenant_id"]
                or raw["azure_client_id"]
                or raw["azure_client_secret"]
            ):
                secret_fields = (
                    "azure_tenant_id",
                    "azure_client_id",
                    "azure_client_secret",
                )
            for field in secret_fields:
                if not raw[field] and stored_secrets.get(field):
                    raw[field] = str(stored_secrets[field])
        return _normalize_hsm(raw, validate_pkcs11_path=True)

    def test_hsm(
        self,
        backend: str,
        *,
        provider_test_hook: Callable[[dict[str, str]], object] | None = None,
        pkcs11_lib: str = "",
        token_label: str = "myOwnCA",
        reader: str = "",
        aws_region: str = "",
        aws_access_key_id: str = "",
        aws_secret_access_key: str = "",
        aws_session_token: str = "",
        azure_vault_url: str = "",
        azure_tenant_id: str = "",
        azure_client_id: str = "",
        azure_client_secret: str = "",
        azure_key_protection: str = "hsm",
        service_key_backend: str = "software",
    ) -> None:
        """Validate local storage or exercise an injected cloud-provider probe.

        Local backends never import a cloud SDK or make a network request.  A
        deployment/test can inject ``provider_test_hook``; otherwise cloud
        choices instantiate their adapter and perform an authenticated probe.
        """
        self._ensure_foundation_unlocked()
        state = load_setup_state(self.state_dir)
        data = self._normalize_hsm_choice(
            state,
            backend=backend,
            pkcs11_lib=pkcs11_lib,
            token_label=token_label,
            reader=reader,
            aws_region=aws_region,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
            azure_vault_url=azure_vault_url,
            azure_tenant_id=azure_tenant_id,
            azure_client_id=azure_client_id,
            azure_client_secret=azure_client_secret,
            azure_key_protection=azure_key_protection,
            service_key_backend=service_key_backend,
        )
        backend = data["backend"]
        if backend not in CLOUD_HSM_BACKENDS:
            return
        # A new probe supersedes any previous success. Persist the invalidation
        # before making a network request so failure/interruption cannot leave
        # a stale success marker behind.
        state.data.pop(_CLOUD_HSM_TEST_KEY, None)
        save_setup_state(self.state_dir, state)
        if provider_test_hook is None:
            _test_cloud_provider_connection(data)
        else:
            try:
                result = provider_test_hook(dict(data))
            except Exception as exc:  # noqa: BLE001 - provider SDK errors become setup errors
                # Provider exceptions may include request metadata.  Do not echo
                # arbitrary exception text next to credential-bearing setup input.
                raise SetupError(
                    f"Cloud provider test failed ({type(exc).__name__})"
                ) from exc
            if result is False:
                raise SetupError("Cloud provider test failed")

        state.data["hsm"] = data
        state.data[_CLOUD_HSM_TEST_KEY] = {
            "backend": backend,
            "digest": _cloud_hsm_test_digest(data),
        }
        state.steps["hsm"] = "done"
        save_setup_state(self.state_dir, state)

    def record_pkcs11_ready(
        self,
        *,
        mode: str,
        token_serial: str,
        dkek_mode: str,
        kcv: str | None,
    ) -> dict[str, object]:
        """Record a non-secret, configuration-bound PKCS#11 readiness marker."""
        self._ensure_foundation_unlocked()
        if mode not in {"existing", "initialized"}:
            raise SetupError("Unknown HSM readiness mode")
        if dkek_mode not in {"shares", "disabled"}:
            raise SetupError("Unknown DKEK readiness mode")
        token_serial = str(token_serial).strip()
        normalized_kcv = str(kcv or "").strip().upper()
        if not token_serial:
            raise SetupError("HSM token serial is required")
        if dkek_mode == "shares" and (
            not normalized_kcv
            or any(char not in "0123456789ABCDEF" for char in normalized_kcv)
        ):
            raise SetupError("A valid DKEK KCV is required")
        if dkek_mode == "disabled" and normalized_kcv:
            raise SetupError("Disabled DKEK readiness cannot include a KCV")

        state = load_setup_state(self.state_dir)
        hsm = _normalize_hsm(
            state.data.get("hsm")
            if isinstance(state.data.get("hsm"), dict)
            else None,
            validate_pkcs11_path=True,
        )
        if hsm["backend"] != "pkcs11":
            raise SetupError("PKCS#11 HSM configuration is required")
        marker = {
            "mode": mode,
            "token_serial": token_serial,
            "dkek_mode": dkek_mode,
            "kcv": normalized_kcv or None,
            "digest": _pkcs11_hsm_digest(hsm),
        }
        state.data[_PKCS11_HSM_READY_KEY] = marker
        state.steps["hsm"] = "done"
        save_setup_state(self.state_dir, state)
        return dict(marker)

    def invalidate_pkcs11_ready(self) -> None:
        """Remove PKCS#11 readiness after a live token/KCV identity mismatch."""
        self._ensure_foundation_unlocked()
        state = load_setup_state(self.state_dir)
        state.data.pop(_PKCS11_HSM_READY_KEY, None)
        save_setup_state(self.state_dir, state)

    def database_url(self) -> str | None:
        """The SQLAlchemy URL for a MariaDB choice (embeds credentials), else None."""
        database = load_setup_state(self.state_dir).data.get("database") or {}
        if database.get("kind") != "mariadb":
            return None
        user = urllib.parse.quote(str(database["user"]), safe="")
        password = urllib.parse.quote(str(database["password"]), safe="")
        name = urllib.parse.quote(str(database["name"]), safe="")
        return (
            f"mysql+pymysql://{user}:{password}"
            f"@{database['host']}:{database['port']}/{name}"
        )

    def _sqlite_probe_path(self) -> Path:
        return self.state_dir / "myownca.sqlite3"

    def test_database(self) -> None:
        """Open a connection and run SELECT 1; raise SetupError on any failure."""
        from sqlalchemy import create_engine, text

        url = self.database_url() or f"sqlite:///{self._sqlite_probe_path()}"
        try:
            engine = create_engine(url)
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        except ModuleNotFoundError as exc:  # pymysql not installed
            raise SetupError("MariaDB driver (pymysql) is not installed") from exc
        except Exception as exc:  # noqa: BLE001 - any driver/connection error is a setup failure
            raise SetupError(f"Database connection failed: {exc}") from exc

    def set_service_urls(self, *, admin: str, superuser: str, frontend: str) -> None:
        self._ensure_not_complete()
        state = load_setup_state(self.state_dir)
        state.data["service_urls"] = {
            "admin": admin,
            "superuser": superuser,
            "frontend": frontend,
        }
        state.steps["service_urls"] = "done"
        save_setup_state(self.state_dir, state)

    def set_listener(
        self,
        *,
        topology: str,
        bind_host: str = "",
        bind_port: int | None = None,
        tls_enabled: bool = False,
        tls_cert: str = "",
        tls_key: str = "",
    ) -> None:
        """Save the post-setup service listener; never changes the setup listener."""

        self._ensure_not_complete()
        listener = _normalize_listener(
            {
                "topology": topology,
                "bind_host": bind_host,
                "bind_port": bind_port,
                "tls_enabled": tls_enabled,
                "tls_cert": tls_cert,
                "tls_key": tls_key,
            }
        )
        state = load_setup_state(self.state_dir)
        state.data["listener"] = listener
        state.steps["listener"] = "done"
        save_setup_state(self.state_dir, state)

    def set_issuance_endpoints(self, *, crl: str, aia: str, ocsp: str) -> None:
        self._ensure_not_complete()
        state = load_setup_state(self.state_dir)
        state.data["issuance_endpoints"] = {"crl": crl, "aia": aia, "ocsp": ocsp}
        state.steps["issuance_endpoints"] = "done"
        save_setup_state(self.state_dir, state)

    def set_root_certificate(self, pem: str) -> None:
        self._ensure_foundation_unlocked()
        normalized = pem.strip() + "\n"
        _validate_root_certificate(normalized)
        state = load_setup_state(self.state_dir)
        state.data["root_certificate"] = normalized
        state.steps["root_certificate"] = "done"
        save_setup_state(self.state_dir, state)

    def verify_root_certificate(self, pem: str) -> dict[str, object]:
        """Validate and summarize a Root CA without changing setup state."""

        self._ensure_foundation_unlocked()
        return _validate_root_certificate(pem)

    def set_admins(self, first: dict, second: dict | None = None) -> None:
        self._ensure_not_complete()
        # Single source of truth for the length rule the service enforces at
        # first-boot bootstrap; if the wizard accepted a shorter password than
        # bootstrap requires, the first boot would fail.
        from myownca.ca_auth.service import PASSWORD_MIN_LENGTH

        state = load_setup_state(self.state_dir)
        governance_mode = state.data.get("governance_mode")
        if governance_mode not in GOVERNANCE_MODES:
            raise SetupError("Choose a valid governance mode before creating administrators")
        if governance_mode == "dual_control" and second is None:
            raise SetupError("Dual-control installations require two administrators")

        normalized_admins: list[dict[str, str]] = []
        for admin in (first,) if second is None else (first, second):
            for field in ("id", "email", "password"):
                if not admin.get(field):
                    raise SetupError(f"Each admin requires a non-empty {field}")
            if len(admin["password"]) < PASSWORD_MIN_LENGTH:
                raise SetupError(
                    f"Admin password must be at least {PASSWORD_MIN_LENGTH} characters"
                )
            normalized_admins.append(
                {
                    "id": admin["id"],
                    "email": _normalize_admin_email(admin["email"]),
                    "password": admin["password"],
                }
            )
        if len(normalized_admins) == 2:
            first_normalized, second_normalized = normalized_admins
            if (
                first_normalized["id"] == second_normalized["id"]
                or first_normalized["email"].casefold()
                == second_normalized["email"].casefold()
            ):
                raise SetupError("The two admins must be distinct (id and email)")
        state.data["admins"] = [
            {"id": a["id"], "email": a["email"], "password": a["password"]}
            for a in normalized_admins
        ]
        state.steps["admins"] = "done"
        save_setup_state(self.state_dir, state)

    def prepare_runtime(self, *, require_governance: bool = True) -> None:
        """Materialize stable runtime configuration before issuer provisioning.

        The first issuer must be written to the same database and keystore the
        online service will use.  This method is therefore intentionally
        idempotent: it creates secrets once, keeps them across setup restarts,
        and refreshes only non-secret draft configuration while the issuer
        foundation remains unlocked.
        """

        self._ensure_not_complete()
        state = load_setup_state(self.state_dir)
        install_type = state.data.get("install_type")
        if install_type not in INSTALL_TYPES:
            raise SetupError("Choose an install type before provisioning the issuer")
        governance_mode = state.data.get("governance_mode")
        if install_type == "lab" and governance_mode is None:
            governance_mode = "single_admin"
            state.data["governance_mode"] = governance_mode
            state.steps["governance_mode"] = "done"
        if governance_mode is not None and governance_mode not in GOVERNANCE_MODES:
            raise SetupError("Choose a governance mode before provisioning the issuer")
        if require_governance and governance_mode is None:
            raise SetupError("Choose a governance mode before provisioning the issuer")
        required_totp_roles = state.data.get("totp_required_roles")
        if required_totp_roles is None:
            required_totp_roles = list(DEFAULT_TOTP_REQUIRED_ROLES)
            state.data["totp_required_roles"] = required_totp_roles
            state.steps["totp_policy"] = "done"
        if (
            not isinstance(required_totp_roles, list)
            or any(role not in AUTH_ROLES for role in required_totp_roles)
        ):
            raise SetupError("Choose a valid TOTP policy before provisioning the issuer")

        hsm = _normalize_hsm(
            state.data.get("hsm") if isinstance(state.data.get("hsm"), dict) else None,
            validate_pkcs11_path=True,
        )
        if (
            hsm["backend"] in CLOUD_HSM_BACKENDS
            and not _cloud_hsm_test_is_current(state, hsm)
        ):
            raise SetupError(
                "Test the current cloud key-storage configuration before provisioning "
                "the issuer"
            )
        if hsm["backend"] == "pkcs11" and not _pkcs11_hsm_is_ready(state, hsm):
            raise SetupError(
                "Initialize or adopt the current HSM and complete DKEK import "
                "before provisioning the issuer"
            )
        _require_cloud_sdk(hsm["backend"])
        if install_type == "production" and not state.data.get("root_certificate"):
            raise SetupError("Import the Root CA certificate before provisioning a Production issuer")

        self._write_runtime_files(
            state,
            install_type=install_type,
            governance_mode=governance_mode,
            required_totp_roles=required_totp_roles,
            hsm=hsm,
            require_listener=False,
        )
        save_setup_state(self.state_dir, state)

    def _write_runtime_files(
        self,
        state: SetupState,
        *,
        install_type: str,
        governance_mode: str | None,
        required_totp_roles: list[str],
        hsm: dict[str, str],
        require_listener: bool = False,
    ) -> None:
        state_root = self.state_dir.resolve()
        config: dict[str, str] = {
            "MYOWNCA_LAB_MODE": "true" if install_type == "lab" else "false",
            "MYOWNCA_HSM_BACKEND": hsm["backend"],
            "MYOWNCA_SERVICE_KEY_BACKEND": hsm.get(
                "service_key_backend", "software"
            ),
            "MYOWNCA_TOTP_REQUIRED_ROLES": ",".join(
                role for role in AUTH_ROLES if role in required_totp_roles
            ),
            "MYOWNCA_DATABASE_PATH": str(state_root / "myownca.sqlite3"),
            "MYOWNCA_ONLINE_KEY_DIR": str(state_root / "online-keys"),
            "MYOWNCA_PKCS11_DKEK_SHARE_DIR": str(state_root / "dkek-shares"),
        }
        if governance_mode is not None:
            config["MYOWNCA_GOVERNANCE_MODE"] = governance_mode
        if hsm["backend"] == "pkcs11":
            config["MYOWNCA_PKCS11_LIB"] = hsm["pkcs11_lib"]
            config["MYOWNCA_PKCS11_TOKEN_LABEL"] = hsm["token_label"]
            if hsm.get("reader"):
                config["MYOWNCA_SC_HSM_READER"] = hsm["reader"]
        elif hsm["backend"] == "aws_kms":
            config["MYOWNCA_AWS_REGION"] = hsm["aws_region"]
        elif hsm["backend"] == "azure_key_vault":
            config["MYOWNCA_AZURE_VAULT_URL"] = hsm["azure_vault_url"]
            config["MYOWNCA_AZURE_KEY_PROTECTION"] = hsm[
                "azure_key_protection"
            ]
        service_urls = state.data.get("service_urls") or {}
        for role in ("admin", "superuser", "frontend"):
            value = service_urls.get(role)
            if value:
                config[f"MYOWNCA_{role.upper()}_BASE_URL"] = value
        endpoints = state.data.get("issuance_endpoints") or {}
        for kind in ("crl", "aia", "ocsp"):
            value = endpoints.get(kind)
            if value:
                config[f"MYOWNCA_{kind.upper()}_URL"] = value
        listener_data = state.data.get("listener")
        if listener_data is not None:
            listener = _normalize_listener(listener_data)
            if listener["topology"] == "direct":
                config["MYOWNCA_BIND_HOST"] = str(listener["bind_host"])
                config["MYOWNCA_BIND_PORT"] = str(listener["bind_port"])
                if listener.get("tls_enabled"):
                    config["MYOWNCA_TLS_CERT"] = str(listener["tls_cert"])
                    config["MYOWNCA_TLS_KEY"] = str(listener["tls_key"])
                    config["MYOWNCA_SESSION_COOKIE_SECURE"] = "true"
        elif require_listener:
            raise SetupError("Choose a deployment topology before finalizing")

        existing_secrets = read_secrets(self.state_dir)
        secrets_map: dict[str, str] = dict(existing_secrets)
        secrets_map.setdefault(
            "MYOWNCA_AUTH_ENCRYPTION_SECRET", secrets.token_urlsafe(32)
        )
        secrets_map.setdefault(
            "MYOWNCA_ONLINE_KEY_PASSPHRASE", secrets.token_urlsafe(32)
        )
        secrets_map.setdefault(
            "MYOWNCA_OFFLINE_KEY_PASSPHRASE", secrets.token_urlsafe(32)
        )
        database_url = self.database_url()
        if database_url:
            secrets_map["MYOWNCA_DATABASE_URL"] = database_url
        else:
            secrets_map.pop("MYOWNCA_DATABASE_URL", None)
        if hsm["backend"] == "aws_kms":
            secrets_map["MYOWNCA_AWS_ACCESS_KEY_ID"] = hsm["aws_access_key_id"]
            secrets_map["MYOWNCA_AWS_SECRET_ACCESS_KEY"] = hsm[
                "aws_secret_access_key"
            ]
            if hsm["aws_session_token"]:
                secrets_map["MYOWNCA_AWS_SESSION_TOKEN"] = hsm[
                    "aws_session_token"
                ]
            else:
                secrets_map.pop("MYOWNCA_AWS_SESSION_TOKEN", None)
        elif hsm["backend"] == "azure_key_vault":
            secrets_map["MYOWNCA_AZURE_TENANT_ID"] = hsm["azure_tenant_id"]
            secrets_map["MYOWNCA_AZURE_CLIENT_ID"] = hsm["azure_client_id"]
            secrets_map["MYOWNCA_AZURE_CLIENT_SECRET"] = hsm[
                "azure_client_secret"
            ]

        write_config(self.state_dir, config)
        write_secrets(self.state_dir, secrets_map)
        root_pem = state.data.get("root_certificate")
        if root_pem:
            root_path = self.state_dir / "setup" / "root-ca.pem"
            root_path.parent.mkdir(parents=True, exist_ok=True)
            root_path.write_text(str(root_pem))

    def finalize(self, *, user_pin: str | None = None) -> None:
        """Write config + generated secrets, then drop the completion latch last.

        Materializes the captured config steps: the lab-mode flag, service base
        URLs and issuance endpoints (non-secret, into config.toml), and — for a
        MariaDB choice — the credential-bearing database URL (into secrets.env).
        Later plans extend this with CA, account, and certificate steps.
        """
        self._ensure_not_complete()
        state = load_setup_state(self.state_dir)
        install_type = state.data.get("install_type")
        if install_type not in INSTALL_TYPES:
            raise SetupError("Choose an install type before finalizing")
        governance_mode = state.data.get("governance_mode")
        if install_type == "lab" and governance_mode is None:
            governance_mode = "single_admin"
            state.data["governance_mode"] = governance_mode
            state.steps["governance_mode"] = "done"
        if governance_mode not in GOVERNANCE_MODES:
            raise SetupError("Choose a governance mode before finalizing")
        required_totp_roles = state.data.get("totp_required_roles")
        if required_totp_roles is None:
            required_totp_roles = list(DEFAULT_TOTP_REQUIRED_ROLES)
            state.data["totp_required_roles"] = required_totp_roles
            state.steps["totp_policy"] = "done"
        if (
            not isinstance(required_totp_roles, list)
            or any(role not in AUTH_ROLES for role in required_totp_roles)
        ):
            raise SetupError("Choose a valid TOTP policy before finalizing")
        admins = state.data.get("admins")
        required_admin_count = 2 if governance_mode == "dual_control" else 1
        if (
            not isinstance(admins, list)
            or len(admins) < required_admin_count
            or len(admins) > 2
            or any(
                not isinstance(admin, dict)
                or not admin.get("id")
                or not admin.get("email")
                or not admin.get("password")
                for admin in admins
            )
        ):
            if governance_mode == "dual_control":
                raise SetupError("Create two bootstrap administrator accounts before finalizing")
            raise SetupError("Create a bootstrap administrator account before finalizing")
        hsm = _normalize_hsm(
            state.data.get("hsm") if isinstance(state.data.get("hsm"), dict) else None,
            validate_pkcs11_path=True,
        )
        if (
            hsm["backend"] in CLOUD_HSM_BACKENDS
            and not _cloud_hsm_test_is_current(state, hsm)
        ):
            raise SetupError(
                "Test the current cloud key-storage configuration before finalizing"
            )
        if hsm["backend"] == "pkcs11" and not _pkcs11_hsm_is_ready(state, hsm):
            raise SetupError(
                "Initialize or adopt the current HSM and complete DKEK import "
                "before finalizing"
            )
        _require_cloud_sdk(hsm["backend"])
        if install_type == "production" and not state.data.get("root_certificate"):
            raise SetupError("Import the Root CA certificate before finalizing")
        self._write_runtime_files(
            state,
            install_type=install_type,
            governance_mode=governance_mode,
            required_totp_roles=required_totp_roles,
            hsm=hsm,
            require_listener=True,
        )

        # Test/Lab keeps its one-click path, but it now materializes a real,
        # persisted SubCA row before the completion latch is allowed.
        from myownca.setup.provisioning import (  # noqa: PLC0415
            SetupProvisioningError,
            SetupProvisioningService,
        )

        try:
            provisioning = SetupProvisioningService(
                self.state_dir,
                user_pin=user_pin,
            )
            issuer_status = provisioning.status()
            if not issuer_status["configured"] and install_type == "lab":
                issuer_status = provisioning.provision_lab()
        except SetupProvisioningError as exc:
            raise SetupError(str(exc)) from exc
        try:
            provisioning.assert_finalizable()
        except SetupProvisioningError as exc:
            raise SetupError(str(exc)) from exc

        write_secret_artifact(
            self.state_dir, "pending-admins.json", json.dumps(admins).encode("utf-8")
        )
        state = load_setup_state(self.state_dir)
        if hsm["backend"] in CLOUD_HSM_BACKENDS:
            # From this point the credentials have their canonical 0600 home.
            # Do not leave a second copy in the resumable setup state.
            state.data["hsm"] = _redact_hsm(hsm)
            state.data.pop(_CLOUD_HSM_TEST_KEY, None)
        state.steps["finalize"] = "done"
        save_setup_state(self.state_dir, state)
        mark_setup_complete(
            self.state_dir,
            {
                "install_type": install_type,
                "governance_mode": governance_mode,
                "totp_required_roles": required_totp_roles,
            },
        )
