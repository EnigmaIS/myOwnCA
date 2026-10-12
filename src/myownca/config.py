from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from myownca_release.bootstrap import licensing_public_keys
from myownca_release.license_keys import reject_license_override


_PKCS11_LIB_CANDIDATES = (
    r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll",
    r"C:\Program Files (x86)\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll",
    "/opt/homebrew/lib/opensc-pkcs11.so",
    "/opt/homebrew/opt/opensc/lib/opensc-pkcs11.so",
    "/opt/homebrew/lib/pkcs11/opensc-pkcs11.so",
    "/usr/local/opt/opensc/lib/opensc-pkcs11.so",
    "/usr/local/lib/pkcs11/opensc-pkcs11.so",
    "/usr/lib/pkcs11/opensc-pkcs11.so",
    "/usr/lib64/pkcs11/opensc-pkcs11.so",
    "/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so",
    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    "/usr/local/lib/opensc-pkcs11.so",
)


@dataclass(frozen=True, slots=True)
class Settings:
    database_path: Path
    database_url: str | None
    online_key_dir: Path
    online_key_passphrase: str | None
    auth_encryption_secret: str
    session_cookie_secure: bool
    lab_mode: bool
    lab_common_name: str
    hsm_backend: str
    pkcs11_lib_path: str | None
    pkcs11_token_label: str
    sc_hsm_tool_path: str
    sc_hsm_reader: str | None
    pkcs11_dkek_share_dir: Path
    service_key_dir: Path
    # Cloud signing providers are bundled, but their credentials remain optional
    # because software/PKCS#11 is still the default local configuration.
    aws_region: str | None = None
    aws_access_key_id: str | None = None
    aws_secret_access_key: str | None = None
    aws_session_token: str | None = None
    azure_vault_url: str | None = None
    azure_tenant_id: str | None = None
    azure_client_id: str | None = None
    azure_client_secret: str | None = None
    azure_key_protection: str = "hsm"
    service_key_backend: str = "software"
    governance_mode: str | None = None
    # None means no explicit install-time override; an empty tuple explicitly
    # disables TOTP for every role.
    totp_required_roles: tuple[str, ...] | None = None
    # Optional external RNG device mixed into software key generation
    # (see myownca.keygen); None means the OS CSPRNG alone.
    entropy_source: str | None = None
    bind_host: str = "127.0.0.1"
    bind_port: int = 8000
    tls_cert: str | None = None
    tls_key: str | None = None
    acme_auto_renew: bool = True
    acme_renew_interval_seconds: int = 86400
    ocsp_auto: bool = True
    ocsp_refresh_interval_seconds: int = 86400
    admin_base_url: str | None = None
    superuser_base_url: str | None = None
    frontend_base_url: str | None = None
    crl_url: str | None = None
    aia_url: str | None = None
    ocsp_url: str | None = None
    license_public_keys: dict[str, str] = field(default_factory=dict)
    license_public_keys_error: str | None = None

    @classmethod
    def from_env(cls) -> "Settings":
        return cls.from_mapping(os.environ)

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, str]) -> "Settings":
        def get(name: str, default: str) -> str:
            value = mapping.get(name)
            return default if value is None else value

        reject_license_override(mapping)
        license_public_keys = licensing_public_keys()
        return cls(
            database_path=Path(get("MYOWNCA_DATABASE_PATH", "./var/myownca.sqlite3")),
            database_url=mapping.get("MYOWNCA_DATABASE_URL") or None,
            online_key_dir=Path(get("MYOWNCA_ONLINE_KEY_DIR", "./var/online-keys")),
            online_key_passphrase=mapping.get("MYOWNCA_ONLINE_KEY_PASSPHRASE"),
            auth_encryption_secret=get(
                "MYOWNCA_AUTH_ENCRYPTION_SECRET",
                "change-me-for-local-testing",
            ),
            session_cookie_secure=_parse_bool(
                get("MYOWNCA_SESSION_COOKIE_SECURE", "false")
            ),
            lab_mode=_parse_bool(get("MYOWNCA_LAB_MODE", "true")),
            governance_mode=(
                mapping.get("MYOWNCA_GOVERNANCE_MODE", "").strip().lower() or None
            ),
            totp_required_roles=_parse_totp_required_roles(
                mapping.get("MYOWNCA_TOTP_REQUIRED_ROLES")
            ),
            lab_common_name=get("MYOWNCA_LAB_COMMON_NAME", "myOwnCA Lab Issuing CA"),
            hsm_backend=get("MYOWNCA_HSM_BACKEND", "software").strip().lower(),
            pkcs11_lib_path=mapping.get("MYOWNCA_PKCS11_LIB"),
            pkcs11_token_label=get("MYOWNCA_PKCS11_TOKEN_LABEL", "myOwnCA"),
            sc_hsm_tool_path=get("MYOWNCA_SC_HSM_TOOL", "sc-hsm-tool"),
            sc_hsm_reader=mapping.get("MYOWNCA_SC_HSM_READER") or None,
            pkcs11_dkek_share_dir=Path(
                get("MYOWNCA_PKCS11_DKEK_SHARE_DIR", "./var/dkek-shares")
            ),
            service_key_dir=Path(get("MYOWNCA_SERVICE_KEY_DIR", "./var/service-keys")),
            aws_region=mapping.get("MYOWNCA_AWS_REGION") or None,
            aws_access_key_id=mapping.get("MYOWNCA_AWS_ACCESS_KEY_ID") or None,
            aws_secret_access_key=mapping.get("MYOWNCA_AWS_SECRET_ACCESS_KEY") or None,
            aws_session_token=mapping.get("MYOWNCA_AWS_SESSION_TOKEN") or None,
            azure_vault_url=mapping.get("MYOWNCA_AZURE_VAULT_URL") or None,
            azure_tenant_id=mapping.get("MYOWNCA_AZURE_TENANT_ID") or None,
            azure_client_id=mapping.get("MYOWNCA_AZURE_CLIENT_ID") or None,
            azure_client_secret=mapping.get("MYOWNCA_AZURE_CLIENT_SECRET") or None,
            azure_key_protection=get(
                "MYOWNCA_AZURE_KEY_PROTECTION", "hsm"
            ).strip().lower(),
            service_key_backend=get(
                "MYOWNCA_SERVICE_KEY_BACKEND", "software"
            ).strip().lower(),
            entropy_source=mapping.get("MYOWNCA_ENTROPY_SOURCE") or None,
            bind_host=get("MYOWNCA_BIND_HOST", "127.0.0.1"),
            bind_port=_parse_port(mapping.get("MYOWNCA_BIND_PORT")),
            tls_cert=mapping.get("MYOWNCA_TLS_CERT") or None,
            tls_key=mapping.get("MYOWNCA_TLS_KEY") or None,
            acme_auto_renew=_parse_bool(get("MYOWNCA_ACME_AUTORENEW", "true")),
            acme_renew_interval_seconds=_parse_positive_int(
                mapping.get("MYOWNCA_ACME_RENEW_INTERVAL_SECONDS"), 86400
            ),
            ocsp_auto=_parse_bool(get("MYOWNCA_OCSP_AUTO", "true")),
            ocsp_refresh_interval_seconds=_parse_positive_int(
                mapping.get("MYOWNCA_OCSP_REFRESH_INTERVAL_SECONDS"), 86400
            ),
            admin_base_url=mapping.get("MYOWNCA_ADMIN_BASE_URL") or None,
            superuser_base_url=mapping.get("MYOWNCA_SUPERUSER_BASE_URL") or None,
            frontend_base_url=mapping.get("MYOWNCA_FRONTEND_BASE_URL") or None,
            crl_url=mapping.get("MYOWNCA_CRL_URL") or None,
            aia_url=mapping.get("MYOWNCA_AIA_URL") or None,
            ocsp_url=mapping.get("MYOWNCA_OCSP_URL") or None,
            license_public_keys=license_public_keys,
            license_public_keys_error=None,
        )

    @classmethod
    def load(
        cls,
        state_dir: str | Path,
        environ: Mapping[str, str] | None = None,
    ) -> "Settings":
        """Merge config.toml + secrets.env under environ (environ wins)."""
        # Local import (no circular dependency): config.py is imported early and
        # widely, so defer config_writer's tomllib/tomli_w cost to load() callers.
        from myownca.setup.config_writer import read_config_env, read_secrets

        environ = os.environ if environ is None else environ
        merged: dict[str, str] = {}
        merged.update(read_config_env(state_dir))
        merged.update(read_secrets(state_dir))
        merged.update(
            {key: value for key, value in environ.items() if key.startswith("MYOWNCA_")}
        )
        return cls.from_mapping(merged)

    def resolve_pkcs11_lib(self) -> str | None:
        if self.pkcs11_lib_path:
            return self.pkcs11_lib_path
        for candidate in _PKCS11_LIB_CANDIDATES:
            if Path(candidate).exists():
                return candidate
        return None


def _parse_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_totp_required_roles(value: str | None) -> tuple[str, ...] | None:
    if value is None:
        return None
    allowed = {"admin", "superuser", "auditor", "user"}
    roles = tuple(
        dict.fromkeys(item.strip().lower() for item in value.split(",") if item.strip())
    )
    invalid = sorted(set(roles) - allowed)
    if invalid:
        raise ValueError(
            "MYOWNCA_TOTP_REQUIRED_ROLES contains unknown roles: "
            + ", ".join(invalid)
        )
    return roles


def _parse_port(value: str | None, default: int = 8000) -> int:
    try:
        port = int(value) if value else default
    except ValueError:
        return default
    return port if 1 <= port <= 65535 else default


def _parse_positive_int(value: str | None, default: int) -> int:
    """A positive int from an env value, falling back to ``default`` on junk/non-positive."""
    try:
        parsed = int(value) if value else default
    except ValueError:
        return default
    return parsed if parsed > 0 else default
