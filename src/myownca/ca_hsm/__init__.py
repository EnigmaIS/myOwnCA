from __future__ import annotations

from pathlib import Path

from myownca.ca_hsm.base import HSMBackend
from myownca.ca_hsm.pin import HSMPinVault
from myownca.ca_hsm.proxy import HSMProxy
from myownca.ca_hsm.software import SoftwareHSM

__all__ = ["HSMBackend", "HSMPinVault", "HSMProxy", "SoftwareHSM", "create_hsm"]


def create_hsm(
    settings,
    *,
    pin_vault: HSMPinVault,
    key_dir: str | Path | None = None,
    backend_name: str | None = None,
    entropy_source=None,
    pkcs11_token_label: str | None = None,
    pkcs11_pin_provider=None,
) -> tuple[HSMBackend, str]:
    """Construct an HSM backend by name (defaults to ``settings.hsm_backend``).

    Returns ``(backend, name)`` so callers can bind the selected backend to a
    read-only :class:`HSMProxy`. The PKCS#11 backend draws its User PIN from
    ``pin_vault`` so signing only works while an admin session has the token
    unlocked.
    """
    name = backend_name if backend_name is not None else settings.hsm_backend
    if name == "aws_kms":
        from myownca.ca_hsm.aws_kms import AWSKMSHSM  # noqa: PLC0415

        if not settings.aws_region:
            raise RuntimeError("AWS KMS requires MYOWNCA_AWS_REGION")
        if not settings.aws_access_key_id or not settings.aws_secret_access_key:
            raise RuntimeError(
                "AWS KMS requires MYOWNCA_AWS_ACCESS_KEY_ID and "
                "MYOWNCA_AWS_SECRET_ACCESS_KEY"
            )
        return (
            AWSKMSHSM(
                region_name=settings.aws_region,
                aws_access_key_id=settings.aws_access_key_id,
                aws_secret_access_key=settings.aws_secret_access_key,
                aws_session_token=settings.aws_session_token,
            ),
            "aws_kms",
        )

    if name == "azure_key_vault":
        from myownca.ca_hsm.azure_key_vault import AzureKeyVaultHSM  # noqa: PLC0415

        missing = [
            env_name
            for env_name, value in (
                ("MYOWNCA_AZURE_VAULT_URL", settings.azure_vault_url),
                ("MYOWNCA_AZURE_TENANT_ID", settings.azure_tenant_id),
                ("MYOWNCA_AZURE_CLIENT_ID", settings.azure_client_id),
                ("MYOWNCA_AZURE_CLIENT_SECRET", settings.azure_client_secret),
            )
            if not value
        ]
        if missing:
            raise RuntimeError("Azure Key Vault requires: " + ", ".join(missing))
        return (
            AzureKeyVaultHSM(
                vault_url=settings.azure_vault_url,
                tenant_id=settings.azure_tenant_id,
                client_id=settings.azure_client_id,
                client_secret=settings.azure_client_secret,
                key_protection=settings.azure_key_protection,
            ),
            "azure_key_vault",
        )

    if name == "pkcs11":
        from myownca.ca_hsm.pkcs11 import PKCS11HSM  # noqa: PLC0415

        lib_path = settings.resolve_pkcs11_lib()
        if lib_path is None:
            raise RuntimeError(
                "MYOWNCA_HSM_BACKEND=pkcs11 but no PKCS#11 module found; "
                "set MYOWNCA_PKCS11_LIB or install OpenSC"
            )
        backend = PKCS11HSM(
            lib_path,
            pkcs11_token_label or settings.pkcs11_token_label,
            pin_provider=pkcs11_pin_provider or pin_vault.active_pin,
        )
        return backend, "pkcs11"

    if name != "software":
        raise ValueError(f"Unknown HSM backend: {name}")
    resolved_key_dir = Path(key_dir) if key_dir is not None else settings.online_key_dir
    backend = SoftwareHSM(
        resolved_key_dir,
        passphrase=settings.online_key_passphrase,
        # A callable lets the web app layer a runtime (admin-portal) override
        # on top of the env default without rebuilding the backend.
        entropy_source=entropy_source if entropy_source is not None else settings.entropy_source,
    )
    return backend, "software"
