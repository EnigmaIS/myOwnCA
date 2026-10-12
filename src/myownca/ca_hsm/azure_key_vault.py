from __future__ import annotations

import base64
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TypeVar
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes

from myownca.ca_hsm.remote import (
    CloudBackendError,
    CloudBackendUnavailable,
    CloudKeyValidationError,
    RemoteSigningBackend,
    SigningPurpose,
    algorithm_name_for,
    hash_payload,
)

_T = TypeVar("_T")

_CURVE_BY_ALGORITHM = {
    "ecdsa-p256": "P-256",
    "ecdsa-p384": "P-384",
    "ecdsa-p521": "P-521",
}
_CURVE_CLASS_BY_NAME = {
    "P-256": ec.SECP256R1,
    "P-384": ec.SECP384R1,
    "P-521": ec.SECP521R1,
}
_RETRYABLE_ERROR_CODES = {
    "GatewayTimeout",
    "InternalServerError",
    "OperationTimedOut",
    "ServerBusy",
    "ServiceUnavailable",
    "TooManyRequests",
}
_RETRYABLE_EXCEPTION_NAMES = {
    "ServiceRequestError",
    "ServiceResponseError",
    "RetryError",
}
_KEY_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,126}")


class AzureKeyVaultUnavailable(CloudBackendUnavailable):
    pass


class AzureKeyVaultError(CloudBackendError):
    pass


@dataclass(frozen=True, slots=True)
class _AzureKeyRecord:
    key_ref: str
    name: str
    version: str
    public_key: CertificatePublicKeyTypes
    algorithm: str
    protection: str


class AzureKeyVaultHSM(RemoteSigningBackend):
    """Non-exportable signing backend for Azure Key Vault and Managed HSM."""

    provider_name = "Azure Key Vault"

    def __init__(
        self,
        *,
        vault_url: str,
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        key_protection: str = "hsm",
        credential: object | None = None,
        key_client: object | None = None,
        cryptography_client_factory: Callable[[str], object] | None = None,
    ) -> None:
        self._vault_url = _normalize_vault_url(vault_url)
        if key_protection not in {"standard", "hsm"}:
            raise ValueError("Azure key protection must be 'standard' or 'hsm'")
        supplied_secrets = (tenant_id, client_id, client_secret)
        if any(value is not None for value in supplied_secrets) and not all(
            value is not None for value in supplied_secrets
        ):
            raise AzureKeyVaultUnavailable(
                self.provider_name,
                "configure client",
                code="INCOMPLETE_CREDENTIALS",
            )
        self._key_protection = key_protection
        self._credential = credential
        self._crypto_factory = cryptography_client_factory
        if key_client is None:
            if self._credential is None:
                if not all(supplied_secrets):
                    raise AzureKeyVaultUnavailable(
                        self.provider_name,
                        "configure client",
                        code="MISSING_CREDENTIALS",
                    )
                self._credential = self._create_credential(
                    tenant_id=tenant_id or "",
                    client_id=client_id or "",
                    client_secret=client_secret or "",
                )
            self._key_client = self._create_key_client(self._vault_url, self._credential)
        else:
            self._key_client = key_client

    @staticmethod
    def _create_credential(*, tenant_id: str, client_id: str, client_secret: str) -> object:
        try:
            from azure.identity import ClientSecretCredential  # noqa: PLC0415
        except ImportError as exc:
            raise AzureKeyVaultUnavailable(
                "Azure Key Vault",
                "load identity SDK",
                code="SDK_NOT_INSTALLED",
                detail="reinstall myownca; the Azure identity SDK is bundled",
            ) from exc
        return ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )

    @staticmethod
    def _create_key_client(vault_url: str, credential: object) -> object:
        try:
            from azure.keyvault.keys import KeyClient  # noqa: PLC0415
        except ImportError as exc:
            raise AzureKeyVaultUnavailable(
                "Azure Key Vault",
                "load keys SDK",
                code="SDK_NOT_INSTALLED",
                detail="reinstall myownca; the Azure Key Vault SDK is bundled",
            ) from exc
        return KeyClient(vault_url=vault_url, credential=credential)

    def generate_key(self, label: str, algorithm: str = "rsa-2048") -> str:
        _validate_key_name(label)
        common = {
            "hardware_protected": self._key_protection == "hsm",
            "key_operations": ["sign", "verify"],
            "enabled": True,
            "tags": {
                "myownca-managed": "true",
                "myownca-label": label,
            },
        }
        if algorithm.startswith("rsa-"):
            try:
                size = int(algorithm.removeprefix("rsa-"))
            except ValueError as exc:
                raise ValueError(f"Unsupported Azure Key Vault key algorithm: {algorithm}") from exc
            if size not in {2048, 3072, 4096}:
                raise ValueError(f"Unsupported Azure Key Vault key algorithm: {algorithm}")
            key = self._call(
                "create RSA key",
                self._key_client.create_rsa_key,
                label,
                size=size,
                **common,
            )
        else:
            try:
                curve = _CURVE_BY_ALGORITHM[algorithm]
            except KeyError as exc:
                raise ValueError(f"Unsupported Azure Key Vault key algorithm: {algorithm}") from exc
            key = self._call(
                "create EC key",
                self._key_client.create_ec_key,
                label,
                curve=curve,
                **common,
            )
        return self._canonical_id(key, operation="create key")

    def canonicalize_key_ref(self, key_ref: str) -> str:
        return self._canonical_id(self._get_key(key_ref), operation="get key")

    def attach_key(self, key_ref: str, expected_algorithm: str | None = None) -> str:
        return str(self.validate_key(key_ref, expected_algorithm=expected_algorithm)["key_ref"])

    def validate_key(
        self, key_ref: str, *, expected_algorithm: str | None = None
    ) -> dict[str, object]:
        record = self._load_key(key_ref)
        if expected_algorithm is not None and record.algorithm != expected_algorithm:
            raise self._validation("validate key", "ALGORITHM_MISMATCH")
        return {
            "provider": "azure_key_vault",
            "key_ref": record.key_ref,
            "algorithm": record.algorithm,
            "protection": record.protection,
            "enabled": True,
            "key_name": record.name,
            "key_version": record.version,
        }

    def public_key(self, key_ref: str) -> CertificatePublicKeyTypes:
        return self._load_key(key_ref).public_key

    def delete_key(self, key_ref: str) -> dict[str, object]:
        """Soft-delete the Azure key name and all of its versions; never purge it."""

        name, _ = self._parse_key_ref(key_ref)
        poller = self._call("delete key", self._key_client.begin_delete_key, name)
        deleted_key = self._call("wait for key deletion", poller.result)
        return {
            "provider": "azure_key_vault",
            "key_ref": key_ref,
            "state": "deleted",
            "recovery_id": getattr(deleted_key, "recovery_id", None),
            "deleted_on": getattr(deleted_key, "deleted_on", None),
        }

    def validate_managed_key_for_deletion(self, key_ref: str) -> str:
        """Prove a version-pinned key name was created and tagged by myOwnCA.

        Azure's delete API operates on the whole key name, not on one version.
        Callers must perform this check and ensure no other registered version
        is still live before invoking :meth:`delete_key`.
        """

        _, requested_version = self._parse_key_ref(key_ref)
        if not requested_version:
            raise self._validation("authorize key deletion", "UNVERSIONED_KEY_REFERENCE")
        key = self._get_key(key_ref)
        canonical = self._canonical_id(key, operation="authorize key deletion")
        if canonical.rstrip("/") != key_ref.rstrip("/"):
            raise self._validation("authorize key deletion", "KEY_REFERENCE_MISMATCH")
        properties = getattr(key, "properties", None)
        tags = getattr(properties, "tags", None) or getattr(key, "tags", None) or {}
        if not isinstance(tags, Mapping) or str(tags.get("myownca-managed", "")).lower() != "true":
            raise self._validation("authorize key deletion", "KEY_NOT_MANAGED_BY_MYOWNCA")
        return canonical

    def recover_key(self, key_ref: str) -> str:
        name, _ = self._parse_key_ref(key_ref)
        poller = self._call("recover key", self._key_client.begin_recover_deleted_key, name)
        recovered_key = self._call("wait for key recovery", poller.result)
        return self._canonical_id(recovered_key, operation="recover key")

    def status(self, key_ref: str | None = None) -> dict[str, object]:
        if key_ref is not None:
            result = self.validate_key(key_ref)
            result["reachable"] = True
            result["vault_url"] = self._vault_url
            return result
        def fetch_first_key() -> object | None:
            return next(iter(self._key_client.list_properties_of_keys()), None)

        self._call("list keys", fetch_first_key)
        return {
            "provider": "azure_key_vault",
            "vault_url": self._vault_url,
            "reachable": True,
        }

    def self_test(self) -> dict[str, object]:
        return self.status()

    def test_connection(self) -> dict[str, object]:
        return self.status()

    def _load_key(self, key_ref: str) -> _AzureKeyRecord:
        key = self._get_key(key_ref)
        canonical_ref = self._canonical_id(key, operation="get key")
        name, version = self._parse_key_ref(canonical_ref)
        properties = getattr(key, "properties", None)
        if properties is not None and getattr(properties, "enabled", None) is False:
            raise self._validation("validate key", "KEY_NOT_ENABLED")
        jwk = getattr(key, "key", None)
        if jwk is None:
            raise self._validation("validate key", "MISSING_PUBLIC_KEY")
        operations = _enum_values(
            getattr(jwk, "key_ops", None) or getattr(key, "key_operations", None) or ()
        )
        if "sign" not in operations:
            raise self._validation("validate key", "INVALID_KEY_USAGE")
        key_type = _enum_value(getattr(key, "key_type", None) or getattr(jwk, "kty", None))
        try:
            public_key = _public_key_from_jwk(jwk, key_type)
            algorithm = algorithm_name_for(public_key)
        except (TypeError, ValueError, CloudKeyValidationError) as exc:
            raise self._validation("validate key", "UNSUPPORTED_PUBLIC_KEY") from exc
        protection = "hsm" if key_type.upper().endswith("-HSM") else "standard"
        return _AzureKeyRecord(
            key_ref=canonical_ref,
            name=name,
            version=version or "",
            public_key=public_key,
            algorithm=algorithm,
            protection=protection,
        )

    def _get_key(self, key_ref: str) -> object:
        name, version = self._parse_key_ref(key_ref)
        return self._call("get key", self._key_client.get_key, name, version)

    def _canonical_id(self, key: object, *, operation: str) -> str:
        key_id = getattr(key, "id", None)
        if not isinstance(key_id, str):
            raise self._validation(operation, "MALFORMED_RESPONSE")
        _, version = self._parse_key_ref(key_id)
        if not version:
            raise self._validation(operation, "UNVERSIONED_KEY_REFERENCE")
        return key_id.rstrip("/")

    def _parse_key_ref(self, key_ref: str) -> tuple[str, str | None]:
        if _KEY_NAME_PATTERN.fullmatch(key_ref):
            return key_ref, None
        parsed = urlsplit(key_ref)
        vault = urlsplit(self._vault_url)
        if (
            parsed.scheme.lower() != vault.scheme.lower()
            or parsed.netloc.lower() != vault.netloc.lower()
            or parsed.query
            or parsed.fragment
        ):
            raise self._validation("parse key reference", "INVALID_KEY_REFERENCE")
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) not in {2, 3} or parts[0].lower() != "keys":
            raise self._validation("parse key reference", "INVALID_KEY_REFERENCE")
        name = parts[1]
        _validate_key_name(name)
        version = parts[2] if len(parts) == 3 else None
        if version is not None and not re.fullmatch(r"[A-Za-z0-9-]+", version):
            raise self._validation("parse key reference", "INVALID_KEY_REFERENCE")
        return name, version

    def _crypto_client(self, key_ref: str) -> object:
        if self._crypto_factory is not None:
            return self._crypto_factory(key_ref)
        name, version = self._parse_key_ref(key_ref)
        getter = getattr(self._key_client, "get_cryptography_client", None)
        if getter is not None:
            return getter(name, key_version=version)
        if self._credential is None:
            raise AzureKeyVaultUnavailable(
                self.provider_name,
                "create cryptography client",
                code="MISSING_CREDENTIAL",
            )
        try:
            from azure.keyvault.keys.crypto import CryptographyClient  # noqa: PLC0415
        except ImportError as exc:
            raise AzureKeyVaultUnavailable(
                self.provider_name,
                "load keys SDK",
                code="SDK_NOT_INSTALLED",
                detail="reinstall myownca; the Azure Key Vault SDK is bundled",
            ) from exc
        return CryptographyClient(key_ref, credential=self._credential)

    def _sign_remote(
        self,
        payload: bytes,
        key_ref: str,
        public_key: CertificatePublicKeyTypes,
        hash_algorithm: hashes.HashAlgorithm,
        purpose: SigningPurpose,
    ) -> bytes:
        algorithm = _azure_signing_algorithm(public_key, hash_algorithm, purpose)
        crypto_client = self._crypto_client(key_ref)
        response = self._call(
            "sign",
            crypto_client.sign,
            _signature_algorithm_value(algorithm),
            hash_payload(payload, hash_algorithm),
        )
        signature = getattr(response, "signature", None)
        if not isinstance(signature, bytes):
            raise self._validation("sign", "MALFORMED_RESPONSE")
        return signature

    def _call(
        self,
        operation: str,
        function: Callable[..., _T],
        *args: object,
        **kwargs: object,
    ) -> _T:
        try:
            return function(*args, **kwargs)
        except CloudBackendError:
            raise
        except Exception as exc:  # noqa: BLE001 - SDK exception types are optional imports
            code, retryable = _classify_azure_error(exc)
            raise AzureKeyVaultError(
                self.provider_name,
                operation,
                code=code,
                retryable=retryable,
            ) from exc

    def _validation(self, operation: str, code: str) -> CloudKeyValidationError:
        return CloudKeyValidationError(self.provider_name, operation, code=code)


def _public_key_from_jwk(jwk: object, key_type: str) -> CertificatePublicKeyTypes:
    normalized_type = key_type.upper()
    if normalized_type in {"RSA", "RSA-HSM"}:
        modulus = int.from_bytes(_jwk_bytes(getattr(jwk, "n", None)), "big")
        exponent = int.from_bytes(_jwk_bytes(getattr(jwk, "e", None)), "big")
        return rsa.RSAPublicNumbers(exponent, modulus).public_key()
    if normalized_type in {"EC", "EC-HSM"}:
        curve_name = _enum_value(getattr(jwk, "crv", None))
        try:
            curve = _CURVE_CLASS_BY_NAME[curve_name]()
        except KeyError as exc:
            raise ValueError(f"Unsupported Azure EC curve: {curve_name}") from exc
        x = int.from_bytes(_jwk_bytes(getattr(jwk, "x", None)), "big")
        y = int.from_bytes(_jwk_bytes(getattr(jwk, "y", None)), "big")
        return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
    raise ValueError(f"Unsupported Azure key type: {key_type}")


def _jwk_bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, int) and value > 0:
        return value.to_bytes((value.bit_length() + 7) // 8, "big")
    if isinstance(value, str):
        padding = "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(value + padding)
    raise ValueError("Azure JWK is missing required public key material")


def _azure_signing_algorithm(
    public_key: CertificatePublicKeyTypes,
    hash_algorithm: hashes.HashAlgorithm,
    purpose: SigningPurpose,
) -> str:
    digest_name = {
        "sha256": "256",
        "sha384": "384",
        "sha512": "512",
    }.get(hash_algorithm.name)
    if digest_name is None:
        raise CloudKeyValidationError(
            "Azure Key Vault",
            "select signing algorithm",
            code="UNSUPPORTED_HASH",
        )
    if isinstance(public_key, rsa.RSAPublicKey):
        prefix = "PS" if purpose is SigningPurpose.DATA else "RS"
        return f"{prefix}{digest_name}"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"ES{digest_name}"
    raise CloudKeyValidationError(
        "Azure Key Vault",
        "select signing algorithm",
        code="UNSUPPORTED_KEY_TYPE",
    )


def _signature_algorithm_value(value: str) -> object:
    # Production uses the SDK enum. Returning the wire value if the bundled SDK
    # is absent keeps injected fake clients usable in isolated test clients.
    try:
        from azure.keyvault.keys.crypto import SignatureAlgorithm  # noqa: PLC0415
    except ImportError:
        return value
    return SignatureAlgorithm(value)


def _normalize_vault_url(vault_url: str) -> str:
    parsed = urlsplit(vault_url)
    if (
        parsed.scheme.lower() != "https"
        or not parsed.netloc
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise ValueError("Azure vault URL must be an HTTPS origin without a path or credentials")
    return f"https://{parsed.netloc.lower()}"


def _validate_key_name(name: str) -> None:
    if not _KEY_NAME_PATTERN.fullmatch(name):
        raise ValueError("Azure key name must be 1-127 alphanumeric or dash characters")


def _enum_value(value: object) -> str:
    enum_value = getattr(value, "value", value)
    return str(enum_value or "")


def _enum_values(values: object) -> set[str]:
    return {_enum_value(value) for value in values} if values else set()


def _classify_azure_error(exc: BaseException) -> tuple[str, bool]:
    code = exc.__class__.__name__
    status = getattr(exc, "status_code", None)
    response = getattr(exc, "response", None)
    if not isinstance(status, int) and response is not None:
        response_status = getattr(response, "status_code", None)
        if isinstance(response_status, int):
            status = response_status
    error = getattr(exc, "error", None)
    error_code = getattr(error, "code", None)
    if error_code:
        code = str(error_code)
    retryable = (
        code in _RETRYABLE_ERROR_CODES
        or exc.__class__.__name__ in _RETRYABLE_EXCEPTION_NAMES
        or status in {408, 429}
        or bool(isinstance(status, int) and status >= 500)
    )
    return code, retryable


# Descriptive alias for integrations that don't use the historical HSM terminology.
AzureKeyVaultBackend = AzureKeyVaultHSM
