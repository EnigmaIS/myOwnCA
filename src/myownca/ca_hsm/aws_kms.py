from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypeVar

from cryptography.hazmat.primitives import hashes, serialization
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

_KEY_SPEC_BY_ALGORITHM = {
    "rsa-2048": "RSA_2048",
    "rsa-3072": "RSA_3072",
    "rsa-4096": "RSA_4096",
    "ecdsa-p256": "ECC_NIST_P256",
    "ecdsa-p384": "ECC_NIST_P384",
    "ecdsa-p521": "ECC_NIST_P521",
}
_ALGORITHM_BY_KEY_SPEC = {value: key for key, value in _KEY_SPEC_BY_ALGORITHM.items()}
_RETRYABLE_ERROR_CODES = {
    "DependencyTimeoutException",
    "InternalException",
    "KMSInternalException",
    "KeyUnavailableException",
    "RequestTimeout",
    "RequestTimeoutException",
    "ServiceUnavailable",
    "ServiceUnavailableException",
    "Throttling",
    "ThrottlingException",
}
_RETRYABLE_EXCEPTION_NAMES = {
    "ConnectionClosedError",
    "ConnectTimeoutError",
    "EndpointConnectionError",
    "HTTPClientError",
    "ReadTimeoutError",
}
_LABEL_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")


class AWSKMSUnavailable(CloudBackendUnavailable):
    pass


class AWSKMSError(CloudBackendError):
    pass


@dataclass(frozen=True, slots=True)
class _AWSKeyRecord:
    key_ref: str
    public_key: CertificatePublicKeyTypes
    algorithm: str
    key_state: str
    signing_algorithms: tuple[str, ...]


class AWSKMSHSM(RemoteSigningBackend):
    """Non-exportable signing backend backed by an asymmetric AWS KMS key."""

    provider_name = "AWS KMS"

    def __init__(
        self,
        *,
        region_name: str,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        aws_session_token: str | None = None,
        client: object | None = None,
    ) -> None:
        if not region_name:
            raise AWSKMSUnavailable(
                self.provider_name,
                "configure client",
                code="MISSING_REGION",
            )
        if (aws_access_key_id is None) != (aws_secret_access_key is None):
            raise AWSKMSUnavailable(
                self.provider_name,
                "configure client",
                code="INCOMPLETE_CREDENTIALS",
            )
        if aws_session_token is not None and aws_access_key_id is None:
            raise AWSKMSUnavailable(
                self.provider_name,
                "configure client",
                code="INCOMPLETE_CREDENTIALS",
            )
        self._region_name = region_name
        self._client = (
            client
            if client is not None
            else self._create_client(
                region_name=region_name,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                aws_session_token=aws_session_token,
            )
        )

    @staticmethod
    def _create_client(
        *,
        region_name: str,
        aws_access_key_id: str | None,
        aws_secret_access_key: str | None,
        aws_session_token: str | None,
    ) -> object:
        try:
            import boto3  # noqa: PLC0415
        except ImportError as exc:
            raise AWSKMSUnavailable(
                "AWS KMS",
                "load SDK",
                code="SDK_NOT_INSTALLED",
                detail="reinstall myownca; the AWS KMS SDK is bundled",
            ) from exc
        options: dict[str, str] = {"region_name": region_name}
        if aws_access_key_id is not None:
            options["aws_access_key_id"] = aws_access_key_id
            options["aws_secret_access_key"] = aws_secret_access_key or ""
        if aws_session_token is not None:
            options["aws_session_token"] = aws_session_token
        return boto3.client("kms", **options)

    def generate_key(self, label: str, algorithm: str = "rsa-2048") -> str:
        _validate_label(label)
        try:
            key_spec = _KEY_SPEC_BY_ALGORITHM[algorithm]
        except KeyError as exc:
            raise ValueError(f"Unsupported AWS KMS key algorithm: {algorithm}") from exc
        response = self._call(
            "create key",
            self._client.create_key,
            Description=f"myOwnCA signing key: {label}",
            KeyUsage="SIGN_VERIFY",
            KeySpec=key_spec,
            Tags=[
                {"TagKey": "myownca:managed", "TagValue": "true"},
                {"TagKey": "myownca:label", "TagValue": label},
            ],
        )
        metadata = response.get("KeyMetadata", {})
        key_ref = metadata.get("Arn")
        if not isinstance(key_ref, str) or not key_ref.startswith("arn:"):
            raise self._validation("create key", "MALFORMED_RESPONSE")
        return key_ref

    def canonicalize_key_ref(self, key_ref: str) -> str:
        metadata = self._describe(key_ref)
        arn = metadata.get("Arn")
        if not isinstance(arn, str) or not arn.startswith("arn:"):
            raise self._validation("describe key", "MALFORMED_RESPONSE")
        return arn

    def attach_key(self, key_ref: str, expected_algorithm: str | None = None) -> str:
        return str(self.validate_key(key_ref, expected_algorithm=expected_algorithm)["key_ref"])

    def validate_key(
        self, key_ref: str, *, expected_algorithm: str | None = None
    ) -> dict[str, object]:
        record = self._load_key(key_ref)
        if expected_algorithm is not None and record.algorithm != expected_algorithm:
            raise self._validation("validate key", "ALGORITHM_MISMATCH")
        return {
            "provider": "aws_kms",
            "key_ref": record.key_ref,
            "algorithm": record.algorithm,
            "protection": "kms",
            "enabled": True,
            "key_state": record.key_state,
            "signing_algorithms": list(record.signing_algorithms),
        }

    def public_key(self, key_ref: str) -> CertificatePublicKeyTypes:
        return self._load_key(key_ref).public_key

    def delete_key(self, key_ref: str, *, pending_window_days: int = 30) -> dict[str, object]:
        if not 7 <= pending_window_days <= 30:
            raise ValueError("AWS KMS pending deletion window must be between 7 and 30 days")
        canonical_ref = self.canonicalize_key_ref(key_ref)
        response = self._call(
            "schedule key deletion",
            self._client.schedule_key_deletion,
            KeyId=canonical_ref,
            PendingWindowInDays=pending_window_days,
        )
        return {
            "provider": "aws_kms",
            "key_ref": canonical_ref,
            "state": "pending_deletion",
            "deletion_date": response.get("DeletionDate"),
        }

    def recover_key(self, key_ref: str) -> str:
        canonical_ref = self.canonicalize_key_ref(key_ref)
        self._call(
            "cancel key deletion",
            self._client.cancel_key_deletion,
            KeyId=canonical_ref,
        )
        # AWS leaves a key disabled after cancellation. Restore the usable state
        # expected by a recovery operation rather than silently returning it disabled.
        self._call("enable key", self._client.enable_key, KeyId=canonical_ref)
        return canonical_ref

    def status(self, key_ref: str | None = None) -> dict[str, object]:
        if key_ref is not None:
            result = self.validate_key(key_ref)
            result["reachable"] = True
            result["region"] = self._region_name
            return result
        self._call("list keys", self._client.list_keys, Limit=1)
        return {
            "provider": "aws_kms",
            "region": self._region_name,
            "reachable": True,
        }

    def self_test(self) -> dict[str, object]:
        return self.status()

    def test_connection(self) -> dict[str, object]:
        return self.status()

    def _load_key(self, key_ref: str) -> _AWSKeyRecord:
        metadata = self._describe(key_ref)
        canonical_ref = metadata.get("Arn")
        if not isinstance(canonical_ref, str) or not canonical_ref.startswith("arn:"):
            raise self._validation("describe key", "MALFORMED_RESPONSE")
        key_state = str(metadata.get("KeyState") or "")
        if metadata.get("Enabled") is False or (key_state and key_state != "Enabled"):
            raise self._validation("validate key", "KEY_NOT_ENABLED")
        if metadata.get("KeyUsage") != "SIGN_VERIFY":
            raise self._validation("validate key", "INVALID_KEY_USAGE")

        response = self._call(
            "get public key",
            self._client.get_public_key,
            KeyId=canonical_ref,
        )
        if response.get("KeyUsage") not in {None, "SIGN_VERIFY"}:
            raise self._validation("validate key", "INVALID_KEY_USAGE")
        public_der = response.get("PublicKey")
        if not isinstance(public_der, bytes):
            raise self._validation("get public key", "MALFORMED_RESPONSE")
        try:
            public_key = serialization.load_der_public_key(public_der)
            algorithm = algorithm_name_for(public_key)
        except (TypeError, ValueError, CloudKeyValidationError) as exc:
            raise self._validation("validate key", "UNSUPPORTED_PUBLIC_KEY") from exc
        key_spec = response.get("KeySpec") or metadata.get("KeySpec")
        if key_spec is not None and _ALGORITHM_BY_KEY_SPEC.get(str(key_spec)) != algorithm:
            raise self._validation("validate key", "KEY_SPEC_MISMATCH")
        signing_algorithms = tuple(str(value) for value in response.get("SigningAlgorithms", ()))
        required = _aws_signing_algorithm(
            public_key, _hash_for_key(public_key), SigningPurpose.X509
        )
        if signing_algorithms and required not in signing_algorithms:
            raise self._validation("validate key", "SIGNING_ALGORITHM_UNAVAILABLE")
        return _AWSKeyRecord(
            key_ref=canonical_ref,
            public_key=public_key,
            algorithm=algorithm,
            key_state=key_state or "Enabled",
            signing_algorithms=signing_algorithms,
        )

    def _describe(self, key_ref: str) -> dict[str, Any]:
        if not key_ref:
            raise self._validation("describe key", "EMPTY_KEY_REFERENCE")
        response = self._call("describe key", self._client.describe_key, KeyId=key_ref)
        metadata = response.get("KeyMetadata")
        if not isinstance(metadata, dict):
            raise self._validation("describe key", "MALFORMED_RESPONSE")
        return metadata

    def _sign_remote(
        self,
        payload: bytes,
        key_ref: str,
        public_key: CertificatePublicKeyTypes,
        hash_algorithm: hashes.HashAlgorithm,
        purpose: SigningPurpose,
    ) -> bytes:
        signing_algorithm = _aws_signing_algorithm(public_key, hash_algorithm, purpose)
        response = self._call(
            "sign",
            self._client.sign,
            KeyId=key_ref,
            Message=hash_payload(payload, hash_algorithm),
            MessageType="DIGEST",
            SigningAlgorithm=signing_algorithm,
        )
        signature = response.get("Signature")
        if not isinstance(signature, bytes):
            raise self._validation("sign", "MALFORMED_RESPONSE")
        return signature

    def _call(
        self,
        operation: str,
        function: Callable[..., _T],
        **kwargs: object,
    ) -> _T:
        try:
            return function(**kwargs)
        except CloudBackendError:
            raise
        except Exception as exc:  # noqa: BLE001 - SDK exception types are optional imports
            code, retryable = _classify_aws_error(exc)
            raise AWSKMSError(
                self.provider_name,
                operation,
                code=code,
                retryable=retryable,
            ) from exc

    def _validation(self, operation: str, code: str) -> CloudKeyValidationError:
        return CloudKeyValidationError(self.provider_name, operation, code=code)


def _aws_signing_algorithm(
    public_key: CertificatePublicKeyTypes,
    hash_algorithm: hashes.HashAlgorithm,
    purpose: SigningPurpose,
) -> str:
    digest_name = {
        "sha256": "SHA_256",
        "sha384": "SHA_384",
        "sha512": "SHA_512",
    }.get(hash_algorithm.name)
    if digest_name is None:
        raise CloudKeyValidationError(
            "AWS KMS",
            "select signing algorithm",
            code="UNSUPPORTED_HASH",
        )
    if isinstance(public_key, rsa.RSAPublicKey):
        prefix = "RSASSA_PSS" if purpose is SigningPurpose.DATA else "RSASSA_PKCS1_V1_5"
        return f"{prefix}_{digest_name}"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"ECDSA_{digest_name}"
    raise CloudKeyValidationError(
        "AWS KMS",
        "select signing algorithm",
        code="UNSUPPORTED_KEY_TYPE",
    )


def _hash_for_key(public_key: CertificatePublicKeyTypes) -> hashes.HashAlgorithm:
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        if public_key.key_size <= 256:
            return hashes.SHA256()
        if public_key.key_size <= 384:
            return hashes.SHA384()
        return hashes.SHA512()
    return hashes.SHA256()


def _validate_label(label: str) -> None:
    if not _LABEL_PATTERN.fullmatch(label):
        raise ValueError(
            "AWS KMS key label must be 1-128 safe alphanumeric, dot, underscore, colon, or dash characters"
        )


def _classify_aws_error(exc: BaseException) -> tuple[str, bool]:
    code = exc.__class__.__name__
    status: int | None = None
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        error = response.get("Error")
        if isinstance(error, dict) and error.get("Code"):
            code = str(error["Code"])
        metadata = response.get("ResponseMetadata")
        if isinstance(metadata, dict) and isinstance(metadata.get("HTTPStatusCode"), int):
            status = metadata["HTTPStatusCode"]
    retryable = (
        code in _RETRYABLE_ERROR_CODES
        or exc.__class__.__name__ in _RETRYABLE_EXCEPTION_NAMES
        or status in {408, 429}
        or bool(status and status >= 500)
    )
    return code, retryable


# Descriptive alias for integrations that don't use the historical HSM terminology.
AWSKMSBackend = AWSKMSHSM
