from __future__ import annotations

import hmac
import io
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes

from myownca.ca_hsm.base import (
    SigningKeyBackend,
    public_key_fingerprint,
)
from myownca.ca_hsm.ceremony import HSMCeremonyError, HSMCeremonyService
from myownca.ca_hsm.scctl import (
    DKEKStatus,
    MAX_WRAPPED_KEY_BYTES,
    ScHsmCtl,
    normalize_key_reference as normalize_sc_hsm_key_reference,
)

_MAX_RAW_BACKUP_ARCHIVE_BYTES = 256 * 1024 * 1024
_MAX_RAW_BACKUP_KEYS = 255


class KeyRecoveryError(ValueError):
    """A native HSM backup or restored key failed a safe validation boundary."""


class KeyRecoveryConflictError(KeyRecoveryError):
    """The live token state conflicts with the requested recovery operation."""


class KeyRecoveryRollbackError(KeyRecoveryError):
    """A failed restore left an object that could not be proven deleted."""

    def __init__(self, message: str, *, created_labels: set[str]) -> None:
        super().__init__(message)
        self.created_labels = tuple(sorted(created_labels))


class RecoveryBackend(SigningKeyBackend, Protocol):
    def list_keys(self) -> list[dict[str, object]]: ...

    def delete_key(self, label: str) -> object: ...

    def delete_key_reference(self, key_reference: int | str) -> object: ...


@dataclass(frozen=True, slots=True)
class WrappedKeyBackup:
    key_reference: int
    wrapped_key: bytes
    dkek_status: DKEKStatus
    dkek_kcv: str


@dataclass(frozen=True, slots=True)
class RestoredHSMKey:
    label: str
    key_reference: int
    public_key_sha256: str
    dkek_kcv: str


class HSMKeyRecoveryService:
    """Single policy boundary for SmartCard-HSM key wrap and restore."""

    def __init__(self, backend: RecoveryBackend, scctl: ScHsmCtl) -> None:
        self.backend = backend
        self.scctl = scctl
        self.ceremony = HSMCeremonyService(backend, scctl)

    def inspect_restore_target(
        self,
        key_reference: int | str,
        *,
        wrapped_key: bytes | None = None,
        expected_label: str | None = None,
        expected_kcv: str | None = None,
    ) -> tuple[int, DKEKStatus]:
        if wrapped_key is not None:
            _validate_wrapped_key(wrapped_key)
        reference = normalize_key_reference(key_reference)
        try:
            status = self.ceremony.dkek_status(
                require_complete=True,
                expected_kcv=expected_kcv,
            )
        except HSMCeremonyError as exc:
            raise KeyRecoveryConflictError(str(exc)) from exc
        inventory = self.backend.list_keys()
        if any(
            _item_reference(item) == reference
            or (expected_label is not None and str(item.get("label") or "") == expected_label)
            for item in inventory
        ):
            raise KeyRecoveryConflictError("The target key reference or label is already occupied")
        return reference, status

    def create_wrapped_backup(
        self,
        key_reference: int | str,
        *,
        user_pin: str,
    ) -> WrappedKeyBackup:
        reference = normalize_key_reference(key_reference)
        try:
            status = self.ceremony.dkek_status(require_complete=True)
        except HSMCeremonyError as exc:
            raise KeyRecoveryConflictError(str(exc)) from exc
        if not any(_item_reference(item) == reference for item in self.backend.list_keys()):
            raise KeyRecoveryError("The selected SmartCard-HSM key reference does not exist")
        wrapped_key = self.scctl.wrap_key(reference, user_pin=user_pin)
        assert status.kcv is not None
        return WrappedKeyBackup(
            key_reference=reference,
            wrapped_key=wrapped_key,
            dkek_status=status,
            dkek_kcv=status.kcv.upper(),
        )

    def create_raw_backup_archive(self, *, user_pin: str) -> bytes:
        """Create a plain ZIP containing untouched OpenSC wrapped-key files."""

        try:
            self.ceremony.dkek_status(require_complete=True)
        except HSMCeremonyError as exc:
            raise KeyRecoveryConflictError(str(exc)) from exc
        inventory = self.backend.list_keys()
        if len(inventory) > _MAX_RAW_BACKUP_KEYS:
            raise KeyRecoveryError("The token contains too many keys for a raw backup archive")

        references: set[int] = set()
        key_references: list[int] = []
        for item in inventory:
            reference = _item_reference(item)
            if reference is None:
                label = str(item.get("label") or "unknown")
                raise KeyRecoveryError(f"Token key '{label}' has no valid key reference")
            if reference in references:
                raise KeyRecoveryError("The token contains duplicate key references")
            references.add(reference)
            key_references.append(reference)

        output = io.BytesIO()
        try:
            with zipfile.ZipFile(
                output,
                mode="w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            ) as archive:
                for reference in sorted(key_references):
                    wrapped_key = self.scctl.wrap_key(reference, user_pin=user_pin)
                    _validate_wrapped_key(wrapped_key)
                    archive.writestr(
                        _zip_info(f"wrapped-key-{reference}.bin"),
                        wrapped_key,
                    )
        except (OSError, zipfile.BadZipFile) as exc:
            raise KeyRecoveryError("Could not create the raw HSM backup archive") from exc
        payload = output.getvalue()
        if len(payload) > _MAX_RAW_BACKUP_ARCHIVE_BYTES:
            raise KeyRecoveryError("The raw HSM backup archive exceeds the 256 MiB limit")
        return payload

    @contextmanager
    def restore_key(
        self,
        wrapped_key: bytes,
        *,
        user_pin: str,
        key_reference: int | str,
        expected_public_key: CertificatePublicKeyTypes,
        expected_label: str | None = None,
        expected_kcv: str | None = None,
    ) -> Iterator[RestoredHSMKey]:
        """Restore and verify a key, rolling it back on any enclosed failure."""

        reference, status = self.inspect_restore_target(
            key_reference,
            wrapped_key=wrapped_key,
            expected_label=expected_label,
            expected_kcv=expected_kcv,
        )
        before = self.backend.list_keys()
        before_labels = {str(item.get("label") or "") for item in before if item.get("label")}
        created_label: str | None = None
        try:
            try:
                self.scctl.unwrap_key(
                    wrapped_key,
                    user_pin=user_pin,
                    key_reference=reference,
                    force=False,
                )
            except Exception as first_error:
                # SmartCard-HSM/OpenSC can leave a certificate EF behind after
                # a key is removed.  PKCS#15 then reports an empty inventory,
                # while sc-hsm-tool refuses the next import unless --force is
                # used.  Retry only after the normal, non-destructive attempt
                # failed and a fresh inventory still proves that no live key
                # occupies the requested reference.
                try:
                    occupied = any(
                        _item_reference(item) == reference
                        for item in self.backend.list_keys()
                    )
                except Exception:
                    raise first_error
                if occupied:
                    raise first_error
                try:
                    self.scctl.unwrap_key(
                        wrapped_key,
                        user_pin=user_pin,
                        key_reference=reference,
                        force=True,
                    )
                except Exception as force_error:
                    raise force_error from first_error
            restored_items = [
                item for item in self.backend.list_keys() if _item_reference(item) == reference
            ]
            if len(restored_items) != 1 or not restored_items[0].get("label"):
                raise KeyRecoveryError("Restored key could not be resolved to one PKCS#11 label")
            created_label = str(restored_items[0]["label"])
            if created_label in before_labels:
                raise KeyRecoveryError(
                    "The restored key label was already present before this attempt"
                )
            if expected_label is not None and created_label != expected_label:
                raise KeyRecoveryError("Restored key metadata does not match the native backup")
            verify_restored_key(
                self.backend,
                created_label,
                expected_public_key,
            )
            fingerprint = public_key_fingerprint(expected_public_key)
            assert status.kcv is not None
            yield RestoredHSMKey(
                label=created_label,
                key_reference=reference,
                public_key_sha256=fingerprint,
                dkek_kcv=status.kcv.upper(),
            )
        except Exception as exc:
            cleanup_labels, cleanup_errors = self._rollback_restore(
                reference=reference,
                before_labels=before_labels,
                created_label=created_label,
                expected_label=expected_label,
            )
            if cleanup_errors:
                raise KeyRecoveryRollbackError(
                    "HSM key restore failed and rollback is incomplete",
                    created_labels=cleanup_labels,
                ) from exc
            raise

    def _rollback_restore(
        self,
        *,
        reference: int,
        before_labels: set[str],
        created_label: str | None,
        expected_label: str | None,
    ) -> tuple[set[str], list[Exception]]:
        labels: set[str] = set()
        if created_label and created_label not in before_labels:
            labels.add(created_label)
        reference_present = False
        try:
            for item in self.backend.list_keys():
                label = str(item.get("label") or "")
                matches_reference = _item_reference(item) == reference
                reference_present = reference_present or matches_reference
                if (
                    label
                    and label not in before_labels
                    and (
                        matches_reference
                        or (expected_label is not None and label == expected_label)
                    )
                ):
                    labels.add(label)
        except Exception as exc:  # noqa: BLE001 - report incomplete rollback
            return labels, [exc]

        errors: list[Exception] = []
        if reference_present:
            reference_deleter = getattr(self.backend, "delete_key_reference", None)
            if callable(reference_deleter):
                try:
                    reference_deleter(reference)
                    if any(_item_reference(item) == reference for item in self.backend.list_keys()):
                        raise KeyRecoveryError(
                            "The restored key reference is still present after rollback"
                        )
                except Exception as exc:  # noqa: BLE001 - report incomplete rollback
                    errors.append(exc)
                return labels, errors
            if not labels:
                errors.append(
                    KeyRecoveryError(
                        "The backend cannot safely roll back the restored key by reference"
                    )
                )
                return labels, errors

        for label in sorted(labels):
            try:
                self.backend.delete_key(label)
            except Exception as exc:  # noqa: BLE001 - collect every cleanup failure
                errors.append(exc)
        return labels, errors


def verify_restored_key(
    hsm: SigningKeyBackend,
    key_ref: str,
    expected_public_key: CertificatePublicKeyTypes,
) -> None:
    """Compare the restored SPKI and prove live control of the private key."""

    actual_public_key = hsm.public_key(key_ref)
    expected_fingerprint = public_key_fingerprint(expected_public_key)
    actual_fingerprint = public_key_fingerprint(actual_public_key)
    if not hmac.compare_digest(expected_fingerprint, actual_fingerprint):
        raise KeyRecoveryError("Restored key fingerprint does not match the backup")
    challenge = b"myOwnCA HSM recovery proof v1\x00" + bytes.fromhex(expected_fingerprint)
    try:
        signature = hsm.sign_data(challenge, key_ref)
        _verify_signature(actual_public_key, challenge, signature)
    except KeyRecoveryError:
        raise
    except Exception as exc:  # noqa: BLE001 - normalize provider errors at this boundary
        raise KeyRecoveryError("Restored key failed its signing proof") from exc


def _verify_signature(
    public_key: CertificatePublicKeyTypes,
    payload: bytes,
    signature: bytes,
) -> None:
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature,
                payload,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
        else:  # pragma: no cover - callers reject unsupported key types
            raise KeyRecoveryError("HSM signature-proof key type is unsupported")
    except InvalidSignature as exc:
        raise KeyRecoveryError("HSM signature proof is invalid") from exc


def _validate_wrapped_key(payload: bytes) -> None:
    if not isinstance(payload, bytes):
        raise TypeError("Wrapped key must be bytes")
    if not payload:
        raise KeyRecoveryError("Wrapped key must not be empty")
    if len(payload) > MAX_WRAPPED_KEY_BYTES:
        raise KeyRecoveryError("Wrapped key exceeds the 1 MiB safety limit")


def normalize_key_reference(value: object) -> int:
    try:
        return normalize_sc_hsm_key_reference(value)
    except ValueError as exc:
        raise KeyRecoveryError("Key reference must be an integer from 1 to 255") from exc


def _item_reference(item: dict[str, object]) -> int | None:
    raw_reference = item.get("key_reference")
    if isinstance(raw_reference, int) and not isinstance(raw_reference, bool):
        return raw_reference if 1 <= raw_reference <= 255 else None
    return None


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.date_time = (1980, 1, 1, 0, 0, 0)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o600 << 16
    return info
