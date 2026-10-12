from __future__ import annotations

import io
import zipfile
from unittest import mock

import pytest

from myownca.ca_hsm import SoftwareHSM
from myownca.ca_hsm.recovery import (
    HSMKeyRecoveryService,
    KeyRecoveryError,
    KeyRecoveryRollbackError,
)
from myownca.ca_hsm.scctl import DKEKStatus, ScHsmError


class _TokenBackend(SoftwareHSM):
    def __init__(self) -> None:
        super().__init__()
        self.references: dict[str, int] = {}
        self.deleted: list[str] = []

    def list_keys(self) -> list[dict[str, object]]:
        items = []
        for item in super().list_keys():
            reference = self.references.get(str(item["label"]))
            if reference is None:
                items.append(item)
                continue
            items.append(
                {
                    **item,
                    "key_reference": reference,
                    "id": reference.to_bytes(1, "big").hex(),
                }
            )
        return items

    def restore(self, label: str, key, reference: int) -> None:
        self.import_key(label, key)
        self.references[label] = reference

    def delete_key(self, label: str) -> int:
        self.deleted.append(label)
        self.references.pop(label, None)
        return super().delete_key(label)


def _service(backend: _TokenBackend) -> tuple[HSMKeyRecoveryService, mock.Mock]:
    scctl = mock.Mock()
    scctl.dkek_status.return_value = DKEKStatus(2, 2, True, "A1B2C3")
    return HSMKeyRecoveryService(backend, scctl), scctl


def test_raw_archive_contains_only_untouched_native_bin_files_for_every_key() -> None:
    backend = _TokenBackend()
    backend.generate_key("managed", "ecdsa-p256")
    backend.references["managed"] = 16
    backend.generate_key("external", "rsa-2048")
    backend.references["external"] = 33
    service, scctl = _service(backend)
    scctl.wrap_key.side_effect = lambda reference, *, user_pin: f"native-{reference}".encode()

    archive_bytes = service.create_raw_backup_archive(user_pin="123456")

    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        assert archive.namelist() == ["wrapped-key-16.bin", "wrapped-key-33.bin"]
        assert archive.read("wrapped-key-16.bin") == b"native-16"
        assert archive.read("wrapped-key-33.bin") == b"native-33"
        assert len(archive.namelist()) == 2
    assert [call.args[0] for call in scctl.wrap_key.call_args_list] == [16, 33]
    assert all(call.kwargs == {"user_pin": "123456"} for call in scctl.wrap_key.call_args_list)


def test_raw_archive_fails_before_wrapping_when_reference_is_missing_or_duplicate() -> None:
    backend = _TokenBackend()
    backend.generate_key("missing", "ecdsa-p256")
    service, scctl = _service(backend)

    backend.references.clear()
    with pytest.raises(KeyRecoveryError, match="no valid key reference"):
        service.create_raw_backup_archive(user_pin="123456")
    scctl.wrap_key.assert_not_called()

    backend.references["missing"] = 16
    backend.generate_key("duplicate", "ecdsa-p256")
    backend.references["duplicate"] = 16
    with pytest.raises(KeyRecoveryError, match="duplicate key references"):
        service.create_raw_backup_archive(user_pin="123456")
    scctl.wrap_key.assert_not_called()


def test_raw_archive_requires_complete_dkek_and_propagates_wrap_failure_without_output() -> None:
    backend = _TokenBackend()
    backend.generate_key("issuer", "ecdsa-p256")
    backend.references["issuer"] = 16
    service, scctl = _service(backend)

    scctl.dkek_status.return_value = DKEKStatus(2, 1, False, None)
    with pytest.raises(KeyRecoveryError, match="DKEK"):
        service.create_raw_backup_archive(user_pin="123456")

    scctl.dkek_status.return_value = DKEKStatus(2, 2, True, "A1B2C3")
    scctl.wrap_key.side_effect = RuntimeError("wrap failed")
    with pytest.raises(RuntimeError, match="wrap failed"):
        service.create_raw_backup_archive(user_pin="123456")


def test_raw_archive_enforces_archive_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = _TokenBackend()
    backend.generate_key("issuer", "ecdsa-p256")
    backend.references["issuer"] = 16
    service, scctl = _service(backend)
    scctl.wrap_key.return_value = b"native"
    monkeypatch.setattr(
        "myownca.ca_hsm.recovery._MAX_RAW_BACKUP_ARCHIVE_BYTES",
        1,
    )

    with pytest.raises(KeyRecoveryError, match="256 MiB limit"):
        service.create_raw_backup_archive(user_pin="123456")


def test_restore_uses_native_bytes_and_force_false() -> None:
    source = SoftwareHSM()
    source.generate_key("issuer-key", "ecdsa-p256")
    target = _TokenBackend()
    service, scctl = _service(target)
    scctl.unwrap_key.side_effect = lambda wrapped, **kwargs: target.restore(
        "issuer-key",
        source.private_key("issuer-key"),
        kwargs["key_reference"],
    )

    with service.restore_key(
        b"native-sc-hsm-bin",
        user_pin="123456",
        key_reference=33,
        expected_public_key=source.public_key("issuer-key"),
        expected_label="issuer-key",
    ):
        pass

    scctl.unwrap_key.assert_called_once_with(
        b"native-sc-hsm-bin",
        user_pin="123456",
        key_reference=33,
        force=False,
    )


def test_restore_retries_force_only_after_failed_import_has_no_live_key() -> None:
    source = SoftwareHSM()
    source.generate_key("issuer-key", "ecdsa-p256")
    target = _TokenBackend()
    service, scctl = _service(target)

    def unwrap(_wrapped, **kwargs):
        if not kwargs["force"]:
            raise ScHsmError("dangling certificate")
        target.restore("issuer-key", source.private_key("issuer-key"), kwargs["key_reference"])

    scctl.unwrap_key.side_effect = unwrap

    with service.restore_key(
        b"native-sc-hsm-bin",
        user_pin="123456",
        key_reference=1,
        expected_public_key=source.public_key("issuer-key"),
        expected_label="issuer-key",
    ):
        pass

    assert [call.kwargs["force"] for call in scctl.unwrap_key.call_args_list] == [False, True]


def test_restore_rolls_back_key_after_validation_failure() -> None:
    source = SoftwareHSM()
    source.generate_key("issuer-key", "ecdsa-p256")
    wrong = SoftwareHSM()
    wrong.generate_key("wrong", "ecdsa-p256")
    target = _TokenBackend()
    service, scctl = _service(target)
    scctl.unwrap_key.side_effect = lambda *_args, **kwargs: target.restore(
        "issuer-key",
        wrong.private_key("wrong"),
        kwargs["key_reference"],
    )

    with pytest.raises(KeyRecoveryError, match="fingerprint"):
        with service.restore_key(
            b"native-sc-hsm-bin",
            user_pin="123456",
            key_reference=33,
            expected_public_key=source.public_key("issuer-key"),
        ):
            pass

    assert target.list_keys() == []
    assert target.deleted == ["issuer-key"]


def test_restore_reports_incomplete_rollback() -> None:
    source = SoftwareHSM()
    source.generate_key("issuer-key", "ecdsa-p256")

    class UndeletableTarget(_TokenBackend):
        def delete_key(self, label: str) -> int:
            raise RuntimeError(f"cannot delete {label}")

    target = UndeletableTarget()
    service, scctl = _service(target)
    scctl.unwrap_key.side_effect = lambda *_args, **kwargs: target.restore(
        "issuer-key",
        source.private_key("issuer-key"),
        kwargs["key_reference"],
    )

    with pytest.raises(KeyRecoveryRollbackError, match="rollback is incomplete"):
        with service.restore_key(
            b"native-sc-hsm-bin",
            user_pin="123456",
            key_reference=33,
            expected_public_key=source.public_key("issuer-key"),
        ):
            raise RuntimeError("downstream failure")
