"""Destructive two-token SmartCard-HSM DKEK recovery acceptance test.

This module is skipped unless every explicit safety input below is present. It
reinitializes both selected devices and therefore must only be used with two
dedicated, disposable test HSMs.
"""

from __future__ import annotations

import os
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

import pytest

from myownca.ca_hsm.pkcs11 import PKCS11HSM
from myownca.ca_hsm.recovery import verify_restored_key
from myownca.ca_hsm.scctl import ScHsmCtl


_ENABLED = os.getenv("MYOWNCA_HSM_TEST_DESTRUCTIVE_DKEK_RECOVERY") == "1"
_LIB = os.getenv("MYOWNCA_PKCS11_LIB")
_TOOL = os.getenv("MYOWNCA_HSM_TEST_SC_HSM_TOOL", "sc-hsm-tool")
_SOURCE_READER = os.getenv("MYOWNCA_HSM_TEST_SOURCE_READER")
_TARGET_READER = os.getenv("MYOWNCA_HSM_TEST_TARGET_READER")
_SOURCE_SO_PIN = os.getenv("MYOWNCA_HSM_TEST_SOURCE_SO_PIN")
_TARGET_SO_PIN = os.getenv("MYOWNCA_HSM_TEST_TARGET_SO_PIN")
_SOURCE_PIN = os.getenv("MYOWNCA_HSM_TEST_SOURCE_PIN")
_TARGET_PIN = os.getenv("MYOWNCA_HSM_TEST_TARGET_PIN")

_REQUIRED = (
    _LIB,
    _SOURCE_READER,
    _TARGET_READER,
    _SOURCE_SO_PIN,
    _TARGET_SO_PIN,
    _SOURCE_PIN,
    _TARGET_PIN,
)


@pytest.mark.skipif(
    not _ENABLED or not all(_REQUIRED),
    reason=(
        "set MYOWNCA_HSM_TEST_DESTRUCTIVE_DKEK_RECOVERY=1 and all two-token "
        "HSM safety variables to run this destructive test"
    ),
)
def test_two_hsm_dkek_recovery_roundtrip() -> None:
    assert _LIB is not None
    assert _SOURCE_READER is not None
    assert _TARGET_READER is not None
    assert _SOURCE_SO_PIN is not None
    assert _TARGET_SO_PIN is not None
    assert _SOURCE_PIN is not None
    assert _TARGET_PIN is not None
    if _SOURCE_READER == _TARGET_READER:
        pytest.fail("source and target reader selectors must differ")

    source_label = f"myOwnCA-source-{uuid4().hex[:8]}"
    target_label = f"myOwnCA-target-{uuid4().hex[:8]}"
    key_label = f"bb-recovery-{uuid4().hex[:10]}"
    source_ctl = ScHsmCtl(_TOOL, _SOURCE_READER)
    target_ctl = ScHsmCtl(_TOOL, _TARGET_READER)
    passwords = [f"share-{uuid4().hex}", f"share-{uuid4().hex}"]

    with TemporaryDirectory(prefix="myownca-two-hsm-recovery-") as tempdir:
        share_paths = [
            Path(tempdir) / f"dkek-share-{index}.pbe"
            for index in (1, 2)
        ]
        for path, password in zip(share_paths, passwords, strict=True):
            source_ctl.create_dkek_share(path, password=password)

        source_ctl.initialize(
            so_pin=_SOURCE_SO_PIN,
            pin=_SOURCE_PIN,
            label=source_label,
            dkek_shares=2,
        )
        source_status = None
        for path, password in zip(share_paths, passwords, strict=True):
            source_status = source_ctl.import_dkek_share(
                path,
                password=password,
                user_pin=_SOURCE_PIN,
            )
        assert source_status is not None
        assert source_status.complete and source_status.kcv

        source_hsm = PKCS11HSM(_LIB, source_label, lambda: _SOURCE_PIN)
        source_hsm.generate_key(key_label, "ecdsa-p256")
        source_keys = [
            item for item in source_hsm.list_keys() if item["label"] == key_label
        ]
        assert len(source_keys) == 1
        reference = source_keys[0]["key_reference"]
        assert isinstance(reference, int) and 1 <= reference <= 255
        wrapped = source_ctl.wrap_key(reference, user_pin=_SOURCE_PIN)
        expected_public_key = source_hsm.public_key(key_label)

        target_ctl.initialize(
            so_pin=_TARGET_SO_PIN,
            pin=_TARGET_PIN,
            label=target_label,
            dkek_shares=2,
        )
        target_status = None
        for path, password in zip(share_paths, passwords, strict=True):
            target_status = target_ctl.import_dkek_share(
                path,
                password=password,
                user_pin=_TARGET_PIN,
            )
        assert target_status is not None
        assert target_status.complete
        assert target_status.kcv == source_status.kcv

        target_ctl.unwrap_key(
            wrapped,
            user_pin=_TARGET_PIN,
            key_reference=reference,
            force=False,
        )
        target_hsm = PKCS11HSM(_LIB, target_label, lambda: _TARGET_PIN)
        verify_restored_key(target_hsm, key_label, expected_public_key)

        target_hsm.delete_key(key_label)
        source_hsm.delete_key(key_label)
