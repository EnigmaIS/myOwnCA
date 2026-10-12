from __future__ import annotations

import hmac
import os
import tempfile
from pathlib import Path
from typing import Protocol

from myownca.ca_hsm.scctl import DKEKStatus, ScHsmCtl

_MAX_SHARE_BYTES = 5 * 1024 * 1024


class HSMCeremonyError(ValueError):
    """A token ceremony failed a non-secret validation boundary."""


class CeremonyBackend(Protocol):
    def status(self) -> dict[str, object]: ...

    def verify_pin(self, pin: str) -> None: ...

    def list_keys(self) -> list[dict[str, object]]: ...


class HSMCeremonyService:
    """Shared SmartCard-HSM setup/admin ceremony boundary.

    PINs and share passwords are accepted only as per-call values. This object
    never stores them, logs them, or returns them in status data.
    """

    def __init__(self, backend: CeremonyBackend, scctl: ScHsmCtl) -> None:
        self.backend = backend
        self.scctl = scctl

    def probe(
        self,
        *,
        user_pin: str | None = None,
        reader: str | None = None,
    ) -> dict[str, object]:
        status = self.backend.status()
        raw_token = status.get("token")
        token = raw_token if isinstance(raw_token, dict) else {}
        keys: list[dict[str, object]] | None = None
        pin_verified = False
        if user_pin and token.get("initialized"):
            self.backend.verify_pin(user_pin)
            keys = self.key_inventory()
            pin_verified = True
        try:
            dkek_status = self.dkek_status()
        except RuntimeError:
            dkek: dict[str, object] = {"available": False}
        else:
            dkek = {
                "available": True,
                "shares_total": dkek_status.shares_total,
                "shares_imported": dkek_status.shares_imported,
                "complete": dkek_status.complete,
                "kcv": dkek_status.kcv,
            }
        return {
            "initialized": bool(token.get("initialized")),
            "label": token.get("label"),
            "serial": token.get("serial"),
            "reader": reader or None,
            "token_present": bool(status.get("token_present")),
            "keys_present": None if keys is None else bool(keys),
            "key_count": None if keys is None else len(keys),
            "keys": keys,
            "pin": {
                "verified": pin_verified,
                "initialized": bool(token.get("user_pin_initialized")),
                "tries_left": status.get("pin_tries_left"),
            },
            "dkek": dkek,
        }

    @staticmethod
    def readiness_matches(
        probe: dict[str, object],
        *,
        expected_serial: str,
        expected_dkek_mode: str,
        expected_kcv: str | None,
    ) -> bool:
        raw_dkek = probe.get("dkek")
        dkek = raw_dkek if isinstance(raw_dkek, dict) else {}
        identity_matches = bool(
            probe.get("token_present")
            and probe.get("initialized")
            and hmac.compare_digest(
                str(probe.get("serial") or ""),
                str(expected_serial),
            )
        )
        if not identity_matches or dkek.get("available") is not True:
            return False
        if expected_dkek_mode == "disabled":
            return bool(
                int(dkek.get("shares_total") or 0) == 0
                and not dkek.get("complete")
                and not dkek.get("kcv")
            )
        if expected_dkek_mode != "shares":
            return False
        return bool(
            dkek.get("complete")
            and hmac.compare_digest(
                str(dkek.get("kcv") or "").upper(),
                str(expected_kcv or "").upper(),
            )
        )

    def assert_readiness(
        self,
        *,
        expected_serial: str,
        expected_dkek_mode: str,
        expected_kcv: str | None,
        user_pin: str | None = None,
        reader: str | None = None,
    ) -> dict[str, object]:
        live = self.probe(user_pin=user_pin, reader=reader)
        if not self.readiness_matches(
            live,
            expected_serial=expected_serial,
            expected_dkek_mode=expected_dkek_mode,
            expected_kcv=expected_kcv,
        ):
            raise HSMCeremonyError("The live HSM token or DKEK state does not match readiness")
        return live

    def initialize(
        self,
        *,
        so_pin: str,
        user_pin: str,
        current_user_pin: str | None,
        label: str,
        dkek_shares: int,
        erase_existing_keys: bool = False,
    ) -> list[dict[str, object]]:
        if dkek_shares < 0 or dkek_shares > 255:
            raise HSMCeremonyError("DKEK share count must be from 0 to 255")
        status = self.backend.status()
        raw_token = status.get("token")
        token = raw_token if isinstance(raw_token, dict) else {}
        existing_keys: list[dict[str, object]] = []
        if not status.get("token_present"):
            raise HSMCeremonyError("The selected HSM token is not present")
        if token.get("initialized"):
            if not current_user_pin:
                raise HSMCeremonyError(
                    "Current User PIN is required to prove an initialized target HSM is empty"
                )
            self.backend.verify_pin(current_user_pin)
            existing_keys = self.key_inventory()
            if existing_keys and not erase_existing_keys:
                raise HSMCeremonyError(
                    "Initialization is blocked because the selected HSM contains keys; "
                    "retry to proceed with erasure"
                )
        self.scctl.initialize(
            so_pin=so_pin,
            pin=user_pin,
            label=label,
            dkek_shares=dkek_shares,
        )
        return existing_keys

    def create_dkek_share(self, *, password: str) -> bytes:
        """Generate one share without retaining it outside the current call."""

        with tempfile.TemporaryDirectory(prefix="myownca-dkek-share-") as temp_dir:
            directory = Path(temp_dir)
            os.chmod(directory, 0o700)
            share_path = directory / "share.pbe"
            self.scctl.create_dkek_share(share_path, password=password)
            payload = share_path.read_bytes()
        if not payload or len(payload) > _MAX_SHARE_BYTES:
            raise HSMCeremonyError("DKEK share has an invalid size")
        return payload

    def create_dkek_shares(
        self,
        *,
        passwords: list[str],
        max_total_bytes: int,
    ) -> list[bytes]:
        """Generate a bounded batch without retaining it beyond the current call."""

        if not passwords or len(passwords) > 255:
            raise HSMCeremonyError("Generate from 1 to 255 DKEK shares")
        shares: list[bytes] = []
        total_bytes = 0
        for password in passwords:
            share = self.create_dkek_share(password=password)
            total_bytes += len(share)
            if total_bytes > max_total_bytes:
                raise HSMCeremonyError(
                    "DKEK share archive exceeds the configured safety limit"
                )
            shares.append(share)
        return shares

    def key_inventory(self) -> list[dict[str, object]]:
        """Return non-secret key metadata with the backend's stable key reference."""

        inventory: list[dict[str, object]] = []
        for item in self.backend.list_keys():
            key = dict(item)
            key_ref = str(key.get("key_ref") or key.get("label") or "").strip()
            if key_ref:
                key["key_ref"] = key_ref
            inventory.append(key)
        return inventory

    def import_dkek_shares(
        self,
        shares: list[tuple[bytes, str]],
        *,
        user_pin: str,
        require_complete: bool = True,
    ) -> DKEKStatus:
        """Import share bytes through private temporary files.

        A completing ceremony must provide exactly the shares still missing
        from the token.  The administrator may import one share at a time by
        setting ``require_complete=False``.
        """

        if not shares:
            raise HSMCeremonyError("Provide at least one DKEK share")
        self.backend.verify_pin(user_pin)
        expected = self.dkek_status()
        if expected.shares_total < 1:
            raise HSMCeremonyError("The selected HSM was not initialized for DKEK")
        missing = max(0, expected.shares_total - expected.shares_imported)
        if require_complete and len(shares) != missing:
            raise HSMCeremonyError(f"Import exactly {missing} missing DKEK shares")
        if len(shares) > missing:
            raise HSMCeremonyError(f"The selected HSM accepts at most {missing} more DKEK shares")
        observed_kcvs: set[str] = set()
        with tempfile.TemporaryDirectory(prefix="myownca-dkek-import-") as temp_dir:
            directory = Path(temp_dir)
            os.chmod(directory, 0o700)
            for index, (share, password) in enumerate(shares, start=1):
                if not share or len(share) > _MAX_SHARE_BYTES:
                    raise HSMCeremonyError(f"DKEK share {index} has an invalid size")
                share_path = directory / f"share-{index}.pbe"
                descriptor = os.open(
                    share_path,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                    0o600,
                )
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(share)
                    handle.flush()
                    os.fsync(handle.fileno())
                share_status = self.scctl.import_dkek_share(
                    share_path,
                    password=password,
                    user_pin=user_pin,
                )
                if share_status.kcv:
                    observed_kcvs.add(share_status.kcv.upper())
        final_status = self.dkek_status()
        if final_status.kcv:
            observed_kcvs.add(final_status.kcv.upper())
        if len(observed_kcvs) > 1:
            raise HSMCeremonyError("DKEK key check values are inconsistent")
        if require_complete and (not final_status.complete or not final_status.kcv):
            raise HSMCeremonyError("DKEK import is incomplete or has no KCV")
        return final_status

    def dkek_status(
        self,
        *,
        require_complete: bool = False,
        expected_kcv: str | None = None,
    ) -> DKEKStatus:
        status = self.scctl.dkek_status()
        if require_complete and (not status.complete or not status.kcv):
            raise HSMCeremonyError("The selected HSM has an incomplete DKEK")
        if expected_kcv is not None:
            if (
                not status.complete
                or not status.kcv
                or not hmac.compare_digest(
                    status.kcv.upper(),
                    expected_kcv.strip().upper(),
                )
            ):
                raise HSMCeremonyError("The selected HSM DKEK KCV does not match the expected KCV")
        return status

    def adopt(
        self,
        *,
        user_pin: str,
    ) -> tuple[dict[str, object], list[dict[str, object]], DKEKStatus]:
        status = self.backend.status()
        raw_token = status.get("token")
        token = raw_token if isinstance(raw_token, dict) else {}
        if not token.get("initialized") or not token.get("user_pin_initialized"):
            raise HSMCeremonyError("The selected HSM is not initialized")
        self.backend.verify_pin(user_pin)
        keys = self.key_inventory()
        dkek = self.dkek_status(require_complete=True)
        return token, keys, dkek
