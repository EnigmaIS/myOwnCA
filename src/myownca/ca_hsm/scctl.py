from __future__ import annotations

import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

_TIMEOUT_SECONDS = 60
# Args carrying secrets that must be redacted before any log/error surface.
_SECRET_FLAGS = {"--so-pin", "--pin", "--password"}
_ENV_SO_PIN = "MYOWNCA_SC_HSM_SO_PIN"
_ENV_USER_PIN = "MYOWNCA_SC_HSM_USER_PIN"
_ENV_SHARE_PASSWORD = "MYOWNCA_SC_HSM_SHARE_PASSWORD"
MAX_WRAPPED_KEY_BYTES = 1024 * 1024
_IMPORT_SUCCESS_MARKER = "Key successfully imported"


class ScHsmError(RuntimeError):
    def __init__(self, message: str, *, operation_completed: bool = False) -> None:
        super().__init__(message)
        self.operation_completed = operation_completed


@dataclass(frozen=True, slots=True)
class DKEKStatus:
    shares_total: int
    shares_imported: int
    complete: bool
    kcv: str | None = None


class ScHsmCtl:
    """Thin wrapper over the OpenSC ``sc-hsm-tool`` binary.

    SmartCard-HSM / NitroKey HSM cannot be initialized through the standard
    PKCS#11 ``C_InitToken`` call, and DKEK backup management is vendor-specific,
    so these administrative operations shell out to ``sc-hsm-tool``.
    """

    def __init__(
        self,
        tool_path: str = "sc-hsm-tool",
        reader: str | None = None,
    ) -> None:
        self._tool = tool_path
        self._reader = reader.strip() if reader and reader.strip() else None

    def initialize(
        self,
        *,
        so_pin: str,
        pin: str,
        label: str,
        dkek_shares: int = 0,
    ) -> None:
        if dkek_shares < 0:
            raise ValueError("dkek_shares must be zero or positive")
        args = [
            "--initialize",
            "--so-pin",
            f"env:{_ENV_SO_PIN}",
            "--pin",
            f"env:{_ENV_USER_PIN}",
            "--label",
            label,
        ]
        if dkek_shares > 0:
            args += ["--dkek-shares", str(dkek_shares)]
        self._run(args, secrets={_ENV_SO_PIN: so_pin, _ENV_USER_PIN: pin})

    def create_dkek_share(
        self,
        output_path: str | Path,
        *,
        password: str,
    ) -> None:
        args = [
            "--create-dkek-share",
            str(output_path),
            "--password",
            f"env:{_ENV_SHARE_PASSWORD}",
        ]
        self._run(args, secrets={_ENV_SHARE_PASSWORD: password})
        share_output = Path(output_path)
        if share_output.exists():
            os.chmod(share_output, 0o600)

    def import_dkek_share(
        self,
        share_path: str | Path,
        *,
        password: str,
        user_pin: str,
    ) -> DKEKStatus:
        result = self._run(
            [
                "--import-dkek-share",
                str(share_path),
                "--password",
                f"env:{_ENV_SHARE_PASSWORD}",
                "--pin",
                f"env:{_ENV_USER_PIN}",
            ],
            secrets={_ENV_SHARE_PASSWORD: password, _ENV_USER_PIN: user_pin},
        )
        return _parse_dkek_status(result)

    def dkek_status(self) -> DKEKStatus:
        # sc-hsm-tool with no action prints token info including DKEK share state.
        return _parse_dkek_status(self._run([]))

    def wrap_key(self, key_reference: int | str, *, user_pin: str) -> bytes:
        """Return a wrapped SmartCard-HSM key bundle without a persistent temp file."""

        reference = str(normalize_key_reference(key_reference))
        if not user_pin:
            raise ValueError("user_pin must not be empty")
        with tempfile.TemporaryDirectory(prefix="myownca-sc-hsm-") as temp_dir:
            directory = Path(temp_dir)
            os.chmod(directory, 0o700)
            output_path = directory / "wrapped-key.bin"
            descriptor = os.open(
                output_path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
            os.close(descriptor)
            self._run(
                [
                    "--wrap-key",
                    str(output_path),
                    "--key-reference",
                    reference,
                    "--pin",
                    f"env:{_ENV_USER_PIN}",
                ],
                secrets={_ENV_USER_PIN: user_pin},
            )
            try:
                size = output_path.stat().st_size
            except FileNotFoundError as exc:
                raise ScHsmError("sc-hsm-tool did not create a wrapped-key bundle") from exc
            if size <= 0:
                raise ScHsmError("sc-hsm-tool created an empty wrapped-key bundle")
            if size > MAX_WRAPPED_KEY_BYTES:
                raise ScHsmError("Wrapped-key bundle exceeds the 1 MiB safety limit")
            return output_path.read_bytes()

    def unwrap_key(
        self,
        wrapped_key: bytes,
        *,
        user_pin: str,
        key_reference: int | str,
        force: bool = False,
    ) -> None:
        """Restore a wrapped bundle through a mode-0600, short-lived input file."""

        if not isinstance(wrapped_key, bytes):
            raise TypeError("wrapped_key must be bytes")
        if not wrapped_key:
            raise ValueError("wrapped_key must not be empty")
        if len(wrapped_key) > MAX_WRAPPED_KEY_BYTES:
            raise ValueError("wrapped_key exceeds the 1 MiB safety limit")
        if not user_pin:
            raise ValueError("user_pin must not be empty")
        reference = str(normalize_key_reference(key_reference))
        with tempfile.TemporaryDirectory(prefix="myownca-sc-hsm-") as temp_dir:
            directory = Path(temp_dir)
            os.chmod(directory, 0o700)
            input_path = directory / "wrapped-key.bin"
            descriptor = os.open(
                input_path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    descriptor = -1
                    handle.write(wrapped_key)
                    handle.flush()
                    os.fsync(handle.fileno())
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
            args = [
                "--unwrap-key",
                str(input_path),
                "--key-reference",
                reference,
                "--pin",
                f"env:{_ENV_USER_PIN}",
            ]
            if force:
                args.append("--force")
            try:
                self._run(args, secrets={_ENV_USER_PIN: user_pin})
            except ScHsmError as exc:
                # Some OpenSC builds can return exit 1 after the card has
                # already completed the import.  The recovery service still
                # verifies the resulting token object and public key before
                # accepting this as success.
                if not exc.operation_completed:
                    raise

    def _run(self, args: list[str], *, secrets: dict[str, str] | None = None) -> str:
        cmd = [self._tool, *args]
        if self._reader is not None:
            cmd += ["--reader", self._reader]
        secret_values = tuple(value for value in (secrets or {}).values() if value)
        environment = os.environ.copy()
        environment.update(secrets or {})
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_TIMEOUT_SECONDS,
                check=False,
                env=environment,
            )
        except FileNotFoundError as exc:
            raise ScHsmError(
                f"sc-hsm-tool not found at '{self._tool}'. Install OpenSC."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise ScHsmError("sc-hsm-tool timed out") from exc
        if completed.returncode != 0:
            detail = "\n".join(
                part.strip()
                for part in (completed.stderr or "", completed.stdout or "")
                if part.strip()
            )
            operation_completed = _IMPORT_SUCCESS_MARKER in detail
            for secret in secret_values:
                detail = detail.replace(secret, "***")
            raise ScHsmError(
                f"{_redact(cmd)} failed (exit {completed.returncode}): {detail}",
                operation_completed=operation_completed,
            )
        return completed.stdout or ""


def _redact(cmd: list[str]) -> str:
    parts: list[str] = []
    redact_next = False
    for token in cmd:
        if redact_next:
            parts.append("***")
            redact_next = False
            continue
        parts.append(token)
        if token in _SECRET_FLAGS:
            redact_next = True
    return " ".join(parts)


def _parse_dkek_status(output: str) -> DKEKStatus:
    # Example lines from sc-hsm-tool:
    #   "DKEK shares          : 3"
    #   "DKEK import pending, 1 of 3 shares missing"
    #   "DKEK key check value : A1B2C3..."
    total_match = re.search(r"DKEK shares\s*[:=]\s*(\d+)", output)
    total = int(total_match.group(1)) if total_match else 0

    kcv_match = re.search(r"DKEK key check value\s*[:=]\s*([0-9A-Fa-f]+)", output)
    kcv = kcv_match.group(1).upper() if kcv_match else None

    legacy_missing = re.search(
        r"(\d+)\s+of\s+(\d+)\s+shares?\s+(?:still\s+)?missing",
        output,
        re.IGNORECASE,
    )
    current_missing = re.search(
        r"(\d+)\s+share(?:\(s\)|s)?\s+(?:still\s+)?missing",
        output,
        re.IGNORECASE,
    )
    if legacy_missing:
        missing = int(legacy_missing.group(1))
        total = int(legacy_missing.group(2))
    elif current_missing:
        missing = int(current_missing.group(1))
    else:
        missing = 0

    imported = max(0, total - missing)
    complete = total > 0 and missing == 0 and kcv is not None

    return DKEKStatus(
        shares_total=total,
        shares_imported=imported,
        complete=complete,
        kcv=kcv,
    )


def normalize_key_reference(value: object) -> int:
    if isinstance(value, bool):
        raise ValueError("key_reference must be an integer from 1 to 255")
    try:
        reference = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("key_reference must be an integer from 1 to 255") from exc
    if reference < 1 or reference > 255:
        raise ValueError("key_reference must be an integer from 1 to 255")
    return reference
