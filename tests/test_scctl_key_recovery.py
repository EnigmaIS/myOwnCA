from __future__ import annotations

import stat
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from myownca.ca_hsm.scctl import ScHsmCtl, ScHsmError


def _completed() -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")


def test_wrap_key_uses_mode_0600_temp_file_and_pin_environment() -> None:
    observed_path: Path | None = None

    def run(cmd, **kwargs):
        nonlocal observed_path
        assert "SENSITIVE-PIN" not in cmd
        assert kwargs["env"]["MYOWNCA_SC_HSM_USER_PIN"] == "SENSITIVE-PIN"
        observed_path = Path(cmd[cmd.index("--wrap-key") + 1])
        assert stat.S_IMODE(observed_path.stat().st_mode) == 0o600
        observed_path.write_bytes(b"wrapped-key-description-certificate")
        return _completed()

    with mock.patch("subprocess.run", side_effect=run):
        wrapped = ScHsmCtl().wrap_key(16, user_pin="SENSITIVE-PIN")

    assert wrapped == b"wrapped-key-description-certificate"
    assert observed_path is not None
    assert not observed_path.exists()


def test_unwrap_key_uses_secure_temp_file_normalizes_reference_and_force() -> None:
    observed_path: Path | None = None

    def run(cmd, **kwargs):
        nonlocal observed_path
        assert "RESTORE-PIN" not in cmd
        assert kwargs["env"]["MYOWNCA_SC_HSM_USER_PIN"] == "RESTORE-PIN"
        assert cmd[cmd.index("--key-reference") + 1] == "16"
        assert "--force" in cmd
        observed_path = Path(cmd[cmd.index("--unwrap-key") + 1])
        assert stat.S_IMODE(observed_path.stat().st_mode) == 0o600
        assert observed_path.read_bytes() == b"wrapped bundle"
        return _completed()

    with mock.patch("subprocess.run", side_effect=run):
        ScHsmCtl().unwrap_key(
            b"wrapped bundle",
            user_pin="RESTORE-PIN",
            key_reference="0x10",
            force=True,
        )

    assert observed_path is not None
    assert not observed_path.exists()


def test_unwrap_key_accepts_import_success_marker_from_nonzero_exit() -> None:
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=1,
        stdout="Wrapped key contains:\nKey successfully imported",
        stderr="Using reader with a card",
    )
    with mock.patch("subprocess.run", return_value=completed):
        ScHsmCtl().unwrap_key(
            b"wrapped bundle",
            user_pin="RESTORE-PIN",
            key_reference=252,
        )


def test_subprocess_error_redacts_secret_even_if_tool_echoes_it() -> None:
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=1,
        stdout="",
        stderr="PIN BAD-PIN rejected",
    )
    with mock.patch("subprocess.run", return_value=completed):
        with pytest.raises(ScHsmError) as caught:
            ScHsmCtl().unwrap_key(
                b"wrapped bundle",
                user_pin="BAD-PIN",
                key_reference=1,
            )

    assert "BAD-PIN" not in str(caught.value)
    assert "***" in str(caught.value)


@pytest.mark.parametrize("reference", [-1, 256, "not-a-number", True])
def test_wrap_rejects_unsafe_key_reference_without_running_tool(reference) -> None:
    with mock.patch("subprocess.run") as run:
        with pytest.raises(ValueError, match="1 to 255"):
            ScHsmCtl().wrap_key(reference, user_pin="pin")
    run.assert_not_called()


def test_unwrap_rejects_empty_or_oversized_bundle_without_running_tool() -> None:
    with mock.patch("subprocess.run") as run:
        with pytest.raises(ValueError, match="must not be empty"):
            ScHsmCtl().unwrap_key(b"", user_pin="pin", key_reference=1)
        with pytest.raises(ValueError, match="1 MiB"):
            ScHsmCtl().unwrap_key(b"x" * (1024 * 1024 + 1), user_pin="pin", key_reference=1)
    run.assert_not_called()


def test_existing_dkek_commands_also_keep_secrets_out_of_argv() -> None:
    with mock.patch("subprocess.run", return_value=_completed()) as run:
        ScHsmCtl().initialize(so_pin="SO-SECRET", pin="USER-SECRET", label="myOwnCA")

    command = run.call_args.args[0]
    environment = run.call_args.kwargs["env"]
    assert "SO-SECRET" not in command
    assert "USER-SECRET" not in command
    assert environment["MYOWNCA_SC_HSM_SO_PIN"] == "SO-SECRET"
    assert environment["MYOWNCA_SC_HSM_USER_PIN"] == "USER-SECRET"
