from __future__ import annotations

import tomllib
from pathlib import Path

import tomli_w
from myownca_release.license_keys import reject_license_override
from myownca_core.private_files import atomic_write

_CONFIG_FILE = Path("config.toml")
_SECRETS_FILE = Path("secrets") / "secrets.env"


def _atomic_write_bytes(path: Path, data: bytes, mode: int) -> None:
    """Write bytes to path crash-safely with an exact file mode."""
    atomic_write(path, data, mode)


def write_secrets(state_dir: str | Path, secrets: dict[str, str]) -> Path:
    """Write MYOWNCA_* secret env vars to a 0600 file in a 0700 directory."""
    path = Path(state_dir) / _SECRETS_FILE
    for key, value in secrets.items():
        # A newline in a value would split into extra KEY=value lines on read,
        # silently injecting/clobbering other secrets (e.g. a DB password).
        if "\n" in value or "\r" in value:
            raise ValueError(f"Secret {key} must not contain newlines")
    body = "".join(f"{key}={value}\n" for key, value in secrets.items())
    _atomic_write_bytes(path, body.encode("utf-8"), 0o600)
    return path


def read_secrets(state_dir: str | Path) -> dict[str, str]:
    path = Path(state_dir) / _SECRETS_FILE
    if not path.exists():
        return {}
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        result[key.strip()] = value
    reject_license_override(result)
    return result


def write_config(state_dir: str | Path, env_settings: dict[str, str]) -> Path:
    """Write non-secret MYOWNCA_* settings under a [env] table in config.toml."""
    path = Path(state_dir) / _CONFIG_FILE
    document = {"env": {key: str(value) for key, value in env_settings.items()}}
    _atomic_write_bytes(path, tomli_w.dumps(document).encode("utf-8"), 0o644)
    return path


def read_config_env(state_dir: str | Path) -> dict[str, str]:
    """Read the [env] table from config.toml as MYOWNCA_* string settings."""
    path = Path(state_dir) / _CONFIG_FILE
    if not path.exists():
        return {}
    with path.open("rb") as handle:
        try:
            document = tomllib.load(handle)
        except tomllib.TOMLDecodeError as exc:
            raise ValueError(f"Corrupt config file: {path}") from exc
    result: dict[str, str] = {}
    for key, value in document.get("env", {}).items():
        # The contract is string-only; a hand-edited native TOML bool/int would
        # otherwise coerce to "True"/"8443" and mislead env-var consumers.
        if not isinstance(value, str):
            raise TypeError(
                f"config.toml [env].{key} must be a quoted string; "
                f"got {type(value).__name__}"
            )
        result[str(key)] = value
    reject_license_override(result)
    return result


def write_secret_artifact(state_dir: str | Path, name: str, data: bytes) -> Path:
    """Write a 0600 artifact under secrets/ (e.g. a pending-accounts JSON)."""
    path = Path(state_dir) / "secrets" / name
    _atomic_write_bytes(path, data, 0o600)
    return path
