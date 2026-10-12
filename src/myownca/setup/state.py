from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from myownca_core.private_files import atomic_write
DEFAULT_STATE_DIR = Path("./var")
_COMPLETE_MARKER = Path("setup") / "complete"
_STATE_FILE = Path("setup") / "state.json"


def resolve_state_dir(
    explicit: str | Path | None = None,
    environ: dict[str, str] | None = None,
) -> Path:
    """State-dir precedence: explicit arg > MYOWNCA_STATE_DIR > ./var."""
    environ = os.environ if environ is None else environ
    if explicit is not None:
        return Path(explicit)
    env_value = environ.get("MYOWNCA_STATE_DIR")
    if env_value:
        return Path(env_value)
    return DEFAULT_STATE_DIR


def _atomic_write_text(path: Path, data: str, mode: int) -> None:
    """Write data to path crash-safely with an exact file mode."""
    atomic_write(path, data.encode("utf-8"), mode)


def is_setup_complete(state_dir: str | Path) -> bool:
    return (Path(state_dir) / _COMPLETE_MARKER).exists()


def mark_setup_complete(
    state_dir: str | Path, payload: dict | None = None
) -> Path:
    """Write the point-of-no-return latch as the very last setup action."""
    marker = Path(state_dir) / _COMPLETE_MARKER
    _atomic_write_text(marker, json.dumps(payload or {}, indent=2) + "\n", 0o600)
    return marker


@dataclass
class SetupState:
    """In-progress wizard state, persisted before the database exists."""

    steps: dict[str, str] = field(default_factory=dict)
    data: dict[str, object] = field(default_factory=dict)


def load_setup_state(state_dir: str | Path) -> SetupState:
    path = Path(state_dir) / _STATE_FILE
    if not path.exists():
        return SetupState()
    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(f"Corrupt setup state file: {path}") from exc
    return SetupState(steps=raw.get("steps", {}), data=raw.get("data", {}))


def save_setup_state(state_dir: str | Path, state: SetupState) -> None:
    path = Path(state_dir) / _STATE_FILE
    payload = json.dumps({"steps": state.steps, "data": state.data}, indent=2) + "\n"
    _atomic_write_text(path, payload, 0o600)
