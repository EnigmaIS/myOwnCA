from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path


def _writable(path: Path) -> bool:
    """True if we can create files at path: probe the first existing ancestor."""
    probe = path
    while not probe.exists():
        if probe.parent == probe:
            return False
        probe = probe.parent
    # The ancestor must be a directory: a file ancestor (e.g. /etc/hosts/sub)
    # is writable but mkdir under it would fail with NotADirectoryError.
    return probe.is_dir() and os.access(probe, os.W_OK)


def preflight(state_dir: str | Path) -> dict[str, object]:
    """Detect what the host can support, to guide the operator's choices."""
    from myownca.config import Settings

    pkcs11_lib = Settings.from_env().resolve_pkcs11_lib()
    return {
        "python_version": ".".join(str(part) for part in sys.version_info[:3]),
        "python_ok": sys.version_info >= (3, 12),
        "pkcs11_lib": pkcs11_lib,
        "hsm_available": pkcs11_lib is not None,
        "state_dir": str(Path(state_dir)),
        "state_dir_writable": _writable(Path(state_dir)),
        "mariadb_driver": importlib.util.find_spec("pymysql") is not None,
    }
