"""Fail closed before importing application modules in installed distributions."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from myownca_release.verify import VerificationError, load_trust, verify_installed
from myownca_release.license_keys import LICENSE_KEYS, read_license_keys, reject_license_override

_verified = False
_license_keys: dict[str, str] = {}


def require_verified() -> None:
    global _verified, _license_keys
    try:
        reject_license_override(os.environ)
    except VerificationError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(78) from exc
    if _verified:
        return
    root = Path(__file__).resolve().parent.parent
    # This is a source-tree layout, never an installed-wheel configuration flag.
    if (root.name == "src" and (root.parent / "pyproject.toml").is_file()
            and (root.parent / "core/myownca_core").is_dir()):
        print("myOwnCA: DEVELOPMENT SOURCE CHECKOUT — release integrity is not enforced",
              file=sys.stderr)
        if (root / LICENSE_KEYS).exists():
            _license_keys = read_license_keys(root / LICENSE_KEYS)
        _verified = True
        return
    try:
        result = verify_installed(root, load_trust(
            Path(sys.prefix) / "etc/myownca/release-trust.json"
        ), include_license_keys=True)
        _license_keys = result.pop("license_public_keys")
    except (OSError, VerificationError) as exc:
        print(json.dumps({"event": "release_integrity", "status": "failed",
                          "time": datetime.now(timezone.utc).isoformat(),
                          "error": str(exc)}), file=sys.stderr)
        raise SystemExit(78) from exc
    print(json.dumps({"event": "release_integrity", "status": "verified", **result}),
          file=sys.stderr)
    _verified = True


def licensing_public_keys() -> dict[str, str]:
    """Return a copy of the ring loaded at the startup verification boundary."""
    require_verified()
    return dict(_license_keys)
