"""Restrictive creation without changing permissions on existing directories."""
from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path


def mkdir_private(path: Path) -> None:
    """Create missing directories with 0700, preserving existing access rules."""
    try:
        path.mkdir(mode=0o700)
    except FileNotFoundError:
        mkdir_private(path.parent)
        mkdir_private(path)
    except FileExistsError:
        if not path.is_dir():
            raise


def atomic_write(
    path: Path, data: bytes, mode: int = 0o600, *, exclusive: bool = False,
    preserve_access: bool = False,
) -> None:
    """Publish a fully written file; temporary secret material is always 0600."""
    mkdir_private(path.parent)
    original = path.lstat() if preserve_access else None
    if original is not None:
        if not stat.S_ISREG(original.st_mode) or original.st_nlink != 1:
            raise ValueError("Cannot preserve access for a linked or non-regular file")
        if os.name == "posix" and original.st_uid != os.geteuid():
            raise PermissionError("Existing file is not owned by the service account")
        mode = stat.S_IMODE(original.st_mode)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            if original is not None and os.name == "posix":
                os.fchown(handle.fileno(), -1, original.st_gid)
            handle.write(data)
            handle.flush()
            if os.name == "posix":
                os.fchmod(handle.fileno(), mode)
            else:
                os.chmod(temporary, mode)
            os.fsync(handle.fileno())
        if exclusive:
            # An atomic no-clobber publication: a concurrent writer cannot be
            # overwritten between the caller's existence check and publication.
            os.link(temporary, path)
        else:
            os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
