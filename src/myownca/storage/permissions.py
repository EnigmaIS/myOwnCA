"""Report-first permission repair. Does not connect to or migrate a database."""
from __future__ import annotations

import os
import stat
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import TextIO

from sqlalchemy.engine import make_url

from myownca.config import Settings
from myownca_core.storage.database import sqlite_file_path


@contextmanager
def _open_target(path: Path, *, directory: bool):
    """Walk through directory descriptors: no symlinks, including ancestors."""
    path = path.absolute()
    if ".." in path.parts or path == Path(path.anchor):
        raise ValueError("Unsafe path")
    descriptor = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
            )
            os.close(descriptor)
            descriptor = child
        info = os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
        if directory:
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError("Not a real directory")
        elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("Not a regular, singly linked file")
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        if directory:
            flags |= os.O_DIRECTORY
        child = os.open(path.name, flags, dir_fd=descriptor)
        os.close(descriptor)
        descriptor = child
        actual = os.fstat(descriptor)
        if (actual.st_dev, actual.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError("Path changed while inspecting it")
        yield descriptor
    finally:
        os.close(descriptor)


def _targets(state_dir: Path, settings: Settings) -> tuple[dict[Path, int], set[Path]]:
    state = state_dir.absolute()
    key_dirs = {settings.online_key_dir.absolute(), settings.service_key_dir.absolute()}
    # Match the app factory's existing state-relative online-key default.
    if settings.online_key_dir == Path("var/online-keys") and state_dir != Path("var"):
        key_dirs.discard(settings.online_key_dir.absolute())
        key_dirs.add(state / "online-keys")
    directories = {state, state / "setup", state / "secrets", state / "tls", *key_dirs}
    targets = dict.fromkeys(directories, 0o700)
    for relative in (
        "setup/state.json", "setup/complete", "secrets/secrets.env",
        "secrets/pending-admins.json", "tls/portal.key",
    ):
        targets[state / relative] = 0o600
    if settings.database_url:
        url = make_url(settings.database_url)
        database_path = None
        if url.get_backend_name() == "sqlite":
            args, kwargs = url.get_dialect()().create_connect_args(url)
            database_path = sqlite_file_path(args[0], uri=bool(kwargs.get("uri")))
    else:
        database_path = settings.database_path
    if database_path is not None:
        for suffix in ("", "-wal", "-shm", "-journal"):
            targets[Path(str(database_path.absolute()) + suffix)] = 0o600
    return targets, key_dirs


def run_permissions(
    state_dir: str | Path, *, execute: bool = False, stdout: TextIO | None = None
) -> int:
    """Return 0 when protected, 1 for proposed changes, 2 for unsafe/error targets."""
    output = stdout or sys.stdout
    if os.name != "posix":
        print("POSIX permission repair is unavailable; configure filesystem ACLs manually.",
              file=output)
        return 2
    state_dir = Path(state_dir)
    try:
        with _open_target(state_dir, directory=True):
            pass
    except (OSError, ValueError) as exc:
        print(f"State directory unavailable or unsafe ({type(exc).__name__}); no changes made.",
              file=output)
        return 2
    try:
        targets, key_dirs = _targets(state_dir, Settings.load(state_dir))
    except Exception as exc:  # noqa: BLE001 - settings exceptions may contain credentials
        print(f"Cannot load permission targets ({type(exc).__name__}); check configuration.",
              file=output)
        return 2
    errors = False
    changes = False
    forbidden = {Path("/"), Path.home().absolute(), Path.cwd().absolute()}
    for directory in sorted(key_dirs):
        if directory in forbidden:
            continue
        try:
            with _open_target(directory, directory=True) as descriptor:
                for name in os.listdir(descriptor):
                    if name.endswith(".pem"):
                        targets[directory / name] = 0o600
        except FileNotFoundError:
            pass
        except (OSError, ValueError):
            # The directory itself is reported and refused below.
            pass
    if execute:
        print("Applying permissions as the service account; stop the service first.", file=output)
    else:
        print("Report only; no files or permissions will be changed.", file=output)
    for path, desired in sorted(targets.items()):
        try:
            if path in forbidden:
                raise ValueError("Broad directory refused")
            with _open_target(path, directory=desired == 0o700) as descriptor:
                info = os.fstat(descriptor)
                current = stat.S_IMODE(info.st_mode)
                prefix = f"{path}: uid={info.st_uid} gid={info.st_gid} {current:04o} -> {desired:04o}"
                if info.st_uid != os.geteuid():
                    print(f"{prefix} REFUSED: not owned by this service account", file=output)
                    errors = True
                    continue
                if current == desired:
                    print(f"{prefix} OK", file=output)
                    continue
                if execute:
                    os.fchmod(descriptor, desired)
                    print(f"{prefix} repaired", file=output)
                else:
                    changes = True
                    print(f"{prefix} would change", file=output)
        except FileNotFoundError:
            print(f"{path}: absent (no action)", file=output)
        except (OSError, ValueError) as exc:
            # Do not include raw exception messages, file contents or DB URLs.
            print(f"{path}: REFUSED ({type(exc).__name__}); check ownership, links and access",
                  file=output)
            errors = True
    if not execute and changes:
        print("Review backup/scheduler access, then rerun with --execute during maintenance.",
              file=output)
    return 2 if errors else 1 if changes else 0
