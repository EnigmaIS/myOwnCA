from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from myownca_release.license_keys import reject_license_override
from myownca_release.verify import VerificationError

from myownca.setup.config_writer import read_config_env, read_secrets
from myownca.setup.state import is_setup_complete, resolve_state_dir


def _apply_state_dir_config_to_env(
    state_dir: str | Path, environ: dict[str, str] | None = None
) -> None:
    """Bridge file config into the environment so the existing service reads it.

    Builds the same file layer Settings.load uses (secrets override config),
    then setdefaults it in so a real environment variable always wins. This keeps
    the launcher's precedence identical to Settings.load: env > secrets > config.
    """
    environ = os.environ if environ is None else environ
    merged: dict[str, str] = {}
    merged.update(read_config_env(state_dir))
    merged.update(read_secrets(state_dir))
    for key, value in merged.items():
        environ.setdefault(key, value)


def _resolve_setup_port(environ: dict[str, str] | None = None) -> int:
    environ = os.environ if environ is None else environ
    try:
        port = int(environ.get("MYOWNCA_SETUP_PORT", "8765"))
    except ValueError:
        return 8765
    # Fall back on an out-of-range value rather than letting uvicorn fail with
    # an opaque socket error on a typo'd env var.
    return port if 1 <= port <= 65535 else 8765


def _resolve_setup_host(environ: dict[str, str] | None = None) -> str:
    environ = os.environ if environ is None else environ
    host = environ.get("MYOWNCA_SETUP_HOST", "").strip()
    # Default to loopback so bare-metal stays localhost-only; a non-empty
    # override (e.g. "0.0.0.0" in a container) opts into a wider bind.
    return host or "127.0.0.1"


def _setup_banner(port: int, token: str, host: str = "127.0.0.1") -> str:
    if host in ("127.0.0.1", "localhost"):
        location = (
            f"  Open:  http://127.0.0.1:{port}/setup\n"
            f"  Token: {token}\n"
            "  (bound to localhost; forward the port over SSH for remote access)\n"
        )
    else:
        location = (
            f"  Open:  the published setup port {port} on this host  (bound to {host})\n"
            f"         e.g. http://<this-host>:{port}/setup\n"
            f"  Token: {token}\n"
            "  (token-gated; restrict who can reach the published port)\n"
        )
    return "\n  myOwnCA first-run setup\n" + location


def _serve_setup_app(app, host: str, port: int) -> None:
    import uvicorn

    config = uvicorn.Config(app, host=host, port=port, log_level="info")
    server = uvicorn.Server(config)
    # Let the finalize endpoint stop this server so the launcher can hand off.
    # This wiring is exercised at runtime by the finalize endpoint (which calls
    # app.state.request_shutdown); it is not unit-tested here because it needs a
    # live uvicorn server, so the handoff tests substitute _serve_setup_app.
    app.state.request_shutdown = lambda: setattr(server, "should_exit", True)
    server.run()


def _issuer_ready(state_dir: str | Path) -> bool:
    """Return whether the immutable first issuer is durably provisioned.

    Older Lab installations used an effective on-disk lab chain without a
    persisted SubCA row.  Adopt that exact key pair once so upgrades do not
    change their effective trust material.
    """

    from myownca.setup.provisioning import SetupProvisioningService
    from myownca.setup.startup import require_existing_issuer

    provisioning = SetupProvisioningService(state_dir)
    if not provisioning.status()["configured"]:
        adopted = provisioning.adopt_legacy_lab()
        if not adopted or not adopted["configured"]:
            return False
    if is_setup_complete(state_dir):
        require_existing_issuer(
            provisioning.repository,
            provisioning.backend,
            provisioning.backend_name,
            lab_mode=provisioning.settings.lab_mode,
        )
    return True


def run_setup(state_dir: str | Path) -> int:
    if is_setup_complete(state_dir):
        print(
            "Setup is already complete; use 'myownca serve' to start the service.",
            file=sys.stderr,
        )
        return 1
    from myownca.setup.app import create_setup_app
    from myownca.setup.token import SetupAuth

    auth = SetupAuth(os.environ.get("MYOWNCA_SETUP_TOKEN") or None)
    host = _resolve_setup_host()
    port = _resolve_setup_port()
    app = create_setup_app(state_dir, auth)
    print(_setup_banner(port, auth.token, host), file=sys.stderr)
    _serve_setup_app(app, host, port)
    # The server only stops after finalize drops the latch; then boot the service.
    if is_setup_complete(state_dir):
        print("Setup complete — starting myOwnCA service.", file=sys.stderr)
        return run_service(state_dir)
    return 1


def run_service(state_dir: str | Path) -> int:
    try:
        if not _issuer_ready(state_dir):
            if is_setup_complete(state_dir):
                raise ValueError("Configured issuer is missing")
            print(
                "Initial issuing CA is not provisioned — returning to setup.",
                file=sys.stderr,
            )
            return run_setup(state_dir)
        _apply_state_dir_config_to_env(state_dir)
        # An explicit --state-dir must also select the runtime completion marker.
        os.environ["MYOWNCA_STATE_DIR"] = str(Path(state_dir).resolve())
        from myownca.online.app import run as run_online

        run_online()
    except Exception:  # noqa: BLE001 - never expose backend exceptions or credentials
        print(
            "myOwnCA startup failed. Check the existing configuration, database availability "
            "and migrations, and issuing CA backend/key access. Restore missing state from "
            "a verified backup; do not rerun setup or remove the completion marker.",
            file=sys.stderr,
        )
        return 1
    return 0  # uvicorn.run returns None; the service exiting cleanly is success


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="myownca",
        description="Run the myOwnCA setup wizard or service.",
    )
    parser.add_argument("--state-dir", help="State directory (default ./var)")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("setup", help="Run the first-run setup wizard")
    subparsers.add_parser("serve", help="Run the configured CA service")
    security = subparsers.add_parser("security", help="Inspect local installation security")
    security_commands = security.add_subparsers(dest="security_command", required=True)
    permissions = security_commands.add_parser(
        "permissions", help="Report private-file permissions without changing them"
    )
    permissions.add_argument(
        "--execute", action="store_true", help="apply repairs as the service account"
    )
    backup = subparsers.add_parser("backup", help="Verify or restore an application backup")
    backup_commands = backup.add_subparsers(dest="backup_command", required=True)
    verify = backup_commands.add_parser("verify", help="Authenticate and inspect a backup")
    verify.add_argument("archive", type=Path)
    restore = backup_commands.add_parser("restore", help="Restore into an empty installation")
    restore.add_argument("archive", type=Path)
    restore.add_argument("--state-dir", dest="backup_state_dir", type=Path, required=True)
    database = restore.add_mutually_exclusive_group()
    database.add_argument("--database-url")
    database.add_argument("--sqlite", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    state_dir = resolve_state_dir(args.state_dir)
    try:
        reject_license_override(os.environ)
        read_config_env(state_dir)
        read_secrets(state_dir)
    except VerificationError as exc:
        print(str(exc), file=sys.stderr)
        return 78
    command = args.command
    if command == "security":
        from myownca.storage.permissions import run_permissions

        return run_permissions(state_dir, execute=args.execute)
    if command == "backup":
        from myownca.backup.cli import run_backup_command

        return run_backup_command(args)
    if command is None:
        command = "serve" if is_setup_complete(state_dir) else "setup"
    if command == "setup":
        return run_setup(state_dir)
    if command == "serve":
        return run_service(state_dir)
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
