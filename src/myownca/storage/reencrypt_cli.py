"""``myownca-reencrypt-secrets`` — audited control over the F-1 secret migration.

The re-encryption also runs automatically at boot, so this command exists for the
cases automation should not decide on its own:

* **inspect before touching anything** — the default is a read-only report, and it
  can be pointed at a *copy* of the database first;
* **diagnose a wrong operator secret** — reported plainly, instead of surfacing
  later as a failed login or a misattributed ACME error;
* **roll back** — ``--to-legacy`` converts the secrets back so an older build,
  which has no domain-separated keys, can read them again.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TextIO

from myownca.config import Settings
from myownca.storage.database import Database
from myownca.storage.reencrypt import reencrypt_secrets


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="myownca-reencrypt-secrets",
        description=(
            "Re-encrypt stored secrets under the per-subsystem keys (finding F-1). "
            "Read-only unless --execute is given."
        ),
    )
    parser.add_argument(
        "--database-path",
        type=Path,
        help="SQLite database path (defaults to MYOWNCA_DATABASE_URL/PATH)",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="write the converted secrets; without this the command only reports",
    )
    parser.add_argument(
        "--to-legacy",
        action="store_true",
        help=(
            "reverse: convert back to the pre-F-1 shared key so an older build can "
            "read them again"
        ),
    )
    return parser


def run(
    argv: list[str] | None = None,
    *,
    settings: Settings | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    args = build_parser().parse_args(argv)
    settings = settings or Settings.from_env()
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr

    database_target = (
        args.database_path
        if args.database_path is not None
        else settings.database_url or settings.database_path
    )
    database = Database(database_target)
    database.migrate()

    direction = "legacy (pre-F-1) key" if args.to_legacy else "domain-separated keys"
    try:
        result = reencrypt_secrets(
            database,
            settings.auth_encryption_secret,
            to_legacy=args.to_legacy,
            dry_run=not args.execute,
        )
    except ValueError as exc:
        print(f"Refusing to continue: {exc}", file=stderr)
        return 2

    verb = "Converted" if args.execute else "Would convert"
    print(f"{verb} {result.converted} secret(s) to the {direction}.", file=stdout)
    for column, count in sorted(result.per_column.items()):
        print(f"  {column}: {count}", file=stdout)
    print(f"Already current: {result.already_current}", file=stdout)
    print(f"Empty or unset (skipped): {result.skipped_empty}", file=stdout)
    if result.failed:
        print(f"Undecryptable: {result.failed}", file=stderr)
        for note in result.failures:
            print(f"  {note}", file=stderr)
    if not args.execute and result.converted:
        print("\nRe-run with --execute to write these changes.", file=stdout)
    return 1 if result.failed else 0


def main() -> None:  # pragma: no cover - console-script shim
    raise SystemExit(run())
