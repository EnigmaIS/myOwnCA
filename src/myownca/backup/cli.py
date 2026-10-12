from __future__ import annotations

import getpass
import json

from myownca.backup.restore import restore_backup, verify_backup


def run_backup_command(args) -> int:
    requester = getpass.getpass("Requester backup passphrase share: ")
    approver = getpass.getpass("Approver backup passphrase share: ")
    if args.backup_command == "verify":
        manifest = verify_backup(
            args.archive,
            requester_passphrase=requester,
            approver_passphrase=approver,
        )
        print(
            json.dumps(
                {
                    "valid": True,
                    "archive_id": manifest.get("archive_id"),
                    "application_version": manifest.get("application_version"),
                    "created_at": manifest.get("created_at"),
                    "source_database": manifest.get("database", {}).get("source_dialect"),
                    "issuer_backend": manifest.get("issuer_backend"),
                    "included": manifest.get("included"),
                    "excluded": manifest.get("excluded"),
                },
                indent=2,
            )
        )
        return 0
    result = restore_backup(
        args.archive,
        state_dir=args.backup_state_dir,
        requester_passphrase=requester,
        approver_passphrase=approver,
        database_url=args.database_url,
        force_sqlite=args.sqlite,
    )
    print(json.dumps(result, indent=2))
    return 0
