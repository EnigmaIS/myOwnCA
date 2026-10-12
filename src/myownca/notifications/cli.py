from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone

from myownca.comms import CommsRepository, CommsService
from myownca.config import Settings
from myownca.holder import SecureLinkRepository, SecureLinkService
from myownca.notifications.base import NotificationEvent
from myownca.notifications.repository import NotificationRepository
from myownca.notifications.service import NotificationService
from myownca.storage.database import Database
from myownca.storage.repositories import PKIRepository


def main(argv: list[str] | None = None) -> int:
    """Manually run due expiring/expired notification rules.

    Cron-friendly: a daily crontab tick is enough — each rule's ``period_days``
    plus its ``last_run_at`` stamp decides whether it actually fires. Writes only
    the plain ``notification_log`` table, never the single-writer audit hash
    chain (that stays in the web process; use the portal's "Run now" for an
    audited run).
    """
    parser = argparse.ArgumentParser(description="Send due certificate notifications.")
    parser.add_argument(
        "--event",
        choices=[NotificationEvent.EXPIRING.value, NotificationEvent.EXPIRED.value],
        help="run only rules for this event type",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="report what would be sent without dispatching or stamping rules",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="ignore each rule's period gate and run it now",
    )
    args = parser.parse_args(argv)

    settings = Settings.from_env()
    database = Database(settings.database_url or settings.database_path)
    database.migrate()
    pki_repository = PKIRepository(database)
    link_repository = SecureLinkRepository(database)
    service = NotificationService(
        NotificationRepository(database),
        pki_repository,
        CommsService(CommsRepository(database), settings.auth_encryption_secret),
        secure_links=SecureLinkService(link_repository, pki_repository),
    )
    now = datetime.now(timezone.utc)
    summary = service.run_scheduled(
        now,
        event=NotificationEvent(args.event) if args.event else None,
        dry_run=args.dry_run,
        force=args.force,
    )
    rules = summary["rules"]
    if not rules:
        print("No enabled expiring/expired notification rules.")
    for entry in rules:
        state = "due" if entry["due"] else "not due"
        mode = " (dry-run)" if entry["dry_run"] else ""
        print(
            f"  - {entry['rule_id']} [{entry['event_type']}/{entry['template_name']}] {state}{mode}: "
            f"matched={entry['matched']} sent={entry['sent']} "
            f"failed={entry['failed']} skipped={entry['skipped']}"
        )
    if not args.dry_run:
        pruned = link_repository.prune(now)
        if pruned:
            print(f"pruned {pruned} dead secure link(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
