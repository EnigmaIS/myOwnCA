from __future__ import annotations

import sys
from datetime import datetime, timezone

from myownca.config import Settings
from myownca.service_certs.keystore import ServiceKeyStore
from myownca.service_certs.repository import ServiceCertRepository
from myownca.service_certs.service import ServiceCertService
from myownca.storage.database import Database


def main(argv: list[str] | None = None) -> int:
    """Report ACME service certificates due for renewal.

    Cron-friendly: exits non-zero when one or more certs are within their
    renewal window, so it can drive alerting. Actual renewal is performed in the
    running web process (which serves HTTP-01 challenges) via the admin portal or
    ``POST /internal/service-certs/{id}/renew``.
    """
    settings = Settings.from_env()
    database = Database(settings.database_path)
    database.migrate()
    service = ServiceCertService(
        ServiceCertRepository(database),
        ServiceKeyStore(
            settings.service_key_dir,
            passphrase=settings.online_key_passphrase,
            entropy_source=settings.entropy_source,
        ),
        settings.auth_encryption_secret,
    )
    now = datetime.now(timezone.utc)
    due = service.due_for_renewal(now)
    if not due:
        print("No ACME service certificates are due for renewal.")
        return 0
    print(f"{len(due)} certificate(s) due for renewal:")
    for cert in due:
        days_left = (cert.not_after - now).days if cert.not_after else "?"
        print(f"  - {cert.name}: expires {cert.not_after} ({days_left} days left)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
