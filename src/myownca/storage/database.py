"""Compatibility shim — the Database engine now lives in myownca-core.

myOwnCA's migrations live next to this file (storage/migrations/*.sql, declared as
package-data), so the no-arg ``migrate()`` keeps working for every existing call site.
"""
from pathlib import Path

from myownca_core.storage.database import Database as _CoreDatabase
from myownca_core.storage.database import IntegrityError  # noqa: F401


class Database(_CoreDatabase):
    def migrate(self) -> None:
        super().migrate(Path(__file__).with_name("migrations"))
