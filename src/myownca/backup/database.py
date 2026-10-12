from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import tempfile
from contextlib import contextmanager
from datetime import date, datetime, time
from decimal import Decimal
from pathlib import Path
from urllib.parse import quote
from zipfile import ZipFile

from sqlalchemy import MetaData, create_engine, inspect, select

from myownca.storage.database import Database


class DatabaseBackupError(RuntimeError):
    """A database could not be captured or restored consistently."""


def migration_fingerprint() -> tuple[str, list[str]]:
    directory = Path(__file__).parents[1] / "storage" / "migrations"
    files = sorted(directory.glob("*.sql"))
    digest = hashlib.sha256()
    for migration in files:
        digest.update(migration.name.encode("utf-8") + b"\x00")
        digest.update(migration.read_bytes())
        digest.update(b"\x00")
    return digest.hexdigest(), [migration.name for migration in files]


@contextmanager
def snapshot_connection(database: Database, staging_dir: Path):
    """Yield one consistent SQLAlchemy connection without external dump tools."""

    engine = database._engine  # application Database owns this core engine
    if database.dialect != "sqlite":
        connection = engine.connect().execution_options(isolation_level="REPEATABLE READ")
        transaction = connection.begin()
        try:
            # Establish the MVCC snapshot before schema/data inspection.
            connection.exec_driver_sql("SELECT 1")
            yield connection
        finally:
            transaction.rollback()
            connection.close()
        return

    raw_path = engine.url.database
    if not raw_path or raw_path == ":memory:":
        raise DatabaseBackupError("SQLite application backups require a file-backed database")
    staging_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, name = tempfile.mkstemp(
        prefix="database-snapshot-", suffix=".sqlite3", dir=staging_dir
    )
    os.close(descriptor)
    snapshot = Path(name)
    os.chmod(snapshot, 0o600)
    source = sqlite3.connect(raw_path)
    target = sqlite3.connect(snapshot)
    try:
        source.backup(target)
        target.close()
        source.close()
        snapshot_engine = create_engine(f"sqlite:///{snapshot}")
        with snapshot_engine.connect() as connection:
            yield connection
        snapshot_engine.dispose()
    except Exception:
        source.close()
        target.close()
        raise
    finally:
        snapshot.unlink(missing_ok=True)


def write_logical_database(
    bundle: ZipFile,
    database: Database,
    *,
    staging_dir: Path,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    """Write all application tables as deterministic JSON Lines members."""

    table_documents: list[dict[str, object]] = []
    entries: list[dict[str, object]] = []
    with snapshot_connection(database, staging_dir) as connection:
        inspector = inspect(connection)
        metadata = MetaData()
        metadata.reflect(bind=connection)
        table_names = sorted(inspector.get_table_names())
        for index, table_name in enumerate(table_names):
            table = metadata.tables[table_name]
            columns = [column.name for column in table.columns]
            primary_key = [column.name for column in table.primary_key.columns]
            statement = select(table)
            if primary_key:
                statement = statement.order_by(*(table.c[name] for name in primary_key))
            member = f"database/tables/{index:04d}-{quote(table_name, safe='')}.jsonl"
            digest = hashlib.sha256()
            size = 0
            row_count = 0
            with bundle.open(member, "w") as output:
                for row in connection.execute(statement):
                    line = (
                        json.dumps(
                            [_encode_value(row._mapping[name]) for name in columns],
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode("utf-8")
                        + b"\n"
                    )
                    output.write(line)
                    digest.update(line)
                    size += len(line)
                    row_count += 1
            entries.append({"path": member, "sha256": digest.hexdigest(), "size": size})
            table_documents.append(
                {
                    "name": table_name,
                    "path": member,
                    "columns": columns,
                    "primary_key": primary_key,
                    "foreign_keys": [
                        {
                            "constrained_columns": fk.get("constrained_columns") or [],
                            "referred_table": fk.get("referred_table"),
                            "referred_columns": fk.get("referred_columns") or [],
                        }
                        for fk in inspector.get_foreign_keys(table_name)
                    ],
                    "row_count": row_count,
                }
            )
    fingerprint, migrations = migration_fingerprint()
    return (
        {
            "source_dialect": database.dialect,
            "migration_fingerprint": fingerprint,
            "migrations": migrations,
            "tables": table_documents,
        },
        entries,
    )


def restore_logical_database(
    bundle: ZipFile,
    manifest: dict[str, object],
    target: Database,
    *,
    restored_at: datetime,
) -> None:
    database_document = manifest.get("database")
    if not isinstance(database_document, dict):
        raise DatabaseBackupError("Backup database manifest is missing")
    expected_fingerprint, expected_migrations = migration_fingerprint()
    if (
        database_document.get("migration_fingerprint") != expected_fingerprint
        or database_document.get("migrations") != expected_migrations
    ):
        raise DatabaseBackupError("Backup database migrations do not match this application")

    target.migrate()
    engine = target._engine
    with engine.connect() as connection:
        inspector = inspect(connection)
        existing = set(inspector.get_table_names())
        tables = database_document.get("tables")
        if not isinstance(tables, list):
            raise DatabaseBackupError("Backup database table manifest is invalid")
        archived_names = {str(item.get("name")) for item in tables if isinstance(item, dict)}
        if existing != archived_names:
            raise DatabaseBackupError("Backup database schema does not match this application")
    metadata = MetaData()
    metadata.reflect(bind=engine)
    table_map = {
        str(item["name"]): item
        for item in tables
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    connection = engine.connect()
    constraints_disabled = False
    try:
        if target.dialect == "sqlite":
            connection.exec_driver_sql("PRAGMA foreign_keys = OFF")
            connection.commit()
            constraints_disabled = True
        elif target.dialect in {"mysql", "mariadb"}:
            connection.exec_driver_sql("SET FOREIGN_KEY_CHECKS = 0")
            connection.commit()
            constraints_disabled = True
        transaction = connection.begin()
        ordered_tables = [metadata.tables[name] for name in sorted(table_map)]
        # Migrations can seed singleton/default rows. The caller has already
        # proved that the target schema was absent before migrate(), so clearing
        # those newly-created rows cannot overwrite an installation.
        for table in reversed(ordered_tables):
            connection.execute(table.delete())
        for table in ordered_tables:
            document = table_map[table.name]
            columns = document.get("columns")
            path = document.get("path")
            if not isinstance(columns, list) or not isinstance(path, str):
                raise DatabaseBackupError(f"Backup table manifest is invalid: {table.name}")
            if columns != [column.name for column in table.columns]:
                raise DatabaseBackupError(f"Backup table columns do not match: {table.name}")
            batch: list[dict[str, object]] = []
            count = 0
            with bundle.open(path) as source:
                for raw_line in source:
                    try:
                        values = json.loads(raw_line)
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        raise DatabaseBackupError(
                            f"Backup table data is invalid: {table.name}"
                        ) from exc
                    if not isinstance(values, list) or len(values) != len(columns):
                        raise DatabaseBackupError(f"Backup table row is invalid: {table.name}")
                    batch.append(
                        {name: _decode_value(value) for name, value in zip(columns, values, strict=True)}
                    )
                    count += 1
                    if len(batch) >= 500:
                        connection.execute(table.insert(), batch)
                        batch.clear()
                if batch:
                    connection.execute(table.insert(), batch)
            if count != document.get("row_count"):
                raise DatabaseBackupError(f"Backup table row count is invalid: {table.name}")
        auth_sessions = metadata.tables.get("auth_sessions")
        if auth_sessions is not None:
            connection.execute(
                auth_sessions.update()
                .where(auth_sessions.c.revoked_at.is_(None))
                .values(revoked_at=restored_at.isoformat())
            )
        transaction.commit()
        if target.dialect == "sqlite":
            violations = connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall()
            if violations:
                raise DatabaseBackupError("Restored database has foreign-key violations")
    except Exception:
        if "transaction" in locals() and transaction.is_active:
            transaction.rollback()
        raise
    finally:
        if constraints_disabled:
            if target.dialect == "sqlite":
                connection.exec_driver_sql("PRAGMA foreign_keys = ON")
            else:
                connection.exec_driver_sql("SET FOREIGN_KEY_CHECKS = 1")
            connection.commit()
        connection.close()


def _encode_value(value: object) -> object:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return {"type": "bytes", "value": base64.b64encode(value).decode("ascii")}
    if isinstance(value, (datetime, date, time)):
        return {"type": "iso8601", "value": value.isoformat()}
    if isinstance(value, Decimal):
        return {"type": "decimal", "value": str(value)}
    raise DatabaseBackupError(f"Unsupported database value type: {type(value).__name__}")


def _decode_value(value: object) -> object:
    if not isinstance(value, dict):
        return value
    kind = value.get("type")
    encoded = value.get("value")
    if not isinstance(encoded, str):
        raise DatabaseBackupError("Backup database value encoding is invalid")
    if kind == "bytes":
        try:
            return base64.b64decode(encoded, validate=True)
        except Exception as exc:
            raise DatabaseBackupError("Backup database byte encoding is invalid") from exc
    if kind in {"iso8601", "decimal"}:
        return encoded
    raise DatabaseBackupError("Backup database value type is unsupported")
