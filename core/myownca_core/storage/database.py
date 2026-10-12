from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from urllib.parse import parse_qs, urlsplit
from urllib.request import url2pathname

from sqlalchemy import create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError as _SAIntegrityError
from sqlalchemy.pool import NullPool

from myownca_core.private_files import mkdir_private
from myownca_core.storage.dialect import key_columns_for_scripts, prepare_ddl, translate_dml


class IntegrityError(RuntimeError):
    """Backend-agnostic unique/foreign-key violation (replaces sqlite3.IntegrityError)."""


class Database:
    """Thin SQLAlchemy-Core wrapper.

    SQLite is the default (zero-config, one file). Pointing at a connection URL
    (e.g. ``mysql+pymysql://user:pass@host/db``) switches to MariaDB/MySQL with
    real pooling. Repositories keep using a sqlite3-style cursor API via the
    connection shim, and SQLite-authored SQL is translated per dialect.
    """

    def __init__(self, target: "str | Path | Database") -> None:
        url = _to_url(target)
        self._dialect = make_url(url).get_backend_name()
        if self._dialect == "sqlite":
            self._engine = create_engine(
                url, poolclass=NullPool, connect_args={"check_same_thread": False}
            )
            event.listen(self._engine, "do_connect", _prepare_sqlite_file)
            event.listen(self._engine, "connect", _enable_sqlite_foreign_keys)
        else:
            self._engine = create_engine(url, pool_pre_ping=True, pool_recycle=1800)

    @property
    def dialect(self) -> str:
        return self._dialect

    @contextmanager
    def connect(self) -> Iterator["_Connection"]:
        connection = self._engine.connect()
        transaction = connection.begin()
        try:
            yield _Connection(connection, self._dialect)
            transaction.commit()
        except Exception:
            transaction.rollback()
            raise
        finally:
            connection.close()

    def migrate(self, migrations_dir: "str | Path") -> None:
        migrations_dir = Path(migrations_dir)
        migration_files = sorted(migrations_dir.glob("*.sql"))
        key_columns = (
            key_columns_for_scripts(migration.read_text() for migration in migration_files)
            if self._dialect in {"mysql", "mariadb"}
            else None
        )
        with self.connect() as connection:
            connection.executescript(self._schema_migrations_ddl())
            applied = {
                row["version"]
                for row in connection.execute("SELECT version FROM schema_migrations").fetchall()
            }
            for migration in migration_files:
                if migration.name in applied:
                    continue
                connection.executescript(migration.read_text(), key_columns=key_columns)
                connection.execute(
                    "INSERT INTO schema_migrations(version) VALUES (?)", (migration.name,)
                )

    def _schema_migrations_ddl(self) -> str:
        if self._dialect == "sqlite":
            return (
                "CREATE TABLE IF NOT EXISTS schema_migrations ("
                "version TEXT PRIMARY KEY, "
                "applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
            )
        return (
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "version VARCHAR(191) PRIMARY KEY, "
            "applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)"
        )


class _Connection:
    """sqlite3-style facade over a SQLAlchemy Core connection."""

    def __init__(self, connection, dialect: str) -> None:
        self._conn = connection
        self._dialect = dialect

    def execute(self, sql: str, params: tuple | list = ()) -> "_Cursor":
        statement = translate_dml(sql, self._dialect)
        try:
            if params:
                result = self._conn.exec_driver_sql(statement, tuple(params))
            else:
                result = self._conn.exec_driver_sql(statement)
        except _SAIntegrityError as exc:
            raise IntegrityError(str(getattr(exc, "orig", exc))) from exc
        return _Cursor(result)

    def executemany(self, sql: str, seq_of_params) -> "_Cursor":
        rows = [tuple(params) for params in seq_of_params]
        if not rows:
            return _Cursor(None)
        statement = translate_dml(sql, self._dialect)
        try:
            result = self._conn.exec_driver_sql(statement, rows)
        except _SAIntegrityError as exc:
            raise IntegrityError(str(getattr(exc, "orig", exc))) from exc
        return _Cursor(result)

    def executescript(
        self, script: str, *, key_columns: dict[str, set[str]] | None = None
    ) -> None:
        for statement in prepare_ddl(script, self._dialect, key_columns=key_columns):
            self._conn.exec_driver_sql(statement)


class _Cursor:
    """Returns rows as plain dicts so existing ``row["col"]`` access keeps working."""

    def __init__(self, result) -> None:
        self._result = result

    def fetchone(self) -> dict | None:
        row = self._result.fetchone()
        return dict(row._mapping) if row is not None else None

    def fetchall(self) -> list[dict]:
        return [dict(row._mapping) for row in self._result.fetchall()]

    def __iter__(self):
        return iter(self.fetchall())

    @property
    def rowcount(self) -> int:
        return self._result.rowcount if self._result is not None else 0


def _enable_sqlite_foreign_keys(dbapi_connection, _record) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys = ON")
    cursor.close()


def sqlite_file_path(filename: str, *, uri: bool = False) -> Path | None:
    """Resolve a SQLite driver's filename without opening or creating anything."""
    if not filename or filename == ":memory:":
        return None
    if uri and filename.startswith("file:"):
        parsed = urlsplit(filename)
        if parsed.path in {"", ":memory:"} or parse_qs(parsed.query).get("mode") == ["memory"]:
            return None
        if parsed.netloc not in {"", "localhost"}:
            raise ValueError("Unsupported SQLite URI authority")
        return Path(url2pathname(parsed.path))
    return Path(filename)


def _prepare_sqlite_file(_dialect, _record, cargs, cparams) -> None:
    filename = cargs[0]
    uri = bool(cparams.get("uri"))
    path = sqlite_file_path(filename, uri=uri)
    if path is None:
        return
    if uri and filename.startswith("file:"):
        mode = parse_qs(urlsplit(filename).query).get("mode", ["rwc"])[0]
        if mode != "rwc":
            return  # Preserve SQLite's refusal to create these databases.
    mkdir_private(path.parent)
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    except FileExistsError:
        return  # Existing installations use the explicit permission repair.
    os.close(descriptor)


def _to_url(target: "str | Path | Database") -> str:
    if isinstance(target, Database):  # pragma: no cover - defensive
        raise TypeError("Database cannot wrap another Database")
    text = str(target)
    if "://" in text:
        return text
    path = Path(target).resolve()
    mkdir_private(path.parent)
    return f"sqlite:///{path}"
