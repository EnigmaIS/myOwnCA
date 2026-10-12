"""Dialect translation so the SQLite-authored SQL also runs on MySQL/MariaDB.

The schema and queries are written once in SQLite's dialect (the SMB default).
For a MySQL/MariaDB engine we translate at execution time:

DML (runtime queries):
- ``?`` placeholders -> ``%s`` (pymysql ``format`` paramstyle)
- ``ON CONFLICT(...) DO UPDATE SET x = excluded.x`` -> ``ON DUPLICATE KEY UPDATE x = VALUES(x)``
- the reserved column name ``key`` -> `` `key` ``

DDL (migrations):
- key/unique/foreign-key/indexed ``TEXT`` columns -> ``VARCHAR(191)`` (MySQL cannot
  index raw TEXT; 191 keeps utf8mb4 indexes within the 767-byte legacy limit)
- all other ``TEXT`` columns -> ``LONGTEXT`` (so PEM/JSON/ciphertext are never truncated)

MariaDB cannot be exercised in this repo's test environment, so the translator's
output is unit-tested as SQL strings; validate against a live server before use.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

_MYSQL_DIALECTS = {"mysql", "mariadb"}
# Reserved words used as bare identifiers in our schema that MySQL needs quoted.
_RESERVED_IDENTIFIERS = ("key",)


def split_statements(script: str) -> list[str]:
    lines = [line for line in script.splitlines() if not line.strip().startswith("--")]
    body = "\n".join(lines)
    return [stmt.strip() for stmt in body.split(";") if stmt.strip()]


# -- DML ----------------------------------------------------------------------


def translate_dml(sql: str, dialect: str) -> str:
    if dialect not in _MYSQL_DIALECTS:
        return sql
    sql = _quote_reserved(sql)
    sql = _upsert_to_mysql(sql)
    return sql.replace("?", "%s")


def _quote_reserved(sql: str) -> str:
    for word in _RESERVED_IDENTIFIERS:
        # Case-sensitive: our columns are lowercase; SQL keywords (PRIMARY KEY) are upper.
        sql = re.sub(rf"(?<![`\w]){word}(?![`\w])", f"`{word}`", sql)
    return sql


def _upsert_to_mysql(sql: str) -> str:
    match = re.search(
        r"ON\s+CONFLICT\s*\([^)]*\)\s*DO\s+UPDATE\s+SET\s+(.+)$",
        sql,
        re.IGNORECASE | re.DOTALL,
    )
    if not match:
        return sql
    assignments = re.sub(r"excluded\.(\w+)", r"VALUES(\1)", match.group(1), flags=re.IGNORECASE)
    return sql[: match.start()] + "ON DUPLICATE KEY UPDATE " + assignments


# -- DDL ----------------------------------------------------------------------


def key_columns_for_scripts(scripts: Iterable[str]) -> dict[str, set[str]]:
    """Return every table column that must have an indexable MySQL length.

    Migrations are applied one file at a time, but a later migration can add an
    index to a ``TEXT`` column created by an earlier one.  Collecting the full
    plan up front lets the earlier DDL use ``VARCHAR(191)`` from the beginning.
    """
    statements = [statement for script in scripts for statement in split_statements(script)]
    return _collect_key_columns(statements)


def prepare_ddl(
    script: str,
    dialect: str,
    *,
    key_columns: dict[str, set[str]] | None = None,
) -> list[str]:
    statements = split_statements(script)
    if dialect not in _MYSQL_DIALECTS:
        return statements
    key_columns = key_columns or _collect_key_columns(statements)
    out: list[str] = []
    for stmt in statements:
        out.extend(_translate_ddl_statement(stmt, key_columns))
    return out


def _table_name(stmt: str, keyword: str) -> str | None:
    match = re.search(rf"{keyword}\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_][\w]*)", stmt, re.IGNORECASE)
    return match.group(1) if match else None


def _collect_key_columns(statements: list[str]) -> dict[str, set[str]]:
    """Columns per table that participate in a key/unique/FK/index (need a real length)."""
    keys: dict[str, set[str]] = {}
    for stmt in statements:
        upper = stmt.upper()
        if upper.startswith("CREATE TABLE"):
            table = _table_name(stmt, "CREATE TABLE")
            if table is None:
                continue
            cols = keys.setdefault(table, set())
            body = stmt[stmt.index("(") + 1 : stmt.rindex(")")]
            for raw in _split_columns(body):
                cols.update(_key_columns_from_definition(raw))
        elif upper.startswith("CREATE INDEX") or upper.startswith("CREATE UNIQUE INDEX"):
            match = re.search(r"ON\s+([A-Za-z_]\w*)\s*\(([^)]*)\)", stmt, re.IGNORECASE)
            if match:
                table, collist = match.group(1), match.group(2)
                cols = keys.setdefault(table, set())
                cols.update(_column_names(collist))
    return keys


def _split_columns(body: str) -> list[str]:
    parts, depth, current, in_quote = [], 0, [], False
    for ch in body:
        if ch == "'":
            in_quote = not in_quote
        elif not in_quote and ch == "(":
            depth += 1
        elif not in_quote and ch == ")":
            depth -= 1
        if ch == "," and depth == 0 and not in_quote:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    if current:
        parts.append("".join(current))
    return [p.strip() for p in parts if p.strip()]


_INLINE_FK_RE = re.compile(
    r"\s+REFERENCES\s+([A-Za-z_]\w*)\s*\(\s*([A-Za-z_]\w*)\s*\)"
    r"(\s+ON\s+DELETE\s+(?:CASCADE|SET\s+NULL|RESTRICT|NO\s+ACTION))?",
    re.IGNORECASE,
)


def _extract_inline_fk(definition: str) -> tuple[str, str | None]:
    """Pull an inline column REFERENCES into a table-level FOREIGN KEY (MySQL ignores inline)."""
    match = _INLINE_FK_RE.search(definition)
    if not match:
        return definition, None
    column = definition.strip().split()[0].strip("`")
    ref_table, ref_col = match.group(1), match.group(2)
    on_delete = (match.group(3) or "").strip()
    cleaned = (definition[: match.start()] + definition[match.end() :]).rstrip()
    fk = f"FOREIGN KEY (`{column}`) REFERENCES {ref_table}(`{ref_col}`)"
    if on_delete:
        fk += " " + " ".join(on_delete.split())
    return cleaned, fk


def _column_names(collist: str) -> set[str]:
    return {c.strip().strip("`").split()[0] for c in collist.split(",") if c.strip()}


def _key_columns_from_definition(definition: str) -> set[str]:
    upper = definition.upper()
    # Table-level constraints.
    if upper.startswith("PRIMARY KEY") or upper.startswith("UNIQUE"):
        inner = definition[definition.index("(") + 1 : definition.rindex(")")]
        return _column_names(inner)
    if upper.startswith("FOREIGN KEY"):
        inner = definition[definition.index("(") + 1 : definition.index(")")]
        return _column_names(inner)
    if upper.startswith(("CHECK", "CONSTRAINT")):
        return set()
    # Inline column definition.
    name = definition.strip().split()[0].strip("`")
    if any(token in upper for token in ("PRIMARY KEY", "UNIQUE", "REFERENCES")):
        return {name}
    return set()


def _translate_ddl_statement(stmt: str, key_columns: dict[str, set[str]]) -> list[str]:
    upper = stmt.upper()
    if upper.startswith("CREATE TABLE"):
        return [_translate_create_table(stmt, key_columns)]
    if upper.startswith("CREATE INDEX") or upper.startswith("CREATE UNIQUE INDEX"):
        # MySQL has no IF NOT EXISTS for CREATE INDEX; migrations run once anyway.
        return [_quote_reserved(re.sub(r"\s+IF\s+NOT\s+EXISTS", "", stmt, flags=re.IGNORECASE))]
    if upper.startswith("ALTER TABLE"):
        return _translate_alter_table(stmt, key_columns)
    return [_quote_reserved(stmt)]


def _translate_create_table(stmt: str, key_columns: dict[str, set[str]]) -> str:
    table = _table_name(stmt, "CREATE TABLE")
    cols = key_columns.get(table or "", set())
    open_idx = stmt.index("(")
    close_idx = stmt.rindex(")")
    head, body, tail = stmt[: open_idx + 1], stmt[open_idx + 1 : close_idx], stmt[close_idx:]
    new_defs: list[str] = []
    fk_clauses: list[str] = []
    for defn in _split_columns(body):
        cleaned, fk = _extract_inline_fk(defn)
        if fk is not None:
            fk_clauses.append(fk)
        new_defs.append(_translate_column(cleaned, cols))
    translated = head + "\n  " + ",\n  ".join(new_defs + fk_clauses) + "\n" + tail
    return _quote_reserved(translated)


_ALTER_ADD_COLUMN_RE = re.compile(
    r"^\s*ALTER\s+TABLE\s+([A-Za-z_]\w*)\s+ADD\s+COLUMN\s+(.+)$",
    re.IGNORECASE | re.DOTALL,
)


def _translate_alter_table(
    stmt: str, key_columns: dict[str, set[str]]
) -> list[str]:
    """Inline ``REFERENCES`` on ADD COLUMN is not honoured by MySQL and errors on a
    TEXT/length mismatch; split it into a VARCHAR column plus a table-level FK."""
    match = _ALTER_ADD_COLUMN_RE.match(stmt)
    if not match:
        return [_quote_reserved(stmt)]
    table, column_def = match.group(1), match.group(2).strip()
    cleaned, fk = _extract_inline_fk(column_def)
    column = cleaned.strip().split()[0].strip("`")
    if fk is not None or column in key_columns.get(table, set()):
        cleaned = _force_varchar(cleaned)
    if fk is None:
        return [_quote_reserved(f"ALTER TABLE {table} ADD COLUMN {cleaned}")]
    add_column = f"ALTER TABLE {table} ADD COLUMN {cleaned}"
    add_fk = f"ALTER TABLE {table} ADD {fk}"
    return [_quote_reserved(add_column), _quote_reserved(add_fk)]


def _force_varchar(column_def: str) -> str:
    tokens = column_def.split()
    if len(tokens) >= 2 and tokens[1].upper() == "TEXT":
        return column_def.replace("TEXT", "VARCHAR(191)", 1)
    return column_def


def _translate_column(definition: str, key_columns: set[str]) -> str:
    upper = definition.upper()
    if upper.startswith(("PRIMARY KEY", "UNIQUE", "FOREIGN KEY", "CHECK", "CONSTRAINT")):
        return definition
    tokens = definition.split()
    if len(tokens) < 2 or tokens[1].upper() != "TEXT":
        return definition
    name = tokens[0].strip("`")
    replacement = "VARCHAR(191)" if name in key_columns else "LONGTEXT"
    return definition.replace("TEXT", replacement, 1)
