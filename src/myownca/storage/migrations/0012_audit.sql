-- Tamper-evident audit trail for all critical actions, plus remote syslog config.
-- Version 2 authenticates all event fields, including prev_hash, as canonical JSON.
-- Detecting terminal truncation or rollback requires an independent checkpoint.

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    hash_version INTEGER NOT NULL,
    sequence INTEGER NOT NULL UNIQUE,
    occurred_at TEXT NOT NULL,
    category TEXT NOT NULL,
    action TEXT NOT NULL,
    outcome TEXT NOT NULL,
    actor_id TEXT,
    actor_email TEXT,
    actor_role TEXT,
    source_ip TEXT,
    object_type TEXT,
    object_id TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    prev_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_sequence ON audit_events(sequence);
CREATE INDEX IF NOT EXISTS idx_audit_category_time ON audit_events(category, occurred_at);
CREATE INDEX IF NOT EXISTS idx_audit_actor_time ON audit_events(actor_id, occurred_at);

CREATE TABLE IF NOT EXISTS audit_syslog_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 0,
    host TEXT NOT NULL DEFAULT '',
    port INTEGER NOT NULL DEFAULT 514,
    protocol TEXT NOT NULL DEFAULT 'udp',
    facility INTEGER NOT NULL DEFAULT 13,
    updated_at TEXT
);
