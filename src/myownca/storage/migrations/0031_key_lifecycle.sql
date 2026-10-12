-- Provider-neutral registry for keys which myOwnCA has explicitly adopted.
-- Discovery is deliberately out of scope: a key appears here only after an
-- application workflow registers it and records its ownership.

CREATE TABLE IF NOT EXISTS key_lifecycle_keys (
    id TEXT PRIMARY KEY,
    backend TEXT NOT NULL,
    key_ref TEXT NOT NULL,
    key_ref_digest TEXT NOT NULL,
    purpose TEXT NOT NULL,
    ownership TEXT NOT NULL,
    status TEXT NOT NULL,
    orphaned_at TEXT,
    delete_after TEXT,
    cleanup_token TEXT,
    cleanup_started_at TEXT,
    cleanup_attempts INTEGER NOT NULL DEFAULT 0,
    last_attempt_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (backend, key_ref_digest),
    CHECK (ownership IN ('managed', 'attached')),
    CHECK (status IN ('active', 'orphaned', 'deleting', 'deleted', 'detached', 'error')),
    CHECK (cleanup_attempts >= 0)
);

CREATE INDEX IF NOT EXISTS idx_key_lifecycle_due
    ON key_lifecycle_keys(status, delete_after);

CREATE INDEX IF NOT EXISTS idx_key_lifecycle_backend
    ON key_lifecycle_keys(backend, status);

CREATE TABLE IF NOT EXISTS key_lifecycle_bindings (
    key_id TEXT NOT NULL
        REFERENCES key_lifecycle_keys(id) ON DELETE CASCADE,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (key_id, resource_type, resource_id)
);

CREATE INDEX IF NOT EXISTS idx_key_lifecycle_binding_resource
    ON key_lifecycle_bindings(resource_type, resource_id);
