-- Optional cloud signing infrastructure.  These tables are additive and are
-- inert for installations which keep all CA keys in software or PKCS#11.

CREATE TABLE IF NOT EXISTS cloud_keys (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    key_ref TEXT NOT NULL,
    key_ref_digest TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    algorithm TEXT NOT NULL,
    protection TEXT,
    purpose TEXT NOT NULL,
    ownership TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    -- Keep the complete provider reference even when it exceeds MariaDB's
    -- portable index length.  The application stores SHA-256(key_ref) here
    -- and still compares the full reference after the indexed lookup.
    UNIQUE (provider, key_ref_digest),
    CHECK (ownership IN ('managed', 'attached')),
    CHECK (status IN ('active', 'disabled', 'pending_deletion', 'deleted', 'unavailable'))
);

CREATE INDEX IF NOT EXISTS idx_cloud_keys_provider_status
    ON cloud_keys(provider, status);

CREATE INDEX IF NOT EXISTS idx_cloud_keys_purpose
    ON cloud_keys(purpose);

CREATE TABLE IF NOT EXISTS signing_jobs (
    id TEXT PRIMARY KEY,
    cloud_key_id TEXT NOT NULL REFERENCES cloud_keys(id),
    operation TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL,
    deduplication_key TEXT NOT NULL,
    active_deduplication_key TEXT UNIQUE,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    retry_window_started_at TEXT NOT NULL,
    next_attempt_at TEXT NOT NULL,
    lease_owner TEXT,
    lease_expires_at TEXT,
    cancel_requested_at TEXT,
    last_error_code TEXT,
    last_error_message TEXT,
    result_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT,
    CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'canceled')),
    CHECK (attempt_count >= 0)
);

CREATE INDEX IF NOT EXISTS idx_signing_jobs_ready
    ON signing_jobs(status, next_attempt_at);

CREATE INDEX IF NOT EXISTS idx_signing_jobs_lease
    ON signing_jobs(status, lease_expires_at);

CREATE INDEX IF NOT EXISTS idx_signing_jobs_cloud_key
    ON signing_jobs(cloud_key_id, created_at);

CREATE INDEX IF NOT EXISTS idx_signing_jobs_resource
    ON signing_jobs(resource_type, resource_id, created_at);
