-- Production licensing: stable installation identity, logical certificate
-- lineages, and short-lived quota reservations. Existing certificate rows are
-- backfilled by LicenseRepository at startup because following renewal chains
-- portably is clearer and safer in Python than in cross-dialect recursive SQL.

CREATE TABLE IF NOT EXISTS certificate_lineages (
    id TEXT PRIMARY KEY,
    root_request_id TEXT NOT NULL UNIQUE REFERENCES certificate_requests(id),
    template_id TEXT NOT NULL REFERENCES certificate_templates(id),
    holder_person_id TEXT REFERENCES people(id),
    holder_device_id TEXT REFERENCES devices(id),
    identity_digest TEXT NOT NULL,
    created_at TEXT NOT NULL
);

ALTER TABLE certificate_requests
    ADD COLUMN lineage_id TEXT REFERENCES certificate_lineages(id);

ALTER TABLE issued_certificates
    ADD COLUMN lineage_id TEXT REFERENCES certificate_lineages(id);

CREATE INDEX IF NOT EXISTS idx_requests_lineage
    ON certificate_requests(lineage_id);

CREATE INDEX IF NOT EXISTS idx_issued_lineage_capacity
    ON issued_certificates(lineage_id, status, expires_at);

CREATE TABLE IF NOT EXISTS license_quota_lock (
    singleton_id INTEGER PRIMARY KEY,
    generation INTEGER NOT NULL
);

INSERT INTO license_quota_lock(singleton_id, generation)
SELECT 1, 0
WHERE NOT EXISTS (
    SELECT 1 FROM license_quota_lock WHERE singleton_id = 1
);

CREATE TABLE IF NOT EXISTS license_quota_reservations (
    request_id TEXT PRIMARY KEY REFERENCES certificate_requests(id),
    lineage_id TEXT NOT NULL UNIQUE REFERENCES certificate_lineages(id),
    reserved_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_license_reservation_expiry
    ON license_quota_reservations(expires_at);

CREATE TABLE IF NOT EXISTS license_lineage_state (
    singleton_id INTEGER PRIMARY KEY,
    status TEXT NOT NULL,
    detail TEXT,
    updated_at TEXT NOT NULL
);

INSERT INTO license_lineage_state(singleton_id, status, detail, updated_at)
SELECT 1, 'pending', NULL, CURRENT_TIMESTAMP
WHERE NOT EXISTS (
    SELECT 1 FROM license_lineage_state WHERE singleton_id = 1
);
