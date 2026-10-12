ALTER TABLE issuer_crls RENAME TO issuer_crls_legacy;

CREATE TABLE issuer_crls (
    issuer_id TEXT,
    issuer_subject TEXT NOT NULL,
    number INTEGER NOT NULL,
    crl_pem TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    this_update TEXT,
    next_update TEXT,
    source TEXT NOT NULL DEFAULT 'local',
    sha256 TEXT NOT NULL DEFAULT ''
);

INSERT INTO issuer_crls(
    issuer_id, issuer_subject, number, crl_pem, generated_at,
    this_update, next_update, source, sha256
)
SELECT
    NULL, issuer_subject, number, crl_pem, generated_at,
    generated_at, NULL, 'local', ''
FROM issuer_crls_legacy;

DROP TABLE issuer_crls_legacy;

CREATE UNIQUE INDEX IF NOT EXISTS idx_issuer_crls_issuer_id_number
    ON issuer_crls(issuer_id, number);

CREATE INDEX IF NOT EXISTS idx_issuer_crls_subject_number
    ON issuer_crls(issuer_subject, number);

CREATE TABLE IF NOT EXISTS issuer_revocations (
    issuer_id TEXT NOT NULL,
    serial_number TEXT NOT NULL,
    reason TEXT NOT NULL,
    revoked_at TEXT NOT NULL,
    invalidity_date TEXT,
    source TEXT NOT NULL,
    source_crl_number INTEGER,
    created_at TEXT NOT NULL,
    PRIMARY KEY (issuer_id, serial_number)
);

CREATE INDEX IF NOT EXISTS idx_issuer_revocations_created
    ON issuer_revocations(issuer_id, created_at);

INSERT INTO issuer_revocations(
    issuer_id, serial_number, reason, revoked_at,
    invalidity_date, source, source_crl_number, created_at
)
SELECT
    i.issuer_id, r.serial_number, r.reason, r.revoked_at,
    NULL, 'local', NULL, r.revoked_at
FROM certificate_revocations r
JOIN certificate_inventory i ON i.certificate_id = r.certificate_id
WHERE i.issuer_id IS NOT NULL
  AND NOT EXISTS (
      SELECT 1 FROM issuer_revocations existing
      WHERE existing.issuer_id = i.issuer_id
        AND existing.serial_number = r.serial_number
  );

CREATE TABLE IF NOT EXISTS crl_jobs (
    issuer_id TEXT PRIMARY KEY,
    issuer_subject TEXT NOT NULL,
    job_id TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    requested_generation INTEGER NOT NULL,
    completed_generation INTEGER NOT NULL,
    requested_at TEXT NOT NULL,
    next_attempt_at TEXT NOT NULL,
    reserved_number INTEGER,
    attempt_count INTEGER NOT NULL,
    lease_owner TEXT,
    lease_expires_at TEXT,
    last_error TEXT,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_crl_jobs_due
    ON crl_jobs(status, next_attempt_at);
