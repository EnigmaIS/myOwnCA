-- Application backups use their own dual-control workflow. This is deliberately
-- separate from native HSM backup proposals and recovery material.
CREATE TABLE IF NOT EXISTS application_backup_proposals (
    id TEXT PRIMARY KEY,
    proposer_id TEXT NOT NULL REFERENCES users(id),
    proposer_email TEXT NOT NULL,
    reason TEXT NOT NULL,
    requester_salt_b64 TEXT NOT NULL,
    pending_guard INTEGER UNIQUE,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    resolved_at TEXT,
    approver_id TEXT REFERENCES users(id),
    approver_email TEXT,
    approval_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_application_backup_proposals_status
    ON application_backup_proposals(status, expires_at);

CREATE TABLE IF NOT EXISTS application_backup_pending_secrets (
    proposal_id TEXT PRIMARY KEY
        REFERENCES application_backup_proposals(id) ON DELETE CASCADE,
    requester_key_ciphertext TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS application_backup_exports (
    id TEXT PRIMARY KEY,
    proposal_id TEXT NOT NULL REFERENCES application_backup_proposals(id),
    requester_id TEXT NOT NULL REFERENCES users(id),
    requester_email TEXT NOT NULL,
    approver_id TEXT NOT NULL REFERENCES users(id),
    approver_email TEXT NOT NULL,
    filename TEXT NOT NULL,
    database_dialect TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    delivered_at TEXT,
    error TEXT
);

CREATE INDEX IF NOT EXISTS idx_application_backup_exports_delivered
    ON application_backup_exports(status, delivered_at);
