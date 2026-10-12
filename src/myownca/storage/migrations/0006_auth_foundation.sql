ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1;

ALTER TABLE certificate_requests ADD COLUMN requested_by_user_id TEXT REFERENCES users(id);

CREATE TABLE IF NOT EXISTS password_credentials (
    user_id TEXT PRIMARY KEY REFERENCES users(id),
    password_hash TEXT NOT NULL,
    must_change_password INTEGER NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS totp_factors (
    user_id TEXT PRIMARY KEY REFERENCES users(id),
    secret_ciphertext TEXT NOT NULL,
    confirmed_at TEXT,
    last_verified_step INTEGER
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL REFERENCES users(id),
    csrf_token TEXT NOT NULL,
    stage TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    absolute_expires_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS auth_events (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    user_id TEXT REFERENCES users(id),
    email TEXT,
    occurred_at TEXT NOT NULL,
    details_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_events_type_email_time
    ON auth_events(event_type, email, occurred_at);
CREATE INDEX IF NOT EXISTS idx_auth_events_type_user_time
    ON auth_events(event_type, user_id, occurred_at);

CREATE TABLE IF NOT EXISTS admin_change_proposals (
    id TEXT PRIMARY KEY,
    change_type TEXT NOT NULL,
    proposer_id TEXT NOT NULL REFERENCES users(id),
    target_user_id TEXT NOT NULL REFERENCES users(id),
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    resolved_at TEXT
);

CREATE TABLE IF NOT EXISTS admin_change_approvals (
    proposal_id TEXT NOT NULL REFERENCES admin_change_proposals(id),
    admin_id TEXT NOT NULL REFERENCES users(id),
    approved_at TEXT NOT NULL,
    PRIMARY KEY (proposal_id, admin_id)
);
