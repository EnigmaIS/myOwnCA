-- Holder/requester front-end: single-purpose secure links (tokens, OTP state,
-- claim sessions — all secrets stored hashed), public access requests, and an
-- origin marker for renewals submitted through a link.
CREATE TABLE IF NOT EXISTS secure_links (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    purpose TEXT NOT NULL,
    person_id TEXT REFERENCES people(id),
    serial_number TEXT REFERENCES issued_certificates(serial_number),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    max_uses INTEGER NOT NULL,
    use_count INTEGER NOT NULL DEFAULT 0,
    revoked_at TEXT,
    locked_at TEXT,
    otp_hash TEXT,
    otp_expires_at TEXT,
    otp_attempts INTEGER NOT NULL DEFAULT 0,
    session_token_hash TEXT,
    session_expires_at TEXT,
    last_used_at TEXT
);

CREATE TABLE IF NOT EXISTS access_requests (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    verify_code_hash TEXT,
    verify_expires_at TEXT,
    verify_attempts INTEGER NOT NULL DEFAULT 0,
    email_verified_at TEXT,
    status TEXT NOT NULL,
    decided_by TEXT,
    decided_at TEXT,
    created_at TEXT NOT NULL
);

ALTER TABLE certificate_requests ADD COLUMN via_link_auth TEXT;

CREATE INDEX IF NOT EXISTS idx_secure_links_serial ON secure_links(serial_number, purpose);
CREATE INDEX IF NOT EXISTS idx_access_requests_status ON access_requests(status, created_at);
