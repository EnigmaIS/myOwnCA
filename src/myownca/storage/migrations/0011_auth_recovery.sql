-- TOTP recovery: offline one-time backup codes, and self-service email-based
-- recovery codes. Both code values are stored as HMAC-SHA256 (peppered with the
-- auth encryption secret) and are single-use.

CREATE TABLE IF NOT EXISTS totp_recovery_codes (
    user_id TEXT NOT NULL REFERENCES users(id),
    code_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    used_at TEXT,
    PRIMARY KEY (user_id, code_hash)
);

CREATE TABLE IF NOT EXISTS email_recovery_challenges (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    code_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_email_recovery_user ON email_recovery_challenges(user_id);
