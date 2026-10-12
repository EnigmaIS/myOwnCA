-- Channel-neutral, single-use account recovery challenges. Existing emailed
-- TOTP challenges are copied so an in-flight 15-minute recovery remains valid
-- across deployment.
CREATE TABLE IF NOT EXISTS account_recovery_challenges (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    purpose TEXT NOT NULL,
    channel TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_account_recovery_user_purpose
    ON account_recovery_challenges(user_id, purpose, created_at);

INSERT INTO account_recovery_challenges(
    id, user_id, purpose, channel, code_hash, created_at, expires_at, consumed_at
)
SELECT id, user_id, 'totp', 'email', code_hash, created_at, expires_at, consumed_at
FROM email_recovery_challenges;

ALTER TABLE auth_events ADD COLUMN source_ip VARCHAR(191);

CREATE INDEX IF NOT EXISTS idx_auth_events_type_source_time
    ON auth_events(event_type, source_ip, occurred_at);
