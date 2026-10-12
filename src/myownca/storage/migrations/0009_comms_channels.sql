-- Communication channel configuration for the notification module.
-- Non-secret settings live in config_json; sensitive values (SMTP password,
-- Slack bot token, webhook signing secret, bearer token) are stored encrypted
-- in secret_ciphertext (Fernet, keyed by MYOWNCA_AUTH_ENCRYPTION_SECRET).

CREATE TABLE IF NOT EXISTS comms_channel_configs (
    channel TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 0,
    config_json TEXT NOT NULL DEFAULT '{}',
    secret_ciphertext TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);
