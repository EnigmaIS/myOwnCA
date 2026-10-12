CREATE TABLE IF NOT EXISTS first_login_guides (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    outcome TEXT NOT NULL,
    dismissed_at TEXT NOT NULL
);
