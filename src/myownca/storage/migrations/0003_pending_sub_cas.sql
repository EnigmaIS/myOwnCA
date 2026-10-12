CREATE TABLE IF NOT EXISTS pending_sub_cas (
    id TEXT PRIMARY KEY,
    bundle_id TEXT NOT NULL UNIQUE,
    key_ref TEXT NOT NULL,
    csr_pem TEXT NOT NULL,
    subject TEXT NOT NULL,
    created_at TEXT NOT NULL
);
