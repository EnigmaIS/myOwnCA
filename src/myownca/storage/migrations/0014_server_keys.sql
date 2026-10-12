-- Server-generated end-entity private keys, held (Fernet-encrypted) for
-- key-bearing certificate exports. One key per request; never hash-chained,
-- never exposed except through the explicit export download.
CREATE TABLE IF NOT EXISTS request_private_keys (
    request_id TEXT PRIMARY KEY REFERENCES certificate_requests(id),
    key_pem_encrypted TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    created_at TEXT NOT NULL
);
