CREATE TABLE pending_sub_cas_without_transfer (
    id TEXT PRIMARY KEY,
    key_ref TEXT NOT NULL,
    csr_pem TEXT NOT NULL,
    subject TEXT NOT NULL,
    created_at TEXT NOT NULL,
    allowed_profiles_json TEXT NOT NULL DEFAULT '["user_auth","host_tls","smime"]',
    key_backend TEXT,
    token_label TEXT
);

INSERT INTO pending_sub_cas_without_transfer(
    id, key_ref, csr_pem, subject, created_at,
    allowed_profiles_json, key_backend, token_label
)
SELECT
    id, key_ref, csr_pem, subject, created_at,
    allowed_profiles_json, key_backend, token_label
FROM pending_sub_cas;

DROP TABLE pending_sub_cas;

ALTER TABLE pending_sub_cas_without_transfer RENAME TO pending_sub_cas;
