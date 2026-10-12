-- Service certificates: publicly-trusted certs for public-facing interfaces
-- (e.g. an OCSP responder's TLS endpoint). Three acquisition sources feed one
-- store: an externally-signed CSR, a directly imported cert+key, or ACME.

CREATE TABLE IF NOT EXISTS service_certificates (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    source TEXT NOT NULL,              -- csr_external | imported | acme
    status TEXT NOT NULL,             -- pending | active | superseded
    key_backend TEXT NOT NULL,        -- software | pkcs11
    key_ref TEXT NOT NULL,
    csr_pem TEXT,
    certificate_pem TEXT,
    chain_pem TEXT,
    subject TEXT,
    not_before TEXT,
    not_after TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS acme_accounts (
    id TEXT PRIMARY KEY,
    directory_url TEXT NOT NULL,
    account_url TEXT,
    account_key_ciphertext TEXT NOT NULL,
    contact TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS acme_cert_configs (
    service_certificate_id TEXT PRIMARY KEY
        REFERENCES service_certificates(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES acme_accounts(id),
    domains_json TEXT NOT NULL,
    challenge_type TEXT NOT NULL,     -- http-01 | dns-01
    renew_before_days INTEGER NOT NULL DEFAULT 30
);

-- Persisted state for two-phase (manual DNS-01) ACME orders awaiting validation.
CREATE TABLE IF NOT EXISTS acme_pending_orders (
    id TEXT PRIMARY KEY,
    service_certificate_id TEXT NOT NULL
        REFERENCES service_certificates(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES acme_accounts(id),
    order_url TEXT NOT NULL,
    order_json TEXT NOT NULL DEFAULT '{}',
    csr_pem TEXT NOT NULL,
    authorizations_json TEXT NOT NULL,
    challenge_type TEXT NOT NULL,
    created_at TEXT NOT NULL
);
