-- Durable ACME checkpoints used by at-least-once cloud signing jobs.  An
-- order is tied to the queue job's stable idempotency key so a lease loss can
-- resume the same ACME order instead of creating another certificate.

CREATE TABLE IF NOT EXISTS acme_order_checkpoints (
    idempotency_key TEXT PRIMARY KEY,
    service_certificate_id TEXT NOT NULL
        REFERENCES service_certificates(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL,             -- issue | renew
    state TEXT NOT NULL DEFAULT 'prepared', -- prepared | creating | created | completed
    csr_pem TEXT NOT NULL,
    csr_sha256 TEXT NOT NULL,
    prior_certificate_sha256 TEXT,
    order_url TEXT,
    order_json TEXT,
    challenges_json TEXT NOT NULL DEFAULT '[]',
    fullchain_pem TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (purpose IN ('issue', 'renew')),
    CHECK (state IN ('prepared', 'creating', 'created', 'completed'))
);

CREATE INDEX IF NOT EXISTS idx_acme_order_checkpoints_certificate
    ON acme_order_checkpoints(service_certificate_id, created_at);
