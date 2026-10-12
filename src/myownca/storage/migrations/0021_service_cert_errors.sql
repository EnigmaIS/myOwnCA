-- Recent ACME / external-cert operation failures, surfaced in-app so an operator
-- can investigate without shell access. Bounded: the repository prunes to the most
-- recent N rows on every insert. The full traceback lives in the server logs, not here.

CREATE TABLE IF NOT EXISTS service_cert_errors (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    operation TEXT NOT NULL,
    target TEXT NOT NULL,
    message TEXT NOT NULL
);
