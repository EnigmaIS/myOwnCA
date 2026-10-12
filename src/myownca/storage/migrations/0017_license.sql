-- Commercial license (usage tier). Single active row, replaced on upload.
-- The raw signed token is re-verified on every load; the parsed columns are
-- for display only and are never trusted for enforcement.
CREATE TABLE IF NOT EXISTS licenses (
    id TEXT PRIMARY KEY,
    token TEXT NOT NULL,
    license_id TEXT NOT NULL,
    licensed_to TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    max_active_certs INTEGER NOT NULL,
    uploaded_by TEXT NOT NULL,
    uploaded_at TEXT NOT NULL
);
