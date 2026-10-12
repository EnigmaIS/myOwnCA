-- Append-only administrator reports of backup and restore-test activity.
-- These rows are attestations, never assertions that myOwnCA verified an archive.
CREATE TABLE IF NOT EXISTS recovery_attestations (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('backup', 'restore_test')),
    performed_at TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_email TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_recovery_attestations_kind_performed
    ON recovery_attestations(kind, performed_at);
