-- Install-level approval policy. Existing installations start in dual control
-- so applying this migration can never silently weaken privileged operations.
-- A setup-written explicit mode replaces this migration default on first boot.
CREATE TABLE IF NOT EXISTS install_governance (
    singleton_id INTEGER PRIMARY KEY,
    mode TEXT NOT NULL CHECK (mode IN ('single_admin', 'dual_control')),
    source TEXT NOT NULL CHECK (
        source IN ('migration_default', 'legacy_preserved', 'install', 'runtime')
    ),
    updated_at TEXT NOT NULL,
    updated_by TEXT
);

INSERT INTO install_governance(singleton_id, mode, source, updated_at, updated_by)
SELECT 1,
       'dual_control',
       CASE
           WHEN EXISTS (SELECT 1 FROM users) THEN 'legacy_preserved'
           ELSE 'migration_default'
       END,
       CURRENT_TIMESTAMP,
       NULL
WHERE NOT EXISTS (SELECT 1 FROM install_governance WHERE singleton_id = 1);
