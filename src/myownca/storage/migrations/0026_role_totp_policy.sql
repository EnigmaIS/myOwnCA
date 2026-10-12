-- Installation-wide TOTP policy, configurable independently for every role.
-- Existing installations preserve the historical requirement for administrators
-- and Certificate Operators. Empty databases may be initialized from setup or
-- CLI configuration before the first account is created.
CREATE TABLE IF NOT EXISTS role_totp_policies (
    role TEXT PRIMARY KEY CHECK (role IN ('admin', 'superuser', 'auditor', 'user')),
    totp_required INTEGER NOT NULL CHECK (totp_required IN (0, 1)),
    source TEXT NOT NULL CHECK (
        source IN ('migration_default', 'legacy_preserved', 'install', 'runtime')
    ),
    updated_at TEXT NOT NULL,
    updated_by TEXT
);

INSERT INTO role_totp_policies(role, totp_required, source, updated_at, updated_by)
SELECT 'admin', 1,
       CASE WHEN EXISTS (SELECT 1 FROM users) THEN 'legacy_preserved' ELSE 'migration_default' END,
       CURRENT_TIMESTAMP, NULL
WHERE NOT EXISTS (SELECT 1 FROM role_totp_policies WHERE role = 'admin');

INSERT INTO role_totp_policies(role, totp_required, source, updated_at, updated_by)
SELECT 'superuser', 1,
       CASE WHEN EXISTS (SELECT 1 FROM users) THEN 'legacy_preserved' ELSE 'migration_default' END,
       CURRENT_TIMESTAMP, NULL
WHERE NOT EXISTS (SELECT 1 FROM role_totp_policies WHERE role = 'superuser');

INSERT INTO role_totp_policies(role, totp_required, source, updated_at, updated_by)
SELECT 'auditor', 0,
       CASE WHEN EXISTS (SELECT 1 FROM users) THEN 'legacy_preserved' ELSE 'migration_default' END,
       CURRENT_TIMESTAMP, NULL
WHERE NOT EXISTS (SELECT 1 FROM role_totp_policies WHERE role = 'auditor');

INSERT INTO role_totp_policies(role, totp_required, source, updated_at, updated_by)
SELECT 'user', 0,
       CASE WHEN EXISTS (SELECT 1 FROM users) THEN 'legacy_preserved' ELSE 'migration_default' END,
       CURRENT_TIMESTAMP, NULL
WHERE NOT EXISTS (SELECT 1 FROM role_totp_policies WHERE role = 'user');

-- Password-based step-up is deliberately distinct from the password used to
-- create a session; only explicit reauthentication populates this timestamp.
ALTER TABLE auth_sessions ADD COLUMN password_verified_at TEXT;
