-- Session-bound MFA time used for step-up authorization of destructive actions.
-- Existing sessions intentionally start NULL and must reauthenticate.
ALTER TABLE auth_sessions ADD COLUMN mfa_verified_at TEXT;
