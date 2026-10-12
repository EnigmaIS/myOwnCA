-- Persist the backend identity of issuer keys.  The active HSM can be changed
-- by an issuer import, so process restart and lifecycle reconciliation must not
-- infer every historical Sub-CA key from the current environment setting.

ALTER TABLE pending_sub_cas ADD COLUMN key_backend TEXT;
ALTER TABLE pending_sub_cas ADD COLUMN token_label TEXT;

ALTER TABLE sub_cas ADD COLUMN key_backend TEXT;
ALTER TABLE sub_cas ADD COLUMN token_label TEXT;
