-- Persist the lifecycle identity used by each vaulted request key.  Renewal
-- reuse may copy the encrypted vault row for request-scoped export while both
-- rows still represent one private key and therefore share one registry entry.

ALTER TABLE certificate_requests
    ADD COLUMN key_registry_id TEXT REFERENCES key_lifecycle_keys(id);

CREATE INDEX IF NOT EXISTS idx_requests_key_registry
    ON certificate_requests(key_registry_id);
