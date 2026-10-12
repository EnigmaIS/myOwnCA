-- Evolve issued_certificates into the common leaf-certificate inventory.
-- Imported certificates use an internal request row so the existing lineage,
-- quota, holder and renewal foreign keys remain authoritative.  Those rows are
-- marked as source=import and are hidden from ordinary request listings.

ALTER TABLE certificate_requests
    ADD COLUMN source TEXT NOT NULL DEFAULT 'request';

ALTER TABLE issued_certificates
    ADD COLUMN certificate_id TEXT;

UPDATE issued_certificates
SET certificate_id = serial_number
WHERE certificate_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_issued_certificate_id
    ON issued_certificates(certificate_id);

ALTER TABLE issued_certificates
    ADD COLUMN source TEXT NOT NULL DEFAULT 'issued';

ALTER TABLE issued_certificates
    ADD COLUMN issuer_id TEXT;

ALTER TABLE issued_certificates
    ADD COLUMN chain_pem TEXT NOT NULL DEFAULT '';

ALTER TABLE issued_certificates
    ADD COLUMN archived_at TEXT;

ALTER TABLE issued_certificates
    ADD COLUMN key_registry_id TEXT;

CREATE INDEX IF NOT EXISTS idx_issued_inventory_source
    ON issued_certificates(source, archived_at, issued_at);

CREATE INDEX IF NOT EXISTS idx_issued_inventory_person
    ON issued_certificates(holder_person_id, archived_at, issued_at);

CREATE INDEX IF NOT EXISTS idx_issued_inventory_device
    ON issued_certificates(holder_device_id, archived_at, issued_at);

CREATE INDEX IF NOT EXISTS idx_issued_inventory_issuer
    ON issued_certificates(issuer_id, status, expires_at);

CREATE UNIQUE INDEX IF NOT EXISTS idx_issued_inventory_issuer_serial
    ON issued_certificates(issuer_id, serial_number);
