-- Move certificate-bound records onto the stable inventory identifier while
-- retaining serial_number for compatibility with existing URLs and clients.

ALTER TABLE revocations
    ADD COLUMN certificate_id TEXT REFERENCES issued_certificates(certificate_id);

UPDATE revocations
SET certificate_id = (
    SELECT issued_certificates.certificate_id
    FROM issued_certificates
    WHERE issued_certificates.serial_number = revocations.serial_number
)
WHERE certificate_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_revocations_certificate_id
    ON revocations(certificate_id);

ALTER TABLE secure_links
    ADD COLUMN certificate_id TEXT REFERENCES issued_certificates(certificate_id);

UPDATE secure_links
SET certificate_id = (
    SELECT issued_certificates.certificate_id
    FROM issued_certificates
    WHERE issued_certificates.serial_number = secure_links.serial_number
)
WHERE certificate_id IS NULL
  AND serial_number IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_secure_links_certificate
    ON secure_links(certificate_id, purpose);
