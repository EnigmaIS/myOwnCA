-- ``issued_certificates.serial_number`` was the original primary key.  Keep
-- that table as a compatibility shadow for old foreign keys, while moving all
-- runtime ownership to a certificate-id keyed inventory.  A serial is only
-- unique within an issuer.

CREATE TABLE IF NOT EXISTS certificate_inventory (
    certificate_id TEXT PRIMARY KEY,
    serial_number TEXT NOT NULL,
    request_id TEXT NOT NULL UNIQUE REFERENCES certificate_requests(id),
    template_id TEXT NOT NULL REFERENCES certificate_templates(id),
    certificate_pem TEXT NOT NULL,
    subject TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    status TEXT NOT NULL,
    holder_person_id TEXT REFERENCES people(id),
    holder_device_id TEXT REFERENCES devices(id),
    lineage_id TEXT REFERENCES certificate_lineages(id),
    source TEXT NOT NULL DEFAULT 'issued',
    issuer_id TEXT NOT NULL,
    chain_pem TEXT NOT NULL DEFAULT '',
    archived_at TEXT,
    key_registry_id TEXT REFERENCES key_lifecycle_keys(id),
    UNIQUE (issuer_id, serial_number)
);

INSERT INTO certificate_inventory(
    certificate_id, serial_number, request_id, template_id, certificate_pem,
    subject, issued_at, expires_at, status, holder_person_id, holder_device_id,
    lineage_id, source, issuer_id, chain_pem, archived_at, key_registry_id
)
SELECT
    COALESCE(NULLIF(certificate_id, ''), serial_number), serial_number,
    request_id, template_id, certificate_pem, subject, issued_at, expires_at,
    status, holder_person_id, holder_device_id, lineage_id, source,
    COALESCE(NULLIF(issuer_id, ''), COALESCE(NULLIF(certificate_id, ''), serial_number)),
    chain_pem, archived_at, key_registry_id
FROM issued_certificates;

CREATE INDEX IF NOT EXISTS idx_certificate_inventory_serial
    ON certificate_inventory(serial_number);

CREATE INDEX IF NOT EXISTS idx_certificate_inventory_source
    ON certificate_inventory(source, archived_at, issued_at);

CREATE INDEX IF NOT EXISTS idx_certificate_inventory_person
    ON certificate_inventory(holder_person_id, archived_at, issued_at);

CREATE INDEX IF NOT EXISTS idx_certificate_inventory_device
    ON certificate_inventory(holder_device_id, archived_at, issued_at);

CREATE INDEX IF NOT EXISTS idx_certificate_inventory_issuer
    ON certificate_inventory(issuer_id, status, expires_at);

-- Canonical revocations can distinguish equal serials from different issuers.
-- ``revocations`` remains populated for the legacy shadow where possible.
CREATE TABLE IF NOT EXISTS certificate_revocations (
    certificate_id TEXT PRIMARY KEY REFERENCES certificate_inventory(certificate_id),
    serial_number TEXT NOT NULL,
    reason TEXT NOT NULL,
    revoked_at TEXT NOT NULL
);

INSERT INTO certificate_revocations(certificate_id, serial_number, reason, revoked_at)
SELECT
    COALESCE(r.certificate_id, i.certificate_id),
    r.serial_number,
    r.reason,
    r.revoked_at
FROM revocations r
JOIN certificate_inventory i
  ON i.serial_number = r.serial_number
 AND (r.certificate_id IS NULL OR r.certificate_id = i.certificate_id);

CREATE INDEX IF NOT EXISTS idx_certificate_revocations_serial
    ON certificate_revocations(serial_number, revoked_at);

-- Keep secure_links itself intact for old installations and old FKs.  This
-- mapping is authoritative and permits a link to target an inventory row that
-- has no distinct row in the serial-keyed compatibility shadow.
CREATE TABLE IF NOT EXISTS secure_link_certificate_refs (
    link_id TEXT PRIMARY KEY REFERENCES secure_links(id) ON DELETE CASCADE,
    certificate_id TEXT NOT NULL REFERENCES certificate_inventory(certificate_id)
);

INSERT INTO secure_link_certificate_refs(link_id, certificate_id)
SELECT id, certificate_id
FROM secure_links
WHERE certificate_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_secure_link_certificate_refs_certificate
    ON secure_link_certificate_refs(certificate_id, link_id);

-- Renewal identity is canonical as well.  renewal_of_serial_number remains a
-- compatibility hint for clients and old rows; the mapping drives runtime.
CREATE TABLE IF NOT EXISTS certificate_request_renewal_refs (
    request_id TEXT PRIMARY KEY REFERENCES certificate_requests(id),
    certificate_id TEXT NOT NULL REFERENCES certificate_inventory(certificate_id)
);

INSERT INTO certificate_request_renewal_refs(request_id, certificate_id)
SELECT r.id, i.certificate_id
FROM certificate_requests r
JOIN certificate_inventory i
  ON i.serial_number = r.renewal_of_serial_number
WHERE r.renewal_of_serial_number IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_request_renewal_refs_certificate
    ON certificate_request_renewal_refs(certificate_id, request_id);
