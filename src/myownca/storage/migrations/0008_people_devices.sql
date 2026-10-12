-- Certificate holders: people and the devices they are responsible for.
-- Every issued certificate is bound to exactly one holder (a person or a
-- device); the "exactly one" rule is enforced in the service layer because
-- SQLite cannot add a table-level CHECK via ALTER TABLE. Every device is
-- bound to a responsible person via admin_id, so a device-held certificate
-- always resolves to a human.

CREATE TABLE IF NOT EXISTS people (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    surname TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    phone TEXT NOT NULL DEFAULT '',
    slack_handle TEXT NOT NULL DEFAULT '',
    company TEXT NOT NULL DEFAULT '',
    comments TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    device_name TEXT NOT NULL,
    fqdn TEXT NOT NULL DEFAULT '',
    admin_id TEXT NOT NULL REFERENCES people(id),
    comments TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_devices_admin ON devices(admin_id);

ALTER TABLE certificate_requests ADD COLUMN holder_person_id TEXT REFERENCES people(id);
ALTER TABLE certificate_requests ADD COLUMN holder_device_id TEXT REFERENCES devices(id);

ALTER TABLE issued_certificates ADD COLUMN holder_person_id TEXT REFERENCES people(id);
ALTER TABLE issued_certificates ADD COLUMN holder_device_id TEXT REFERENCES devices(id);
