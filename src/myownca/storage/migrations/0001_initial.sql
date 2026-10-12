CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS certificate_templates (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    profile TEXT NOT NULL,
    validity_days INTEGER NOT NULL,
    first_issuance_approvals INTEGER NOT NULL,
    renewal_approvals INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS certificate_requests (
    id TEXT PRIMARY KEY,
    template_id TEXT NOT NULL REFERENCES certificate_templates(id),
    csr_pem TEXT NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
    request_id TEXT NOT NULL REFERENCES certificate_requests(id),
    superuser_id TEXT NOT NULL REFERENCES users(id),
    approved_at TEXT NOT NULL,
    PRIMARY KEY (request_id, superuser_id)
);

CREATE TABLE IF NOT EXISTS issued_certificates (
    serial_number TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE REFERENCES certificate_requests(id),
    template_id TEXT NOT NULL REFERENCES certificate_templates(id),
    certificate_pem TEXT NOT NULL,
    subject TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS revocations (
    serial_number TEXT PRIMARY KEY REFERENCES issued_certificates(serial_number),
    reason TEXT NOT NULL,
    revoked_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sub_cas (
    id TEXT PRIMARY KEY,
    certificate_pem TEXT NOT NULL,
    key_ref TEXT NOT NULL,
    subject TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS root_crls (
    number INTEGER PRIMARY KEY,
    crl_pem TEXT NOT NULL,
    generated_at TEXT NOT NULL
);
