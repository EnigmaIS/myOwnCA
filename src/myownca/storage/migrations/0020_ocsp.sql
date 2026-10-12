-- OCSP: a delegated responder identity per issuer, and pre-produced responses
-- (DER stored base64 in TEXT for cross-dialect safety), one row per
-- (issuer, serial, CertID hash algorithm).

CREATE TABLE IF NOT EXISTS ocsp_responders (
    issuer_subject TEXT PRIMARY KEY,
    cert_pem TEXT NOT NULL,
    key_ref TEXT NOT NULL,
    not_after TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ocsp_responses (
    issuer_subject TEXT NOT NULL,
    serial_number TEXT NOT NULL,
    cert_id_hash TEXT NOT NULL,
    response_b64 TEXT NOT NULL,
    this_update TEXT NOT NULL,
    next_update TEXT NOT NULL,
    produced_at TEXT NOT NULL,
    PRIMARY KEY (issuer_subject, serial_number, cert_id_hash)
);
