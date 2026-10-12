CREATE TABLE IF NOT EXISTS issuer_crls (
    issuer_subject TEXT NOT NULL,
    number INTEGER NOT NULL,
    crl_pem TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    PRIMARY KEY (issuer_subject, number)
);
