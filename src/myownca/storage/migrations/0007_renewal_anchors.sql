ALTER TABLE certificate_requests
    ADD COLUMN renewal_of_serial_number TEXT REFERENCES issued_certificates(serial_number);
