ALTER TABLE certificate_templates
ADD COLUMN allowed_key_algorithms_json TEXT NOT NULL DEFAULT '["rsa-2048","rsa-3072","rsa-4096","ecdsa-p256","ecdsa-p384","ecdsa-p521"]';
