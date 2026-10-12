ALTER TABLE certificate_templates ADD COLUMN key_usages_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE certificate_templates ADD COLUMN extended_key_usages_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE certificate_templates ADD COLUMN key_usage_critical INTEGER NOT NULL DEFAULT 1;
ALTER TABLE certificate_templates ADD COLUMN extended_key_usage_critical INTEGER NOT NULL DEFAULT 0;

UPDATE certificate_templates
SET key_usages_json = CASE profile
    WHEN 'user_auth' THEN '["digital_signature"]'
    WHEN 'host_tls' THEN '["digital_signature","key_encipherment"]'
    WHEN 'smime' THEN '["digital_signature","content_commitment","key_encipherment"]'
    ELSE key_usages_json
END
WHERE key_usages_json = '[]';

UPDATE certificate_templates
SET extended_key_usages_json = CASE profile
    WHEN 'user_auth' THEN '["client_auth"]'
    WHEN 'host_tls' THEN '["server_auth"]'
    WHEN 'smime' THEN '["email_protection"]'
    ELSE extended_key_usages_json
END
WHERE extended_key_usages_json = '[]';

ALTER TABLE pending_sub_cas ADD COLUMN allowed_profiles_json TEXT NOT NULL
    DEFAULT '["user_auth","host_tls","smime"]';
ALTER TABLE sub_cas ADD COLUMN allowed_profiles_json TEXT NOT NULL
    DEFAULT '["user_auth","host_tls","smime"]';
