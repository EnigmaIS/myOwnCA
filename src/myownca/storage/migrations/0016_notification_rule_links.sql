-- Expiring/expired notification rules can embed a renewal claim link
-- ($renewal_url) for the certificate holder.
ALTER TABLE notification_rules ADD COLUMN include_renewal_link INTEGER NOT NULL DEFAULT 0;
