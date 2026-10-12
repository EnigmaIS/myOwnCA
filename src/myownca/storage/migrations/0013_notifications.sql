-- Notification module: named templates, scheduling/dispatch rules, delivery log.
-- Templates render with $variable placeholders (string.Template); rules bind an
-- event type to a template + comms channel + audience. The delivery log is a
-- plain append table (NOT hash-chained) so the cron runner can write it safely
-- without touching the single-writer audit_events chain.

CREATE TABLE IF NOT EXISTS notification_templates (
    name TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    format TEXT NOT NULL DEFAULT 'text',
    subject TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL DEFAULT '',
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS notification_rules (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    template_name TEXT NOT NULL REFERENCES notification_templates(name),
    channel TEXT NOT NULL,
    audience TEXT NOT NULL DEFAULT 'holder',
    enabled INTEGER NOT NULL DEFAULT 1,
    period_days INTEGER NOT NULL DEFAULT 1,
    threshold_days INTEGER NOT NULL DEFAULT 30,
    notification_text TEXT NOT NULL DEFAULT '',
    last_run_at TEXT
);

CREATE TABLE IF NOT EXISTS notification_log (
    id TEXT PRIMARY KEY,
    rule_id TEXT,
    event_type TEXT NOT NULL,
    template_name TEXT NOT NULL,
    channel TEXT NOT NULL,
    recipient TEXT NOT NULL,
    subject TEXT NOT NULL DEFAULT '',
    object_ref TEXT,
    success INTEGER NOT NULL DEFAULT 0,
    detail TEXT NOT NULL DEFAULT '',
    sent_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_notification_log_object ON notification_log(rule_id, object_ref, sent_at);
CREATE INDEX IF NOT EXISTS idx_notification_rules_event ON notification_rules(event_type, enabled);
