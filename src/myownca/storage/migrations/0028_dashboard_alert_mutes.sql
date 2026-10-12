-- Per-user dashboard alert preferences. A mute suppresses only the red visual
-- emphasis; the underlying operational alert remains visible and actionable.
CREATE TABLE IF NOT EXISTS dashboard_alert_mutes (
    user_id VARCHAR(191) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    portal VARCHAR(32) NOT NULL,
    alert_id VARCHAR(191) NOT NULL,
    muted_at TEXT NOT NULL,
    PRIMARY KEY (user_id, portal, alert_id),
    CHECK (portal IN ('admin', 'superuser'))
);
