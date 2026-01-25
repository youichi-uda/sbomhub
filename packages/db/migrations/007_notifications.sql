-- 007_notifications.sql
-- Notification settings and logs for Slack/Discord integration

CREATE TABLE IF NOT EXISTS notification_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    slack_webhook_url TEXT,
    discord_webhook_url TEXT,
    notify_critical BOOLEAN DEFAULT true,
    notify_high BOOLEAN DEFAULT true,
    notify_medium BOOLEAN DEFAULT false,
    notify_low BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(project_id)
);

CREATE TABLE IF NOT EXISTS notification_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    channel VARCHAR(20) NOT NULL,  -- 'slack' or 'discord'
    payload JSONB NOT NULL,
    status VARCHAR(20) NOT NULL,   -- 'sent', 'failed'
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_notification_logs_project ON notification_logs(project_id);
CREATE INDEX IF NOT EXISTS idx_notification_logs_created ON notification_logs(created_at DESC);
