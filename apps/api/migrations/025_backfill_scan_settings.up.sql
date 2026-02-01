-- Backfill scan_settings for existing tenants that don't have settings
-- This ensures all tenants have vulnerability scanning enabled by default

INSERT INTO scan_settings (id, tenant_id, enabled, schedule_type, schedule_hour, notify_critical, notify_high, next_scan_at)
SELECT
    uuid_generate_v4(),
    t.id,
    true,           -- enabled by default
    'daily',        -- daily schedule
    6,              -- 6:00 AM
    true,           -- notify on critical
    true,           -- notify on high
    NOW()           -- scan immediately on next run
FROM tenants t
WHERE NOT EXISTS (
    SELECT 1 FROM scan_settings ss WHERE ss.tenant_id = t.id
);
