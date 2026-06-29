-- Reverse of 046_diff_webhook_settings.up.sql (M11-4 #79).
DROP TRIGGER IF EXISTS trg_tenant_diff_webhook_settings_updated_at
    ON tenant_diff_webhook_settings;
DROP FUNCTION IF EXISTS tenant_diff_webhook_settings_set_updated_at();
DROP TABLE IF EXISTS tenant_diff_webhook_settings;
