-- Drop IPA integration tables

DROP POLICY IF EXISTS "ipa_sync_settings_tenant_isolation" ON ipa_sync_settings;

DROP TABLE IF EXISTS ipa_vulnerability_mapping;
DROP TABLE IF EXISTS ipa_sync_settings;
DROP TABLE IF EXISTS ipa_announcements;
