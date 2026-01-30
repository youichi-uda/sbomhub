-- Remove email_addresses column from notification_settings
ALTER TABLE notification_settings
DROP COLUMN IF EXISTS email_addresses;
