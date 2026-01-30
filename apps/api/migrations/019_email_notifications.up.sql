-- Add email_addresses column to notification_settings
ALTER TABLE notification_settings
ADD COLUMN email_addresses TEXT;
