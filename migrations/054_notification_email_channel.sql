-- Allow SMTP email notification channel.
ALTER TABLE notification_rules DROP CONSTRAINT IF EXISTS notification_rules_channel_type_check;
ALTER TABLE notification_rules ADD CONSTRAINT notification_rules_channel_type_check
    CHECK (channel_type IN ('webhook', 'log', 'email'));
