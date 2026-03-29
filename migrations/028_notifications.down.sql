-- Rollback 028: Notification System Tables

DROP INDEX IF EXISTS idx_notification_prefs_user;
DROP INDEX IF EXISTS idx_notifications_user;
DROP TABLE IF EXISTS notification_preferences;
DROP TABLE IF NOT EXISTS notifications;
