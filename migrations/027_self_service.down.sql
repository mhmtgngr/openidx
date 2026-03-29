-- Rollback 027: Self-Service Portal Tables

DROP INDEX IF EXISTS idx_user_app_assignments_user;
DROP TABLE IF EXISTS user_application_assignments;
DROP INDEX IF EXISTS idx_group_requests_status;
DROP INDEX IF EXISTS idx_group_requests_user;
DROP TABLE IF EXISTS group_join_requests;
