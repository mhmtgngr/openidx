-- Rollback 009: Performance Indexes

-- Compliance Reports
DROP INDEX IF EXISTS idx_compliance_reports_framework;
DROP INDEX IF EXISTS idx_compliance_reports_generated_at;
DROP INDEX IF EXISTS idx_compliance_reports_status;
DROP INDEX IF EXISTS idx_compliance_reports_type;

-- Audit
DROP INDEX IF EXISTS idx_audit_events_outcome;
DROP INDEX IF EXISTS idx_audit_events_category;
DROP INDEX IF EXISTS idx_audit_events_type;
DROP INDEX IF EXISTS idx_audit_events_actor;
DROP INDEX IF EXISTS idx_audit_events_timestamp;

-- Applications
DROP INDEX IF EXISTS idx_application_sso_settings_application_id;
DROP INDEX IF EXISTS idx_applications_client_id;

-- Sessions
DROP INDEX IF EXISTS idx_user_sessions_token;
DROP INDEX IF EXISTS idx_user_sessions_user_id;
DROP INDEX IF EXISTS idx_sessions_expires_at;
DROP INDEX IF EXISTS idx_sessions_user_id;

-- MFA
DROP INDEX IF EXISTS idx_push_challenges_expires_at;
DROP INDEX IF EXISTS idx_push_challenges_status;
DROP INDEX IF EXISTS idx_push_challenges_user_id;
DROP INDEX IF EXISTS idx_push_devices_token;
DROP INDEX IF EXISTS idx_push_devices_user_id;
DROP INDEX IF EXISTS idx_webauthn_credential_id;
DROP INDEX IF EXISTS idx_webauthn_user_id;

-- Governance
DROP INDEX IF EXISTS idx_policies_type;
DROP INDEX IF EXISTS idx_review_items_user_id;
DROP INDEX IF EXISTS idx_review_items_review_id;
DROP INDEX IF EXISTS idx_access_reviews_status;

-- SCIM
DROP INDEX IF EXISTS idx_scim_groups_external_id;
DROP INDEX IF EXISTS idx_scim_users_external_id;

-- OAuth
DROP INDEX IF EXISTS idx_oauth_refresh_tokens_client_id;
DROP INDEX IF EXISTS idx_oauth_access_tokens_user_id;
DROP INDEX IF EXISTS idx_oauth_access_tokens_client_id;
DROP INDEX IF EXISTS idx_oauth_authorization_codes_user_id;
DROP INDEX IF EXISTS idx_oauth_authorization_codes_client_id;
DROP INDEX IF EXISTS idx_oauth_clients_client_id;

-- Roles
DROP INDEX IF EXISTS idx_user_roles_role_id;
DROP INDEX IF EXISTS idx_user_roles_user_id;

-- Users and Groups
DROP INDEX IF EXISTS idx_groups_name;
DROP INDEX IF EXISTS idx_users_username;
DROP INDEX IF EXISTS idx_users_email;
