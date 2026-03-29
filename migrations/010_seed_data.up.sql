-- Migration 010: Initial Seed Data

-- Insert default admin user (password: Admin@123)
-- bcrypt hash generated with cost 12 for "Admin@123"
INSERT INTO users (id, username, email, password_hash, first_name, last_name, enabled, email_verified)
VALUES ('00000000-0000-0000-0000-000000000001', 'admin', 'admin@openidx.local', '$2b$12$oX..0F6dHbNip8vASE5VdOgXiBfyqRZ768PU5vArjeOMxG5MGEEdq', 'System', 'Admin', true, true)
ON CONFLICT (id) DO NOTHING;

-- Insert sample roles
INSERT INTO roles (id, name, description, is_composite) VALUES
('60000000-0000-0000-0000-000000000001', 'admin', 'System administrator with full access', false),
('60000000-0000-0000-0000-000000000002', 'user', 'Standard user role', false),
('60000000-0000-0000-0000-000000000003', 'manager', 'Manager role with additional permissions', false),
('60000000-0000-0000-0000-000000000004', 'auditor', 'Audit and compliance role', false),
('60000000-0000-0000-0000-000000000005', 'developer', 'Software developer role', false)
ON CONFLICT (id) DO NOTHING;

-- Insert sample users
INSERT INTO users (id, username, email, first_name, last_name, enabled, email_verified) VALUES
('00000000-0000-0000-0000-000000000002', 'jsmith', 'john.smith@example.com', 'John', 'Smith', true, true),
('00000000-0000-0000-0000-000000000003', 'jdoe', 'jane.doe@example.com', 'Jane', 'Doe', true, true),
('00000000-0000-0000-0000-000000000004', 'bwilson', 'bob.wilson@example.com', 'Bob', 'Wilson', true, false),
('00000000-0000-0000-0000-000000000005', 'amartin', 'alice.martin@example.com', 'Alice', 'Martin', false, true)
ON CONFLICT (id) DO NOTHING;

-- Insert sample groups
INSERT INTO groups (id, name, description, parent_id) VALUES
('10000000-0000-0000-0000-000000000001', 'Administrators', 'System administrators with full access', NULL),
('10000000-0000-0000-0000-000000000002', 'Developers', 'Software development team', NULL),
('10000000-0000-0000-0000-000000000003', 'DevOps', 'DevOps engineering team', '10000000-0000-0000-0000-000000000002'),
('10000000-0000-0000-0000-000000000004', 'QA Team', 'Quality assurance team', '10000000-0000-0000-0000-000000000002'),
('10000000-0000-0000-0000-000000000005', 'Finance', 'Finance department', NULL),
('10000000-0000-0000-0000-000000000006', 'HR', 'Human resources department', NULL)
ON CONFLICT (id) DO NOTHING;

-- Insert group memberships
INSERT INTO group_memberships (user_id, group_id) VALUES
('00000000-0000-0000-0000-000000000001', '10000000-0000-0000-0000-000000000001'),
('00000000-0000-0000-0000-000000000002', '10000000-0000-0000-0000-000000000002'),
('00000000-0000-0000-0000-000000000002', '10000000-0000-0000-0000-000000000003'),
('00000000-0000-0000-0000-000000000003', '10000000-0000-0000-0000-000000000002'),
('00000000-0000-0000-0000-000000000003', '10000000-0000-0000-0000-000000000004'),
('00000000-0000-0000-0000-000000000004', '10000000-0000-0000-0000-000000000005'),
('00000000-0000-0000-0000-000000000005', '10000000-0000-0000-0000-000000000006')
ON CONFLICT DO NOTHING;

-- Insert sample applications
INSERT INTO applications (id, client_id, name, description, type, protocol, base_url, redirect_uris, enabled) VALUES
('40000000-0000-0000-0000-000000000001', 'admin-console', 'Admin Console', 'OpenIDX Administration Console', 'web', 'openid-connect', 'http://localhost:3000', ARRAY['http://localhost:3000/callback'], true),
('40000000-0000-0000-0000-000000000002', 'sample-spa', 'Sample SPA', 'Sample Single Page Application', 'spa', 'openid-connect', 'http://localhost:4000', ARRAY['http://localhost:4000/callback'], true),
('40000000-0000-0000-0000-000000000003', 'api-service', 'API Service', 'Backend API Service', 'service', 'openid-connect', NULL, NULL, true)
ON CONFLICT (id) DO NOTHING;

-- Insert OAuth clients (public and confidential)
INSERT INTO oauth_clients (id, client_id, client_secret, name, description, type, redirect_uris, grant_types, response_types, scopes, pkce_required, allow_refresh_token, access_token_lifetime, refresh_token_lifetime) VALUES
-- Admin Console - public client (no secret, PKCE required)
('80000000-0000-0000-0000-000000000001', 'admin-console', NULL, 'Admin Console', 'OpenIDX Administration Console', 'public',
 '["http://localhost:3000/login", "http://localhost:3000/callback"]'::jsonb,
 '["authorization_code", "refresh_token"]'::jsonb,
 '["code"]'::jsonb,
 '["openid", "profile", "email", "offline_access"]'::jsonb,
 true, true, 3600, 86400),
-- API Service - confidential client
('80000000-0000-0000-0000-000000000002', 'api-service', 'api-service-secret', 'API Service', 'Backend API Service', 'confidential',
 '[]'::jsonb,
 '["client_credentials"]'::jsonb,
 '[]'::jsonb,
 '["openid", "api"]'::jsonb,
 false, false, 3600, 0)
ON CONFLICT (id) DO NOTHING;

-- Add test client for debugging
INSERT INTO oauth_clients (id, client_id, client_secret, name, description, type, redirect_uris, grant_types, response_types, scopes, pkce_required, allow_refresh_token, access_token_lifetime, refresh_token_lifetime) VALUES
('80000000-0000-0000-0000-000000000003', 'test-client', 'test-secret', 'Test Client', 'Client for testing authentication flow', 'confidential',
 '[]'::jsonb,
 '["authorization_code", "refresh_token", "client_credentials"]'::jsonb,
 '["code"]'::jsonb,
 '["openid", "profile", "email"]'::jsonb,
 false, true, 3600, 86400)
ON CONFLICT (id) DO NOTHING;

-- Insert sample application SSO settings
INSERT INTO application_sso_settings (id, application_id, enabled, use_refresh_tokens, access_token_lifetime, refresh_token_lifetime, require_consent) VALUES
('50000000-0000-0000-0000-000000000001', '40000000-0000-0000-0000-000000000001', true, true, 3600, 86400, false),
('50000000-0000-0000-0000-000000000002', '40000000-0000-0000-0000-000000000002', true, true, 1800, 43200, true),
('50000000-0000-0000-0000-000000000003', '40000000-0000-0000-0000-000000000003', true, false, 3600, 0, false)
ON CONFLICT (id) DO NOTHING;

-- Assign admin role to admin user
INSERT INTO user_roles (user_id, role_id, assigned_by) VALUES
('00000000-0000-0000-0000-000000000001', '60000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000001')
ON CONFLICT DO NOTHING;

-- Insert sample access review
INSERT INTO access_reviews (id, name, description, type, status, reviewer_id, start_date, end_date) VALUES
('70000000-0000-0000-0000-000000000001', 'Q1 2026 Access Review', 'Quarterly access review for all users', 'user-access', 'pending', '00000000-0000-0000-0000-000000000001', '2026-01-01', '2026-03-31')
ON CONFLICT (id) DO NOTHING;
