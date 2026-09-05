-- deployments/docker/seed.sql
-- Bootstrap seed for docker-compose: the functional delta the migrations do NOT
-- already seed. migrate-from-empty already creates the default org, admin user,
-- admin-console OAuth client, roles, permissions, user_roles, system_settings.
-- This file adds role_permissions (granular RBAC for non-admin roles; admin is
-- privileged by role name) and default policy/config rows.
--
-- Runs as the superuser AFTER `migrate up`, with app.bypass_rls set so the FORCE'd
-- RLS belt permits inserts into org-scoped tables. Scoped tables (role_permissions,
-- privacy_retention_policies, tenant_branding) have a DEFAULT of the default-org
-- UUID (migration v36), so INSERTs that omit org_id still land in the default org.
--
-- EXCLUDED (sample data, not required for a functional install): demo users
-- (jsmith/jdoe/bwilson), demo proxy_routes, demo applications, ziti_user_sync demo.
--
-- Idempotent: every INSERT is ON CONFLICT DO NOTHING.
SET app.bypass_rls = 'on';

-- Admin: all permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT '60000000-0000-0000-0000-000000000001', id FROM permissions
ON CONFLICT DO NOTHING;

-- Manager: read/write users, read/write groups, read roles, read applications, read audit, read sessions
INSERT INTO role_permissions (role_id, permission_id) VALUES
('60000000-0000-0000-0000-000000000003', 'a0000000-0000-0000-0000-000000000001'),
('60000000-0000-0000-0000-000000000003', 'a0000000-0000-0000-0000-000000000002'),
('60000000-0000-0000-0000-000000000003', 'a0000000-0000-0000-0000-000000000004'),
('60000000-0000-0000-0000-000000000003', 'a0000000-0000-0000-0000-000000000006'),
('60000000-0000-0000-0000-000000000003', 'a0000000-0000-0000-0000-000000000008'),
('60000000-0000-0000-0000-000000000003', 'a0000000-0000-0000-0000-000000000010'),
('60000000-0000-0000-0000-000000000003', 'a0000000-0000-0000-0000-000000000011'),
('60000000-0000-0000-0000-000000000003', 'a0000000-0000-0000-0000-000000000017')
ON CONFLICT DO NOTHING;

-- Auditor: read users, read roles, read applications, read audit, read policies, read sessions, read settings
INSERT INTO role_permissions (role_id, permission_id) VALUES
('60000000-0000-0000-0000-000000000004', 'a0000000-0000-0000-0000-000000000001'),
('60000000-0000-0000-0000-000000000004', 'a0000000-0000-0000-0000-000000000004'),
('60000000-0000-0000-0000-000000000004', 'a0000000-0000-0000-0000-000000000006'),
('60000000-0000-0000-0000-000000000004', 'a0000000-0000-0000-0000-000000000008'),
('60000000-0000-0000-0000-000000000004', 'a0000000-0000-0000-0000-000000000010'),
('60000000-0000-0000-0000-000000000004', 'a0000000-0000-0000-0000-000000000013'),
('60000000-0000-0000-0000-000000000004', 'a0000000-0000-0000-0000-000000000017'),
('60000000-0000-0000-0000-000000000004', 'a0000000-0000-0000-0000-000000000020')
ON CONFLICT DO NOTHING;

-- User: read users, read roles, read applications, read groups
INSERT INTO role_permissions (role_id, permission_id) VALUES
('60000000-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-000000000001'),
('60000000-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-000000000004'),
('60000000-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-000000000006'),
('60000000-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-000000000010')
ON CONFLICT DO NOTHING;

-- Developer: read users, read roles, read applications, read groups, read directories
INSERT INTO role_permissions (role_id, permission_id) VALUES
('60000000-0000-0000-0000-000000000005', 'a0000000-0000-0000-0000-000000000001'),
('60000000-0000-0000-0000-000000000005', 'a0000000-0000-0000-0000-000000000004'),
('60000000-0000-0000-0000-000000000005', 'a0000000-0000-0000-0000-000000000006'),
('60000000-0000-0000-0000-000000000005', 'a0000000-0000-0000-0000-000000000010'),
('60000000-0000-0000-0000-000000000005', 'a0000000-0000-0000-0000-000000000015')
ON CONFLICT DO NOTHING;

-- Posture check types
INSERT INTO posture_check_types (id, name, description, category, parameters) VALUES
('a0000000-0000-0000-0000-000000000001', 'os_check', 'Operating System Version Check', 'device', '{"os_types": ["Windows", "macOS", "Linux"], "min_versions": {}}'),
('a0000000-0000-0000-0000-000000000002', 'domain_check', 'Windows Domain Membership Check', 'device', '{"domains": []}'),
('a0000000-0000-0000-0000-000000000003', 'mac_address_check', 'MAC Address Allowlist Check', 'network', '{"mac_addresses": []}'),
('a0000000-0000-0000-0000-000000000004', 'mfa_check', 'Multi-Factor Authentication Check', 'authentication', '{"timeout_seconds": 300}'),
('a0000000-0000-0000-0000-000000000005', 'process_check', 'Running Process Check', 'endpoint', '{"os_type": "", "path": "", "hashes": []}')
ON CONFLICT (id) DO NOTHING;

-- Risk policies (default org)
--
-- Explicit ids pinned so re-applying the seed is idempotent: risk_policies has no
-- unique key other than the id PK, so a bare ON CONFLICT (on the auto-generated id)
-- would never collide and would duplicate all rows on every re-apply.
--
-- org_id is named explicitly. Migration v153 made risk_policies per-tenant with
-- NOT NULL and no column DEFAULT (the register programme does not add defaults --
-- a default is how a row acquires a tenant it was never given), so unlike the
-- v36-era scoped tables above, an INSERT that omits org_id fails rather than
-- landing in the default org. These are starter rules for the default
-- organization; another organization gets its own, and one organization's rules
-- no longer apply to another organization's logins.
INSERT INTO risk_policies (id, org_id, name, description, priority, conditions, actions)
SELECT v.id::uuid, o.id, v.name, v.description, v.priority, v.conditions::jsonb, v.actions::jsonb
FROM organizations o
CROSS JOIN (VALUES
    (
        'f1000000-0000-0000-0000-000000000001',
        'New Device MFA',
        'Require MFA when logging in from a new device',
        100,
        '{"new_device": true}',
        '{"require_mfa": true, "mfa_methods": ["any"]}'
    ),
    (
        'f1000000-0000-0000-0000-000000000002',
        'New Location MFA',
        'Require MFA when logging in from a new location',
        90,
        '{"new_location": true}',
        '{"require_mfa": true, "mfa_methods": ["any"]}'
    ),
    (
        'f1000000-0000-0000-0000-000000000003',
        'High Risk Score',
        'Require strong MFA for high-risk logins',
        80,
        '{"risk_score_min": 50}',
        '{"require_mfa": true, "mfa_methods": ["webauthn", "push"], "step_up": true}'
    ),
    (
        'f1000000-0000-0000-0000-000000000004',
        'Impossible Travel',
        'Block or require step-up auth for impossible travel',
        70,
        '{"impossible_travel": true}',
        '{"require_mfa": true, "mfa_methods": ["webauthn", "push"], "step_up": true, "notify_admin": true}'
    ),
    (
        'f1000000-0000-0000-0000-000000000005',
        'Blocked IP',
        'Deny access from blocked IP addresses',
        60,
        '{"ip_blocked": true}',
        '{"deny": true, "notify_admin": true}'
    )
) AS v(id, name, description, priority, conditions, actions)
WHERE o.slug = 'default'
ON CONFLICT (id) DO NOTHING;

-- ISPM rules: NOT seeded here any more. ispm_rules is per-tenant since
-- migration v138 (org_id NOT NULL, FORCE RLS), so a single install-wide seed row
-- cannot belong to every organization. The admin service seeds each org's rule
-- set on first use from the checks the scan engine actually implements
-- (internal/admin/ispm.go, postureCheckDefs / ensureDefaultRules). The old seed
-- listed ten rules of which six had no check behind them; those are gone with it.

-- Lifecycle policies. Per-tenant since migration v154 (org_id NOT NULL, FORCE
-- RLS), so these name the default organization rather than belonging to none:
-- they are starter rules for that organization, and another organization
-- authors its own. Both ship disabled -- one of them deletes accounts.
INSERT INTO lifecycle_policies (id, org_id, name, description, policy_type, conditions, actions, enabled, schedule)
SELECT v.id::uuid, o.id, v.name, v.description, v.policy_type, v.conditions::jsonb, v.actions::jsonb, false, v.schedule
FROM organizations o
CROSS JOIN (VALUES
  ('d0000000-0000-0000-0000-000000000001', 'Stale Account Auto-Disable', 'Automatically disable accounts that have not logged in for 90 days', 'stale_account_disable', '{"inactive_days": 90}', '{"action": "disable", "notify_user": true}', 'daily'),
  ('d0000000-0000-0000-0000-000000000002', 'Disabled Account Cleanup', 'Delete accounts that have been disabled for 180 days', 'disabled_account_cleanup', '{"disabled_days": 180}', '{"action": "delete", "notify_admin": true}', 'weekly')
) AS v(id, name, description, policy_type, conditions, actions, schedule)
WHERE o.slug = 'default'
ON CONFLICT (id) DO NOTHING;

-- Tenant branding (default org)
INSERT INTO tenant_branding (id, org_id, logo_url, primary_color, secondary_color, login_page_title, portal_title)
SELECT 'f1700000-0000-0000-0000-000000000001', id, '', '#1e40af', '#3b82f6', 'Sign In', 'OpenIDX Portal'
FROM organizations WHERE slug = 'default'
ON CONFLICT DO NOTHING;

-- Privacy retention policies
INSERT INTO privacy_retention_policies (id, name, data_category, retention_days, action, enabled) VALUES
('f1700000-0000-0000-0001-000000000001', 'Audit Log Retention', 'audit_logs', 365, 'delete', false),
('f1700000-0000-0000-0001-000000000002', 'Session Data Retention', 'sessions', 90, 'delete', false),
('f1700000-0000-0000-0001-000000000003', 'Login History Retention', 'login_history', 180, 'anonymize', false)
ON CONFLICT (id) DO NOTHING;

-- Notification routing rules
INSERT INTO notification_routing_rules (id, name, event_type, channels, enabled) VALUES
('f1700000-0000-0000-0003-000000000001', 'Security Alerts - All Channels', 'security_alert', '["in_app", "email"]'::jsonb, true),
('f1700000-0000-0000-0003-000000000002', 'Access Reviews - In-App', 'review_assigned', '["in_app"]'::jsonb, true),
('f1700000-0000-0000-0003-000000000003', 'Password Expiry - Email', 'password_expiry', '["email"]'::jsonb, true)
ON CONFLICT (id) DO NOTHING;
