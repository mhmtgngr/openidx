package migrations

// Migration v214 -- external (vendor) identities.
//
// A person from a supplier who supports the organization's systems is a user
// of the organization, not a tenant of their own: the targets they reach are
// the organization's PAM entries and applications, and putting them in another
// tenant would need exactly the cross-tenant grant row-level security exists
// to forbid. So an external user is a row of users with user_type 'external',
// tied to a vendor organization, with a sponsor (an internal user who answers
// for them) and an expiry.
//
// The columns sit on users rather than in a profile table because every
// predicate that restricts such a user (the role ceiling, group membership,
// login, the sweeps) already reads that row; a separate table would put a JOIN
// in each of them, and the query that forgets the JOIN is the defect this
// schema has been fixed for four times.
//
// vendor_organizations: the supplier, inside the tenant, under the same FORCE
// RLS belt as every org-scoped table. Closing one ends every external user it
// holds; nothing reopens it.
//
// users:
//   - user_type: 'internal' (every existing row), 'external' or 'service'.
//   - account_status: the external lifecycle (invited, pending_mfa, active,
//     suspended, expired, disabled). Internal users are 'active' and keep using
//     users.enabled exactly as before; this column decides nothing for them.
//   - vendor_org_id, sponsor_user_id, account_expires_at: required for an
//     external user by CHECK (invariant I1). A sponsor may be absent only once
//     the account is no longer live: deleting a sponsor sets the column NULL,
//     which the CHECK refuses for a live account, so the delete path suspends
//     the sponsor's external users first and a raw DELETE that skips it fails
//     loudly instead of leaving an unsponsored live account.
//   - users_external_enabled_check: an external account is enabled only while
//     it is live (active, or pending_mfa while it enrolls a second factor), so
//     no writer can re-enable a suspended, expired or disabled one.
//   - status_changed_at, access_severed_at: when the status last changed, and
//     when the sweep last ran the kill switch for a non-live account, so each
//     departure is severed once rather than on every sweep.
//
// groups.external_allowed: an external user may be a member only of a group
// an administrator marked for it (invariant I3). FALSE for every existing
// group, so nothing an external user is added to later is reachable by
// default.
//
// user_invitations: the same four fields, so an invitation can be for an
// external user and the acceptance creates the account with them.
//
// THE GUARD TRIGGERS. Roles are written in eight places (identity, admin bulk
// import and bulk operations, governance fulfilment, provisioning rules) and
// group memberships in thirteen (add directory sync, provisioning, portal
// self-join). A ceiling checked in each writer is a ceiling the ninth writer
// forgets, which is the defect class this schema keeps meeting. So the
// invariants that bound what an external user may be given are checked where
// every writer meets them, by external_identity_guard():
//   - user_roles: an external user holds only the role named "user" (I2).
//   - group_memberships: an external user joins only an external_allowed
//     group (I3).
//   - admin_delegations: an external user neither delegates nor receives a
//     delegation (I2).
//   - access_request_approvals: an external user is never an approver (I2).
//   - users: user_type cannot change after creation, so an internal account
//     cannot be turned into an external one around these checks, nor an
//     external one into an internal one around its expiry.
//   - groups: a group cannot be closed to external users while it has
//     external members.
// Each refusal is SQLSTATE 23514 with a constraint name the API layer maps to
// a 403 and a stable code (internal/externalid).
//
// Down drops everything this adds; external users, if any were created,
// become internal users with no sponsor or expiry, which is why the down path
// first disables them.

var externalIdentitiesUp = `-- Migration 214: external (vendor) identities.
CREATE TABLE IF NOT EXISTS vendor_organizations (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                  UUID NOT NULL,
    name                    VARCHAR(255) NOT NULL,
    status                  VARCHAR(16) NOT NULL DEFAULT 'active'
                            CHECK (status IN ('active','suspended','closed')),
    contact_name            VARCHAR(255),
    contact_email           VARCHAR(255),
    contract_start          DATE,
    contract_end            DATE,
    allowed_email_domains   TEXT[] NOT NULL DEFAULT '{}',
    default_expiry_days     INTEGER NOT NULL DEFAULT 90
                            CHECK (default_expiry_days BETWEEN 1 AND 365),
    default_sponsor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    notes                   TEXT,
    created_by              UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at               TIMESTAMPTZ,
    CONSTRAINT vendor_organizations_contract_order
        CHECK (contract_start IS NULL OR contract_end IS NULL OR contract_start <= contract_end),
    CONSTRAINT vendor_organizations_closed_at
        CHECK ((status = 'closed') = (closed_at IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_vendor_organizations_org_name
    ON vendor_organizations (org_id, lower(name));
CREATE INDEX IF NOT EXISTS idx_vendor_organizations_org_id ON vendor_organizations (org_id);

DROP POLICY IF EXISTS pol_vendor_organizations_org_scope ON vendor_organizations;
CREATE POLICY pol_vendor_organizations_org_scope ON vendor_organizations
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE vendor_organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE vendor_organizations FORCE  ROW LEVEL SECURITY;

ALTER TABLE users ADD COLUMN IF NOT EXISTS user_type VARCHAR(16) NOT NULL DEFAULT 'internal';
ALTER TABLE users ADD COLUMN IF NOT EXISTS account_status VARCHAR(16) NOT NULL DEFAULT 'active';
ALTER TABLE users ADD COLUMN IF NOT EXISTS vendor_org_id UUID REFERENCES vendor_organizations(id) ON DELETE RESTRICT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS sponsor_user_id UUID REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS account_expires_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS status_changed_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS access_severed_at TIMESTAMPTZ;

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_user_type_check;
ALTER TABLE users ADD CONSTRAINT users_user_type_check
    CHECK (user_type IN ('internal','external','service'));
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_account_status_check;
ALTER TABLE users ADD CONSTRAINT users_account_status_check
    CHECK (account_status IN ('invited','pending_mfa','active','suspended','expired','disabled'));
-- I1: an external user has a vendor, an expiry and, while the account is
-- live, a sponsor. Only an external user carries any of the three.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_external_identity_check;
ALTER TABLE users ADD CONSTRAINT users_external_identity_check CHECK (
    (user_type = 'external'
        AND vendor_org_id IS NOT NULL
        AND account_expires_at IS NOT NULL
        AND (sponsor_user_id IS NOT NULL OR account_status IN ('suspended','expired','disabled')))
    OR (user_type <> 'external'
        AND vendor_org_id IS NULL
        AND sponsor_user_id IS NULL
        AND account_expires_at IS NULL)
);
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_sponsor_not_self;
ALTER TABLE users ADD CONSTRAINT users_sponsor_not_self CHECK (sponsor_user_id IS NULL OR sponsor_user_id <> id);
-- An external account can sign in only while it is live: every writer that
-- flips users.enabled (the console's user edit among them) meets this, so a
-- suspended, expired or disabled external user cannot be re-enabled around
-- its lifecycle.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_external_enabled_check;
ALTER TABLE users ADD CONSTRAINT users_external_enabled_check CHECK (
    user_type <> 'external' OR NOT COALESCE(enabled, false) OR account_status IN ('active','pending_mfa')
);

CREATE INDEX IF NOT EXISTS idx_users_external
    ON users (org_id, account_status, account_expires_at) WHERE user_type = 'external';
CREATE INDEX IF NOT EXISTS idx_users_sponsor ON users (sponsor_user_id) WHERE sponsor_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_vendor_org ON users (vendor_org_id) WHERE vendor_org_id IS NOT NULL;

ALTER TABLE groups ADD COLUMN IF NOT EXISTS external_allowed BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE user_invitations ADD COLUMN IF NOT EXISTS user_type VARCHAR(16) NOT NULL DEFAULT 'internal';
ALTER TABLE user_invitations ADD COLUMN IF NOT EXISTS vendor_org_id UUID REFERENCES vendor_organizations(id) ON DELETE CASCADE;
ALTER TABLE user_invitations ADD COLUMN IF NOT EXISTS sponsor_user_id UUID REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE user_invitations ADD COLUMN IF NOT EXISTS account_expires_at TIMESTAMPTZ;
ALTER TABLE user_invitations DROP CONSTRAINT IF EXISTS user_invitations_external_check;
ALTER TABLE user_invitations ADD CONSTRAINT user_invitations_external_check CHECK (
    (user_type = 'external' AND vendor_org_id IS NOT NULL AND sponsor_user_id IS NOT NULL AND account_expires_at IS NOT NULL)
    OR (user_type = 'internal' AND vendor_org_id IS NULL AND sponsor_user_id IS NULL AND account_expires_at IS NULL)
);
CREATE OR REPLACE FUNCTION external_identity_guard() RETURNS trigger
LANGUAGE plpgsql
AS
$$
BEGIN
    IF TG_TABLE_NAME = 'user_roles' THEN
        IF EXISTS (SELECT 1 FROM users u WHERE u.id = NEW.user_id AND u.user_type = 'external')
           AND NOT EXISTS (SELECT 1 FROM roles r WHERE r.id = NEW.role_id AND lower(r.name) = 'user') THEN
            RAISE EXCEPTION 'an external user may hold only the user role'
                USING ERRCODE = '23514', CONSTRAINT = 'external_role_cap';
        END IF;
    ELSIF TG_TABLE_NAME = 'group_memberships' THEN
        IF EXISTS (SELECT 1 FROM users u WHERE u.id = NEW.user_id AND u.user_type = 'external')
           AND NOT EXISTS (SELECT 1 FROM groups g WHERE g.id = NEW.group_id AND g.external_allowed) THEN
            RAISE EXCEPTION 'this group is not open to external users'
                USING ERRCODE = '23514', CONSTRAINT = 'external_group_not_allowed';
        END IF;
    ELSIF TG_TABLE_NAME = 'admin_delegations' THEN
        IF EXISTS (SELECT 1 FROM users u WHERE u.id IN (NEW.delegate_id, NEW.delegated_by) AND u.user_type = 'external') THEN
            RAISE EXCEPTION 'an external user cannot approve or be delegated authority'
                USING ERRCODE = '23514', CONSTRAINT = 'external_cannot_approve';
        END IF;
    ELSIF TG_TABLE_NAME = 'access_request_approvals' THEN
        IF EXISTS (SELECT 1 FROM users u WHERE u.id = NEW.approver_id AND u.user_type = 'external') THEN
            RAISE EXCEPTION 'an external user cannot approve or be delegated authority'
                USING ERRCODE = '23514', CONSTRAINT = 'external_cannot_approve';
        END IF;
    ELSIF TG_TABLE_NAME = 'users' THEN
        IF NEW.user_type IS DISTINCT FROM OLD.user_type THEN
            RAISE EXCEPTION 'a user type is fixed when the account is created'
                USING ERRCODE = '23514', CONSTRAINT = 'user_type_immutable';
        END IF;
    ELSIF TG_TABLE_NAME = 'groups' THEN
        IF OLD.external_allowed AND NOT NEW.external_allowed
           AND EXISTS (SELECT 1 FROM group_memberships m JOIN users u ON u.id = m.user_id
                        WHERE m.group_id = NEW.id AND u.user_type = 'external') THEN
            RAISE EXCEPTION 'remove the external members before closing this group to external users'
                USING ERRCODE = '23514', CONSTRAINT = 'external_group_has_members';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_user_roles_external_guard ON user_roles;
CREATE TRIGGER trg_user_roles_external_guard BEFORE INSERT OR UPDATE ON user_roles
    FOR EACH ROW EXECUTE FUNCTION external_identity_guard();
DROP TRIGGER IF EXISTS trg_group_memberships_external_guard ON group_memberships;
CREATE TRIGGER trg_group_memberships_external_guard BEFORE INSERT OR UPDATE ON group_memberships
    FOR EACH ROW EXECUTE FUNCTION external_identity_guard();
DROP TRIGGER IF EXISTS trg_admin_delegations_external_guard ON admin_delegations;
CREATE TRIGGER trg_admin_delegations_external_guard BEFORE INSERT OR UPDATE ON admin_delegations
    FOR EACH ROW EXECUTE FUNCTION external_identity_guard();
DROP TRIGGER IF EXISTS trg_access_request_approvals_external_guard ON access_request_approvals;
CREATE TRIGGER trg_access_request_approvals_external_guard BEFORE INSERT OR UPDATE OF approver_id ON access_request_approvals
    FOR EACH ROW EXECUTE FUNCTION external_identity_guard();
DROP TRIGGER IF EXISTS trg_users_external_guard ON users;
CREATE TRIGGER trg_users_external_guard BEFORE UPDATE OF user_type ON users
    FOR EACH ROW EXECUTE FUNCTION external_identity_guard();
DROP TRIGGER IF EXISTS trg_groups_external_guard ON groups;
CREATE TRIGGER trg_groups_external_guard BEFORE UPDATE OF external_allowed ON groups
    FOR EACH ROW EXECUTE FUNCTION external_identity_guard();
`

var externalIdentitiesDown = `-- Migration 214 down: drop external identities.
DROP TRIGGER IF EXISTS trg_groups_external_guard ON groups;
DROP TRIGGER IF EXISTS trg_users_external_guard ON users;
DROP TRIGGER IF EXISTS trg_access_request_approvals_external_guard ON access_request_approvals;
DROP TRIGGER IF EXISTS trg_admin_delegations_external_guard ON admin_delegations;
DROP TRIGGER IF EXISTS trg_group_memberships_external_guard ON group_memberships;
DROP TRIGGER IF EXISTS trg_user_roles_external_guard ON user_roles;
DROP FUNCTION IF EXISTS external_identity_guard();
UPDATE users SET enabled = false WHERE user_type = 'external';
ALTER TABLE user_invitations DROP CONSTRAINT IF EXISTS user_invitations_external_check;
ALTER TABLE user_invitations DROP COLUMN IF EXISTS account_expires_at;
ALTER TABLE user_invitations DROP COLUMN IF EXISTS sponsor_user_id;
ALTER TABLE user_invitations DROP COLUMN IF EXISTS vendor_org_id;
ALTER TABLE user_invitations DROP COLUMN IF EXISTS user_type;
ALTER TABLE groups DROP COLUMN IF EXISTS external_allowed;
DROP INDEX IF EXISTS idx_users_vendor_org;
DROP INDEX IF EXISTS idx_users_sponsor;
DROP INDEX IF EXISTS idx_users_external;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_external_enabled_check;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_sponsor_not_self;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_external_identity_check;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_account_status_check;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_user_type_check;
ALTER TABLE users DROP COLUMN IF EXISTS access_severed_at;
ALTER TABLE users DROP COLUMN IF EXISTS status_changed_at;
ALTER TABLE users DROP COLUMN IF EXISTS account_expires_at;
ALTER TABLE users DROP COLUMN IF EXISTS sponsor_user_id;
ALTER TABLE users DROP COLUMN IF EXISTS vendor_org_id;
ALTER TABLE users DROP COLUMN IF EXISTS account_status;
ALTER TABLE users DROP COLUMN IF EXISTS user_type;
DROP TABLE IF EXISTS vendor_organizations;
`
