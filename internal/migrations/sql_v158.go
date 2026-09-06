package migrations

// Migration v158 — biometric preferences and the policies over them.
//
// v54 created both tables with no tenant column. `biometric_preferences` is one
// row per user — whether a platform authenticator (Face ID, Touch ID) is
// preferred, whether cross-platform keys are allowed, whether user verification
// is required, whether the account is biometric-only, whether a resident key is
// required. `biometric_policies` is the administrator's rule over those
// choices: which authenticator types are allowed at all, whether a platform
// authenticator is required, and which groups and roles the rule applies to.
//
// A POLICY LIST WITH NO TENANT TERM, READ BY THE FUNCTION THAT DECIDES. The
// list is the whole query:
//
//	SELECT id, name, description, enabled, applies_to_groups, applies_to_roles,
//	       require_platform_authenticator, allowed_authenticator_types,
//	       min_authenticator_level, created_at
//	FROM biometric_policies
//	ORDER BY name
//
// and GetApplicableBiometricPolicy calls it, walks the result, and returns the
// FIRST policy that applies. A policy with no groups and no roles named
// "applies to all" by the code's own comment. So on an installation with more
// than one organization, any administrator creating an untargeted policy
// governed every user on the installation — and because the list is ordered by
// name, which one won was decided alphabetically. A control aimed by sort
// order is aimed by whoever picks the earlier name.
//
// The direction matters both ways. The foreign policy can be stricter than
// yours, and it can be looser: allowed_authenticator_types defaults to
// ARRAY['platform', 'cross-platform'], so a permissive foreign policy sorting
// before your restrictive one replaces it, and the check that was supposed to
// refuse a security key accepts it.
//
// GetApplicableBiometricPolicy scopes everything it reads EXCEPT the policies.
// It resolves orgctx, reads group_memberships with AND org_id = $2 and the
// user's roles with AND org_id = $2 — both fixed in an earlier pass of this
// programme, whose comments are still there — and then matches those tenant-
// scoped groups and roles against an install-wide list of rules. Same shape as
// v154's lifecycle policies: the actions were scoped and the rule that aims
// them was not.
//
// AND NOTHING CONSULTS IT. ValidateAuthenticatorForPolicy is the only caller of
// GetApplicableBiometricPolicy outside a test, and a search of the tree finds
// no caller of ValidateAuthenticatorForPolicy at all. No WebAuthn registration
// path checks it; no login path checks it. So the four routes under
// /biometric/policies author rules, list them back, and constrain no
// enrolment — the same shape as v155's custom_claims_mappings and v156's
// developer_settings, and recorded here rather than fixed for the same reason:
// giving a policy an enforcement point is a feature, and a scoping batch is the
// wrong place to smuggle one in.
//
// What is NOT hypothetical is the read and the writes. GET /biometric/policies
// returned every organization's rules, including the group UUIDs and role names
// each one targets, which is a disclosure of another tenant's directory
// structure. PUT and DELETE address a policy by bare id, so one administrator
// could rewrite or delete another organization's rule outright.
//
// THE PREFERENCES ARE READ AND WRITTEN BY BARE user_id, and the one place that
// checks the tenant shows what was intended: EnableBiometricOnly resolves
// orgctx and counts the user's WebAuthn credentials with AND org_id = $2 before
// flipping the flag, then calls GetBiometricPreferences and
// UpdateBiometricPreferences, which name no organization at all. The gate was
// scoped and the write it guards was not.
//
// GetBiometricPreferences also returns the permissive built-in defaults on ANY
// error, not only on "no row". A connection failure, a permission error, a
// belted table read without app.org_id set — every one of them was
// indistinguishable from "this user has not set preferences", and the caller
// got RequireUserVerification true, ResidentKeyRequired false and a nil error.
// After this migration the table is belted, so that path stops being
// theoretical: a read without tenant context returns no rows, and returning
// defaults for it would silently loosen a user's stored requirements. It now
// distinguishes the two.
//
// BACKFILL. A preferences row goes to the organization of the user it belongs
// to, through v54's enforced foreign key: exact, not inferred. A policy has no
// attribution column of any kind — no created_by, no org_id, nothing — so
// policies go to the oldest organization, and an administrator elsewhere who
// was relying on a rule another organization authored, which they were never
// entitled to, must author their own. Given that no code path consults these
// policies, the practical effect of that is confined to the page that lists
// them.
//
// Plain statements only -- the runner's splitSQL cannot handle DO $$ blocks.
var biometricScopeUp = `-- Migration 158: scope and belt the biometric preferences and policies.

ALTER TABLE biometric_preferences ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE biometric_policies    ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- Exact: v54 gave biometric_preferences user_id UUID REFERENCES users(id).
UPDATE biometric_preferences b SET org_id = u.org_id FROM users u WHERE u.id = b.user_id AND b.org_id IS NULL;

-- A preferences row whose user is gone, and every policy, which carries no
-- attribution at all.
UPDATE biometric_preferences SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;
UPDATE biometric_policies    SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE biometric_preferences ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE biometric_policies    ALTER COLUMN org_id SET NOT NULL;

-- The policy list reads (org_id, name) in that order, because ORDER BY name is
-- what decides which rule applies.
CREATE INDEX IF NOT EXISTS idx_biometric_policies_org_name ON biometric_policies(org_id, name);

-- The passwordless adoption figure counts biometric-only accounts per tenant.
CREATE INDEX IF NOT EXISTS idx_biometric_prefs_org_only ON biometric_preferences(org_id) WHERE biometric_only_enabled = true;

DROP POLICY IF EXISTS pol_biometric_preferences_org_scope ON biometric_preferences;
CREATE POLICY pol_biometric_preferences_org_scope ON biometric_preferences
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE biometric_preferences ENABLE ROW LEVEL SECURITY;
ALTER TABLE biometric_preferences FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_biometric_policies_org_scope ON biometric_policies;
CREATE POLICY pol_biometric_policies_org_scope ON biometric_policies
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE biometric_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE biometric_policies FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON biometric_preferences TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON biometric_policies    TO openidx_app;
`

// Down lifts the belt and drops the columns and indexes. Unlike v138, v155,
// v156 and v157 there is no install-wide key to restore here — v54 gave
// biometric_policies no unique constraint and biometric_preferences only
// user_id, which stays correct in either direction because a user belongs to
// one organization. So this rollback cannot fail on data.
var biometricScopeDown = `-- Rollback 158.

ALTER TABLE biometric_policies NO FORCE ROW LEVEL SECURITY;
ALTER TABLE biometric_policies DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_biometric_policies_org_scope ON biometric_policies;

ALTER TABLE biometric_preferences NO FORCE ROW LEVEL SECURITY;
ALTER TABLE biometric_preferences DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_biometric_preferences_org_scope ON biometric_preferences;

DROP INDEX IF EXISTS idx_biometric_prefs_org_only;
DROP INDEX IF EXISTS idx_biometric_policies_org_name;

ALTER TABLE biometric_policies    DROP COLUMN IF EXISTS org_id;
ALTER TABLE biometric_preferences DROP COLUMN IF EXISTS org_id;
`
