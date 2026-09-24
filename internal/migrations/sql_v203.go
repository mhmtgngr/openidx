package migrations

// Migration v203 -- mfa_policy_grace: when each user's grace period under an
// MFA policy began.
//
// A policy may again require particular methods (#990 follow-up). A user who
// has none of them enrolled gets the policy's grace period to add one, counted
// from the first sign-in at which the policy found them without one. The window
// has to be counted per user: a single deadline per policy would give a user
// created after it no window at all, and their first sign-in would be refused.
// So the first such sign-in records the start here, and every later sign-in
// reads it back. The deadline is started_at + grace_period_hours, computed at
// sign-in, so an administrator who raises the grace period extends every
// running window without touching this table.
//
// A row belongs to one user under one policy. Deleting either removes it
// (ON DELETE CASCADE), and the admin API deletes a policy's rows when its
// method list changes, which starts every user's window again: a window is
// the time to add one of THOSE methods.
//
// Forced org-scoped RLS, like every tenant table since v37. The sign-in reads
// and writes it under the tenant's org context.
//
// THE UPDATE CLEARS STORED METHODS AND GRACE PERIODS. Until this release no
// code read required_methods or grace_period_hours (#990): a policy that
// listed WebAuthn was satisfied by any factor, and #991 stopped the API from
// accepting them. Policies created before #991 may still store both, and the
// column default gave every such policy 24 hours. Enforcing those stored
// values on upgrade would start windows nobody chose, and refuse sign-ins a
// day later. So they are cleared, and the grace default becomes 0: on
// upgrade, every policy does exactly what it did before, and an administrator
// who wants methods enforced sets them again in the console. Conditions are
// not touched: nothing enforces them yet either, and the console still flags
// them.
//
// Down drops the table and restores the column default. It cannot restore
// the cleared values: they were never enforced, and the upgrade note says so.

var mfaPolicyGraceUp = `-- Migration 203: per-user grace periods under MFA policies that require methods.
CREATE TABLE IF NOT EXISTS mfa_policy_grace (
    org_id     UUID NOT NULL,
    policy_id  UUID NOT NULL REFERENCES mfa_policies(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (policy_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_mfa_policy_grace_org_id ON mfa_policy_grace (org_id);
CREATE INDEX IF NOT EXISTS idx_mfa_policy_grace_user_id ON mfa_policy_grace (user_id);

DROP POLICY IF EXISTS pol_mfa_policy_grace_org_scope ON mfa_policy_grace;
CREATE POLICY pol_mfa_policy_grace_org_scope ON mfa_policy_grace
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE mfa_policy_grace ENABLE ROW LEVEL SECURITY;
ALTER TABLE mfa_policy_grace FORCE  ROW LEVEL SECURITY;

-- Stored methods and grace periods were never enforced; enforcing them on
-- upgrade would start windows nobody chose.
UPDATE mfa_policies
   SET required_methods = '[]'::jsonb, grace_period_hours = 0, updated_at = NOW()
 WHERE required_methods IS DISTINCT FROM '[]'::jsonb
    OR grace_period_hours IS DISTINCT FROM 0;

ALTER TABLE mfa_policies ALTER COLUMN grace_period_hours SET DEFAULT 0;
`

var mfaPolicyGraceDown = `-- Migration 203 down: drop the grace table and restore the old default.
DROP TABLE IF EXISTS mfa_policy_grace;
ALTER TABLE mfa_policies ALTER COLUMN grace_period_hours SET DEFAULT 24;
`
