package migrations

// Migration v152 — delegated administration.
//
// An `admin_delegations` row hands one person a named set of administrative
// permissions: "this user may do users:write, within this scope, until this
// date." It is read by the policy enforcement point itself —
// `PermissionResolver` in internal/common/middleware — and merged into the
// permission set that `RequirePermission` then decides on. It carried no
// tenant.
//
// THE COMMENT WAS COPIED WITHOUT THE PREDICATE. Two reads sit in the same
// function, eight lines apart, both under `orgctx.WithBypassRLS`. The first:
//
//	// This read is already scoped to the caller's org by the explicit
//	// r.org_id = $2 predicate, so WithBypassRLS ... is the correct,
//	// leak-free fix.
//	SELECT DISTINCT p.resource, p.action FROM permissions p
//	  JOIN role_permissions rp ... JOIN roles r ...
//	 WHERE r.name = ANY($1) AND r.org_id = $2
//
// The second:
//
//	// Same RLS reasoning as the role_permissions read above: scoped by the
//	// explicit delegate_id = $1 predicate, so bypass is safe and necessary.
//	SELECT permissions, scope_type, scope_id::text FROM admin_delegations
//	 WHERE delegate_id = $1 AND enabled = true
//	   AND (expires_at IS NULL OR expires_at > NOW())
//
// It is not the same reasoning. `r.org_id = $2` is a tenant term;
// `delegate_id = $1` is a user id. The first read is scoped and its comment is
// true; the second borrowed the sentence and dropped the thing the sentence was
// about, over a table that had no tenant column to name even if someone had
// tried. A delegation granted in one organization therefore applied to that
// user in every organization they could authenticate into.
//
// AND THE ADMIN API COULD WRITE ACROSS THE BOUNDARY. `UpdateDelegation` builds
// `UPDATE admin_delegations SET ... WHERE id = $N` with no tenant term, and
// `permissions` is one of the fields it will set. `DeleteDelegation` is
// `DELETE FROM admin_delegations WHERE id = $1`. `CreateDelegation` inserted
// whatever `delegate_id` the caller supplied. So an administrator of one
// tenant could rewrite the permission list on another tenant's delegation, or
// mint a new one naming another tenant's user, and the unscoped read in the
// enforcement point would honour it. This migration and the predicates in the
// same commit close both halves; the create path additionally verifies that
// the delegate, the grantor and the scope all belong to the caller's
// organization, because a delegation pointing out of its own tenant is not a
// row worth keeping.
//
// BACKFILL. The delegate is the attribution: the permissions are theirs to
// use, so they belong to the delegate's organization. Where the delegate has
// no organization the grantor decides, and where neither does the row goes to
// the oldest organization so an operator can find it.
//
// WHAT THIS MIGRATION DELIBERATELY DOES NOT DO. `scope_type`/`scope_id` — the
// half of this feature that says "within this group" or "for this application"
// — are resolved by PermissionResolver, cached, and then never read:
// `RequirePermission` compares resource and action only. A delegation scoped to
// one group grants its permissions everywhere that permission is checked. That
// is a real finding of the same class as the rest of this programme, and it is
// NOT fixed here, because every way of fixing it changes what an existing,
// shipped delegation grants — either narrowing live access or widening it — and
// that is a product decision, not a scoping one. It is written up in the guide
// and the PR so it is chosen rather than inherited.
//
// Plain statements only — the runner's splitSQL cannot handle DO $$ blocks.
var adminDelegationScopeUp = `-- Migration 152: scope and belt admin_delegations.

ALTER TABLE admin_delegations ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- The delegate owns the permissions, so the delegate owns the row.
UPDATE admin_delegations d SET org_id = u.org_id FROM users u
 WHERE u.id = d.delegate_id AND d.org_id IS NULL AND u.org_id IS NOT NULL;

-- Failing that, the administrator who granted it.
UPDATE admin_delegations d SET org_id = u.org_id FROM users u
 WHERE u.id = d.delegated_by AND d.org_id IS NULL AND u.org_id IS NOT NULL;

UPDATE admin_delegations SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE admin_delegations ALTER COLUMN org_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_admin_delegations_org ON admin_delegations(org_id);

-- The enforcement point looks a delegation up by delegate; give that lookup its
-- tenant term in the index as well as in the query.
CREATE INDEX IF NOT EXISTS idx_admin_delegations_org_delegate ON admin_delegations(org_id, delegate_id);

DROP POLICY IF EXISTS pol_admin_delegations_org_scope ON admin_delegations;
CREATE POLICY pol_admin_delegations_org_scope ON admin_delegations
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE admin_delegations ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_delegations FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON admin_delegations TO openidx_app;
`

// Down lifts the belt and drops the column. The attribution is lost with it,
// which is correct: a rolled-back binary reads this table with no tenant term
// at all, so leaving a column it ignores would be worse than leaving none.
var adminDelegationScopeDown = `-- Rollback 152.

ALTER TABLE admin_delegations NO FORCE ROW LEVEL SECURITY;
ALTER TABLE admin_delegations DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_admin_delegations_org_scope ON admin_delegations;
DROP INDEX IF EXISTS idx_admin_delegations_org_delegate;
DROP INDEX IF EXISTS idx_admin_delegations_org;
ALTER TABLE admin_delegations DROP COLUMN IF EXISTS org_id;
`
