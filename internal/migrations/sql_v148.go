package migrations

// Migration v148 — the temporary vendor access surface, and a waiver that
// expired.
//
// `temp_access_links` is PAM temporary vendor access: a link that grants an
// outside party SSH/RDP/VNC into an internal host, carrying the target host and
// port, the username to log in as, and the URL that redeems it.
// `temp_access_usage` is the record of who redeemed one — link, IP address,
// user agent, connect and disconnect times.
//
// V71 ALREADY FIXED THE HOLE HERE, AND WROTE DOWN WHY IT STOPPED WHERE IT DID.
// That migration added org_id to temp_access_links to close a cross-tenant IDOR
// — the list/get/revoke handlers filtered by id alone, so any authenticated
// user could enumerate, read and revoke every other tenant's vendor access —
// and then said, in as many words:
//
//	Deliberately NOT placed under the v37 FORCE-RLS belt: the public
//	token-redemption path (GET /temp-access/:token -> handleUseTempAccess) runs
//	with no authenticated org context, so FORCE RLS would fail-closed and break
//	redemption for the vendor. That path is keyed by a unique unguessable secret
//	token (not an enumerable id), and every management path is now org-filtered
//	in code + admin-gated, so the belt would add no protection there.
//
// The first half of that was true and is now obsolete. A lookup keyed on a
// globally-unique secret that runs before the tenant is known is a shape this
// branch has since met four times — api-key-by-hash, route-by-host, SAML
// entity_id, and v145's magic-link token, which is the SAME SHAPE as this one:
// a single-use secret redeemed by someone with no session. The remedy exists,
// is uniform, and is pinned: the lookup runs under orgctx.WithBypassRLS and
// TestPreResolutionLookupsUnderRLS holds it there. v71 declined the belt
// because it had no way to keep redemption working; that is no longer the case,
// and a waiver whose reason has expired is just a gap.
//
// The second half — "the belt would add no protection there" — is the claim
// this whole register programme exists to answer. The belt does not protect
// against the queries that exist when it is installed; those were audited on
// the way in. It protects against the NEXT query, written by someone who did
// not read v71's comment.
//
// THAT QUERY WAS ALREADY THERE. `temp_access_usage`, created by v54 alongside
// the links table, has no tenant column at all, and handleGetTempAccessUsage
// reads it with `WHERE link_id = $1` and nothing else. It is safe today only
// because a SEPARATE statement runs first to check the link belongs to the
// caller's org. Two queries where one predicate would do, and the safety lives
// in the order they are written in — which is the shape v147 found written down
// as a property in ai_intelligence.go, and v143 found in social_providers:
// implicit scoping through a joined set holds for exactly as long as every
// consumer keeps joining, and nothing makes that true. The usage row names an
// IP address and a user agent for an outside party connecting to an internal
// host; it gets its own org_id.
//
// THE EXPIRY WORKER IS THE THIRD PATTERN, and it is neither of the other two.
// internal/governance/jit_expiry.go runs `UPDATE temp_access_links SET status =
// 'expired' WHERE status = 'active' AND expires_at < NOW()` across the whole
// install, deliberately: a link past its expiry is expired in every tenant, and
// a sweep that had to iterate organizations would leave links live in any
// tenant it missed. Under the belt that write matches zero rows unless it says
// so, so it runs bypassed and says why at the call site. Install-wide is a
// legitimate answer; going install-wide by accident is not.
//
// BACKFILL. A usage row takes its link's organization — the link is NOT NULL on
// org_id since v71, so there is nothing to fall through to and the oldest-org
// fallback here is a formality that covers only a row whose link is gone, which
// the ON DELETE CASCADE makes impossible. It is kept anyway: SET NOT NULL fails
// for the whole install on one unattributed row, and a formality that costs
// nothing is cheaper than an upgrade that aborts.
//
// Plain statements only — the runner's splitSQL cannot handle DO $$ blocks.
var tempAccessTenantScopeUp = `-- Migration 148: the belt v71 deferred, plus org_id on the usage record.

-- temp_access_usage ---------------------------------------------------------
ALTER TABLE temp_access_usage ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- Each usage row belongs to its link's tenant; temp_access_links.org_id is
-- NOT NULL since v71, so this attributes every row that has a link.
UPDATE temp_access_usage u SET org_id = l.org_id FROM temp_access_links l
 WHERE u.link_id = l.id AND u.org_id IS NULL;
UPDATE temp_access_usage SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE temp_access_usage ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_temp_access_usage_org ON temp_access_usage(org_id, connected_at DESC);

DROP POLICY IF EXISTS pol_temp_access_usage_org_scope ON temp_access_usage;
CREATE POLICY pol_temp_access_usage_org_scope ON temp_access_usage
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE temp_access_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE temp_access_usage FORCE  ROW LEVEL SECURITY;

-- temp_access_links ---------------------------------------------------------
-- org_id already exists and is NOT NULL (v71); only the belt is new. The
-- token-redemption read and the use-count write run bypassed, the same way
-- v145's magic-link redemption does.
DROP POLICY IF EXISTS pol_temp_access_links_org_scope ON temp_access_links;
CREATE POLICY pol_temp_access_links_org_scope ON temp_access_links
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE temp_access_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE temp_access_links FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON temp_access_links, temp_access_usage TO openidx_app;
`

// Down removes the belt from both tables and the column from the usage record.
// temp_access_links keeps its org_id: that column is v71's, not this
// migration's, and dropping it here would silently undo the IDOR fix.
var tempAccessTenantScopeDown = `-- Rollback 148.

ALTER TABLE temp_access_links NO FORCE ROW LEVEL SECURITY;
ALTER TABLE temp_access_links DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_temp_access_links_org_scope ON temp_access_links;

ALTER TABLE temp_access_usage NO FORCE ROW LEVEL SECURITY;
ALTER TABLE temp_access_usage DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_temp_access_usage_org_scope ON temp_access_usage;
DROP INDEX IF EXISTS idx_temp_access_usage_org;
ALTER TABLE temp_access_usage DROP COLUMN IF EXISTS org_id;
`
