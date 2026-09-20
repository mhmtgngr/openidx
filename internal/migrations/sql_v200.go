package migrations

// Migration v200 -- the external identity links are per-tenant.
//
// user_identity_links and social_account_links were the last two tables on
// orgscope's needsScoping register, parked there on a product question the
// lint could not answer: may one external account link to a user in two
// tenants at once, and if so, which tenant owns the link row?
//
// THE DECISION (2026-09-20): a link belongs to the tenant of the identity
// provider it was made through. identity_providers has carried org_id since
// v155 -- every provider row is one organization's -- so provider_id already
// names exactly one tenant, and a consultant with an account in two
// organizations signs in through two DIFFERENT provider rows and holds two
// links, one in each tenant, neither visible from the other. That answers the
// question with "yes, once per tenant", keeps the belt uniform, and breaks no
// existing sign-in: every link that exists today was made through a provider
// that belongs to somebody.
//
// UNIQUENESS STAYS (provider_id, external_id). Widening it to
// (org_id, provider_id, external_id) would be redundant -- provider_id is
// already a tenant term -- and the constraint swap would give Down a statement
// that can fail on data for no gain. What is added is the belt: org_id NOT
// NULL with a foreign key, an index, the standard policy and FORCE ROW LEVEL
// SECURITY, so a query that forgets its predicate is scoped by the database and
// orgscope's missing-predicate rule now covers every query on both tables.
//
// WHAT THE MISSING COLUMN COST. Both admin list handlers joined
// identity_providers with `LEFT JOIN ... AND ip.org_id = $2`, which is v155's
// federation_rules defect in the same words: the tenant term on a LEFT JOIN
// filters nothing, so the lists returned a user's links regardless of which
// tenant was asking, with the foreign provider's name rendered empty. Both
// DELETEs addressed a link by bare id. With the column, those queries carry
// `uil.org_id = $N` on the link row itself, and the policy backs them.
//
// BACKFILL, most exact source first: the provider's organization (an enforced
// NOT NULL foreign key on user_identity_links; nullable on social_account_links
// but set by every writer), then the user's organization, then the oldest
// organization for anything unattributed -- the same order v197 used. No
// column DEFAULT: a default would make every future insert that forgets the
// tenant land silently in one organization, which is the defect in a new coat.
var identityLinksPerTenantUp = `-- Migration 200: the external identity links are per-tenant.

ALTER TABLE user_identity_links  ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE social_account_links ADD COLUMN IF NOT EXISTS org_id UUID;

-- Backfill: the provider's organization is the link's organization.
UPDATE user_identity_links l SET org_id = ip.org_id FROM identity_providers ip
  WHERE l.org_id IS NULL AND l.provider_id = ip.id AND ip.org_id IS NOT NULL;
UPDATE user_identity_links l SET org_id = u.org_id FROM users u
  WHERE l.org_id IS NULL AND l.user_id = u.id;
UPDATE user_identity_links SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1)
  WHERE org_id IS NULL;

UPDATE social_account_links l SET org_id = ip.org_id FROM identity_providers ip
  WHERE l.org_id IS NULL AND l.provider_id = ip.id AND ip.org_id IS NOT NULL;
UPDATE social_account_links l SET org_id = u.org_id FROM users u
  WHERE l.org_id IS NULL AND l.user_id = u.id;
UPDATE social_account_links SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1)
  WHERE org_id IS NULL;

ALTER TABLE user_identity_links  ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE social_account_links ALTER COLUMN org_id SET NOT NULL;

ALTER TABLE user_identity_links  DROP CONSTRAINT IF EXISTS fk_user_identity_links_org;
ALTER TABLE user_identity_links  ADD  CONSTRAINT fk_user_identity_links_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE social_account_links DROP CONSTRAINT IF EXISTS fk_social_account_links_org;
ALTER TABLE social_account_links ADD  CONSTRAINT fk_social_account_links_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_user_identity_links_org  ON user_identity_links(org_id, user_id);
CREATE INDEX IF NOT EXISTS idx_social_account_links_org ON social_account_links(org_id, user_id);

DROP POLICY IF EXISTS pol_user_identity_links_org_scope ON user_identity_links;
CREATE POLICY pol_user_identity_links_org_scope ON user_identity_links
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE user_identity_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_identity_links FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_social_account_links_org_scope ON social_account_links;
CREATE POLICY pol_social_account_links_org_scope ON social_account_links
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE social_account_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE social_account_links FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON user_identity_links  TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON social_account_links TO openidx_app;
`

// Down lifts both belts and drops the tenant columns. Nothing here can fail
// on data: the uniqueness key was not changed, so there is no install-wide
// constraint to recreate.
var identityLinksPerTenantDown = `-- Rollback 200.

ALTER TABLE social_account_links NO FORCE ROW LEVEL SECURITY;
ALTER TABLE social_account_links DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_social_account_links_org_scope ON social_account_links;

ALTER TABLE user_identity_links NO FORCE ROW LEVEL SECURITY;
ALTER TABLE user_identity_links DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_user_identity_links_org_scope ON user_identity_links;

DROP INDEX IF EXISTS idx_social_account_links_org;
DROP INDEX IF EXISTS idx_user_identity_links_org;

ALTER TABLE social_account_links DROP COLUMN IF EXISTS org_id;
ALTER TABLE user_identity_links  DROP COLUMN IF EXISTS org_id;
`
