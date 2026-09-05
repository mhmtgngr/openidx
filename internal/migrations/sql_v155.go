package migrations

// Migration v155 — identity federation configuration.
//
// Two tables. `federation_rules` maps an email domain to the identity provider
// that should authenticate it — the row that decides where a user typing their
// address is sent to sign in. `custom_claims_mappings` decides what an
// application is told about whoever signed in. v54 created both with no tenant
// column.
//
// A LEFT JOIN IS NOT A TENANT PREDICATE. The two reads of `federation_rules`
// are the same query written twice, one word apart. The login path
// (internal/identity/handlers_federation.go) has:
//
//	FROM federation_rules fr
//	JOIN identity_providers ip ON fr.provider_id = ip.id AND ip.org_id = $2
//
// and the admin list (internal/admin/federation.go) has:
//
//	FROM federation_rules fr
//	LEFT JOIN identity_providers ip ON fr.provider_id = ip.id AND ip.org_id = $1
//
// An inner join drops the rows that fail the condition. A LEFT JOIN keeps every
// row of the left table and nulls the right side, so `ip.org_id = $1` stopped
// being a filter and became a decoration: the list returned EVERY
// organization's federation rules, with `COALESCE(ip.name,”)` rendering the
// foreign ones' provider as an empty string. The code even reads as though it
// were scoped, which is why it survived. A join is a tenant predicate only when
// failing it removes the row.
//
// AND email_domain WAS GLOBALLY UNIQUE. v54 declared it inline:
//
//	email_domain VARCHAR(255) NOT NULL UNIQUE
//
// One organization per domain, for the whole installation. Whoever registers
// `example.com` first owns it; the next organization to try gets a unique
// violation that `handleCreateFederationRule` reports as a bare 500, with no
// hint that another tenant is holding the name. Same shape as v138's
// `ispm_rules.check_type` and `ai_agents.name`, and it is re-scoped the same
// way, to (org_id, email_domain).
//
// The rest is the familiar list. Update and delete addressed rules by bare id,
// so one administrator could disable or delete another organization's SSO
// routing — the users of that domain stop being federated and fall back to
// password, quietly. Create inserted whatever `provider_id` the caller
// supplied, with no check that the provider was theirs.
//
// custom_claims_mappings IS THE SAME DEFECT WITH NOTHING BEHIND IT. Its list,
// update and delete take a bare `application_id` or a bare id, so one tenant
// could add, retarget or remove the claim mappings on another tenant's
// application. That would be an identity-forgery primitive — B decides what A's
// application is told about the person signing in — except that a search of the
// whole tree finds no reader. The table is written by its own admin CRUD and
// the console page that drives it, and by nothing else: no token mint, no
// /userinfo. The columns `include_in_id_token`, `include_in_access_token` and
// `include_in_userinfo` name three destinations that have no consumer. An
// administrator can map "department" into the ID token as `dept`, save it, see
// it listed back, and no token ever carries it.
//
// It is scoped here rather than dropped. v151 dropped `guacamole_connection_pool`
// because it was never read AND its only write had failed since v54; this table
// holds configuration an operator really entered through a live page, so
// deleting it would destroy their work. The gap is named in the guide and the
// CHANGELOG instead, where it can be fixed as a feature rather than smuggled
// into a scoping batch.
//
// A THIRD INSTALL-WIDE KEY, FOUND BY THIS BATCH'S OWN TEST. Seeding an
// identity provider for each of two organizations failed:
//
//	duplicate key value violates unique constraint "identity_providers_issuer_url_key"
//
// The base schema declares `issuer_url VARCHAR(255) UNIQUE NOT NULL`.
// `identity_providers` is otherwise a model citizen — it carries org_id, it is
// ENABLE + FORCE row-level-secured, it sits on no register, every lint passes
// over it — and two organizations still cannot both federate to the same
// issuer. Which is not an exotic case: it is two tenants on the same Entra
// common endpoint, two subsidiaries in one Okta org, or simply both of them
// using `https://accounts.google.com`. The second to configure it gets a
// unique violation. A table can be fully scoped, fully belted, and still be
// unusable by more than one tenant because of a key written before tenants
// existed. Re-scoped here to (org_id, issuer_url), with the other two.
//
// BACKFILL. Both tables have an enforced NOT NULL foreign key to a table that
// is already org-scoped, so attribution is exact rather than inferred: a
// federation rule goes to the organization of the identity provider it routes
// to, and a claim mapping to the organization of the application it decorates.
// The oldest-organization fallback is there for form; neither FK can be null.
//
// Plain statements only — the runner's splitSQL cannot handle DO $$ blocks.
var federationScopeUp = `-- Migration 155: scope and belt the federation configuration.

ALTER TABLE federation_rules        ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE custom_claims_mappings  ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- Exact attribution through an enforced FK to an already-scoped parent.
UPDATE federation_rules fr SET org_id = ip.org_id FROM identity_providers ip WHERE ip.id = fr.provider_id AND fr.org_id IS NULL;
UPDATE custom_claims_mappings cc SET org_id = a.org_id FROM applications a WHERE a.id = cc.application_id AND cc.org_id IS NULL;

UPDATE federation_rules       SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;
UPDATE custom_claims_mappings SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE federation_rules       ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE custom_claims_mappings ALTER COLUMN org_id SET NOT NULL;

-- One organization per domain becomes one organization per domain PER TENANT.
-- The name is the one Postgres generates for v54's inline UNIQUE.
ALTER TABLE federation_rules DROP CONSTRAINT IF EXISTS federation_rules_email_domain_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_federation_rules_org_domain ON federation_rules(org_id, email_domain);

-- identity_providers is already scoped and belted; only its key was written
-- before tenants existed. Two organizations may now federate to one issuer.
ALTER TABLE identity_providers DROP CONSTRAINT IF EXISTS identity_providers_issuer_url_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_providers_org_issuer ON identity_providers(org_id, issuer_url);

-- v54's idx_federation_rules_domain and idx_custom_claims_app are the same
-- reads without their tenant term; they are left in place.
CREATE INDEX IF NOT EXISTS idx_custom_claims_org_app ON custom_claims_mappings(org_id, application_id);

DROP POLICY IF EXISTS pol_federation_rules_org_scope ON federation_rules;
CREATE POLICY pol_federation_rules_org_scope ON federation_rules
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE federation_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE federation_rules FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_custom_claims_mappings_org_scope ON custom_claims_mappings;
CREATE POLICY pol_custom_claims_mappings_org_scope ON custom_claims_mappings
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE custom_claims_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE custom_claims_mappings FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON federation_rules       TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON custom_claims_mappings TO openidx_app;
`

// Down lifts the belt, drops the columns, and restores v54's install-wide
// UNIQUE on email_domain. That restore is the one statement here that can fail:
// if two organizations have each registered a rule for the same domain while
// v155 was applied — which is the whole point of the migration — the global
// constraint cannot be recreated and the rollback stops there. That is the same
// trade v138 made on ispm_rules.check_type and ai_agents.name, and it is the
// honest one: silently dropping one tenant's rule to make a rollback succeed
// would be worse than refusing.
var federationScopeDown = `-- Rollback 155.

ALTER TABLE custom_claims_mappings NO FORCE ROW LEVEL SECURITY;
ALTER TABLE custom_claims_mappings DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_custom_claims_mappings_org_scope ON custom_claims_mappings;

ALTER TABLE federation_rules NO FORCE ROW LEVEL SECURITY;
ALTER TABLE federation_rules DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_federation_rules_org_scope ON federation_rules;

DROP INDEX IF EXISTS idx_custom_claims_org_app;
DROP INDEX IF EXISTS idx_federation_rules_org_domain;
DROP INDEX IF EXISTS idx_identity_providers_org_issuer;

ALTER TABLE custom_claims_mappings DROP COLUMN IF EXISTS org_id;
ALTER TABLE federation_rules       DROP COLUMN IF EXISTS org_id;

ALTER TABLE federation_rules   ADD CONSTRAINT federation_rules_email_domain_key   UNIQUE (email_domain);
ALTER TABLE identity_providers ADD CONSTRAINT identity_providers_issuer_url_key UNIQUE (issuer_url);
`
