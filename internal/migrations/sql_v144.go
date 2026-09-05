package migrations

// Migration v144 — the SAML identity-provider surface.
//
// `saml_service_providers` is the registry of service providers this install
// acts as an IdP for: entity id, ACS URL, and the CERTIFICATE used to verify
// their requests and encrypt assertions to them. Every handler in
// internal/oauth/saml_sp.go read it install-wide — the list and its count had
// no org predicate at all, and get, update and delete took a bare id. One
// tenant's admin could enumerate every other tenant's federation partners,
// rewrite an ACS URL to point assertions at a host of their choosing, or
// replace the certificate. That is not disclosure; it is a redirect of another
// tenant's single sign-on.
//
// `saml_sessions` is the SLO bookkeeping: which user has a live session with
// which SP, so a logout request can be propagated. Keyed by user_id, so it was
// scoped in practice, but the belt makes that structural.
//
// ENTITY_ID STAYS UNIQUE INSTALL-WIDE, and this is the interesting part of the
// batch. v143 re-scoped social_providers.provider_key to (org_id, provider_key)
// because the install-wide key let the first tenant to register 'google' take
// the name from everybody else. The same reasoning does NOT apply here, and
// applying it mechanically would break the protocol:
//
//   - A SAML entity id is a globally unique URI by specification. Two tenants
//     registering the same one is a configuration error, not a legitimate case.
//   - `GetServiceProviderByEntityID` is a PRE-TENANT-RESOLUTION lookup: an
//     incoming AuthnRequest names an entity id and nothing else, and the SP it
//     finds is what tells the IdP whose request this is. Scope that lookup by
//     org and it can never succeed; make the key per-org and it becomes
//     ambiguous. The same holds for the SLO path, which finds a session by
//     (session_index, sp_entity_id) before it knows the user.
//
// So the constraint is kept, those two lookups run bypassed with the reason
// recorded at the call site, and they join the api-key-by-hash and
// route-by-host class that TestPreResolutionLookupsUnderRLS already pins. Not
// every install-wide unique key is a bug; the question is whether the key is
// the thing that resolves the tenant.
//
// BACKFILL. saml_sessions derives its org from its user. saml_service_providers
// has no user and no FK to anything org-scoped, so every existing row goes to
// the oldest org — the v141 audit_retention_policies rule: put the remainder
// somewhere an operator can see and re-file it, rather than leaving rows nobody
// can read. No column DEFAULT.
//
// Plain statements only — the runner's splitSQL cannot handle DO $$ blocks.
var samlTenantScopeUp = `-- Migration 144: org_id + FORCE RLS on the SAML tables.

-- saml_service_providers ---------------------------------------------------
ALTER TABLE saml_service_providers ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- Nothing on the row says whose partner this is, so existing registrations go
-- to the oldest org, visible and re-fileable.
UPDATE saml_service_providers SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE saml_service_providers ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_saml_sp_org ON saml_service_providers(org_id);

-- entity_id keeps its install-wide UNIQUE: it is a globally unique URI by the
-- SAML specification, and it is what resolves the tenant on an incoming
-- request. See the file comment.

DROP POLICY IF EXISTS pol_saml_service_providers_org_scope ON saml_service_providers;
CREATE POLICY pol_saml_service_providers_org_scope ON saml_service_providers
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE saml_service_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_service_providers FORCE  ROW LEVEL SECURITY;

-- saml_sessions ------------------------------------------------------------
ALTER TABLE saml_sessions ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE saml_sessions s SET org_id = u.org_id FROM users u WHERE s.user_id = u.id AND s.org_id IS NULL;

ALTER TABLE saml_sessions ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_saml_sessions_org ON saml_sessions(org_id, user_id);

DROP POLICY IF EXISTS pol_saml_sessions_org_scope ON saml_sessions;
CREATE POLICY pol_saml_sessions_org_scope ON saml_sessions
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE saml_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_sessions FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON saml_service_providers, saml_sessions TO openidx_app;
`

// Down drops the belt and the column. The backfill is not reversed: the rows it
// attributed had no org before, and a re-apply cannot reconstruct an
// attribution once the user it was derived from is gone.
var samlTenantScopeDown = `-- Rollback 144.

ALTER TABLE saml_service_providers NO FORCE ROW LEVEL SECURITY;
ALTER TABLE saml_service_providers DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_saml_service_providers_org_scope ON saml_service_providers;
DROP INDEX IF EXISTS idx_saml_sp_org;
ALTER TABLE saml_service_providers DROP COLUMN IF EXISTS org_id;

ALTER TABLE saml_sessions NO FORCE ROW LEVEL SECURITY;
ALTER TABLE saml_sessions DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_saml_sessions_org_scope ON saml_sessions;
DROP INDEX IF EXISTS idx_saml_sessions_org;
ALTER TABLE saml_sessions DROP COLUMN IF EXISTS org_id;
`
