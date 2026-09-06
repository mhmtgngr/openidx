package migrations

// Migration v165 — EDR posture ingestion: the belt, and a device match that
// crossed tenants into an enforcement decision.
//
// v98 created `edr_posture_sources` and `edr_device_mappings` so an external
// EDR/MDM — CrowdStrike, Intune, Jamf — can feed the Ziti-bound posture
// pipeline. Its registry description says "Org-scoped, encrypted creds." Both
// tables got a nullable `org_id UUID` with no foreign key, and neither got FORCE
// ROW LEVEL SECURITY. The needsBelt register has carried a specific warning
// against `edr_device_mappings` since it was written, and v150 and v164 both
// cite it: the ingest writes a NULL org_id when the source has none, so a belt
// would HIDE rows rather than scope them.
//
// THE MATCH CROSSED TENANTS, AND THE MATCH IS AN ENFORCEMENT DECISION. This is
// the finding, and it is not a read. resolveIdentityForDevice turns an EDR
// device report into a local Ziti identity using the source's match strategy,
// and all three of its queries name no organization:
//
//	email:    SELECT zi.id FROM ziti_identities zi JOIN users u ON u.id = zi.user_id
//	           WHERE lower(u.email) = lower($1) LIMIT 1
//	hostname: ... JOIN enrolled_agents ea ON ea.enrolled_by_user_id = zi.user_id
//	           WHERE lower(ea.metadata->>'hostname') = lower($1) LIMIT 1
//	serial:   ... WHERE ea.metadata->>'serial' = $1 LIMIT 1
//
// So a device reported by ONE organization's EDR connection was matched against
// EVERY organization's identities, and `LIMIT 1` with no ORDER BY means which
// one it picked was decided by the query planner. The identity it returns is
// then handed to RecordPostureResult, and a failing posture result is what the
// proxy and continuous verification read to revoke the session and sever the
// overlay circuit.
//
// The consequence is therefore not a leak but a REVOCATION: one tenant's EDR
// reporting a laptop as non-compliant could fail the posture check on another
// tenant's user and cut their access, on nothing more than a shared email
// address, hostname or device serial. Emails collide across tenants routinely —
// the same person employed by two organizations on one installation is the
// ordinary case — and the direction of the error is deny, so it costs
// availability rather than granting anything. All three queries now carry the
// source's organization, matched on ziti_identities.org_id, which also closes
// the two that reach through enrolled_agents: that table has no tenant of its
// own (the fleet decision this programme has deferred twice), but an agent
// enrolled by a user in another organization cannot join to an identity in this
// one, so the identity's tenant is sufficient.
//
// THE SAME WILDCARD AS v164. Get, List and Delete read
// an OR-empty-string escape hatch on the tenant term, and the helper that feeds them
// returns the empty string when the request carries no organization — so an
// absent organization meant every organization. connectorForSource goes further
// and passes the wildcard EXPLICITLY, `GetEDRSource(ctx, "", id)`, while itself
// reading the encrypted API credentials for the source by bare id and
// decrypting them into a live connector. As in v164 this is not reachable
// through the mounted routes, which run TenantResolver in front of every one of
// them, and as in v164 it contradicts the belt: under FORCE ROW LEVEL SECURITY
// an unscoped query returns nothing, so the escape hatch stops meaning "every
// organization" and starts meaning "no rows", silently. The wildcard is
// removed, the handlers refuse a request with no organization, and the one
// caller that legitimately spans tenants — the ingestion worker — keeps the
// explicit RLS bypass it already had.
//
// THE WORKER ALREADY HAD ITS BYPASS: StartEDRIngestionWorker runs the poll loop
// under orgctx.WithBypassRLS, and runDueEDRSources selects by `enabled` and
// poll interval across every organization by design — a source the sweep cannot
// see never polls, and a device that stops reporting must still age out to
// failing. Its by-id statements carry //orgscope:ignore with the reason.
//
// BACKFILL. A device mapping follows its source through v98's enforced foreign
// key, which is exact. A source carries no attribution column, so one stored
// with a NULL organization goes to the oldest organization — and an operator
// with more than one should check which EDR connection belongs to whom before
// the next poll, because that poll writes posture results.
//
// Plain statements only -- the runner's splitSQL cannot handle DO $$ blocks.
var edrPostureBeltUp = `-- Migration 165: belt the EDR posture tables and make their tenant column real.

UPDATE edr_device_mappings m SET org_id = s.org_id FROM edr_posture_sources s
  WHERE s.id = m.source_id AND m.org_id IS NULL AND s.org_id IS NOT NULL;

UPDATE edr_posture_sources  SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;
UPDATE edr_device_mappings  SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE edr_posture_sources ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE edr_device_mappings ALTER COLUMN org_id SET NOT NULL;

ALTER TABLE edr_posture_sources DROP CONSTRAINT IF EXISTS fk_edr_posture_sources_org;
ALTER TABLE edr_posture_sources ADD  CONSTRAINT fk_edr_posture_sources_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE edr_device_mappings DROP CONSTRAINT IF EXISTS fk_edr_device_mappings_org;
ALTER TABLE edr_device_mappings ADD  CONSTRAINT fk_edr_device_mappings_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_edr_mappings_org_source ON edr_device_mappings(org_id, source_id);

DROP POLICY IF EXISTS pol_edr_posture_sources_org_scope ON edr_posture_sources;
CREATE POLICY pol_edr_posture_sources_org_scope ON edr_posture_sources
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE edr_posture_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE edr_posture_sources FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_edr_device_mappings_org_scope ON edr_device_mappings;
CREATE POLICY pol_edr_device_mappings_org_scope ON edr_device_mappings
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE edr_device_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE edr_device_mappings FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON edr_posture_sources TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON edr_device_mappings TO openidx_app;
`

// Down lifts the belt, drops the index and the foreign keys, and returns org_id
// to nullable. The column itself stays -- v98 created it -- so this rollback
// cannot fail on data.
var edrPostureBeltDown = `-- Rollback 165.

ALTER TABLE edr_device_mappings NO FORCE ROW LEVEL SECURITY;
ALTER TABLE edr_device_mappings DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_edr_device_mappings_org_scope ON edr_device_mappings;

ALTER TABLE edr_posture_sources NO FORCE ROW LEVEL SECURITY;
ALTER TABLE edr_posture_sources DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_edr_posture_sources_org_scope ON edr_posture_sources;

DROP INDEX IF EXISTS idx_edr_mappings_org_source;

ALTER TABLE edr_device_mappings DROP CONSTRAINT IF EXISTS fk_edr_device_mappings_org;
ALTER TABLE edr_posture_sources DROP CONSTRAINT IF EXISTS fk_edr_posture_sources_org;

ALTER TABLE edr_device_mappings ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE edr_posture_sources ALTER COLUMN org_id DROP NOT NULL;
`
