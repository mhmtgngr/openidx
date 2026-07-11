package migrations

// Migration v72 — device_trust_requests tenant isolation. device_trust_requests
// (admin device-trust approval workflow, created by v39) has no org_id, and
// internal/identity/device_trust_approval.go acted on rows by bare id with no
// org filter: an admin in one org could approve or reject another org's pending
// device-trust requests (cross-tenant IDOR), and GetPendingRequestCount /
// ListDeviceTrustRequests' COUNT leaked global cross-org counts. This adds
// org_id (backfilled from the requesting user, NOT NULL, FK) + an index; the
// service methods now carry an org predicate on every query.
//
// Deliberately NOT placed under the v37 FORCE-RLS belt: ExpireOldRequests is a
// maintenance sweep that runs across orgs, and the request-scoped methods now
// filter by org_id explicitly. Plain statements only — the runner's splitSQL
// cannot handle DO $$ blocks.
var deviceTrustReqOrgIsolationUp = `-- Migration 072: device_trust_requests tenant isolation.
ALTER TABLE device_trust_requests ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- Backfill each request to its requesting user's org.
UPDATE device_trust_requests d SET org_id = u.org_id FROM users u WHERE d.user_id = u.id AND d.org_id IS NULL;

-- Any orphan (user deleted/unknown) -> oldest (primary) org so SET NOT NULL can't fail.
UPDATE device_trust_requests SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE device_trust_requests ALTER COLUMN org_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_device_trust_requests_org ON device_trust_requests(org_id);
`

var deviceTrustReqOrgIsolationDown = `-- Migration 072 down.
DROP INDEX IF EXISTS idx_device_trust_requests_org;
ALTER TABLE device_trust_requests DROP COLUMN IF EXISTS org_id;
`
