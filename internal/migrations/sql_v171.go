package migrations

// Migration v171 — the last three on the belt register, and a request that was
// never filed.
//
// THE REQUEST THAT WAS NEVER FILED. When an untrusted device reaches a
// device-trust-protected resource, the proxy refuses it and — in the words of
// its own doc comment — "files a pending device-trust request for an untrusted
// device that attempted access, so an admin can approve it".
//
// v72 added org_id to device_trust_requests and made it NOT NULL, with no
// default. internal/access/device_trust.go's INSERT was never updated. So since
// v72 that statement has failed on EVERY call with
//
//	null value in column "org_id" of relation "device_trust_requests"
//	violates not-null constraint (SQLSTATE 23502)
//
// and the error was logged at WARN and swallowed, because the whole function is
// best-effort so it can never block the proxied request. The enforcement path
// refused the device, said it was raising a request, and raised nothing. Every
// time, on every install, for as long as the column has existed.
//
// The identity-side writer in internal/identity/device_trust_approval.go always
// wrote the tenant, and every read there carries `AND org_id = $N`. This is the
// pair's other half: the seventh time this programme has found a pair guarded
// on one side and not the other, and the second time (after v163's entitlement
// Save) that the unguarded half turned out never to have worked at all. The
// difference is which way it fails: v163's returned a 500 the user could see,
// this one returned nothing at all, because nobody was waiting on it.
//
// It is fixed rather than merely belted. The tenant comes from the
// already-authenticated user, which is exact — a user belongs to exactly one
// organization — and the forward-auth path has no resolved org of its own,
// which is why it already ran under an explicit bypass.
//
// THE BACKGROUND WRITER, AGAIN. report_exports is scoped on create, list and
// download, and unscoped in exactly one place: updateExportStatus, called from
// generateReportAsync, which ran on context.Background(). That is v73's
// discovery goroutine one batch later, and the same fix: the goroutine carries
// the tenant on its context and the UPDATE carries it in SQL. Without it the
// belt would leave an export at "generating" for ever, with the file on disk
// and the download endpoint answering "export is not completed".
//
// THE ONE GENUINE PRE-TENANT PATH IN THE WHOLE REGISTER. enrollment_sessions is
// read by the public /agent/enroll endpoint when an agent redeems its enrolment
// token: no JWT, no subdomain the resolver can trust to be the enroling
// tenant's, and on an install with the default-org fallback on it would be
// handed the PRIMARY org — the wrong one for a device enroling into any other
// tenant. Its in-tree comment said, correctly for its time, that
// "enrollment_sessions is a global table like agent_enrollment_tokens, so no
// RLS bypass is needed for this high-entropy-keyed read". Belting the table
// makes that false, so the two public-path functions opt out explicitly with
// orgctx.WithBypassRLS and the comment is corrected in the same commit. The key
// there is the SHA-256 of the enrolment token; the session's own org_id scopes
// everything after it. The two user-facing handlers (poll status, cancel) do
// carry a tenant and now say so.
//
// With these three the needsBelt register is EMPTY. It began this programme at
// 34 tables whose own migrations had drifted out of the v37/v121 belt, and the
// count has only ever gone down, pinned by ddl_test.go so it could not grow
// back. What remains on any register is the five deferred needsScoping tables,
// each waiting on a product decision rather than a migration.
//
// Plain statements only -- the runner's splitSQL cannot handle DO $$ blocks.
var lastBeltTablesUp = `-- Migration 171: the last three tables on the belt register.

UPDATE report_exports e SET org_id = u.org_id FROM users u
  WHERE u.id = e.generated_by AND e.org_id IS NULL;
UPDATE report_exports SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1)
  WHERE org_id IS NULL;
ALTER TABLE report_exports ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE report_exports DROP CONSTRAINT IF EXISTS fk_report_exports_org;
ALTER TABLE report_exports ADD  CONSTRAINT fk_report_exports_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_report_exports_org ON report_exports(org_id);

DROP POLICY IF EXISTS pol_report_exports_org_scope ON report_exports;
CREATE POLICY pol_report_exports_org_scope ON report_exports
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE report_exports ENABLE ROW LEVEL SECURITY;
ALTER TABLE report_exports FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_device_trust_requests_org_scope ON device_trust_requests;
CREATE POLICY pol_device_trust_requests_org_scope ON device_trust_requests
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE device_trust_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_trust_requests FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_enrollment_sessions_org_scope ON enrollment_sessions;
CREATE POLICY pol_enrollment_sessions_org_scope ON enrollment_sessions
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE enrollment_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE enrollment_sessions FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON report_exports        TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON device_trust_requests TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON enrollment_sessions   TO openidx_app;
`

// Down lifts the three belts and returns report_exports.org_id to nullable.
// device_trust_requests and enrollment_sessions keep the NOT NULL their own
// migrations gave them. Nothing here can fail on data.
var lastBeltTablesDown = `-- Rollback 171.

ALTER TABLE enrollment_sessions NO FORCE ROW LEVEL SECURITY;
ALTER TABLE enrollment_sessions DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_enrollment_sessions_org_scope ON enrollment_sessions;

ALTER TABLE device_trust_requests NO FORCE ROW LEVEL SECURITY;
ALTER TABLE device_trust_requests DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_device_trust_requests_org_scope ON device_trust_requests;

ALTER TABLE report_exports NO FORCE ROW LEVEL SECURITY;
ALTER TABLE report_exports DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_report_exports_org_scope ON report_exports;

DROP INDEX IF EXISTS idx_report_exports_org;
ALTER TABLE report_exports DROP CONSTRAINT IF EXISTS fk_report_exports_org;
ALTER TABLE report_exports ALTER COLUMN org_id DROP NOT NULL;
`
