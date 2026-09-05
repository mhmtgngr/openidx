package migrations

// Migration v141 — give the admin audit log and the audit archives a tenant.
//
// Three tables that hold one tenant's compliance record and had no column
// saying whose it was:
//
//   - admin_audit_log — every admin action with actor, target and the full
//     before/after state. `handleGetAdminAuditLog` listed it `WHERE 1=1`,
//     `handleGetAdminAuditEntry` fetched by bare id, and the settings-history
//     view counted every install-wide row. One tenant's admin could read every
//     other tenant's administrative history, including the before/after JSON of
//     changes they never had access to make.
//   - audit_archives — exported audit archives, with the file path of the
//     export. Listed unscoped, fetched by bare id, and `handleRestoreAuditArchive`
//     restored by bare id, so a tenant could name another tenant's archive and
//     have the product read that file back for them. That one is exfiltration,
//     not just disclosure.
//   - audit_retention_policies — how long each tenant keeps what. Listed
//     unscoped and updated or deleted by bare id, so one tenant could shorten
//     another's retention.
//
// This is the same shape as the ISPM/AI tables in v138: rows that belong to
// somebody, in a table with nowhere to record who, read and mutated by id.
//
// The backfill derives the org from the row's own actor where there is one
// (admin_audit_log.actor_id, audit_archives.created_by) and falls back to the
// oldest org for rows whose actor has been deleted and for the retention
// policies, which carry no user at all. That is the v69/v138 rule: attribute
// what can be attributed, put the remainder somewhere visible, and let the
// operator re-file rather than leaving rows nobody can see. No column DEFAULT,
// so a rolled-back binary fails loudly instead of writing new rows into
// whichever org a default happened to name.
//
// Plain statements only — the runner's splitSQL cannot handle DO $$ blocks.
var auditTenantScopeUp = `-- Migration 141: org_id + FORCE RLS on the admin audit log and audit archives.

-- admin_audit_log --------------------------------------------------------------
ALTER TABLE admin_audit_log ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- An action belongs to the org of the admin who performed it.
UPDATE admin_audit_log a SET org_id = u.org_id FROM users u WHERE a.actor_id = u.id AND a.org_id IS NULL;
-- Rows whose actor has since been deleted (actor_id is ON DELETE SET NULL).
UPDATE admin_audit_log SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE admin_audit_log ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_admin_audit_org ON admin_audit_log(org_id, created_at DESC);

DROP POLICY IF EXISTS pol_admin_audit_log_org_scope ON admin_audit_log;
CREATE POLICY pol_admin_audit_log_org_scope ON admin_audit_log
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE admin_audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_audit_log FORCE  ROW LEVEL SECURITY;

-- audit_archives ---------------------------------------------------------------
ALTER TABLE audit_archives ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE audit_archives a SET org_id = u.org_id FROM users u WHERE a.created_by = u.id AND a.org_id IS NULL;
UPDATE audit_archives SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE audit_archives ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_archives_org ON audit_archives(org_id, created_at DESC);

DROP POLICY IF EXISTS pol_audit_archives_org_scope ON audit_archives;
CREATE POLICY pol_audit_archives_org_scope ON audit_archives
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE audit_archives ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_archives FORCE  ROW LEVEL SECURITY;

-- audit_retention_policies -----------------------------------------------------
ALTER TABLE audit_retention_policies ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- No actor column: every existing policy goes to the oldest org, where it stays
-- visible and can be re-filed, rather than to a NULL nobody can see.
UPDATE audit_retention_policies SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE audit_retention_policies ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_retention_org ON audit_retention_policies(org_id);

DROP POLICY IF EXISTS pol_audit_retention_policies_org_scope ON audit_retention_policies;
CREATE POLICY pol_audit_retention_policies_org_scope ON audit_retention_policies
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE audit_retention_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_retention_policies FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON admin_audit_log, audit_archives, audit_retention_policies TO openidx_app;
`

// Down drops the belt and the column. The backfill is not reversed: the rows it
// attributed had no org before, and putting them back would lose the
// attribution a re-apply cannot reconstruct once actors are gone.
var auditTenantScopeDown = `-- Rollback 141.

ALTER TABLE admin_audit_log          NO FORCE ROW LEVEL SECURITY;
ALTER TABLE admin_audit_log          DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_admin_audit_log_org_scope ON admin_audit_log;
DROP INDEX IF EXISTS idx_admin_audit_org;
ALTER TABLE admin_audit_log          DROP COLUMN IF EXISTS org_id;

ALTER TABLE audit_archives           NO FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_archives           DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_audit_archives_org_scope ON audit_archives;
DROP INDEX IF EXISTS idx_audit_archives_org;
ALTER TABLE audit_archives           DROP COLUMN IF EXISTS org_id;

ALTER TABLE audit_retention_policies NO FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_retention_policies DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_audit_retention_policies_org_scope ON audit_retention_policies;
DROP INDEX IF EXISTS idx_audit_retention_org;
ALTER TABLE audit_retention_policies DROP COLUMN IF EXISTS org_id;
`
