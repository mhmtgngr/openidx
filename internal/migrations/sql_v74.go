package migrations

// Migration v74 — create the detailed_compliance_reports table.
//
// internal/audit/compliance_enhanced.go persisted every generated SOC 2 /
// ISO 27001 detailed report via storeDetailedReport into a
// `detailed_compliance_reports` table that no migration created: every INSERT
// failed (logged at Warn and swallowed), and the live evidence endpoint
// (GET /reports/:id/evidence) always fell through to its degraded
// compliance_reports fallback — detailed control-level evidence was never
// downloadable.
//
// The table is org-scoped (org_id NOT NULL, FK ON DELETE CASCADE) and the
// audit-service queries carry the org predicate explicitly, so one tenant's
// evidence package can never be fetched by another tenant's report id.
// Deliberately NOT placed under the v37 FORCE-RLS belt, matching v72/v73
// precedent for tables whose access paths filter explicitly. Plain statements
// only — the runner's splitSQL cannot handle DO $$ blocks.
var detailedComplianceReportsUp = `-- Migration 074: detailed_compliance_reports storage (was a phantom table).
CREATE TABLE IF NOT EXISTS detailed_compliance_reports (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    framework VARCHAR(50) NOT NULL,
    period VARCHAR(255),
    generated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    overall_score DOUBLE PRECISION NOT NULL DEFAULT 0,
    summary TEXT,
    report_data JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_detailed_compliance_reports_org ON detailed_compliance_reports(org_id);
CREATE INDEX IF NOT EXISTS idx_detailed_compliance_reports_framework ON detailed_compliance_reports(org_id, framework, generated_at DESC);`

var detailedComplianceReportsDown = `-- Rollback 074
DROP INDEX IF EXISTS idx_detailed_compliance_reports_framework;
DROP INDEX IF EXISTS idx_detailed_compliance_reports_org;
DROP TABLE IF EXISTS detailed_compliance_reports;`
