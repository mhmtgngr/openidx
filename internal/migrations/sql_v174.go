package migrations

// v174 — the four columns security_alerts was written against but never had.
//
// internal/risk/alert.go INSERTs twenty-one columns. Six of them do not exist:
// tenant_id, ip_address, user_agent, deliveries, acknowledged_by and
// acknowledged_at. The statement has therefore never executed, on any install,
// since it was written -- no security alert has ever been persisted, the alerts
// page has always been empty, and the failure surfaced as an error return that
// the caller logs and moves past.
//
// Two of the six were a naming disagreement rather than missing data and are
// fixed in the Go rather than here: tenant_id is org_id, which the same
// statement already sets, and ip_address is source_ip. The remaining four are
// real fields with nowhere to go, so they get columns:
//
//	user_agent       the client string captured with the alert
//	deliveries       AlertDelivery records -- which channel, sent or failed,
//	                 when, and the error -- the only evidence that an alert
//	                 reached anyone
//	acknowledged_by  AcknowledgeAlert's whole purpose; the table had resolved_by
//	acknowledged_at  and resolved_at but not the acknowledgement pair
//
// All four are nullable with no backfill, because there are no rows: a table
// whose only writer never succeeded is empty by construction. The one exception
// is deliveries, which defaults to '[]' so a reader can decode it without a
// nil check.
//
// Found by tools/sqlprepare, which PREPAREs every SQL literal in the tree
// against a migrated database. It is worth naming how this survived: the
// statement is valid SQL, the Go compiles, the package's tests pass, and a
// commit on this branch already corrected this exact statement's RLS org
// context -- reading it closely enough to fix the connection setting, and not
// once checking that its column list existed.
const securityAlertColumnsUp = `
ALTER TABLE security_alerts ADD COLUMN IF NOT EXISTS user_agent TEXT;
ALTER TABLE security_alerts ADD COLUMN IF NOT EXISTS deliveries JSONB DEFAULT '[]';
ALTER TABLE security_alerts ADD COLUMN IF NOT EXISTS acknowledged_by UUID;
ALTER TABLE security_alerts ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMP WITH TIME ZONE;

-- The alerts page lists open alerts newest first, per tenant.
CREATE INDEX IF NOT EXISTS idx_security_alerts_org_status_created
    ON security_alerts(org_id, status, created_at DESC);
`

// Down drops the four columns. Unlike most rollbacks in this chain this one
// loses data that was written after the migration -- acknowledgements and
// delivery records -- and there is no way to keep them in a table that has no
// column for them. Rolling back past v174 also returns the INSERT to failing,
// which is the state the migration exists to leave.
const securityAlertColumnsDown = `
DROP INDEX IF EXISTS idx_security_alerts_org_status_created;
ALTER TABLE security_alerts DROP COLUMN IF EXISTS acknowledged_at;
ALTER TABLE security_alerts DROP COLUMN IF EXISTS acknowledged_by;
ALTER TABLE security_alerts DROP COLUMN IF EXISTS deliveries;
ALTER TABLE security_alerts DROP COLUMN IF EXISTS user_agent;
`
