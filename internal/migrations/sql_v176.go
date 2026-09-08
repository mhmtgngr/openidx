package migrations

// v176 — drop the two tables the product read and nothing wrote.
//
// Found by tools/tablewriters, which holds the set of tables the migration
// registry creates next to the set a SQL literal in the product writes. Both of
// these were read on a user-facing surface and neither has ever had a row.
//
// api_usage_metrics (v54) backed the Usage Analytics card: total requests, top
// endpoints, error rate, average latency. The table's columns are exactly what
// an hourly request aggregate needs -- (endpoint, method, service, status_code,
// count, avg_latency_ms, hour) with a UNIQUE on all but the counters -- and no
// handler, worker or seed has ever inserted into it. The read could not have
// worked either: it named request_count, error_count and recorded_at, which the
// table does not have, so all four statements failed to plan and the handler
// returned the Go zero beside each. Request volume, latency and status codes
// are measured, by the Prometheus middleware every service mounts; the second
// copy aggregated into Postgres was never written, and building that writer is
// a feature rather than a fix. The card and the endpoint go with the table.
//
// risk_factors (v77) was the continuous-auth engine's detail table. The engine
// computes five weighted factors, sums them into a score, and returned the
// RiskFactors slice exactly as empty as it was initialised -- while writing the
// literal "{}" into session_risks.risk_factors, the column that exists for that
// detail. Its only reader had no caller. The factors now travel with the score
// that produced them, in the response and in session_risks.risk_factors, so
// there is one place the detail lives instead of two, one of them always empty.
//
// Nothing is lost. A table with no writer has no rows, on any install, at any
// version -- that is what the census establishes, and it is why these two are
// dropped rather than scoped or backfilled.
const unwrittenTablesUp = `-- Migration 176: drop api_usage_metrics and risk_factors.

DROP TABLE IF EXISTS api_usage_metrics;

DROP TABLE IF EXISTS risk_factors;
`

// Down recreates both verbatim -- the v54 and v77 definitions, plus the RLS
// policy v121 added to risk_factors, so a rollback lands on the schema the
// chain describes rather than an approximation of it. Grants need no statement:
// v53 set ALTER DEFAULT PRIVILEGES for openidx_app in this schema, so a table
// created by the migration role carries them.
//
// Recreated empty, which is what they were.
const unwrittenTablesDown = `
CREATE TABLE IF NOT EXISTS api_usage_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL,
    service VARCHAR(100) NOT NULL,
    status_code INT,
    count INT DEFAULT 1,
    avg_latency_ms FLOAT DEFAULT 0,
    hour TIMESTAMP WITH TIME ZONE NOT NULL,
    UNIQUE(endpoint, method, service, status_code, hour)
);

CREATE INDEX IF NOT EXISTS idx_api_metrics_hour ON api_usage_metrics(hour);

CREATE INDEX IF NOT EXISTS idx_api_metrics_endpoint ON api_usage_metrics(endpoint, hour);

CREATE TABLE IF NOT EXISTS risk_factors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL,
    type VARCHAR(50) NOT NULL,
    severity DOUBLE PRECISION NOT NULL DEFAULT 0,
    description TEXT,
    detected_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    resolved BOOLEAN NOT NULL DEFAULT false,
    resolved_at TIMESTAMP WITH TIME ZONE,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_risk_factors_session ON risk_factors(session_id) WHERE resolved = false;

CREATE INDEX IF NOT EXISTS idx_risk_factors_org_id ON risk_factors(org_id);

DROP POLICY IF EXISTS pol_risk_factors_org_scope ON risk_factors;
CREATE POLICY pol_risk_factors_org_scope ON risk_factors
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE risk_factors ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_factors FORCE  ROW LEVEL SECURITY;
`
