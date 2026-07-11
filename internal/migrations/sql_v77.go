package migrations

// Migration v77 — session_risks + risk_factors for continuous authentication.
//
// The routed continuous-auth endpoints (internal/admin/continuous_auth.go)
// read and write these tables on every risk calculation, but no runner
// migration ever created them: the previous-risk lookup and the risk-history
// INSERT silently failed (errors discarded), so risk deltas were always
// computed against 0 and no history was ever stored, and GetRiskFactors
// errored outright. Both tables are org-belted like their sibling
// stepup_challenges. Plain statements only — the runner's splitSQL cannot
// handle DO $$ blocks.
var sessionRiskHistoryUp = `-- Migration 077: session_risks + risk_factors (continuous-auth history was never persisted).
CREATE TABLE IF NOT EXISTS session_risks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL,
    overall_risk DOUBLE PRECISION NOT NULL DEFAULT 0,
    risk_level VARCHAR(20),
    action_required VARCHAR(50),
    risk_factors JSONB NOT NULL DEFAULT '{}',
    calculated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    previous_risk DOUBLE PRECISION NOT NULL DEFAULT 0,
    risk_delta DOUBLE PRECISION NOT NULL DEFAULT 0,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_session_risks_session ON session_risks(session_id, calculated_at DESC);

CREATE INDEX IF NOT EXISTS idx_session_risks_org_id ON session_risks(org_id);

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

CREATE INDEX IF NOT EXISTS idx_risk_factors_org_id ON risk_factors(org_id);`

var sessionRiskHistoryDown = `-- Rollback 077
DROP TABLE IF EXISTS risk_factors;

DROP TABLE IF EXISTS session_risks;`
