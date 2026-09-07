package migrations

// v182 — drop request_approval_chains, the table only unreachable code wrote.
//
// Migration v58 created it because internal/governance/request.go INSERTed it
// in SubmitRequest and its escalation sweep read it; v64 put it under the
// FORCE-RLS belt. Neither was wrong about the code. What nobody checked was
// whether that code runs: NewRequestService is called by nothing, so the INSERT
// has never executed on any install, the escalation sweep's INNER JOIN has
// always matched zero rows, and the live approval workflow in workflows.go
// writes access_request_approvals instead and has never touched this table.
// tools/deadservice found the service; tools/tablewriters could not, because a
// census of SQL literals cannot tell a statement that runs from one that
// cannot -- it counted that INSERT as a writer.
//
// The table is empty on every install by construction, so this drops data
// nowhere. It is separated from the code deletion in the same commit only by
// file: both halves have to land together, or the belt keeps a policy on a
// table nothing references and the next reader has to work out why.
//
// Down recreates it in the v58 shape with the v64 belt, so a rollback past this
// point lands on the schema the code at that point expects.
var dropRequestApprovalChainsUp = `-- Migration 182: drop request_approval_chains.
DROP TABLE IF EXISTS request_approval_chains CASCADE;`

var dropRequestApprovalChainsDown = `-- Rollback 182: recreate request_approval_chains (v58 shape + v64 org_id and belt).
CREATE TABLE IF NOT EXISTS request_approval_chains (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id           UUID NOT NULL UNIQUE REFERENCES access_requests(id) ON DELETE CASCADE,
    steps                JSONB NOT NULL DEFAULT '[]',
    escalate_after_hours INTEGER NOT NULL DEFAULT 24,
    escalate_to          JSONB NOT NULL DEFAULT '[]',
    escalation_due_at    TIMESTAMPTZ NOT NULL,
    current_step         INTEGER NOT NULL DEFAULT 0,
    escalation_notified  BOOLEAN NOT NULL DEFAULT false,
    org_id               UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_rac_escalation ON request_approval_chains(escalation_due_at)
    WHERE escalation_notified = false;
CREATE INDEX IF NOT EXISTS idx_request_approval_chains_org ON request_approval_chains(org_id);
DROP POLICY IF EXISTS pol_request_approval_chains_org_scope ON request_approval_chains;
CREATE POLICY pol_request_approval_chains_org_scope ON request_approval_chains
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE request_approval_chains ENABLE ROW LEVEL SECURITY;
ALTER TABLE request_approval_chains FORCE  ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON request_approval_chains TO openidx_app;`
