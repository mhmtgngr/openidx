package migrations

// Migration 262: proposals the platform makes and a person decides.
//
// agentic_proposals holds a step the rollout operator (and later operators)
// recommends but may not take on its own: widening an update ring, or pausing
// one when automation is not allowed to. A proposal is bound to the state it
// was drawn from (base_hash), is good for a few hours, and is decided once:
// approved (and applied), rejected, expired or superseded. At most one
// proposal of a kind is pending per organization, so an operator is never
// asked the same question twice.

var agenticProposalsUp = `-- Migration 262: agentic proposals.
CREATE TABLE IF NOT EXISTS agentic_proposals (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind        VARCHAR(32) NOT NULL CHECK (kind IN ('rollout_pause', 'rollout_advance')),
    target_type VARCHAR(32) NOT NULL DEFAULT 'org',
    target_id   VARCHAR(255) NOT NULL DEFAULT '',
    params      JSONB NOT NULL DEFAULT '{}',
    reasons     JSONB NOT NULL DEFAULT '[]',
    base_hash   VARCHAR(64) NOT NULL,
    status      VARCHAR(16) NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'applied', 'rejected', 'expired', 'superseded')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '4 hours',
    decided_by  UUID,
    decided_at  TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_agentic_proposals_pending ON agentic_proposals (org_id, kind) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_agentic_proposals_org ON agentic_proposals (org_id, created_at DESC);
GRANT SELECT, INSERT, UPDATE, DELETE ON agentic_proposals TO openidx_app;
DROP POLICY IF EXISTS pol_agentic_proposals_org_scope ON agentic_proposals;
CREATE POLICY pol_agentic_proposals_org_scope ON agentic_proposals
  USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE agentic_proposals ENABLE ROW LEVEL SECURITY;
ALTER TABLE agentic_proposals FORCE  ROW LEVEL SECURITY;
`

var agenticProposalsDown = `-- Rollback migration 262.
DROP TABLE IF EXISTS agentic_proposals;
`
