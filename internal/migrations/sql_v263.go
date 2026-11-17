package migrations

// Migration 263: access plans.
//
// agentic_proposals (v262) held the rollout operator's steps. The setup
// operator's "open this application to that group" is the same shape of thing:
// a step the platform lays out, a person approves, and the platform carries out.
// So the table gains the kind ('access_open'), a place for what happened
// (outcome: whether the grant was made and what the check afterwards found,
// which is what an undo needs), and a status for a plan that was undone.
//
// "One pending per kind" was right for the rollout (one ring per organization)
// and wrong for plans (many resources and groups), so the uniqueness is now per
// target: the rollout's target is the organization, a plan's is its resource and
// group.

var accessPlansUp = `-- Migration 263: access plans.
ALTER TABLE agentic_proposals DROP CONSTRAINT IF EXISTS agentic_proposals_kind_check;
ALTER TABLE agentic_proposals ADD CONSTRAINT agentic_proposals_kind_check
    CHECK (kind IN ('rollout_pause', 'rollout_advance', 'access_open'));
ALTER TABLE agentic_proposals DROP CONSTRAINT IF EXISTS agentic_proposals_status_check;
ALTER TABLE agentic_proposals ADD CONSTRAINT agentic_proposals_status_check
    CHECK (status IN ('pending', 'applied', 'rejected', 'expired', 'superseded', 'undone'));
ALTER TABLE agentic_proposals ADD COLUMN IF NOT EXISTS outcome JSONB NOT NULL DEFAULT '{}';
DROP INDEX IF EXISTS uq_agentic_proposals_pending;
CREATE UNIQUE INDEX IF NOT EXISTS uq_agentic_proposals_pending_target
    ON agentic_proposals (org_id, kind, target_id) WHERE status = 'pending';
`

var accessPlansDown = `-- Rollback migration 263.
DELETE FROM agentic_proposals WHERE kind = 'access_open' OR status = 'undone';
DROP INDEX IF EXISTS uq_agentic_proposals_pending_target;
CREATE UNIQUE INDEX IF NOT EXISTS uq_agentic_proposals_pending ON agentic_proposals (org_id, kind) WHERE status = 'pending';
ALTER TABLE agentic_proposals DROP COLUMN IF EXISTS outcome;
ALTER TABLE agentic_proposals DROP CONSTRAINT IF EXISTS agentic_proposals_status_check;
ALTER TABLE agentic_proposals ADD CONSTRAINT agentic_proposals_status_check
    CHECK (status IN ('pending', 'applied', 'rejected', 'expired', 'superseded'));
ALTER TABLE agentic_proposals DROP CONSTRAINT IF EXISTS agentic_proposals_kind_check;
ALTER TABLE agentic_proposals ADD CONSTRAINT agentic_proposals_kind_check
    CHECK (kind IN ('rollout_pause', 'rollout_advance'));
`
