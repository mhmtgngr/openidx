package migrations

// Migration v128 — normalize out-of-range enrolled_agents.compliance_score.
//
// compliance_score is documented and computed server-side as a 0.0–1.0 weighted
// ratio (see internal/access/agent_api.go). Some agents historically reported an
// already-percentage 0–100 value, which was persisted verbatim. The admin
// console multiplies the score by 100 to render a percentage, so a stored 100
// showed up as "10000%".
//
// The handler now clamps on write, but existing rows still hold bad values. Fold
// any score > 1 back into range: a value that looks like a 0–100 percentage
// (<= 100) is divided by 100; anything larger is clamped to 1.0. Negative scores
// are floored at 0.0. Idempotent — re-running leaves in-range values untouched.
var normalizeAgentComplianceScoreUp = `-- Migration 128: clamp compliance_score to 0.0–1.0.
UPDATE enrolled_agents
SET compliance_score = CASE
    WHEN compliance_score < 0 THEN 0.0
    WHEN compliance_score > 1 AND compliance_score <= 100 THEN compliance_score / 100.0
    WHEN compliance_score > 100 THEN 1.0
    ELSE compliance_score
END
WHERE compliance_score < 0 OR compliance_score > 1;
`

// Down is a no-op: the original out-of-range values were data corruption, so
// there is nothing meaningful to restore.
var normalizeAgentComplianceScoreDown = `-- Rollback 128: no-op (cannot un-normalize corrupted scores).
SELECT 1;
`
