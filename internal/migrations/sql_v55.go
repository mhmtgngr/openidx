package migrations

// Migration v55 — split the deprovisioning policy-run log into its own table.
//
// init-db.sql historically defined lifecycle_executions twice with incompatible
// schemas: a workflow form (workflow_id/user_id, used by internal/identity, which
// wins and is created by v54) and a policy form (policy_id/users_scanned, used by
// internal/admin/deprovisioning). The policy form lost, so deprovisioning's
// INSERT/UPDATE/SELECT referenced non-existent columns and failed on every
// install. This creates the policy-run table under its own name; init-db.sql is
// updated in lockstep (the second block renamed) and deprovisioning.go is
// repointed. Idempotent; not under the v37 RLS belt (non-FORCE table). The FK to
// lifecycle_policies(id) resolves — v54 created lifecycle_policies and v55 runs
// after it.
var lifecyclePolicyExecUp = `-- Migration 055: lifecycle_policy_executions (deprovisioning policy-run log).
CREATE TABLE IF NOT EXISTS lifecycle_policy_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID NOT NULL REFERENCES lifecycle_policies(id) ON DELETE CASCADE,
    status VARCHAR(50) DEFAULT 'running',
    users_scanned INTEGER DEFAULT 0,
    users_affected INTEGER DEFAULT 0,
    actions_taken JSONB DEFAULT '[]',
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_lifecycle_policy_exec ON lifecycle_policy_executions(policy_id, started_at DESC);
`

var lifecyclePolicyExecDown = `-- Migration 055 down.
DROP TABLE IF EXISTS lifecycle_policy_executions CASCADE;
`
