package migrations

// Migration v58 — JIT/approval schema drift fix (PAM M2a).
//
// Creates two tables that Go code references but no migration (and not init-db.sql)
// ever created — the same init-db<->migrations drift class as v38-v55, but for tables
// that existed nowhere:
//
//   - jit_grants: internal/governance/jit.go INSERT/SELECT/UPDATEs it across the
//     JIT-elevation service and the 30s StartExpiryChecker worker. Missing → every JIT
//     elevation and the expiry worker error on "relation jit_grants does not exist".
//   - request_approval_chains: internal/governance/request.go INSERTs it in SubmitRequest
//     and reads it in the escalation worker + GetRequest. Missing → POST
//     /api/v1/governance/requests 500s and the escalation checker errors each tick.
//
// Columns match the code's exact SQL usage (verified against jit.go / request.go).
// Not under the v37 FORCE-RLS belt: jit_grants is not org-scoped in code (org isolation
// is implicit via the user/role FKs), and request_approval_chains is a child of
// access_requests reached only through the RLS-scoped parent by request_id — matching the
// v42-v55 reconcile precedent. Idempotent (IF NOT EXISTS).
var jitDriftFixUp = `-- Migration 058: create jit_grants + request_approval_chains (drift fix).
CREATE TABLE IF NOT EXISTS jit_grants (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id       UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    role_name     VARCHAR(255) NOT NULL,
    granted_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    justification TEXT NOT NULL,
    duration      VARCHAR(32) NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at    TIMESTAMPTZ,
    revoked_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    status        VARCHAR(16) NOT NULL DEFAULT 'active'
);
CREATE INDEX IF NOT EXISTS idx_jit_grants_user_role ON jit_grants(user_id, role_id, status);
CREATE INDEX IF NOT EXISTS idx_jit_grants_expiry    ON jit_grants(status, expires_at);

CREATE TABLE IF NOT EXISTS request_approval_chains (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id           UUID NOT NULL UNIQUE REFERENCES access_requests(id) ON DELETE CASCADE,
    steps                JSONB NOT NULL DEFAULT '[]',
    escalate_after_hours INTEGER NOT NULL DEFAULT 24,
    escalate_to          JSONB NOT NULL DEFAULT '[]',
    escalation_due_at    TIMESTAMPTZ NOT NULL,
    current_step         INTEGER NOT NULL DEFAULT 0,
    escalation_notified  BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS idx_rac_escalation ON request_approval_chains(escalation_due_at)
    WHERE escalation_notified = false;
`

var jitDriftFixDown = `-- Migration 058 down.
DROP TABLE IF EXISTS request_approval_chains CASCADE;
DROP TABLE IF EXISTS jit_grants CASCADE;
`
