package migrations

// Migration v100 — network revocation queue (governance -> Ziti circuit severance).
//
// When governance revokes a grant (an access-review/certification decision or a
// JIT expiry), the DB assignment is removed and the periodic ziti-user-sync
// reconcile drops the corresponding Ziti role attribute, so *new* dials are
// denied. But an already-open overlay circuit survives until the app closes it.
//
// This queue lets the governance service (which has no Ziti access) hand off a
// circuit-severance intent to the access-service, which owns the ZitiManager. A
// worker drains it and terminates the subject's live controller sessions, so a
// certification revoke completes decision-to-packet: the grant is deleted, the
// attribute detached, AND the circuit severed.
//
// Additive + idempotent; no behavior change until governance enqueues an intent.
var networkRevocationQueueUp = `-- Migration 100: network revocation queue.
CREATE TABLE IF NOT EXISTS network_revocation_queue (
    id          BIGSERIAL PRIMARY KEY,
    org_id      UUID,
    -- The user whose live overlay circuits should be severed.
    user_id     UUID NOT NULL,
    -- Why (audit): 'access_review' | 'certification' | 'jit_expiry' | ...
    reason      VARCHAR(64) NOT NULL,
    state       VARCHAR(16) NOT NULL DEFAULT 'pending', -- pending|done|failed
    attempts    INTEGER NOT NULL DEFAULT 0,
    last_error  TEXT,
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_net_revoke_pending
    ON network_revocation_queue(created_at) WHERE state = 'pending';
`

var networkRevocationQueueDown = `-- Rollback 100.
DROP TABLE IF EXISTS network_revocation_queue;
`
