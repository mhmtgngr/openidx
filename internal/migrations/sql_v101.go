package migrations

// Migration v101 — JIT network grants (Wave B1).
//
// The differentiator demo: "approve an access request -> the network path exists
// for N hours -> it vanishes." When a request for a network_service resource is
// fulfilled, the user's Ziti identity gets a TIME-BOUND role attribute
// (jit-<request-id>) that a Ziti service policy matches to allow the dial; when
// the request expires, the attribute is removed and the live circuit severed
// (reusing the Wave B2 network_revocation_queue).
//
// The governance service has no Ziti access, so grants are handed off via this
// queue to the access-service, which owns the ZitiManager. This is the "add
// attribute" counterpart to network_revocation_queue's "remove + sever".
//
// Additive + idempotent; no behavior change until a network_service request is
// fulfilled.
var networkGrantQueueUp = `-- Migration 101: JIT network grant queue.
CREATE TABLE IF NOT EXISTS network_grant_queue (
    id            BIGSERIAL PRIMARY KEY,
    org_id        UUID,
    -- The user whose Ziti identity gets the time-bound attribute.
    user_id       UUID NOT NULL,
    -- The access request this grant fulfills (audit + attribute naming).
    request_id    UUID,
    -- The Ziti role attribute to add, e.g. 'jit-<request-id>'. A service policy
    -- bindings this attribute is what actually opens the dial.
    attribute     VARCHAR(128) NOT NULL,
    -- When the grant expires; informational (the expiry sweep drives removal via
    -- network_revocation_queue). NULL = no auto-expiry.
    expires_at    TIMESTAMP WITH TIME ZONE,
    state         VARCHAR(16) NOT NULL DEFAULT 'pending', -- pending|done|failed
    attempts      INTEGER NOT NULL DEFAULT 0,
    last_error    TEXT,
    created_at    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_net_grant_pending
    ON network_grant_queue(created_at) WHERE state = 'pending';

-- network_revocation_queue gains an optional attribute column so an expiry can
-- ask the worker to REMOVE a specific JIT attribute (not just sever sessions).
-- Existing rows keep it NULL (sever-only), so no behavior change.
ALTER TABLE network_revocation_queue
    ADD COLUMN IF NOT EXISTS attribute VARCHAR(128);
`

var networkGrantQueueDown = `-- Rollback 101.
ALTER TABLE network_revocation_queue DROP COLUMN IF EXISTS attribute;
DROP TABLE IF EXISTS network_grant_queue;
`
