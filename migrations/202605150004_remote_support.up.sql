-- 202605150004: Phase 4 — remote support session tracking.
--
-- One row per attempt by an admin to remote-control / remote-view an agent.
-- Active rows are also the signal the agent polls for via /agent/config:
-- when a row with status='pending' or 'active' exists for an agent_id, the
-- /agent/config response includes a remote_support block telling the agent
-- which WebSocket to connect to.
--
-- Signaling messages themselves are NOT persisted — they relay through an
-- in-memory broker in the access service (see internal/access/remote_support_api.go).
-- We only persist start / end / final disposition so audit history survives
-- restarts and stale sessions can be cleaned up by the grace-period job.

CREATE TABLE IF NOT EXISTS remote_support_sessions (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id           VARCHAR(64) NOT NULL,
    admin_user_id      UUID REFERENCES users(id) ON DELETE SET NULL,
    -- status:
    --   pending  — admin started session; agent hasn't accepted yet
    --   active   — both peers connected; WebRTC track flowing
    --   ended    — explicit end (admin or agent)
    --   expired  — janitor closed an orphan session
    --   declined — agent's local user rejected the consent prompt
    status             VARCHAR(16) NOT NULL DEFAULT 'pending',
    -- Mode: view-only or interactive (decides whether the agent enables
    -- the input-injection data channel).
    mode               VARCHAR(16) NOT NULL DEFAULT 'interactive',
    -- ICE servers (STUN / TURN) the peers should use. Stored as JSON so we
    -- can add credentials without schema churn. Empty array = no STUN/TURN
    -- (LAN-only, useful for Ziti-only deployments where the overlay handles
    -- NAT traversal).
    ice_servers        JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- The reason supplied when the session ended (admin-supplied for
    -- ended, system-supplied for expired/declined).
    end_reason         VARCHAR(255),
    -- Optional URL of an uploaded recording, if recording is enabled on this
    -- tenant. Recording itself is out of scope for Phase 4 MVP; the field
    -- is reserved.
    recording_url      VARCHAR(512),
    started_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    accepted_at        TIMESTAMPTZ,
    ended_at           TIMESTAMPTZ,
    -- Free-form admin notes (case ID, user-reported issue, etc.).
    notes              TEXT,
    -- Stamped on every signaling-broker activity so the janitor can spot
    -- WebRTC negotiations that stalled mid-handshake.
    last_activity_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_remote_support_sessions_agent
    ON remote_support_sessions(agent_id, status);

CREATE INDEX IF NOT EXISTS idx_remote_support_sessions_admin
    ON remote_support_sessions(admin_user_id, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_remote_support_sessions_active
    ON remote_support_sessions(status)
 WHERE status IN ('pending', 'active');
