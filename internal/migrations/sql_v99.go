package migrations

// Migration v99 — SSF/CAEP (Shared Signals Framework + Continuous Access
// Evaluation Profile).
//
// OpenIDX becomes both an SSF transmitter and receiver:
//
//	Transmitter — when OpenIDX revokes a session (kill-switch, continuous
//	verify, EDR posture failure), it pushes a signed Security Event Token (SET,
//	RFC 8417) carrying a CAEP event (e.g. session-revoked) to every subscribed
//	receiver. Downstream apps drop the user immediately instead of waiting for
//	token expiry.
//
//	Receiver — OpenIDX accepts SETs from an upstream IdP (Okta/Entra/Ping) and
//	applies the CAEP event. The differentiating actuator is NETWORK termination:
//	a session-revoked signal doesn't just clear a token, it severs the user's
//	Ziti overlay sessions via the controller. First OSS SSF/CAEP with native
//	network termination.
//
// Three tables (org-scoped for RLS):
//
//	ssf_streams          — a configured transmitter push stream (audience,
//	                       endpoint URL, requested event types, auth).
//	ssf_stream_delivery  — the outbox of SETs to push, drained by a worker with
//	                       at-least-once delivery + retry/backoff.
//	ssf_received_events  — dedup/audit log of inbound SETs (by jti) so a
//	                       re-delivered event is applied at most once.
//
// Additive + idempotent. No behavior change until a stream is configured (Tx)
// or a SET is received (Rx).
var ssfCaepUp = `-- Migration 099: SSF/CAEP transmitter + receiver.

CREATE TABLE IF NOT EXISTS ssf_streams (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID,
    -- Human label for the stream.
    description     VARCHAR(255),
    -- The receiver's audience identifier (SET 'aud').
    audience        TEXT NOT NULL,
    -- Push delivery endpoint (RFC 8935); OpenIDX POSTs application/secevent+jwt.
    delivery_endpoint TEXT NOT NULL,
    -- Optional bearer token the receiver requires; encrypted at rest.
    delivery_auth_enc TEXT,
    -- CAEP/RISC event URIs this stream should receive (JSON array).
    events_requested JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- SSF stream status per spec: 'enabled' | 'paused' | 'disabled'.
    status          VARCHAR(16) NOT NULL DEFAULT 'enabled',
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ssf_streams_org ON ssf_streams(org_id);
CREATE INDEX IF NOT EXISTS idx_ssf_streams_status ON ssf_streams(status) WHERE status = 'enabled';

CREATE TABLE IF NOT EXISTS ssf_stream_delivery (
    id              BIGSERIAL PRIMARY KEY,
    org_id          UUID,
    stream_id       UUID NOT NULL REFERENCES ssf_streams(id) ON DELETE CASCADE,
    -- The CAEP/RISC event URI (e.g. https://schemas.openid.net/secevent/caep/event-type/session-revoked).
    event_type      TEXT NOT NULL,
    -- The subject the event is about (user id / email), for audit + ordering.
    subject         TEXT,
    -- The fully-formed, signed SET (compact JWS) to POST.
    set_jwt         TEXT NOT NULL,
    state           VARCHAR(16) NOT NULL DEFAULT 'pending', -- pending|delivered|failed|dead
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT,
    next_attempt_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ssf_delivery_ready
    ON ssf_stream_delivery(next_attempt_at) WHERE state = 'pending';
CREATE INDEX IF NOT EXISTS idx_ssf_delivery_stream ON ssf_stream_delivery(stream_id);

CREATE TABLE IF NOT EXISTS ssf_received_events (
    -- The SET's jti (RFC 8417) — dedup key so a re-delivery is applied once.
    jti             VARCHAR(255) PRIMARY KEY,
    org_id          UUID,
    issuer          TEXT,
    event_type      TEXT,
    subject         TEXT,
    -- Outcome of applying the event: 'applied' | 'ignored' | 'error'.
    outcome         VARCHAR(16) NOT NULL DEFAULT 'applied',
    detail          TEXT,
    received_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ssf_received_subject ON ssf_received_events(subject, received_at DESC);
`

var ssfCaepDown = `-- Rollback 099: SSF/CAEP.
DROP TABLE IF EXISTS ssf_received_events;
DROP TABLE IF EXISTS ssf_stream_delivery;
DROP TABLE IF EXISTS ssf_streams;
`
