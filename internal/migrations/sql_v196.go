package migrations

// Migration v196 -- ssf_pending_events: the seam between the paths that sever
// an account and the process that can sign a security event about it.
//
// THE PROBLEM IT SOLVES IS STRUCTURAL, NOT AN OVERSIGHT. The SSF transmitter
// (EmitCAEPEvent) is a method on oauth-service: it reads the tenant's streams,
// signs a SET with the issuer's key and enqueues it on ssf_stream_delivery.
// The paths that disable or delete a user live in identity, directory and
// admin -- other binaries, other databases' worth of concerns, no signing key.
// None of them can call it. The sever census fixed nine of them to revoke
// tokens; none of them can tell a federated partner that the account is gone,
// which is what the RISC account-disabled event exists for. The product
// advertised that event for months and never sent it once.
//
// WHY NOT THE OUTBOX, WHICH LOOKS LIKE EXACTLY THIS. Two reasons, both
// measured. The outbox has ONE consumer by construction: the relay claims a row
// with FOR UPDATE SKIP LOCKED and deletes it when the sink accepts, so a second
// consumer draining the same table would see only what the first had not
// reached yet -- the rows would be split between them, not shared. And the
// outbox's sink is NATS, whose chart default is off; a security signal placed
// behind a broker the default install does not run is a signal the default
// install never sends. The decision recorded in the plan is that the event
// path is an accelerator, never the only route for a security-critical
// outcome. So this is its own table, in the same PostgreSQL every severing path
// already writes to, drained by the one process that holds the key.
//
// THE SHAPE IS THE OUTBOX'S SHAPE, on purpose: a row per event, org-scoped,
// claimed with SKIP LOCKED, published_at as the done marker, attempts as the
// poison guard, a partial index on the backlog. The differences are the ones
// the different consumer needs -- claimed_at, so a drainer that dies mid-batch
// hands its rows back after a grace, and streams_enqueued, so an operator can
// see that an event was drained into zero streams (no receiver subscribed)
// rather than lost.
//
// THE BELT is the same forced org-scoped RLS as v192 and v195: the producer
// writes under its request's tenant, the drainer reads every tenant under
// orgctx.WithBypassRLS the way the SSF push worker already does, and nothing in
// between can read another tenant's pending signals.
//
// Down drops the table. A pending signal is a work item, not a record: an
// install rolling back to v195 is one where account-disabled was never sent,
// which is where it already was.

var ssfPendingEventsUp = `-- Migration 196: pending security signals from the severing paths.
CREATE TABLE IF NOT EXISTS ssf_pending_events (
    id               BIGSERIAL PRIMARY KEY,
    org_id           UUID NOT NULL,
    event_type       TEXT NOT NULL CHECK (event_type <> ''),
    subject_id       TEXT NOT NULL CHECK (subject_id <> ''),
    subject_email    TEXT NOT NULL DEFAULT '',
    claims           JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claimed_at       TIMESTAMPTZ,
    published_at     TIMESTAMPTZ,
    attempts         INT NOT NULL DEFAULT 0,
    streams_enqueued INT
);

-- The backlog is what the drainer reads on every tick; the rest is history.
CREATE INDEX IF NOT EXISTS idx_ssf_pending_events_backlog
    ON ssf_pending_events (id)
    WHERE published_at IS NULL;

DROP POLICY IF EXISTS pol_ssf_pending_events_org_scope ON ssf_pending_events;
CREATE POLICY pol_ssf_pending_events_org_scope ON ssf_pending_events
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE ssf_pending_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE ssf_pending_events FORCE  ROW LEVEL SECURITY;
`

var ssfPendingEventsDown = `-- Migration 196 down: drop the pending-signal table.
DROP TABLE IF EXISTS ssf_pending_events;
`
