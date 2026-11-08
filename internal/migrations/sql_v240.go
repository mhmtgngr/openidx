package migrations

// Migration 240: when the broker last served a PAM entry session.
//
// pam_entry_sessions rows were marked ended only by an explicit end (the
// session's End button, the kill switch, a lapsed grant, a disabled user, the
// risk scorer, a moderation ending, the browser terminal closing). A user who
// simply closed the tab left the row 'active' for ever: the reference install
// had 107 rows, every one 'active', the oldest four months old. The ledger
// therefore over-counts live sessions, and anything that waits for a session
// to end (sealing its recording, purging it on retention) never runs.
//
// broker_last_seen_at is stamped by the lifecycle sweep each time the broker
// lists the session among its active connections. A session the broker has not
// served for the grace period is ended with reason 'disconnected'. NULL means
// the broker has never been seen serving it; the sweep then measures the grace
// from started_at, so a launch whose browser never opened ends too.
//
// Nullable column under the table's existing org policy; down drops it.

var pamEntrySessionBrokerSeenUp = `-- Migration 240: pam_entry_sessions.broker_last_seen_at.
ALTER TABLE pam_entry_sessions ADD COLUMN IF NOT EXISTS broker_last_seen_at TIMESTAMPTZ;
`

var pamEntrySessionBrokerSeenDown = `-- Rollback migration 240.
ALTER TABLE pam_entry_sessions DROP COLUMN IF EXISTS broker_last_seen_at;
`
