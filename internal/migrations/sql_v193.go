package migrations

// Migration v193 -- the stale Guacamole grant sweep gets somewhere to record
// that it has done its work.
//
// THE SWEEP HAD NO STOPPING CONDITION. sweepStaleGuacGrants selects PAM
// sessions that have ended (or have been active for more than twelve hours),
// revokes the per-connection READ each one left behind on a standing Guacamole
// account, and writes nothing. The rows it just handled still match its
// predicate on the next tick, and on every tick after that -- so a session that
// ended in March is still being revoked in June, every five minutes, forever.
// Re-revoking an absent grant is a tolerated 404, which is why this was never
// loud: the sweep looked like it was working because it never failed.
//
// It has two costs and they compound. The first is the obvious one: N replicas
// times 200 rows times twelve ticks an hour of broker API calls that do nothing.
// The second is the one that matters, and it is a SECURITY cost rather than a
// waste. The query carries LIMIT 200 with no ordering and no progress marker, so
// once more than two hundred rows match, which grows as the install ages and
// never shrinks, the sweep revisits an arbitrary two hundred of them and the
// rest may never be reached at all. The grants that most need revoking -- the
// ones from sessions whose browser was closed and which nothing else will clean
// up -- are exactly the ones that can sit behind that limit indefinitely.
//
// guac_revoked_at is the marker: set when the broker confirms the revoke, and
// the sweep's predicate excludes rows that carry one. The backlog then drains,
// the LIMIT becomes a batch size rather than a ceiling, and a replica repeating
// the work of another is merely redundant instead of permanent.
//
// The index is PARTIAL on the same predicate for the same reason the outbox's
// is: the swept rows are the overwhelming majority within a week and the sweep
// never wants them again, so an index the size of the BACKLOG answers the hot
// query at constant cost while the table grows.
//
// Existing rows get NULL, which reads as "not yet revoked" -- the safe
// direction. The first sweeps after this migration will re-revoke the historical
// backlog once each (tolerated 404s, as before) and then stop, which is the
// behaviour that was missing.
var guacRevokedMarkerUp = `-- Migration 193: a progress marker for the stale Guacamole grant sweep.
ALTER TABLE pam_entry_sessions ADD COLUMN IF NOT EXISTS guac_revoked_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_pam_entry_sessions_guac_unrevoked
    ON pam_entry_sessions (started_at)
    WHERE guac_username IS NOT NULL
      AND guac_connection_id IS NOT NULL
      AND guac_revoked_at IS NULL;
`

// Down drops both. The sweep reverts to its previous behaviour -- correct, and
// never finished -- rather than breaking.
var guacRevokedMarkerDown = `-- Migration 193 down.
DROP INDEX IF EXISTS idx_pam_entry_sessions_guac_unrevoked;
ALTER TABLE pam_entry_sessions DROP COLUMN IF EXISTS guac_revoked_at;
`
