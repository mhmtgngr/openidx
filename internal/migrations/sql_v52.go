package migrations

// Migration v52 — reconcile the continuous-verification columns that exist only
// in init-db.sql onto migrate-based installs. The continuous session verifier
// (internal/access/continuous_verify.go) selects proxy_sessions.device_trusted
// and filters on proxy_sessions.last_verified_at; on installs provisioned by the
// migration runner (not init-db.sql) those columns are absent and the verifier's
// query errors every run. This mirrors init-db.sql (lines ~1614-1619, 2153-2160).
// Same init-db<->migrations gap reconciled for other tables in v42-v45. Idempotent.
var continuousVerifyColumnsUp = `-- Migration 052: reconcile continuous-verify columns.
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS last_verified_at TIMESTAMPTZ;
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS verification_failures INTEGER DEFAULT 0;
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS geo_country VARCHAR(10);
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS geo_city VARCHAR(255);
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS idp_id UUID;
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS device_trusted BOOLEAN DEFAULT false;
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS device_trusted BOOLEAN DEFAULT false;
CREATE INDEX IF NOT EXISTS idx_user_sessions_device_trusted ON user_sessions(device_trusted);
`

// Down is intentionally a no-op. The Up uses ADD COLUMN IF NOT EXISTS, so on an
// init-db-provisioned install these columns already existed before this migration
// ran — it cannot know whether it created them or they pre-existed. Dropping them
// on rollback would re-break continuous-verify on exactly those installs (and
// idp_id is depended on across the access service). A gap-reconcile migration is
// not faithfully reversible by column-drop; the columns are harmless to leave.
var continuousVerifyColumnsDown = `-- Migration 052 down: intentionally a no-op (see sql_v52.go).
SELECT 1;
`
