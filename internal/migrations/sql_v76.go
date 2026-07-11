package migrations

// Migration v76 — known_devices.seen_count + org backfill for mis-tenanted rows.
//
// The risk engine's device fingerprinting (internal/risk/device.go) reads and
// writes a `seen_count` column that v19 never created — and also referenced
// `first_seen`/`last_seen` columns that never existed (the real columns are
// created_at/last_seen_at). The INSERT for every NEW device therefore failed
// ("column seen_count does not exist"), so risk-based device tracking never
// recorded a device and trust levels never progressed. The code now uses
// created_at/last_seen_at; seen_count is the one column with no existing
// equivalent, added here (DEFAULT 1: every existing row has been seen at
// least once).
//
// Also folds in the backfill promised in the portal device fix: rows that the
// portal registered before it stamped org_id landed under the column DEFAULT
// (the primary org) even when the owning user belongs to another org. Retenant
// them from their owner. Rows whose user genuinely belongs to the primary org
// are untouched. Not reversed on down — it corrects data that was wrong.
// Plain statements only — the runner's splitSQL cannot handle DO $$ blocks.
var knownDevicesSeenCountUp = `-- Migration 076: known_devices.seen_count (risk device tracking was broken) + org retenant.
ALTER TABLE known_devices ADD COLUMN IF NOT EXISTS seen_count INTEGER NOT NULL DEFAULT 1;

-- Retenant portal-registered devices that fell into the primary org by DEFAULT
-- while their owner belongs to another org.
UPDATE known_devices kd SET org_id = u.org_id FROM users u WHERE kd.user_id = u.id AND kd.org_id = '00000000-0000-0000-0000-000000000010' AND u.org_id <> '00000000-0000-0000-0000-000000000010';`

var knownDevicesSeenCountDown = `-- Rollback 076 (the org retenant is a data correction and is not reversed)
ALTER TABLE known_devices DROP COLUMN IF EXISTS seen_count;`
