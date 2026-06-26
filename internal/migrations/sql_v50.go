package migrations

// Migration v50 — device_posture_results upsert key.
//
// The device posture bridge (HandleReport → device_posture_results) keeps one
// latest result per (identity, check). A unique index on (identity_id, check_id)
// makes that an idempotent ON CONFLICT upsert instead of accumulating a row per
// report. The table is empty today, so the index is safe to add. Idempotent.
var devicePostureUpsertKeyUp = `-- Migration 050: device_posture_results upsert key.
CREATE UNIQUE INDEX IF NOT EXISTS device_posture_results_identity_check
  ON device_posture_results (identity_id, check_id);
`

var devicePostureUpsertKeyDown = `-- Migration 050 down.
DROP INDEX IF EXISTS device_posture_results_identity_check;
`
