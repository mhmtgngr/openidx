package migrations

// Migration 255: posture checks targeted by device tag (Faz B8.7).
//
// posture_checks gains tags, a JSONB array with the same NULL semantics as
// platforms: NULL (or empty) means the check reaches every device; otherwise
// only devices carrying at least one of the tags (enrolled_agents.tags,
// v250) are given it. Column under the table's existing org policy; down
// drops it.

var postureCheckTagsUp = `-- Migration 255: posture check tags.
ALTER TABLE posture_checks ADD COLUMN IF NOT EXISTS tags JSONB;
`

var postureCheckTagsDown = `-- Rollback migration 255.
ALTER TABLE posture_checks DROP COLUMN IF EXISTS tags;
`
