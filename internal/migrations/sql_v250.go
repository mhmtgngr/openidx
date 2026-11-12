package migrations

// Migration 250: fleet tokens and device tags.
//
// A fleet (reusable) enrollment token becomes a console object: it has a
// name, an optional cap on how many devices it may enrol (max_uses, NULL =
// no cap), a counter the redeemer increments atomically (uses), the tags it
// stamps on every device it enrols (default_tags) and when it was last used.
// New tokens may live at most a year (366 days, so a leap year fits); the
// CHECK is NOT VALID so the ten-year fleet tokens minted before this change
// keep working until they are revoked or rotated.
//
// enrolled_agents gains tags (GIN-indexed for the tag filter) and the token
// that enrolled it, so an administrator can see which rollout a device came
// from. Columns under the tables' existing org policies; down drops them.

var fleetTokensAndTagsUp = `-- Migration 250: fleet tokens and tags.
ALTER TABLE agent_enrollment_tokens ADD COLUMN IF NOT EXISTS name         VARCHAR(255);
ALTER TABLE agent_enrollment_tokens ADD COLUMN IF NOT EXISTS max_uses     INTEGER CHECK (max_uses IS NULL OR max_uses > 0);
ALTER TABLE agent_enrollment_tokens ADD COLUMN IF NOT EXISTS uses         INTEGER NOT NULL DEFAULT 0;
ALTER TABLE agent_enrollment_tokens ADD COLUMN IF NOT EXISTS default_tags TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE agent_enrollment_tokens ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;
ALTER TABLE agent_enrollment_tokens DROP CONSTRAINT IF EXISTS chk_enrollment_token_ttl_max_one_year;
ALTER TABLE agent_enrollment_tokens ADD CONSTRAINT chk_enrollment_token_ttl_max_one_year
  CHECK (expires_at <= created_at + INTERVAL '366 days') NOT VALID;
ALTER TABLE enrolled_agents ADD COLUMN IF NOT EXISTS tags TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE enrolled_agents ADD COLUMN IF NOT EXISTS enrolled_with_token_id UUID;
CREATE INDEX IF NOT EXISTS idx_enrolled_agents_tags ON enrolled_agents USING GIN (tags);
`

var fleetTokensAndTagsDown = `-- Rollback migration 250.
DROP INDEX IF EXISTS idx_enrolled_agents_tags;
ALTER TABLE enrolled_agents DROP COLUMN IF EXISTS enrolled_with_token_id;
ALTER TABLE enrolled_agents DROP COLUMN IF EXISTS tags;
ALTER TABLE agent_enrollment_tokens DROP CONSTRAINT IF EXISTS chk_enrollment_token_ttl_max_one_year;
ALTER TABLE agent_enrollment_tokens DROP COLUMN IF EXISTS last_used_at;
ALTER TABLE agent_enrollment_tokens DROP COLUMN IF EXISTS default_tags;
ALTER TABLE agent_enrollment_tokens DROP COLUMN IF EXISTS uses;
ALTER TABLE agent_enrollment_tokens DROP COLUMN IF EXISTS max_uses;
ALTER TABLE agent_enrollment_tokens DROP COLUMN IF EXISTS name;
`
