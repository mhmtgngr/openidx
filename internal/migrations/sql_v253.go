package migrations

// Migration 253: agent version telemetry and update rings (Faz B8.5).
//
// enrolled_agents gains agent_version (what the device last reported it
// runs) and update_state (the outcome of its last update attempt, as the
// agent reported it: {"state": "ok|failed|applying", "version", "error",
// "at"}).
//
// org_agent_settings gains the organization's update ring:
//
//	update_channel          stable (default) or beta: which release feed.
//	update_pin_version      when set, the fleet's target; a device on a newer
//	                        build is told it may downgrade to it.
//	update_rollout_percent  0..100 (default 100): the share of the fleet a
//	                        new target reaches, chosen by fnv(agent_id) % 100
//	                        so a device stays in or out across checks.
//	update_paused           true holds every device on what it runs.
//
// Columns under the tables' existing org policies; down drops them.

var agentUpdateRingsUp = `-- Migration 253: agent update rings.
ALTER TABLE enrolled_agents ADD COLUMN IF NOT EXISTS agent_version VARCHAR(64);
ALTER TABLE enrolled_agents ADD COLUMN IF NOT EXISTS update_state  JSONB;
ALTER TABLE org_agent_settings ADD COLUMN IF NOT EXISTS update_channel VARCHAR(16) NOT NULL DEFAULT 'stable'
  CHECK (update_channel IN ('stable', 'beta'));
ALTER TABLE org_agent_settings ADD COLUMN IF NOT EXISTS update_pin_version VARCHAR(64);
ALTER TABLE org_agent_settings ADD COLUMN IF NOT EXISTS update_rollout_percent INTEGER NOT NULL DEFAULT 100
  CHECK (update_rollout_percent BETWEEN 0 AND 100);
ALTER TABLE org_agent_settings ADD COLUMN IF NOT EXISTS update_paused BOOLEAN NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS idx_enrolled_agents_agent_version ON enrolled_agents (org_id, agent_version);
`

var agentUpdateRingsDown = `-- Rollback migration 253.
DROP INDEX IF EXISTS idx_enrolled_agents_agent_version;
ALTER TABLE org_agent_settings DROP COLUMN IF EXISTS update_paused;
ALTER TABLE org_agent_settings DROP COLUMN IF EXISTS update_rollout_percent;
ALTER TABLE org_agent_settings DROP COLUMN IF EXISTS update_pin_version;
ALTER TABLE org_agent_settings DROP COLUMN IF EXISTS update_channel;
ALTER TABLE enrolled_agents DROP COLUMN IF EXISTS update_state;
ALTER TABLE enrolled_agents DROP COLUMN IF EXISTS agent_version;
`
