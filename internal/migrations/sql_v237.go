package migrations

// Migration 237: the tunnel policy a device applied.
//
// org_network_policy (migration 232) is now delivered to every agent in
// /agent/config and in the answer to its posture report, with a version: a
// digest of the switches and of the corporate ranges the block covers
// (internal/access/tunnel_policy.go). The agent echoes the version it applied
// in its tunnel_status. enrolled_agents keeps it in a column of its own,
// tunnel_policy_version, so the console can count the devices that run the
// current policy and the ones still pending it without reading every JSON
// document, and tunnel_policy_applied_at, the server's clock when the version
// a device reports last changed.
//
// No new table: the columns are under enrolled_agents' existing org policy.
// Down drops them.
var tunnelPolicyAppliedUp = `-- Migration 237: the tunnel policy a device applied.
ALTER TABLE enrolled_agents ADD COLUMN IF NOT EXISTS tunnel_policy_version VARCHAR(64);
ALTER TABLE enrolled_agents ADD COLUMN IF NOT EXISTS tunnel_policy_applied_at TIMESTAMPTZ;
`

var tunnelPolicyAppliedDown = `-- Rollback migration 237.
ALTER TABLE enrolled_agents DROP COLUMN IF EXISTS tunnel_policy_applied_at;
ALTER TABLE enrolled_agents DROP COLUMN IF EXISTS tunnel_policy_version;
`
