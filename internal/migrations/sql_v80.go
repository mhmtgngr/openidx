package migrations

// Migration v80 — link the two per-user device registries.
//
// OpenIDX has carried two disjoint device registries: known_devices (the IAM
// device-trust registry — browser/endpoint fingerprints with a trusted flag,
// written by the portal and the login risk engine) and enrolled_agents (the
// Ziti endpoint-agent registry — each agent gets a Ziti "Device" identity plus
// posture/compliance reporting). Nothing linked a user's known_devices row to
// the enrolled_agent running on that same machine, so device trust (IAM) and
// device compliance (Ziti) could never be reconciled for one physical device.
//
// This adds a nullable enrolled_agents.known_device_id FK to known_devices.
// It is populated going forward by the user-bound (OAuth) agent-enrollment
// path, which now upserts a known_devices row for the enrolling device and
// links it — so the two registries converge for agent-enrolled devices while
// legacy rows and token-enrolled (unattributed) agents keep known_device_id
// NULL. ON DELETE SET NULL keeps an agent row alive if its known_devices row
// is pruned. enrolled_agents has no org_id column (it is scoped through
// enrolled_by_user_id); the FK target carries the org via known_devices.
//
// Idempotent. Plain statements only — the runner's splitSQL cannot handle
// DO $$ blocks.
var enrolledAgentDeviceLinkUp = `-- Migration 080: link enrolled_agents to known_devices (converge the two device registries).
ALTER TABLE enrolled_agents
    ADD COLUMN IF NOT EXISTS known_device_id UUID REFERENCES known_devices(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_enrolled_agents_known_device ON enrolled_agents(known_device_id);`

var enrolledAgentDeviceLinkDown = `-- Rollback 080
DROP INDEX IF EXISTS idx_enrolled_agents_known_device;
ALTER TABLE enrolled_agents DROP COLUMN IF EXISTS known_device_id;`
