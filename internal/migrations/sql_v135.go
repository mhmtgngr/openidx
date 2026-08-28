package migrations

// Migration v135 — link mfa_push_devices back to the enrolled agent that
// auto-registered it (FastPass convergence).
//
// When a device redeems an enrollment code, the access-service now mints a
// push-enrollment ticket carrying the enrolled agent's identity + its server-
// verified auto-trust decision, so the phone self-registers as a push approver
// in one step. These nullable columns record that provenance:
//   - agent_id  / device_id            — the enrolled agent this approver IS
//   - enrollment_session_id            — audit lineage to the redeemed session
//
// All nullable so the existing QR self-enroll path (no agent linkage) is
// unaffected. agent_id is indexed because it is the de-dup key across FCM-token
// rotation and the join used by login-time device preference (Phase 2).
var pushDeviceAgentLinkUp = `-- Migration 135: link push devices to enrolled agents.
ALTER TABLE mfa_push_devices ADD COLUMN IF NOT EXISTS agent_id TEXT;
ALTER TABLE mfa_push_devices ADD COLUMN IF NOT EXISTS device_id TEXT;
ALTER TABLE mfa_push_devices ADD COLUMN IF NOT EXISTS enrollment_session_id UUID;
CREATE INDEX IF NOT EXISTS idx_mfa_push_devices_agent_id ON mfa_push_devices(agent_id);
`

var pushDeviceAgentLinkDown = `-- Rollback migration 135.
DROP INDEX IF EXISTS idx_mfa_push_devices_agent_id;
ALTER TABLE mfa_push_devices DROP COLUMN IF EXISTS enrollment_session_id;
ALTER TABLE mfa_push_devices DROP COLUMN IF EXISTS device_id;
ALTER TABLE mfa_push_devices DROP COLUMN IF EXISTS agent_id;
`
