package migrations

// Migration v227 -- an enrolled agent can hold a device key, and once it does,
// its posture reports must be signed with it.
//
// An agent proved itself with one bearer token, readable by every signed-in
// user of a Windows machine (the tray reads agent.json). Whoever copied it
// could report posture as the device from anywhere. The desktop agent now
// keeps an ECDSA P-256 key the operating system will not export (in the TPM
// where there is one) and signs its reports with it.
//
// enrolled_agents gains the key's public half (base64 PKIX DER), its kind as
// the agent describes it ('tpm', 'software' or 'file') and when the server
// bound it. The access service stores the key at enrolment, or from the
// agent's own signed registration when the device enrolled before it had one,
// and from then on refuses a report without a valid signature. A row with no
// key is treated as before.
//
// Down drops the columns; reports go back to being accepted on the token alone.

var agentDeviceKeysUp = `-- Migration 227: agent device keys.
ALTER TABLE enrolled_agents ADD COLUMN IF NOT EXISTS device_public_key TEXT;
ALTER TABLE enrolled_agents ADD COLUMN IF NOT EXISTS device_key_kind VARCHAR(16);
ALTER TABLE enrolled_agents ADD COLUMN IF NOT EXISTS device_key_bound_at TIMESTAMPTZ;
ALTER TABLE enrolled_agents DROP CONSTRAINT IF EXISTS enrolled_agents_device_key_kind_check;
ALTER TABLE enrolled_agents ADD CONSTRAINT enrolled_agents_device_key_kind_check
    CHECK (device_key_kind IS NULL OR device_key_kind IN ('tpm', 'software', 'file'));
`

var agentDeviceKeysDown = `-- Migration 227 down: agents no longer hold device keys.
ALTER TABLE enrolled_agents DROP CONSTRAINT IF EXISTS enrolled_agents_device_key_kind_check;
ALTER TABLE enrolled_agents DROP COLUMN IF EXISTS device_key_bound_at;
ALTER TABLE enrolled_agents DROP COLUMN IF EXISTS device_key_kind;
ALTER TABLE enrolled_agents DROP COLUMN IF EXISTS device_public_key;
`
