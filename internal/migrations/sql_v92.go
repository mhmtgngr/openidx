package migrations

// Migration v92 — stable per-device enrollment identity.
//
// Before this, every call to /agent/enroll minted a brand-new
// agent-<rand>/device-<rand> pair, so a single physical machine that was
// re-installed or re-enrolled (which happened on every MSI upgrade) accumulated
// many enrolled_agents rows. Operators then could not tell which agent_id to
// target for remote support, and the device picker was cluttered with stale
// duplicates.
//
// This adds a nullable device_fingerprint column (a stable client-supplied
// identifier: Windows MachineGuid, else a hostname-derived fallback) plus a
// partial UNIQUE index over the non-null values. Enrollment can then upsert by
// fingerprint and hand back the SAME agent_id/auth_token for a device it has
// seen before. Existing rows keep fingerprint NULL and are unaffected (the
// partial index ignores NULLs), so this is additive + idempotent with no
// behavior change until the enrollment handler starts sending a fingerprint.
var deviceFingerprintUp = `-- Migration 092: stable per-device enrollment identity.
ALTER TABLE enrolled_agents ADD COLUMN IF NOT EXISTS device_fingerprint TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS enrolled_agents_device_fingerprint_key
    ON enrolled_agents (device_fingerprint)
    WHERE device_fingerprint IS NOT NULL;
`

var deviceFingerprintDown = `-- Rollback 092.
DROP INDEX IF EXISTS enrolled_agents_device_fingerprint_key;
ALTER TABLE enrolled_agents DROP COLUMN IF EXISTS device_fingerprint;
`
