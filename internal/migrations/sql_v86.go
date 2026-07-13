package migrations

// Migration v86 — reusable agent enrollment tokens.
//
// The default enrollment token is single-use + 24h (validate rejects a used or
// expired token). For hands-off MDM/GPO/Intune fleet rollout, add a `reusable`
// flag: a reusable token can enroll many devices and isn't consumed (used_at is
// not enforced for it). Enrollment validation skips the single-use check when
// reusable=true. Additive/idempotent.
var reusableTokensUp = `-- Migration 086: reusable agent enrollment tokens (fleet/MDM bootstrap).
ALTER TABLE agent_enrollment_tokens ADD COLUMN IF NOT EXISTS reusable BOOLEAN NOT NULL DEFAULT false;`

var reusableTokensDown = `-- Rollback 086.
ALTER TABLE agent_enrollment_tokens DROP COLUMN IF EXISTS reusable;`
