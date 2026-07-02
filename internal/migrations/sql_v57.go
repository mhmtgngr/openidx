package migrations

// Migration v57 — PAM rotation engine (M1b). Adds credential_rotation_policies
// (one-per-secret schedule + connector config) and reconciles the dead
// credential_rotations table into a run ledger (adds org_id, policy_id,
// secret_id, version_from/to, connector_type, trigger, error_message,
// started_at, completed_at; drops NOT NULL on service_account_id). Both tables
// go under the v37 FORCE-RLS belt. Idempotent. Mirrored into
// deployments/docker/init-db.sql so TestInitDBParity stays green.
var credentialRotationUp = `-- Migration 057: PAM rotation engine — policies table + credential_rotations ledger reconcile.

-- Rotation policy: binds a vault secret to a target connector + schedule.
CREATE TABLE IF NOT EXISTS credential_rotation_policies (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id            UUID NOT NULL,
    secret_id         UUID NOT NULL REFERENCES vault_secrets(id) ON DELETE CASCADE,
    connector_type    VARCHAR(32) NOT NULL,
    connector_config  JSONB NOT NULL DEFAULT '{}',
    generation_policy JSONB NOT NULL DEFAULT '{}',
    interval_seconds  INTEGER NOT NULL DEFAULT 0,
    rotate_on_checkout BOOLEAN NOT NULL DEFAULT false,
    enabled           BOOLEAN NOT NULL DEFAULT true,
    next_run_at       TIMESTAMPTZ,
    last_run_at       TIMESTAMPTZ,
    last_status       VARCHAR(16),
    created_by        UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (secret_id)
);
CREATE INDEX IF NOT EXISTS idx_rotation_policies_due
    ON credential_rotation_policies(enabled, next_run_at) WHERE enabled;

-- Reconcile the dead credential_rotations into a run ledger (one row per attempt).
-- DROP NOT NULL is idempotent — repeated runs are safe.
ALTER TABLE credential_rotations ALTER COLUMN service_account_id DROP NOT NULL;
ALTER TABLE credential_rotations ADD COLUMN IF NOT EXISTS org_id         UUID;
ALTER TABLE credential_rotations ADD COLUMN IF NOT EXISTS policy_id      UUID REFERENCES credential_rotation_policies(id) ON DELETE SET NULL;
ALTER TABLE credential_rotations ADD COLUMN IF NOT EXISTS secret_id      UUID REFERENCES vault_secrets(id) ON DELETE CASCADE;
ALTER TABLE credential_rotations ADD COLUMN IF NOT EXISTS version_from   INTEGER;
ALTER TABLE credential_rotations ADD COLUMN IF NOT EXISTS version_to     INTEGER;
ALTER TABLE credential_rotations ADD COLUMN IF NOT EXISTS connector_type VARCHAR(32);
ALTER TABLE credential_rotations ADD COLUMN IF NOT EXISTS trigger        VARCHAR(16);
ALTER TABLE credential_rotations ADD COLUMN IF NOT EXISTS error_message  TEXT;
ALTER TABLE credential_rotations ADD COLUMN IF NOT EXISTS started_at     TIMESTAMPTZ;
ALTER TABLE credential_rotations ADD COLUMN IF NOT EXISTS completed_at   TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_credential_rotations_secret ON credential_rotations(secret_id, started_at DESC);

-- v37-style RLS belt for credential_rotation_policies.
DROP POLICY IF EXISTS pol_credential_rotation_policies_org_scope ON credential_rotation_policies;
CREATE POLICY pol_credential_rotation_policies_org_scope ON credential_rotation_policies
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE credential_rotation_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE credential_rotation_policies FORCE  ROW LEVEL SECURITY;

-- v37-style RLS belt for credential_rotations (now that it carries org_id).
DROP POLICY IF EXISTS pol_credential_rotations_org_scope ON credential_rotations;
CREATE POLICY pol_credential_rotations_org_scope ON credential_rotations
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE credential_rotations ENABLE ROW LEVEL SECURITY;
ALTER TABLE credential_rotations FORCE  ROW LEVEL SECURITY;

-- Grant DML to the runtime app role when present (matches v53/v56).
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openidx_app') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON
      credential_rotation_policies, credential_rotations
      TO openidx_app;
  END IF;
END $$;
`

var credentialRotationDown = `-- Migration 057 down.
-- NOTE: credential_rotations columns added in up are intentionally left in place
-- (best-effort down — removing them could lose rotation history on downgrade).
DROP TABLE IF EXISTS credential_rotation_policies CASCADE;
`
