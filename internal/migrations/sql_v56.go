package migrations

// Migration v56 — PAM credential vault store (M1). Four org-scoped tables under
// the v37 FORCE-RLS belt: vault_secrets (metadata, no value), vault_secret_versions
// (the only ciphertext home), vault_access_grants (use/reveal), vault_checkouts
// (lease + audit ledger). Idempotent. Rotation (credential_rotation_policies) is
// intentionally NOT here — that is M1b. The same DDL is mirrored into
// deployments/docker/init-db.sql so TestInitDBParity stays green.
var vaultStoreUp = `-- Migration 056: PAM credential vault store.
CREATE TABLE IF NOT EXISTS vault_secrets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL,
    name            VARCHAR(255) NOT NULL,
    type            VARCHAR(32)  NOT NULL DEFAULT 'generic',
    description     TEXT,
    owner_id        UUID REFERENCES users(id) ON DELETE SET NULL,
    metadata        JSONB NOT NULL DEFAULT '{}',
    current_version INTEGER NOT NULL DEFAULT 0,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name)
);

CREATE TABLE IF NOT EXISTS vault_secret_versions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL,
    secret_id   UUID NOT NULL REFERENCES vault_secrets(id) ON DELETE CASCADE,
    version     INTEGER NOT NULL,
    key_id      SMALLINT NOT NULL,
    ciphertext  BYTEA NOT NULL,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (secret_id, version)
);

CREATE TABLE IF NOT EXISTS vault_access_grants (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         UUID NOT NULL,
    secret_id      UUID NOT NULL REFERENCES vault_secrets(id) ON DELETE CASCADE,
    principal_type VARCHAR(32) NOT NULL,
    principal_id   UUID NOT NULL,
    actions        TEXT[] NOT NULL DEFAULT '{}',
    granted_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at     TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (secret_id, principal_type, principal_id)
);

CREATE TABLE IF NOT EXISTS vault_checkouts (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         UUID NOT NULL,
    secret_id      UUID NOT NULL REFERENCES vault_secrets(id) ON DELETE CASCADE,
    secret_version INTEGER NOT NULL,
    principal_id   UUID,
    mode           VARCHAR(16) NOT NULL,
    reason         TEXT,
    leased_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at     TIMESTAMPTZ,
    returned_at    TIMESTAMPTZ,
    status         VARCHAR(16) NOT NULL DEFAULT 'active'
);

CREATE INDEX IF NOT EXISTS idx_vault_versions_secret  ON vault_secret_versions(secret_id, version DESC);
CREATE INDEX IF NOT EXISTS idx_vault_grants_secret    ON vault_access_grants(secret_id);
CREATE INDEX IF NOT EXISTS idx_vault_checkouts_secret ON vault_checkouts(secret_id, leased_at DESC);
CREATE INDEX IF NOT EXISTS idx_vault_checkouts_active ON vault_checkouts(status, expires_at) WHERE status = 'active';

-- v37-style RLS belt: fail-closed org predicate + FORCE (app connects as owner).
DROP POLICY IF EXISTS pol_vault_secrets_org_scope ON vault_secrets;
CREATE POLICY pol_vault_secrets_org_scope ON vault_secrets
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE vault_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault_secrets FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_vault_secret_versions_org_scope ON vault_secret_versions;
CREATE POLICY pol_vault_secret_versions_org_scope ON vault_secret_versions
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE vault_secret_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault_secret_versions FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_vault_access_grants_org_scope ON vault_access_grants;
CREATE POLICY pol_vault_access_grants_org_scope ON vault_access_grants
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE vault_access_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault_access_grants FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_vault_checkouts_org_scope ON vault_checkouts;
CREATE POLICY pol_vault_checkouts_org_scope ON vault_checkouts
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE vault_checkouts ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault_checkouts FORCE  ROW LEVEL SECURITY;

-- Grant DML to the runtime app role when present (matches v53).
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openidx_app') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON
      vault_secrets, vault_secret_versions, vault_access_grants, vault_checkouts
      TO openidx_app;
  END IF;
END $$;
`

var vaultStoreDown = `-- Migration 056 down.
DROP TABLE IF EXISTS vault_checkouts CASCADE;
DROP TABLE IF EXISTS vault_access_grants CASCADE;
DROP TABLE IF EXISTS vault_secret_versions CASCADE;
DROP TABLE IF EXISTS vault_secrets CASCADE;
`
