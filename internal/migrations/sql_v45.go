package migrations

// Migration v45 — ziti_browzer_config (init-db↔migrations gap, like v42–v44).
//
// BootstrapBrowZer persists the external-JWT-signer / auth-policy / dial-policy
// IDs + OIDC settings here, and GET /ziti/browzer/status reads it. The table
// lived only in deployments/docker/init-db.sql, so on managed-RDS/Helm/migrate
// installs BrowZer bootstrap logged "relation ziti_browzer_config does not
// exist" and the status always reported not-configured. Idempotent.
var zitiBrowzerConfigUp = `-- Migration 045: ziti_browzer_config.
CREATE TABLE IF NOT EXISTS ziti_browzer_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    external_jwt_signer_id VARCHAR(255),
    auth_policy_id VARCHAR(255),
    dial_policy_id VARCHAR(255),
    oidc_issuer VARCHAR(500),
    oidc_client_id VARCHAR(255),
    enabled BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
`

var zitiBrowzerConfigDown = `-- Migration 045 down.
DROP TABLE IF EXISTS ziti_browzer_config;
`
