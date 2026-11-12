package migrations

// Migration 248: signing keys for the Entra external authentication method.
//
// When OpenIDX acts as an external authentication method (EAM) for Microsoft
// Entra ID, Entra fetches <issuer>/eam/jwks and verifies the id_token OpenIDX
// posts back after the second factor. Entra expects an x5c certificate on
// each key and caches the set, so a new key is published for days before it
// signs anything. These keys are separate from the platform's token signing
// keys (signing_keys): their audience is one Entra application, their
// rotation follows Entra's cache, and a compromise of one is not a compromise
// of the other.
//
// Platform level, not per organization: one Entra application registration
// points at one discovery document. No org_id, no RLS; only the oauth
// service reads or writes it, as openidx_app. private_key_enc is the PEM
// sealed with the install's secret cipher (the IdP secret cipher).
var eamSigningKeysUp = `-- Migration 248: EAM signing keys.
CREATE TABLE IF NOT EXISTS eam_signing_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kid             VARCHAR(64) NOT NULL UNIQUE,
    private_key_enc TEXT NOT NULL,
    cert_pem        TEXT NOT NULL,
    not_before      TIMESTAMPTZ NOT NULL,
    not_after       TIMESTAMPTZ NOT NULL,
    active          BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_eam_signing_keys_not_before ON eam_signing_keys (not_before);
GRANT SELECT, INSERT, UPDATE, DELETE ON eam_signing_keys TO openidx_app;
`

var eamSigningKeysDown = `-- Rollback migration 248.
DROP TABLE IF EXISTS eam_signing_keys;
`
