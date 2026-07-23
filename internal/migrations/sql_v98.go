package migrations

// Migration v98 — EDR/MDM device-posture ingestion.
//
// OpenIDX already runs a Ziti-bound posture pipeline: agent-reported checks land
// in device_posture_results (keyed by ziti_identities.id), EvaluateIdentityPosture
// reads them, and the proxy/continuous-verify path revokes the session AND severs
// the Ziti circuit when a check fails. What was missing is a way to feed that
// same pipeline from an external EDR/MDM (CrowdStrike Falcon, Microsoft Intune,
// Jamf): when the endpoint tool marks a device non-compliant / high-risk,
// OpenIDX should write a failing posture result so the existing enforcement cuts
// the device off the overlay automatically.
//
// Two tables (org-scoped for RLS):
//
//	edr_posture_sources  — a configured EDR/MDM connection (provider, API creds
//	                       encrypted at rest, poll interval, and which posture
//	                       check the ingested compliance signal maps to).
//	edr_device_mappings  — the external device id <-> local user / ziti identity
//	                       mapping, resolved by serial/hostname/email, so an
//	                       EDR device report can be attributed to the right
//	                       overlay identity for enforcement.
//
// Additive + idempotent. No behavior change until an EDR source is configured.
var edrPostureUp = `-- Migration 098: EDR/MDM posture ingestion.

CREATE TABLE IF NOT EXISTS edr_posture_sources (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID,
    name            VARCHAR(255) NOT NULL,
    -- Provider dialect: 'crowdstrike' | 'intune' | 'jamf'.
    provider        VARCHAR(32) NOT NULL,
    -- API root override (provider defaults used when empty).
    base_url        TEXT,
    -- OAuth2 client-credentials (CrowdStrike/Intune) — client_id is non-secret,
    -- client_secret_enc is secretcrypt-encrypted. Jamf uses api_user/api_token.
    client_id       TEXT,
    client_secret_enc TEXT,
    tenant_id       TEXT,           -- Intune (Entra) tenant / CrowdStrike cloud region hint
    api_user        TEXT,           -- Jamf basic/api user
    api_token_enc   TEXT,           -- Jamf api token (encrypted)
    -- Which local posture_checks.id an ingested non-compliant signal fails.
    posture_check_id UUID,
    -- How to match an EDR device to a local identity: 'serial' | 'hostname' | 'email'.
    match_strategy  VARCHAR(16) NOT NULL DEFAULT 'serial',
    -- Result TTL in minutes: a passing result expires after this so a device
    -- that stops reporting fails closed (matches the agent posture model).
    result_ttl_minutes INTEGER NOT NULL DEFAULT 60,
    poll_interval_minutes INTEGER NOT NULL DEFAULT 15,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    last_sync_at    TIMESTAMP WITH TIME ZONE,
    last_sync_status VARCHAR(32),
    last_sync_error TEXT,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_edr_sources_org ON edr_posture_sources(org_id);
CREATE INDEX IF NOT EXISTS idx_edr_sources_enabled ON edr_posture_sources(enabled) WHERE enabled;

CREATE TABLE IF NOT EXISTS edr_device_mappings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID,
    source_id       UUID NOT NULL REFERENCES edr_posture_sources(id) ON DELETE CASCADE,
    -- The EDR/MDM-assigned device id (aid / managedDeviceId / jamf id).
    external_device_id VARCHAR(255) NOT NULL,
    -- Matching key value observed on the EDR record (serial/hostname/email).
    match_value     VARCHAR(255),
    -- Resolved local principals (nullable until a match is found).
    user_id         UUID,
    identity_id     UUID,           -- ziti_identities.id, the enforcement key
    last_compliant  BOOLEAN,
    last_risk       VARCHAR(32),    -- provider risk level: low|medium|high|critical
    last_seen_at    TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (source_id, external_device_id)
);
CREATE INDEX IF NOT EXISTS idx_edr_mappings_source ON edr_device_mappings(source_id);
CREATE INDEX IF NOT EXISTS idx_edr_mappings_identity ON edr_device_mappings(identity_id) WHERE identity_id IS NOT NULL;
`

var edrPostureDown = `-- Rollback 098: EDR/MDM posture ingestion.
DROP TABLE IF EXISTS edr_device_mappings;
DROP TABLE IF EXISTS edr_posture_sources;
`
