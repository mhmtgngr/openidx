package migrations

// Migration v95 — outbound SCIM provisioning (OpenIDX as a SCIM 2.0 client).
//
// Until now OpenIDX could be provisioned *into* (it ships a SCIM 2.0 server in
// internal/provisioning), but it could not provision *out to* downstream SaaS
// apps. This migration adds the persistence for an outbound SCIM client so
// OpenIDX can push its users/groups to any SCIM 2.0 service provider (Okta,
// Entra, Slack, GitHub, Zoom, ...), closing the single biggest workforce-IAM
// functional gap vs Okta/Entra and unlocking automated deprovisioning + IGA
// fulfillment.
//
// Three tables, all org-scoped for multi-tenant RLS:
//
//	scim_target_apps         — a configured downstream SCIM endpoint (base URL,
//	                           auth, feature flags). One row per SaaS connection.
//	scim_provisioning_records — the mapping between a local user/group and its
//	                           remote resource id on a given target, plus the
//	                           last-known sync state. This is what makes
//	                           subsequent updates PATCH the right remote id and
//	                           lets deprovision find what to deactivate/delete.
//	scim_provisioning_queue  — the outbox. Every local change fans out one row
//	                           per enabled target; a worker drains it with
//	                           at-least-once delivery, retry/backoff, and a
//	                           dead-letter state. Mirrors the SIEM-forwarder
//	                           outbox pattern already in the tree.
//
// Additive + idempotent. No existing behavior changes until an operator
// configures a target app.
var outboundScimUp = `-- Migration 095: outbound SCIM provisioning.

-- A configured downstream SCIM 2.0 service provider.
CREATE TABLE IF NOT EXISTS scim_target_apps (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID,
    name            VARCHAR(255) NOT NULL,
    -- Base URL of the target's SCIM 2.0 root, e.g. https://api.slack.com/scim/v2
    base_url        TEXT NOT NULL,
    -- Auth: currently 'bearer' (static token) or 'oauth2' (client-credentials).
    auth_type       VARCHAR(32) NOT NULL DEFAULT 'bearer',
    -- Encrypted at the application layer via secretcrypt (tagged base64
    -- AES-256-GCM). Never plaintext at rest.
    auth_token_enc  TEXT,
    -- OAuth2 client-credentials fields (auth_type='oauth2'); token_url/client_id
    -- are non-secret, client_secret_enc is secretcrypt-encrypted.
    oauth_token_url TEXT,
    oauth_client_id TEXT,
    oauth_client_secret_enc TEXT,
    oauth_scope     TEXT,
    -- Capability flags: which resource types / ops this target should receive.
    provision_users   BOOLEAN NOT NULL DEFAULT true,
    provision_groups  BOOLEAN NOT NULL DEFAULT false,
    -- Deprovision policy: 'deactivate' (PATCH active=false, reversible, default)
    -- or 'delete' (DELETE, irreversible). Most SaaS prefer deactivate.
    deprovision_action VARCHAR(16) NOT NULL DEFAULT 'deactivate',
    -- Optional JSON attribute mapping override (local field -> SCIM path).
    attribute_mapping JSONB NOT NULL DEFAULT '{}'::jsonb,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    -- Last successful full reconcile, for the admin UI.
    last_sync_at    TIMESTAMP WITH TIME ZONE,
    last_sync_status VARCHAR(32),
    last_sync_error TEXT,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_scim_target_apps_org ON scim_target_apps(org_id);
CREATE INDEX IF NOT EXISTS idx_scim_target_apps_enabled ON scim_target_apps(enabled) WHERE enabled;

-- Mapping of a local principal to its remote resource on one target.
CREATE TABLE IF NOT EXISTS scim_provisioning_records (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID,
    target_id       UUID NOT NULL REFERENCES scim_target_apps(id) ON DELETE CASCADE,
    -- 'user' or 'group'.
    resource_type   VARCHAR(16) NOT NULL,
    -- Local id (users.id / groups.id).
    local_id        UUID NOT NULL,
    -- Remote resource id assigned by the target on create. NULL until created.
    remote_id       VARCHAR(255),
    -- Lifecycle: pending | active | deprovisioned | error.
    status          VARCHAR(32) NOT NULL DEFAULT 'pending',
    -- Hash of the last successfully pushed payload, to skip no-op updates.
    last_payload_hash VARCHAR(64),
    last_error      TEXT,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    -- One mapping per (target, resource_type, local principal).
    UNIQUE (target_id, resource_type, local_id)
);
CREATE INDEX IF NOT EXISTS idx_scim_prov_records_target ON scim_provisioning_records(target_id);
CREATE INDEX IF NOT EXISTS idx_scim_prov_records_local ON scim_provisioning_records(resource_type, local_id);

-- Outbox of pending provisioning operations, drained by a worker.
CREATE TABLE IF NOT EXISTS scim_provisioning_queue (
    id              BIGSERIAL PRIMARY KEY,
    org_id          UUID,
    target_id       UUID NOT NULL REFERENCES scim_target_apps(id) ON DELETE CASCADE,
    resource_type   VARCHAR(16) NOT NULL,   -- user | group
    local_id        UUID NOT NULL,
    -- Operation: create | update | deactivate | activate | delete.
    operation       VARCHAR(16) NOT NULL,
    -- Snapshot of the local principal at enqueue time (JSON). The worker maps
    -- this to a SCIM payload; snapshotting avoids racing a later local delete.
    payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Delivery state: pending | processing | done | failed | dead.
    state           VARCHAR(16) NOT NULL DEFAULT 'pending',
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT,
    -- Earliest time the worker may (re)attempt this item; drives backoff.
    next_attempt_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_scim_queue_ready
    ON scim_provisioning_queue(next_attempt_at)
    WHERE state = 'pending';
CREATE INDEX IF NOT EXISTS idx_scim_queue_target ON scim_provisioning_queue(target_id);
`

var outboundScimDown = `-- Rollback 095: outbound SCIM provisioning.
DROP TABLE IF EXISTS scim_provisioning_queue CASCADE;
DROP TABLE IF EXISTS scim_provisioning_records CASCADE;
DROP TABLE IF EXISTS scim_target_apps CASCADE;
`
