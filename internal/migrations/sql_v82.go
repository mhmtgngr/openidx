package migrations

// Migration v82 — PAM entry reach mode (OpenZiti target hop).
//
// Adds a per-entry data-plane selector to pam_entries so a brokered
// RDP/SSH/VNC/telnet session can reach its target either directly (guacd →
// TCP → target, the default and prior behaviour) or over the OpenZiti overlay
// (guacd → loopback → ziti-tunnel → edge-router-hosted host.v1 → target),
// which removes any inbound exposure of the target to the broker network.
//
//   - reach_mode          'direct' (default) | 'ziti'
//   - ziti_service_name   the provisioned per-entry Ziti service name (NULL until enabled)
//   - ziti_intercept_port the broker-side loopback port the ziti-tunnel binds for this
//     service; access-service points the Guacamole connection at
//     127.0.0.1:<port> in ziti mode (NULL for direct)
//
// Additive and idempotent (ADD COLUMN IF NOT EXISTS); every existing entry
// keeps reach_mode='direct' so behaviour is unchanged. pam_entries is already
// org-scoped under the v37 FORCE-RLS belt (v81), so no new policy is needed.
// Plain statements only (splitSQL cannot handle DO $$).
var pamReachModeUp = `-- Migration 082: PAM entry reach mode (direct | ziti overlay).
ALTER TABLE pam_entries ADD COLUMN IF NOT EXISTS reach_mode          VARCHAR(16) NOT NULL DEFAULT 'direct';
ALTER TABLE pam_entries ADD COLUMN IF NOT EXISTS ziti_service_name   VARCHAR(255);
ALTER TABLE pam_entries ADD COLUMN IF NOT EXISTS ziti_intercept_port INTEGER;

-- The PAM broker's ziti-tunnel is a single install-wide process binding one
-- loopback port per ziti-enabled entry, so the port must be GLOBALLY unique
-- (not per-org) — two entries in different orgs sharing a port would collide on
-- the broker. Partial unique index enforces it only where a port is assigned.
CREATE UNIQUE INDEX IF NOT EXISTS uq_pam_entries_ziti_port
    ON pam_entries(ziti_intercept_port)
    WHERE ziti_intercept_port IS NOT NULL;`

var pamReachModeDown = `-- Rollback 082.
DROP INDEX IF EXISTS uq_pam_entries_ziti_port;
ALTER TABLE pam_entries DROP COLUMN IF EXISTS ziti_intercept_port;
ALTER TABLE pam_entries DROP COLUMN IF EXISTS ziti_service_name;
ALTER TABLE pam_entries DROP COLUMN IF EXISTS reach_mode;`
