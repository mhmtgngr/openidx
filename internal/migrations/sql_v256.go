package migrations

// Migration 256: the tunnel turns on per group of devices.
//
// org_network_policy gains tunnel_scope ('all', 'tagged' or 'off') and
// tunnel_tags. 'all' turns the tunnel on on every device (what always_on=true
// meant), 'off' on none, 'tagged' on the devices whose enrolled_agents.tags
// intersect tunnel_tags. Backfill: always_on=true becomes 'all', anything else
// 'off'. always_on stays, kept equal to tunnel_scope = 'all' by the API, for
// readers that predate the scope. Columns under the table's existing org
// policy; down drops them.

var tunnelScopeUp = `-- Migration 256: tunnel scope.
ALTER TABLE org_network_policy ADD COLUMN IF NOT EXISTS tunnel_scope VARCHAR(16);
UPDATE org_network_policy SET tunnel_scope = CASE WHEN always_on THEN 'all' ELSE 'off' END
 WHERE tunnel_scope IS NULL;
ALTER TABLE org_network_policy ALTER COLUMN tunnel_scope SET DEFAULT 'tagged';
ALTER TABLE org_network_policy ALTER COLUMN tunnel_scope SET NOT NULL;
ALTER TABLE org_network_policy DROP CONSTRAINT IF EXISTS org_network_policy_tunnel_scope_check;
ALTER TABLE org_network_policy ADD CONSTRAINT org_network_policy_tunnel_scope_check
  CHECK (tunnel_scope IN ('all', 'tagged', 'off'));
ALTER TABLE org_network_policy ADD COLUMN IF NOT EXISTS tunnel_tags TEXT[] NOT NULL DEFAULT '{}';
`

var tunnelScopeDown = `-- Rollback migration 256.
ALTER TABLE org_network_policy DROP CONSTRAINT IF EXISTS org_network_policy_tunnel_scope_check;
ALTER TABLE org_network_policy DROP COLUMN IF EXISTS tunnel_tags;
ALTER TABLE org_network_policy DROP COLUMN IF EXISTS tunnel_scope;
`
