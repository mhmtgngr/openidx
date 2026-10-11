package migrations

// Migration 232: network services are resources.
//
// The VPN replacement puts the official OpenZiti tunneler on each device. What
// the tunneler intercepts, and where the router hosting it forwards, used to be
// typed into the free-form "Add service" form as one host and one port, with
// dial roles written by hand. From here a network service is an applications
// row of kind 'network', assigned like any other resource, and network_targets
// says what it covers: hosts, CIDRs and DNS names, port ranges, protocols, and
// optionally a fixed forward address. The Ziti reconciler turns each row into
// a service with intercept.v1 and host.v1 configs and dial policies naming the
// device identities.
//
// org_network_policy holds the organization's tunnel posture: whether the
// tunnel is always on, whether it is split (only resources go through the
// overlay) and whether direct traffic to corporate CIDRs is refused. A missing
// row means the defaults: on demand, split, nothing blocked.
//
// enrolled_agents gains tunnel_status, the last state the agent reported for
// its tunneler (state, version, the services it had, dial failures), and
// tunnel_last_seen, so the console can show a device whose tunnel is down and
// an alert can fire on it.
//
// The policies scope by app.org_id only: bypass-marked work runs as the
// openidx_bypass role since migration 231, and a new policy carries no
// app.bypass_rls clause.
var networkResourcesUp = `-- Migration 232: network services are resources.
CREATE TABLE IF NOT EXISTS network_targets (
  application_id UUID PRIMARY KEY REFERENCES applications(id) ON DELETE CASCADE,
  org_id UUID NOT NULL,
  hosts TEXT[] NOT NULL DEFAULT '{}',
  cidrs CIDR[] NOT NULL DEFAULT '{}',
  dns_names TEXT[] NOT NULL DEFAULT '{}',
  port_ranges JSONB NOT NULL DEFAULT '[]'::jsonb,
  protocols TEXT[] NOT NULL DEFAULT '{tcp,udp}',
  forward_address TEXT,
  forward_port INTEGER CHECK (forward_port IS NULL OR (forward_port >= 1 AND forward_port <= 65535)),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT network_targets_protocols_check CHECK (protocols <@ ARRAY['tcp','udp']::text[] AND cardinality(protocols) > 0),
  CONSTRAINT network_targets_address_check CHECK (cardinality(hosts) + cardinality(cidrs) + cardinality(dns_names) > 0)
);
CREATE INDEX IF NOT EXISTS idx_network_targets_org ON network_targets(org_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON network_targets TO openidx_app;
DROP POLICY IF EXISTS pol_network_targets_org_scope ON network_targets;
CREATE POLICY pol_network_targets_org_scope ON network_targets
  USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE network_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE network_targets FORCE  ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS org_network_policy (
  org_id UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  always_on BOOLEAN NOT NULL DEFAULT false,
  split_tunnel BOOLEAN NOT NULL DEFAULT true,
  block_direct_corporate_cidrs BOOLEAN NOT NULL DEFAULT false,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by UUID
);
GRANT SELECT, INSERT, UPDATE, DELETE ON org_network_policy TO openidx_app;
DROP POLICY IF EXISTS pol_org_network_policy_org_scope ON org_network_policy;
CREATE POLICY pol_org_network_policy_org_scope ON org_network_policy
  USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE org_network_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_network_policy FORCE  ROW LEVEL SECURITY;

ALTER TABLE enrolled_agents ADD COLUMN IF NOT EXISTS tunnel_status JSONB;
ALTER TABLE enrolled_agents ADD COLUMN IF NOT EXISTS tunnel_last_seen TIMESTAMPTZ;
`

var networkResourcesDown = `-- Migration 232 down.
ALTER TABLE enrolled_agents DROP COLUMN IF EXISTS tunnel_last_seen;
ALTER TABLE enrolled_agents DROP COLUMN IF EXISTS tunnel_status;
DROP TABLE IF EXISTS org_network_policy;
DROP TABLE IF EXISTS network_targets;
`
