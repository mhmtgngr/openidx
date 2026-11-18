package migrations

// Migration 264: who answers the names of tunneled applications.
//
// The tunneler answers DNS for the names of a network resource's application,
// and next to a VPN client that enforces its own DNS the question never reaches
// it (the client answers every UDP/53 question on the machine). Two additions
// let the agent answer them locally instead:
//
//   - org_network_policy.name_resolution: 'tunnel' (the default, today's
//     behavior: the tunneler answers, nothing changes) or 'agent' (the agent
//     answers for the resources that have a pin).
//   - network_targets.pin_ip: a stable overlay address the server gives a
//     resource that has exactly one DNS name, taken from 100.127.0.0/16. It is
//     added to the service's intercept addresses, so a device that resolves the
//     name to the pin reaches the same service. Unique per organization; the
//     CHECK keeps a stray write from putting anything else in the column.
//
// Nothing is backfilled: pins are allocated by the reconciler, and only for an
// organization that turns the setting on.

var nameResolutionUp = `-- Migration 264: name resolution and pinned overlay addresses.
ALTER TABLE org_network_policy ADD COLUMN IF NOT EXISTS name_resolution VARCHAR(16) NOT NULL DEFAULT 'tunnel';
ALTER TABLE org_network_policy DROP CONSTRAINT IF EXISTS org_network_policy_name_resolution_check;
ALTER TABLE org_network_policy ADD CONSTRAINT org_network_policy_name_resolution_check
  CHECK (name_resolution IN ('tunnel', 'agent'));
ALTER TABLE network_targets ADD COLUMN IF NOT EXISTS pin_ip INET;
ALTER TABLE network_targets DROP CONSTRAINT IF EXISTS network_targets_pin_ip_check;
ALTER TABLE network_targets ADD CONSTRAINT network_targets_pin_ip_check
  CHECK (pin_ip IS NULL OR pin_ip << '100.127.0.0/16'::inet);
CREATE UNIQUE INDEX IF NOT EXISTS network_targets_org_pin_ip
  ON network_targets (org_id, pin_ip) WHERE pin_ip IS NOT NULL;
`

var nameResolutionDown = `-- Rollback migration 264.
DROP INDEX IF EXISTS network_targets_org_pin_ip;
ALTER TABLE network_targets DROP CONSTRAINT IF EXISTS network_targets_pin_ip_check;
ALTER TABLE network_targets DROP COLUMN IF EXISTS pin_ip;
ALTER TABLE org_network_policy DROP CONSTRAINT IF EXISTS org_network_policy_name_resolution_check;
ALTER TABLE org_network_policy DROP COLUMN IF EXISTS name_resolution;
`
