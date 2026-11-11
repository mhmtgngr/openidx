package migrations

// Migration 252: agent identity continuity.
//
// One physical machine is one agent row for as long as it is in use. Until
// now the agent's fingerprint folded the hostname into the machine id, so
// renaming a PC (the usual step when it changes hands) enrolled it as a new
// device and left the old row behind. The agent now fingerprints the machine
// id alone and, for a few releases, sends the old hostname-folded value as
// device_fingerprint_prev so the server can move the existing row over.
//
// enrolled_agents gains:
//
//	hostname          the device's name as an attribute (it used to live
//	                  only in metadata->>'hostname'), backfilled from there.
//	retired_at        when an administrator retired the device: it is out of
//	                  the fleet for good and its fingerprint is free, so the
//	                  same machine enrolling again gets a new row.
//	reinstated_at     when an administrator lifted a revoke so the device may
//	                  enrol again.
//	owner_changed_by/at  who last reassigned the device's owner, and when.
//
// The per-tenant fingerprint key (v197) excludes retired rows. Before it is
// built, any duplicate (org_id, device_fingerprint) among non-retired rows is
// collapsed: every row but the newest (last_seen_at, then enrolled_at) is
// retired. Plain SQL, no DO block.

var agentIdentityContinuityUp = `-- Migration 252: agent identity continuity.
ALTER TABLE enrolled_agents ADD COLUMN IF NOT EXISTS hostname         TEXT;
ALTER TABLE enrolled_agents ADD COLUMN IF NOT EXISTS retired_at       TIMESTAMPTZ;
ALTER TABLE enrolled_agents ADD COLUMN IF NOT EXISTS reinstated_at    TIMESTAMPTZ;
ALTER TABLE enrolled_agents ADD COLUMN IF NOT EXISTS owner_changed_by UUID;
ALTER TABLE enrolled_agents ADD COLUMN IF NOT EXISTS owner_changed_at TIMESTAMPTZ;

UPDATE enrolled_agents
   SET hostname = NULLIF(metadata->>'hostname', '')
 WHERE hostname IS NULL AND metadata IS NOT NULL;

UPDATE enrolled_agents ea
   SET status = 'retired', retired_at = NOW()
  FROM (
        SELECT agent_id,
               ROW_NUMBER() OVER (PARTITION BY org_id, device_fingerprint
                                  ORDER BY last_seen_at DESC NULLS LAST,
                                           enrolled_at DESC NULLS LAST,
                                           agent_id DESC) AS rn
          FROM enrolled_agents
         WHERE device_fingerprint IS NOT NULL AND status <> 'retired'
       ) d
 WHERE ea.agent_id = d.agent_id AND d.rn > 1;

DROP INDEX IF EXISTS enrolled_agents_org_device_fingerprint_key;
CREATE UNIQUE INDEX IF NOT EXISTS enrolled_agents_org_device_fingerprint_key
    ON enrolled_agents (org_id, device_fingerprint)
    WHERE device_fingerprint IS NOT NULL AND status <> 'retired';
`

// Down cannot bring the install-wide-per-tenant key back over retired rows
// that share a fingerprint with a live one, so it drops the retired rows'
// fingerprints first; the rows themselves stay.
var agentIdentityContinuityDown = `-- Rollback migration 252.
UPDATE enrolled_agents SET device_fingerprint = NULL WHERE status = 'retired';
DROP INDEX IF EXISTS enrolled_agents_org_device_fingerprint_key;
CREATE UNIQUE INDEX IF NOT EXISTS enrolled_agents_org_device_fingerprint_key
    ON enrolled_agents (org_id, device_fingerprint)
    WHERE device_fingerprint IS NOT NULL;
ALTER TABLE enrolled_agents DROP COLUMN IF EXISTS owner_changed_at;
ALTER TABLE enrolled_agents DROP COLUMN IF EXISTS owner_changed_by;
ALTER TABLE enrolled_agents DROP COLUMN IF EXISTS reinstated_at;
ALTER TABLE enrolled_agents DROP COLUMN IF EXISTS retired_at;
ALTER TABLE enrolled_agents DROP COLUMN IF EXISTS hostname;
`
