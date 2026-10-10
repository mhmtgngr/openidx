package migrations

// Migration 231: a device's overlay identity is recorded against its agent.
//
// Every enrolled agent already gets an OpenZiti identity of its own, but
// ziti_identities never recorded it: the table knew only user identities, so
// the console, the attribute sync and the posture code could not find a
// device's identity except through its enrolling user. agent_id ties the row
// to enrolled_agents; one identity per agent, and user_id stays for the
// person the device belongs to.
var deviceIdentityAgentUp = `-- Migration 231: ziti_identities.agent_id.
ALTER TABLE ziti_identities ADD COLUMN IF NOT EXISTS agent_id VARCHAR(255);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ziti_identities_agent ON ziti_identities(agent_id) WHERE agent_id IS NOT NULL;
`

var deviceIdentityAgentDown = `-- Migration 231 down.
DROP INDEX IF EXISTS idx_ziti_identities_agent;
ALTER TABLE ziti_identities DROP COLUMN IF EXISTS agent_id;
`
