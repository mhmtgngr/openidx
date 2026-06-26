package migrations

// Migration v51 — drop the dead ZTPolicy tables.
//
// The ZTPolicy subsystem (handler/store/model) was never wired into any
// service: NewZTPolicyStore was constructed only in tests, so its lazy
// CREATE TABLE never ran on a real install and these tables do not exist
// there. This is a belt-and-suspenders cleanup — a no-op on every real
// deployment, and a tidy-up on any environment where the store was ever
// constructed (e.g. a stray test against a shared DB). Idempotent.
//
// The child table (zt_policy_versions, FK → zt_policies) is dropped first.
var ztPolicyDropUp = `-- Migration 051: drop the dead ZTPolicy tables.
DROP TABLE IF EXISTS zt_policy_versions;
DROP TABLE IF EXISTS zt_policies;
`

// Down recreates the exact schema ZTPolicyStore.initSchema used, for strict
// reversibility — even though nothing consumes these tables.
var ztPolicyDropDown = `-- Migration 051 down: recreate the ZTPolicy tables.
CREATE TABLE IF NOT EXISTS zt_policies (
	id UUID PRIMARY KEY,
	name VARCHAR(255) NOT NULL,
	description TEXT,
	effect VARCHAR(20) NOT NULL CHECK (effect IN ('allow', 'deny')),
	conditions JSONB NOT NULL,
	priority INTEGER DEFAULT 0,
	enabled BOOLEAN DEFAULT true,
	tenant_id VARCHAR(255),
	version INTEGER DEFAULT 1,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	created_by VARCHAR(255),
	updated_by VARCHAR(255),
	metadata JSONB
);
CREATE TABLE IF NOT EXISTS zt_policy_versions (
	id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	policy_id UUID NOT NULL,
	version INTEGER NOT NULL,
	policy_data JSONB NOT NULL,
	change_type VARCHAR(50) NOT NULL,
	changed_by VARCHAR(255),
	change_reason TEXT,
	changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (policy_id) REFERENCES zt_policies(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_zt_policies_tenant_id ON zt_policies(tenant_id);
CREATE INDEX IF NOT EXISTS idx_zt_policies_enabled ON zt_policies(enabled);
CREATE INDEX IF NOT EXISTS idx_zt_policies_priority ON zt_policies(priority DESC);
CREATE INDEX IF NOT EXISTS idx_zt_policies_effect ON zt_policies(effect);
CREATE INDEX IF NOT EXISTS idx_zt_policy_versions_policy_id ON zt_policy_versions(policy_id);
CREATE INDEX IF NOT EXISTS idx_zt_policy_versions_changed_at ON zt_policy_versions(changed_at DESC);
`
