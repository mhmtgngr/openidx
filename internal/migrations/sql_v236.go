package migrations

// Migration 236: the retired temporary access links leave the schema.
//
// D2 (v1.44.0) retired the anonymous temporary access link: none is issued,
// none redeems, and GET /temp-access/:token answers 410 from a page that reads
// nothing. What stayed was the history -- temp_access_links and
// temp_access_usage, with read-only list, get, revoke and usage routes and a
// history section in the console -- kept until an operator had exported it.
// This migration drops both tables, and the release removes everything that
// read or wrote them: the four admin routes, the console section, the kill
// switch's and lifecycle sweep's revoke step (a link that cannot redeem has
// nothing to revoke), and the governance expiry sweep's UPDATE.
//
// EXPORT FIRST. The rows are not copied anywhere. An install that wants the
// record exports the two tables before upgrading (pg_dump -t temp_access_links
// -t temp_access_usage, or COPY ... TO); after this migration they are gone.
//
// The usage table goes first: it references the links. The policies and
// indexes go with their tables, as do the grants to openidx_app; the policies
// are dropped by name first only so the statement list says what leaves.
//
// Down recreates both tables EMPTY, in the shape they had at 235 (v54's
// columns, v71's org_id, v148's usage org_id and FORCE'd org policies, v188's
// pam_entry_id), with the policies in their post-231 form: no app.bypass_rls
// clause. The rows themselves come back only from the export.
var tempAccessTablesDropUp = `-- Migration 236: drop the retired temporary access tables.
DROP POLICY IF EXISTS pol_temp_access_usage_org_scope ON temp_access_usage;
DROP POLICY IF EXISTS pol_temp_access_links_org_scope ON temp_access_links;
DROP TABLE IF EXISTS temp_access_usage;
DROP TABLE IF EXISTS temp_access_links;
`

var tempAccessTablesDropDown = `-- Rollback migration 236: the tables come back empty.
CREATE TABLE IF NOT EXISTS temp_access_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    protocol VARCHAR(20) NOT NULL CHECK (protocol IN ('ssh', 'rdp', 'vnc')),
    target_host VARCHAR(255) NOT NULL,
    target_port INTEGER NOT NULL CHECK (target_port > 0 AND target_port <= 65535),
    username VARCHAR(255),
    created_by UUID NOT NULL,
    created_by_email VARCHAR(255),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    max_uses INTEGER DEFAULT 0,
    current_uses INTEGER DEFAULT 0,
    allowed_ips TEXT[],
    require_mfa BOOLEAN DEFAULT FALSE,
    notify_on_use BOOLEAN DEFAULT FALSE,
    notify_email VARCHAR(255),
    route_id UUID REFERENCES proxy_routes(id) ON DELETE SET NULL,
    guacamole_connection_id VARCHAR(255),
    access_url TEXT,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'expired', 'revoked', 'used')),
    last_used_at TIMESTAMP WITH TIME ZONE,
    last_used_ip VARCHAR(45),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    pam_entry_id UUID REFERENCES pam_entries(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_temp_access_token ON temp_access_links(token);
CREATE INDEX IF NOT EXISTS idx_temp_access_status ON temp_access_links(status);
CREATE INDEX IF NOT EXISTS idx_temp_access_expires ON temp_access_links(expires_at);
CREATE INDEX IF NOT EXISTS idx_temp_access_created_by ON temp_access_links(created_by);
CREATE INDEX IF NOT EXISTS idx_temp_access_links_org ON temp_access_links(org_id);
CREATE INDEX IF NOT EXISTS idx_temp_access_links_pam_entry
    ON temp_access_links (pam_entry_id) WHERE pam_entry_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS temp_access_usage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    link_id UUID NOT NULL REFERENCES temp_access_links(id) ON DELETE CASCADE,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    connected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    disconnected_at TIMESTAMP WITH TIME ZONE,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_temp_access_usage_link ON temp_access_usage(link_id);
CREATE INDEX IF NOT EXISTS idx_temp_access_usage_time ON temp_access_usage(connected_at);
CREATE INDEX IF NOT EXISTS idx_temp_access_usage_org ON temp_access_usage(org_id, connected_at DESC);

DROP POLICY IF EXISTS pol_temp_access_links_org_scope ON temp_access_links;
CREATE POLICY pol_temp_access_links_org_scope ON temp_access_links
  USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE temp_access_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE temp_access_links FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_temp_access_usage_org_scope ON temp_access_usage;
CREATE POLICY pol_temp_access_usage_org_scope ON temp_access_usage
  USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE temp_access_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE temp_access_usage FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON temp_access_links, temp_access_usage TO openidx_app;
`
