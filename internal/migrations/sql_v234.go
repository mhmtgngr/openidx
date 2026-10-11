package migrations

// Migration 234: vendor engagements.
//
// A vendor's people were given access one request at a time, each with its
// own window, and nothing said what the work was, when it started or ended,
// or what happened during it. An engagement is that unit: a vendor
// organization, an internal sponsor, a window (starts_at, ends_at), the
// vendor's people on it (member_user_ids, empty meaning every live external
// user of the vendor) and its targets (vendor_engagement_targets): the
// applications (network resources are applications since v232), PAM entries
// and enrolled devices (agent ids, for remote support) the work needs.
//
// While an engagement runs, the identity service writes the grants it
// implies and keeps them to its window; when it ends or is closed, it cuts
// them. A PAM connect grant carries the engagement's id (pam_entry_grants.
// engagement_id, one row per engagement, entry and member, outside v216's
// standing key). An application assignment is one row per user and
// application, shared with requests and administrators, so the window the
// engagement wrote is recorded (vendor_engagement_app_grants.written_until)
// and the engagement cuts only a row that still carries it.
//
// vendor_organizations.require_engagement is the switch for the stricter
// rule: an external user of such a vendor reaches an application, launches a
// PAM entry and asks for access only inside a running engagement that covers
// the target (internal/externalid.CheckEngagement). The column defaults to
// off, so existing vendors and any writer that does not name it change
// nothing; the vendor API creates a vendor with it on unless told otherwise.
//
// Tenant tables under FORCE'd RLS on org_id. The policies scope by app.org_id
// only: bypass-marked work runs as the openidx_bypass role since migration
// 231, and a new policy carries no app.bypass_rls clause.
//
// Down drops the tables, the grant column and the switch. The PAM grants the
// engagements wrote are deleted (without their engagement they would collide
// under v216's standing key); application assignments keep the windows they
// were given.
var vendorEngagementsUp = `-- Migration 234: vendor engagements.
ALTER TABLE vendor_organizations ADD COLUMN IF NOT EXISTS require_engagement BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS vendor_engagements (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID NOT NULL,
    vendor_org_id    UUID NOT NULL REFERENCES vendor_organizations(id) ON DELETE CASCADE,
    sponsor_user_id  UUID REFERENCES users(id) ON DELETE SET NULL,
    title            VARCHAR(200) NOT NULL,
    purpose          TEXT NOT NULL DEFAULT '',
    ticket_ref       VARCHAR(200) NOT NULL DEFAULT '',
    starts_at        TIMESTAMPTZ NOT NULL,
    ends_at          TIMESTAMPTZ NOT NULL,
    member_user_ids  UUID[] NOT NULL DEFAULT '{}',
    status           VARCHAR(16) NOT NULL DEFAULT 'open',
    closed_at        TIMESTAMPTZ,
    closed_by        UUID REFERENCES users(id) ON DELETE SET NULL,
    close_reason     VARCHAR(32),
    grants_synced_at TIMESTAMPTZ,
    created_by       UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT vendor_engagements_window CHECK (starts_at < ends_at),
    CONSTRAINT vendor_engagements_status CHECK (status IN ('open', 'closed')),
    CONSTRAINT vendor_engagements_closed CHECK ((status = 'closed') = (closed_at IS NOT NULL)),
    CONSTRAINT vendor_engagements_reason CHECK (close_reason IS NULL OR close_reason IN ('ended', 'closed', 'cancelled', 'vendor_closed'))
);
CREATE INDEX IF NOT EXISTS idx_vendor_engagements_vendor ON vendor_engagements (vendor_org_id, starts_at DESC);
CREATE INDEX IF NOT EXISTS idx_vendor_engagements_open ON vendor_engagements (ends_at) WHERE status = 'open';
GRANT SELECT, INSERT, UPDATE, DELETE ON vendor_engagements TO openidx_app;
DROP POLICY IF EXISTS pol_vendor_engagements_org_scope ON vendor_engagements;
CREATE POLICY pol_vendor_engagements_org_scope ON vendor_engagements
  USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE vendor_engagements ENABLE ROW LEVEL SECURITY;
ALTER TABLE vendor_engagements FORCE  ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS vendor_engagement_targets (
    engagement_id UUID NOT NULL REFERENCES vendor_engagements(id) ON DELETE CASCADE,
    org_id        UUID NOT NULL,
    target_type   VARCHAR(32) NOT NULL CHECK (target_type IN ('application', 'pam_entry', 'device')),
    target_id     TEXT NOT NULL,
    PRIMARY KEY (engagement_id, target_type, target_id)
);
CREATE INDEX IF NOT EXISTS idx_vendor_engagement_targets_target ON vendor_engagement_targets (org_id, target_type, target_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON vendor_engagement_targets TO openidx_app;
DROP POLICY IF EXISTS pol_vendor_engagement_targets_org_scope ON vendor_engagement_targets;
CREATE POLICY pol_vendor_engagement_targets_org_scope ON vendor_engagement_targets
  USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE vendor_engagement_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE vendor_engagement_targets FORCE  ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS vendor_engagement_app_grants (
    engagement_id  UUID NOT NULL REFERENCES vendor_engagements(id) ON DELETE CASCADE,
    org_id         UUID NOT NULL,
    user_id        UUID NOT NULL,
    application_id UUID NOT NULL,
    written_until  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (engagement_id, user_id, application_id)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON vendor_engagement_app_grants TO openidx_app;
DROP POLICY IF EXISTS pol_vendor_engagement_app_grants_org_scope ON vendor_engagement_app_grants;
CREATE POLICY pol_vendor_engagement_app_grants_org_scope ON vendor_engagement_app_grants
  USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE vendor_engagement_app_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE vendor_engagement_app_grants FORCE  ROW LEVEL SECURITY;

ALTER TABLE pam_entry_grants ADD COLUMN IF NOT EXISTS engagement_id UUID REFERENCES vendor_engagements(id) ON DELETE CASCADE;
DROP INDEX IF EXISTS pam_entry_grants_standing_key;
CREATE UNIQUE INDEX IF NOT EXISTS pam_entry_grants_standing_key
    ON pam_entry_grants (entry_id, principal_type, principal_id) WHERE request_id IS NULL AND engagement_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS pam_entry_grants_engagement_key
    ON pam_entry_grants (engagement_id, entry_id, principal_id) WHERE engagement_id IS NOT NULL;
`

var vendorEngagementsDown = `-- Rollback migration 234.
DROP INDEX IF EXISTS pam_entry_grants_engagement_key;
DELETE FROM pam_entry_grants WHERE engagement_id IS NOT NULL;
DROP INDEX IF EXISTS pam_entry_grants_standing_key;
ALTER TABLE pam_entry_grants DROP COLUMN IF EXISTS engagement_id;
CREATE UNIQUE INDEX IF NOT EXISTS pam_entry_grants_standing_key
    ON pam_entry_grants (entry_id, principal_type, principal_id) WHERE request_id IS NULL;
DROP TABLE IF EXISTS vendor_engagement_app_grants;
DROP TABLE IF EXISTS vendor_engagement_targets;
DROP TABLE IF EXISTS vendor_engagements;
ALTER TABLE vendor_organizations DROP COLUMN IF EXISTS require_engagement;
`
