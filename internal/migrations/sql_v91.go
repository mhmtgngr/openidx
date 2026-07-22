package migrations

// Migration v91 — quick_links (curated support/collaboration launcher).
//
// A quick link is an admin-curated, user-searchable shortcut. Two kinds:
//   - type='external' — a plain URL (Teams, Zoom, status page, docs, ticketing)
//     opened in a new tab.
//   - type='pam'      — references a pam_entries row; opening it launches that
//     connection CLIENTLESSLY via the entry's renderer (guacamole tab or the
//     in-browser wasm-ssh terminal). No connection config is duplicated; the
//     PAM permission/approval gate still applies at launch.
//
// Role-gated by min_role (hierarchical, matches the nav model). Org-scoped with
// forced RLS like its peers. Additive + idempotent. The DO block keeps `$$` on
// its own line so the migration runner's statement splitter (see migration.go
// splitSQL) does not break on the inner ';'.
var quickLinksUp = `-- Migration 091: quick_links (support/collaboration launcher).
CREATE TABLE IF NOT EXISTS quick_links (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000010'::uuid REFERENCES organizations(id) ON DELETE CASCADE,
    title        VARCHAR(255) NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    category     VARCHAR(64) NOT NULL DEFAULT 'Other',
    icon         VARCHAR(64) NOT NULL DEFAULT 'Link2',
    type         VARCHAR(16) NOT NULL DEFAULT 'external',
    url          TEXT NOT NULL DEFAULT '',
    pam_entry_id UUID REFERENCES pam_entries(id) ON DELETE CASCADE,
    min_role     VARCHAR(32) NOT NULL DEFAULT 'user',
    sort_order   INTEGER NOT NULL DEFAULT 0,
    enabled      BOOLEAN NOT NULL DEFAULT true,
    open_in_new  BOOLEAN NOT NULL DEFAULT true,
    created_by   UUID,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_quick_links_org ON quick_links(org_id);
CREATE INDEX IF NOT EXISTS idx_quick_links_enabled ON quick_links(org_id, enabled);
ALTER TABLE quick_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE quick_links FORCE ROW LEVEL SECURITY;
DO
$$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'quick_links' AND policyname = 'pol_quick_links_org_scope') THEN
        CREATE POLICY pol_quick_links_org_scope ON quick_links
            USING ((current_setting('app.bypass_rls', true) = 'on')
                   OR (org_id = (NULLIF(current_setting('app.org_id', true), ''))::uuid))
            WITH CHECK ((current_setting('app.bypass_rls', true) = 'on')
                   OR (org_id = (NULLIF(current_setting('app.org_id', true), ''))::uuid));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'quick_links_type_check') THEN
        ALTER TABLE quick_links ADD CONSTRAINT quick_links_type_check CHECK (type IN ('external', 'pam'));
    END IF;
END
$$;`

var quickLinksDown = `-- Rollback 090.
DROP TABLE IF EXISTS quick_links CASCADE;`
