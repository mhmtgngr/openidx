package migrations

// Migration 249: sites.
//
// A site is a place applications live in and edge routers run in: the
// on-premises box is the "default" site, an Azure VNet with its own router is
// another. A network resource or a proxied application is hosted (Ziti Bind)
// by the routers of its site, so traffic for an Azure application leaves the
// fabric in Azure. network_targets.site_id and proxy_routes.site_id are NULL
// for the default site, so nothing changes on upgrade. site_routers maps a
// Ziti edge router to its site; a router not listed belongs to the default
// site. Both are platform tables (the overlay is install-wide), without RLS.

var sitesUp = `-- Migration 249: sites.
CREATE TABLE IF NOT EXISTS sites (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        TEXT NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,38}$'),
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    hop_addr    TEXT,
    is_default  BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sites_single_default ON sites ((is_default)) WHERE is_default;
INSERT INTO sites (slug, name, is_default) VALUES ('default', 'Default site', true)
    ON CONFLICT (slug) DO NOTHING;

CREATE TABLE IF NOT EXISTS site_routers (
    ziti_router_id  TEXT PRIMARY KEY,
    site_id         UUID NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    name            TEXT NOT NULL DEFAULT '',
    advertised_host TEXT NOT NULL DEFAULT '',
    image_tag       TEXT NOT NULL DEFAULT '',
    enrolled_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_site_routers_site ON site_routers (site_id);

ALTER TABLE network_targets ADD COLUMN IF NOT EXISTS site_id UUID REFERENCES sites(id) ON DELETE RESTRICT;
ALTER TABLE proxy_routes    ADD COLUMN IF NOT EXISTS site_id UUID REFERENCES sites(id) ON DELETE RESTRICT;

GRANT SELECT, INSERT, UPDATE, DELETE ON sites        TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON site_routers TO openidx_app;
`

var sitesDown = `-- Rollback migration 249.
ALTER TABLE proxy_routes    DROP COLUMN IF EXISTS site_id;
ALTER TABLE network_targets DROP COLUMN IF EXISTS site_id;
DROP TABLE IF EXISTS site_routers;
DROP TABLE IF EXISTS sites;
`
