package migrations

// Migration v47 — proxy_routes.hosting_mode.
//
// The Ziti reconciler chooses a hosting model per route: "identity" (the
// access-proxy is the Ziti terminator and injects X-Forwarded-* headers) or
// "direct" (the edge router hosts via host.v1). BrowZer-enabled routes require
// "direct". Backfill preserves today's behavior: every existing ziti route is
// "identity" except BrowZer-enabled ones, which become "direct". Idempotent.
var hostingModeUp = `-- Migration 047: proxy_routes.hosting_mode.
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS hosting_mode TEXT NOT NULL DEFAULT 'identity';
UPDATE proxy_routes SET hosting_mode = 'direct' WHERE browzer_enabled = true;
`

var hostingModeDown = `-- Migration 047 down.
ALTER TABLE proxy_routes DROP COLUMN IF EXISTS hosting_mode;
`
