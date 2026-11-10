package migrations

// Migration 244: purpose justification on proxied applications.
//
// proxy_routes gains require_justification and justification_ttl_minutes.
// On a route that requires it, a signed-in person who may reach the
// application is asked, once per proxy session and for the TTL, why they are
// opening it; the reason is audited (proxy.access_justified) before the
// request reaches the application. It is an extra step after the access
// decision, never instead of it.
//
// Default false, so no route changes on upgrade.

var routeJustificationUp = `-- Migration 244: route purpose justification.
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS require_justification BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS justification_ttl_minutes INTEGER NOT NULL DEFAULT 480
    CHECK (justification_ttl_minutes BETWEEN 5 AND 1440);
`

var routeJustificationDown = `-- Rollback migration 244.
ALTER TABLE proxy_routes DROP COLUMN IF EXISTS justification_ttl_minutes;
ALTER TABLE proxy_routes DROP COLUMN IF EXISTS require_justification;
`
