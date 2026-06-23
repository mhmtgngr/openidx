package migrations

// Migration v48 — proxy_routes.landing_path.
//
// The path a published route should open at when a visitor hits its bare host.
// Many apps serve their UI under a subpath (e.g. /ui/) and 404 at "/", so when
// reached clientlessly via BrowZer the bare host lands on a 404. The BrowZer
// router uses this to emit a `location = / { return 302 <landing_path>; }`
// redirect for routes whose landing_path is not "/". Default "/" preserves
// today's behavior. Idempotent.
var landingPathUp = `-- Migration 048: proxy_routes.landing_path.
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS landing_path TEXT NOT NULL DEFAULT '/';
`

var landingPathDown = `-- Migration 048 down.
ALTER TABLE proxy_routes DROP COLUMN IF EXISTS landing_path;
`
