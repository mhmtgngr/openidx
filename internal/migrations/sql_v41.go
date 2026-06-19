package migrations

// Migration v41 — one-click "open internal app" support.
//
// The one-click publish flow (POST /api/v1/access/apps/:id/publish-app) records
// the externally reachable host it assigned to a published app so the App
// Publish UI can display it and re-publishing is idempotent. The column existed
// only as runtime behaviour; this brings it under the migration runner.
//
// Idempotent (ADD COLUMN IF NOT EXISTS) — a no-op where it already exists.
var oneClickAppsUp = `-- Migration 041: one-click publishing metadata on published_apps.
ALTER TABLE published_apps ADD COLUMN IF NOT EXISTS public_host VARCHAR(255);
-- landing_path is where the launcher tile points (e.g. "/ui/") for apps whose
-- UI is not at the site root. Defaults to "/".
ALTER TABLE published_apps ADD COLUMN IF NOT EXISTS landing_path VARCHAR(255) DEFAULT '/';
`

var oneClickAppsDown = `-- Migration 041 down.
ALTER TABLE published_apps DROP COLUMN IF EXISTS public_host;
ALTER TABLE published_apps DROP COLUMN IF EXISTS landing_path;
`
