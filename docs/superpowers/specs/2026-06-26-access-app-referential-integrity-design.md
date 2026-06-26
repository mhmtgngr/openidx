# Access App referential integrity (sub-project 2) — design

## Context

Sub-project 1 (the Relations & Integrity Doctor) *detects and heals* cross-domain drift. Sub-project 2 *prevents* the in-database slice of that drift by giving the app↔route↔oauth_client relations real foreign keys, so orphan launcher tiles and orphan app rows become structurally impossible rather than something to heal after the fact.

**Scope reality:** only in-DB relations can be foreign-keyed. The external relations (Ziti controller services/policies, APISIX routes, bootstrapper/hop config files, browzer-client redirect_uris) are not DB rows and stay reconciler + doctor managed. This sub-project covers the in-DB triangle: `applications` ↔ `proxy_routes` ↔ `oauth_clients`.

**The problem:** `applications.client_id` (UNIQUE, NOT NULL) is overloaded with no FK either way — it is either a real `oauth_clients.client_id` (OIDC apps) or the string `"proxy-app-<routeID>"` (proxy launcher tiles). With no referential integrity, deleting a route or an oauth_client silently orphans its `applications` row (the exact drift the doctor kept finding: stranded tiles after rename/delete/consolidation).

**Decision (confirmed):** add explicit FK columns; **CASCADE on both** (deleting a route or an oauth_client auto-deletes its `applications` row — perfect lockstep, no orphans ever). Keep `client_id` as a legacy/display field so the many existing readers/UI keep working.

## Design

### Migration v49 (additive, idempotent, non-destructive)
Add two nullable FK columns to `applications`:
- `route_id UUID REFERENCES proxy_routes(id) ON DELETE CASCADE` — proxy tiles.
- `oauth_client_id UUID REFERENCES oauth_clients(id) ON DELETE CASCADE` — OIDC apps.
Plus indexes on both. Backfill from the existing string conventions:
- proxy tiles: `route_id` = the uuid embedded in `client_id` ("proxy-app-<uuid>"), only where that route exists.
- OIDC apps: `oauth_client_id` = `oauth_clients.id` where `oauth_clients.client_id = applications.client_id`.

`client_id` is left intact (legacy/display + still UNIQUE). Existing orphan tiles (no matching route) are left with `route_id = NULL` (the migration is non-destructive); the doctor still flags/heals those. Down migration drops the two columns (and their FKs/indexes).

SQL:
```sql
-- up
ALTER TABLE applications ADD COLUMN IF NOT EXISTS route_id UUID REFERENCES proxy_routes(id) ON DELETE CASCADE;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS oauth_client_id UUID REFERENCES oauth_clients(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_applications_route_id ON applications(route_id);
CREATE INDEX IF NOT EXISTS idx_applications_oauth_client_id ON applications(oauth_client_id);
UPDATE applications a
   SET route_id = substring(a.client_id from 'proxy-app-(.*)')::uuid
 WHERE a.route_id IS NULL AND a.client_id LIKE 'proxy-app-%'
   AND EXISTS (SELECT 1 FROM proxy_routes r WHERE r.id::text = substring(a.client_id from 'proxy-app-(.*)'));
UPDATE applications a
   SET oauth_client_id = oc.id
  FROM oauth_clients oc
 WHERE a.oauth_client_id IS NULL AND a.client_id NOT LIKE 'proxy-app-%' AND oc.client_id = a.client_id;
-- down
ALTER TABLE applications DROP COLUMN IF EXISTS route_id;
ALTER TABLE applications DROP COLUMN IF EXISTS oauth_client_id;
```
The SET cast `substring(...)::uuid` only runs for rows whose substring equals an existing `proxy_routes.id::text` (the EXISTS guard uses a text compare, no cast), so a malformed client_id never reaches the cast.

### Code (minimal — set the new FK columns)
- `upsertAppLauncherTile` (`internal/access/app_publish.go`): the `appID` param is the route id for every proxy-tile caller (route create/update #225, publish, consolidate), so set `route_id = appID` in the INSERT/upsert.
- `handleCreateClient` OIDC dual-write (`internal/oauth/service.go`, #224): set `oauth_client_id = client.ID` (the new oauth_clients uuid) on the `applications` insert.
- Route delete / consolidate: the explicit `deleteAppTile` calls become redundant safety nets (the FK CASCADE removes the tile on `DELETE FROM proxy_routes`). Leave them — harmless.

The oauth-service writing `applications.oauth_client_id` is an existing cross-domain write pattern (#224 already inserts the row). No new coupling.

### Acceptance = the doctor
After migration + deploy, the doctor's `route-tile` and `app-client` checks must report `ok`, and deleting a route must leave **no** orphan tile (cascade), proving drift can't recur. These are the acceptance tests.

## Verification
- `go build ./...`, `go vet`, `go test ./internal/access/`; migration replay `migrate down`/`up` clean.
- Live: apply v49 (restart identity-service / `openidx migrate up`); confirm `applications.route_id`/`oauth_client_id` backfilled for all 5 proxy tiles + 3 OIDC apps; delete a throwaway test route → its tile auto-disappears (cascade); doctor scan → route-tile/app-client `ok`.

## Out of scope / non-goals
External relations (Ziti/APISIX/config) — stay reconciler+doctor managed. Dropping/restructuring `client_id` — kept for backward compat. No frontend change (the tile still surfaces via `client_id`/name as today).
