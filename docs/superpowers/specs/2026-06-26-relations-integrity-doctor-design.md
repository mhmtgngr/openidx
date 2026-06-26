# Relations & Integrity Doctor — design

## Context

OpenIDX spans five domains — **identity/users, devices, applications, governance, and network/access (OpenZiti/BrowZer)** — but the relations *between* them are weak and split across multiple sources of truth, so the system drifts and is hard to manage. A live analysis of the running box (2026-06-26) showed:

- **Cross-domain links are mostly *soft* (string match, not foreign keys).** Real FKs exist almost only to `organizations`. Examples that have no referential integrity:
  - `applications.client_id` → `oauth_clients.client_id` — **1 orphan** (app with no client).
  - `proxy_routes.ziti_service_name` → `ziti_services.name` — **3 of 5 broken**.
  - `proxy_routes` ↔ launcher tile (`applications` row `proxy-app-<routeID>`).
  - `proxy_routes` ↔ APISIX `browzer-<host>` route ↔ bootstrapper target ↔ hop block ↔ `browzer-client` redirect_uris.
- **Multiple sources of truth that drift:** Postgres ↔ the **Ziti controller** ↔ **APISIX** ↔ **config files** (bootstrapper `config.json`, hop conf). The Ziti reconciler creates controller services *without* a `ziti_services` DB row, so the DB table is stale (3 of 5 missing) and any view reading it is wrong.
- **Cruft / unwired domains:** `ziti_browzer_config` has **56 rows** (should be ~1); `devices`, `posture`, and `policies` tables are **empty** (governance isn't wired to devices/decisions yet).

This loose coupling is the root cause of the orphan/mismatch bugs seen in practice this cycle (stranded Ziti services after rename/delete, missing launcher tiles, the kibana-dev per-path explosion, missing `browzer-client` redirect_uris, etc.). The user wants the large system to be **easy to manage in a compact way** — to *see* the cross-domain relations, *find gaps*, and *make it work*.

**Decisions (confirmed):**
- Build **(1) a Relations & Integrity "Doctor"** first; **(2) a unified entity model** later, only if #1 proves it worthwhile.
- Fix model: **auto-fix clearly-safe drift, require a click for risky/destructive fixes.**
- Trigger: **on-demand (Health page / API) + after mutations** (publish/toggle/route change heals the touched route). No background sweep.

## Goals / non-goals

**Goals:** one engine that knows the cross-domain relations, scans every source of truth, reports findings (ok / drift / orphan) by domain + severity, auto-heals safe drift, and offers a one-click fix for risky drift. Make adding a new relation check a one-unit change.

**Non-goals (this spec):** refactoring the soft links into real FKs (that is sub-project 2); deep governance/device feature work (those domains are empty — presence checks only).

---

## Sub-project 1 — the Doctor (this spec)

### Architecture: a check-registry engine

A new package `internal/integrity` (engine + checks) with a small, uniform unit:

```go
type Finding struct {
    CheckID   string
    Domain    string   // "access" | "apps" | "ziti" | "identity" | "governance" | "devices"
    Severity  string   // "info" | "warn" | "error"
    Status    string   // "ok" | "drift" | "orphan"
    Subject   string   // e.g. route name / host / service name
    Detail    string
    Safe      bool     // true → eligible for auto-heal; false → needs confirm
    Action    string   // human label for the fix, e.g. "regenerate edge configs"
}

type Check interface {
    ID() string
    Domain() string
    Detect(ctx context.Context) ([]Finding, error)
    Fix(ctx context.Context, f Finding) error   // no-op if the check is detect-only
}
```

The **engine** holds a registry of `Check`s and exposes:
- `Scan(ctx) Report` — run every `Detect`, aggregate findings.
- `ScanAndHeal(ctx, applySafe bool) Report` — scan; if `applySafe`, run `Fix` for every `Safe` finding; return the report with `healed[]` and `remaining[]` (the risky ones needing confirm).
- `FixOne(ctx, checkID, subject) error` — run a specific (risky) fix on explicit confirmation.

Adding a relation later = register one more `Check`. That is the "compact" property.

### Four source-of-truth readers (reuse existing clients)

- **Postgres** — the domain tables (`s.db.Pool`).
- **Ziti controller** — `ZitiManager` management API. MUST use **name-filter queries** (`?filter=name="…"`) — `ListServices`/`GetServiceByName` paginate at 10 and silently miss objects.
- **APISIX** — `APISIXClient.ListRouteNames` / Admin API.
- **Config files** — bootstrapper `config.json`, hop conf (read + compare to desired via `BrowZerTargetManager`).

### Fix model + trigger

- `ScanAndHeal(applySafe=true)` runs safe fixes automatically; risky fixes are returned as `remaining` for a click.
- Triggers: **on-demand** (Health page open / API call) and **after mutations** — publish/toggle/route create/update/delete already call `RegenerateConfigs` + `enqueueReconcile`; the doctor's after-mutation hook runs the *safe* checks for the touched route (tile sync, edge regen, redirect register, dedup). No periodic background sweep.

### Check catalog (v1)

Deep checks + fixes on the access/app/Ziti cluster (where the real drift is); presence-only on the empty domains.

| # | Check (relation) | Detects | Fix | Safe |
|---|---|---|---|---|
| 1 | route ↔ launcher tile | orphan tile / missing tile | upsert/delete tile (`upsertAppLauncherTile`/`deleteAppTile`) | ✓ |
| 2 | route ↔ APISIX `browzer-<host>` | missing / stale / same-host collision | `RegenerateConfigs` (prunes stale, dedups) | ✓ |
| 3 | route ↔ bootstrapper target + hop block | missing / stale / hop-port drift | `RegenerateConfigs` | ✓ |
| 4 | `browzer-client` redirect_uris ↔ hosts | missing host redirect | re-register (RegenerateConfigs) | ✓ |
| 5 | route ↔ Ziti service / policies / host.v1 | missing service, wrong dial role, missing host.v1 | `enqueueReconcile` (reconciler converges) | ✓ |
| 6 | orphan Ziti controller objects | svc/policy/config/SERP with no owning route | `TeardownZitiServiceByName` | ⚠ |
| 7 | per-host uniqueness | >1 proxy_route on one host | `consolidateApp` | ⚠ |
| 8 | app ↔ oauth_client | app w/o client / client w/o tile | tile sync (✓) / report (client) | mixed |
| 9 | `ziti_browzer_config` dup rows | the 56→1 cruft | dedup to the newest enabled row | ✓ |
| 10 | published_app ↔ discovered_paths ↔ route + status | inconsistent links / status | relink to canonical route, fix status | ✓ |
| 11 | users ↔ ziti_identities (`user_id`) | users without identity / identity without user | report (sync is ✓ where a sync routine exists) | mixed |
| 12 | governance / devices wired? | empty/unwired domains | report only | n/a |

"Orphan owner" for checks 6/7 is resolved by name convention (`openidx-<service>` ↔ `proxy_routes.ziti_service_name`) and host slug (`browzer-<host>` ↔ `from_url` host).

### Surface

- **API** (access service, where most checks + fix routines live):
  - `GET /api/v1/access/health/relations[?heal=safe]` → the report (findings grouped by domain; when `heal=safe`, applies safe fixes first and returns healed + remaining).
  - `POST /api/v1/access/health/fix/:checkId` with `{subject}` → run a specific risky fix (admin-confirmed).
- **Console:** a **"System Health / Relations"** page: findings grouped by domain, colored by severity, each row showing status + suggested action; a **Scan & heal (safe)** button and a per-finding **Fix** button for the risky ones.
- **After-mutation hook:** the existing publish/toggle/delete paths invoke the safe checks for the touched route (mostly already done via `RegenerateConfigs`/`enqueueReconcile`; the hook adds tile-sync + dedup coverage).

### Reuse (almost everything exists)

`consolidateApp`, `TeardownZitiForRoute` / `TeardownZitiServiceByName`, `RegenerateConfigs`, `enqueueReconcile`, `upsertAppLauncherTile` / `deleteAppTile`, the `browzer-client` redirect auto-register (in `RegenerateConfigs`), `dedupRoutesByHost`, `APISIXClient.ListRouteNames`, `effectiveHostingMode`, Ziti `deleteEdgeEntityByName` + name-filter queries.

### Testing

- **Unit:** each Check's `Detect` against mocked/fixture sources (httptest fake Ziti/APISIX like the existing `*_test.go`); the engine's safe/risky partition; the report shape; `FixOne` dispatch.
- **Live verification:** run `GET /health/relations` on the box — it must surface today's real gaps (the 1 orphan app, `ziti_browzer_config` 56→1, any route↔service drift, the empty governance/device domains) and `?heal=safe` must clear the safe ones (dup config, tiles, edge regen) while leaving risky ones (orphan teardown, consolidate) as confirm-needed. Re-scan → clean.

---

## Sub-project 2 — unified "Access App" entity model (later, separate spec)

If the Doctor shows the soft-link drift is chronic, collapse the per-host artifacts (proxy_route + oauth/tile + Ziti service + bootstrapper target + hop block + APISIX route + redirect_uris) into one **Access App aggregate** with real referential integrity (FKs + a single owning row), so the relations can't drift in the first place. The Doctor's checks become the acceptance tests for that refactor. Scoped in its own spec after #1 lands.
