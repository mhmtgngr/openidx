# OpenIDX ↔ OpenZiti Integration — Reconciler Design

**Date:** 2026-06-23
**Status:** Approved design, pending implementation plan
**Goal:** Replace the current hand-assembled, drift-prone OpenZiti integration with a portable, admin-managed, self-healing design that delivers smooth configuration, easy management, and stability.

## Background & motivation

The current integration was assembled incrementally and is fragile. A long debugging session surfaced a recurring class of problems, all stemming from the same root: **provisioning happens once on an event, then drifts**, and **multiple things mutate Ziti concurrently**. Concrete failures observed:

- BrowZer config regeneration ran in racing background goroutines that intermittently wrote empty configs.
- The bootstrapper entrypoint crash-looped on `EADDRINUSE` when configs changed.
- Hosted-service terminators went stale after SDK reconnects, faulting every dial with `no destination for circuit` until a manual restart.
- The embedded `sdk-golang` (v1.3.1) was protocol-skewed from the controller (v1.6.12), so hosted terminators bound but never serviced dials.
- The shared `browzer-router-zt` service + nginx Host-demux dropped BrowZer requests on a blank landing page because the SDK's tunneled `Host` header didn't match the expected vhost.
- Hand-edited container/nginx files and `/tmp` configs drifted and were silently reverted on restart.
- Knowing whether anything worked required reading router logs.

The fix is structural, not more patches: make OpenIDX a **reconciler** for Ziti — the DB is the single source of truth, the admin panel drives it, and a continuous reconcile loop converges Ziti to match, owning every derived artifact.

## Goals

- **Smooth config:** one source of truth (DB), driven from the admin panel.
- **Easy management:** health is visible in the UI; no terminal/file edits; one-button remediation.
- **Stability:** self-healing convergence — restarts, reconnects, drift, partial failures all auto-correct.
- **Portability:** the OpenIDX integration code is identical whether Ziti runs as local containers or managed K8s; only a deployment profile differs.
- **Per-route identity choice:** some apps get authenticated-user header injection, others go direct.

## Non-goals (v1)

- Automatic identity-header injection for BrowZer (clientless) routes — out of scope; documented limitation (see Limitations).
- Replacing the OpenIDX OAuth/OIDC service or the access-proxy's non-Ziti responsibilities.
- Multi-controller Ziti HA topologies (single logical controller assumed; multiple edge routers supported).

## Architecture

OpenIDX (access-service) runs a **Ziti reconcile loop** that drives the Ziti controller toward the desired state in the DB — the Kubernetes-controller pattern.

```
┌─────────────────────── OpenIDX (access-service) ───────────────────────┐
│  DB (desired state)          Reconciler                Ziti (actual)    │
│  ┌────────────────┐        ┌───────────────┐                           │
│  │ proxy_routes   │        │  diff desired  │   mgmt API  ┌──────────┐  │
│  │  + hosting_mode│──────► │  vs actual,    │ ──────────► │controller│  │
│  │ ziti_connection│        │  apply idempot.│             └──────────┘  │
│  │ browzer_config │        │  self-heal     │   SDK host  ┌──────────┐  │
│  └────────────────┘        └───────┬───────┘ ──────────► │  router  │  │
│         ▲                          │  generates                       │
│         │ admin panel              ▼  owned artifacts     ┌──────────┐  │
│    (sole writer)        bootstrapper targets, host.v1,   │ browzer  │  │
│                         policies ───────────────────────►│bootstrap │  │
└─────────────────────────────────────────────────────────└──────────┘──┘
```

Three building blocks:

1. **Desired state** — lives only in the DB, written only via the admin panel/API.
2. **Reconciler** — the sole mutator of Ziti; event-triggered and periodic; idempotent and self-healing; owns all derived artifacts.
3. **Deployment profile** — deploy-time abstraction of *where/how* Ziti runs, read through adapters so the reconciler logic is environment-agnostic.

The central shift: provisioning becomes **convergence**. If Ziti's state is wrong for any reason, the next reconcile fixes it.

## Desired-state schema (DB)

Source of truth, admin-managed:

- **`proxy_routes`** (extended): existing fields plus
  - `ziti_enabled` (bool)
  - `hosting_mode` (enum: `identity` | `direct`) — new
  - `browzer_enabled` (bool) — implies `hosting_mode = direct`
  - `ziti_service_name`, upstream target (`to_url`)
- **`ziti_connection`** (existing `system_settings` key): controller URL, admin user, encrypted password, identity dir, insecure flag, enabled. Admin-overridable; profile provides defaults.
- **`ziti_browzer_config`** (existing): external-jwt-signer / auth-policy / dial-policy IDs, OIDC issuer/client, enabled.
- **`ziti_identities`** (existing): user→Ziti identity mirror; reconciled to carry `externalId` + BrowZer auth-policy + `#browzer-users` role for BrowZer-eligible users.

The deployment profile (addresses, router selection, credential refs, artifact sink) is **not** in this schema — it is deploy-time config (see Deployment profile).

## The reconcile loop

**Single writer, serialized.** The reconciler is the only thing that mutates Ziti. The admin panel writes desired state to the DB and enqueues a reconcile; it never calls the Ziti API directly. One reconcile runs at a time (single worker + coalescing queue), which structurally eliminates concurrent-mutation races.

**Triggers (all funnel into the same loop):**
- **Periodic** sweep (~30s) — the drift safety net.
- **Event** — an admin change enqueues a reconcile, debounced so a burst of toggles is one run.
- **SDK re-auth/reconnect** — enqueues a reconcile so hosting is re-established after a connection blip.

**One pass (`reconcileOnce`), dependency-ordered, each step idempotent and error-isolated:**

```
1. ensureConnection()      SDK context + mgmt auth alive; rebuild on change/death.
                           If not connected → record status, stop.
2. ensureBrowZerBackend()  external-jwt-signer, auth-policy, dial-policy (if BrowZer on).
3. for each ziti-enabled route:
     ensureService()       service + role attributes
     ensureHostConfig()    fixed host.v1 config (direct routes)
     ensurePolicies()      bind/dial/service-edge-router per hosting mode
     ensureHosting()       identity → access-proxy SDK-Listen terminator
                           direct  → router Bind → host.v1 terminator
                           (verify terminator exists; recreate if stale)
4. for each browzer-eligible user:
     ensureIdentity()      externalId + browzer auth-policy + #browzer-users role
5. renderArtifacts()       bootstrapper targets (+ per-app configs) FROM DB;
                           write-if-changed via the artifact sink, then signal consumers.
                           OpenIDX owns these — overwrites manual drift.
6. (optional) prune        remove Ziti objects OpenIDX owns (tagged / naming-convention)
                           for routes that no longer exist. Conservative, opt-in.
7. recordStatus()          per-object synced/error → DB → admin panel health view.
```

**Idempotency rule:** every operation is "ensure" — look up by stable name/tag, create if absent, patch if drifted, no-op if correct. Nothing assumes a clean slate.

**Failure handling:** a failing step logs + records error status and the loop continues to the next object; persistent failures get backoff. Per-object reconcile status is surfaced in the admin panel.

**Fixed by construction:** stale terminator → recreated; deleted policy → recreated; hand-edited artifact → overwritten; SDK reconnect → hosting re-established; toggle storm → one coalesced run.

## Hosting models

Two modes, chosen per route, each fully set up by the reconciler.

### Mode `identity` — access-proxy in path (SDK-Listen)
The access-proxy is the Ziti terminator (`Listen()`). On each incoming connection it resolves the caller from the Ziti `SourceIdentifier` and injects `X-Forwarded-User/Email/Roles`, then reverse-proxies to the backend.
- **Reconciler sets up:** service + role attrs, Bind policy (`#access-proxy-clients` → service), Dial policy, service-edge-router policy. Hosting = access-proxy `Listen()` + accept loop. No `host.v1` config.
- **Use for:** native Ziti clients (tunneler/agent/desktop) — they set `SourceIdentifier`, so identity is reliable.
- **Not for:** clientless BrowZer (WSS doesn't bridge this hosting; browser clients don't set `SourceIdentifier`).

### Mode `direct` — router `host.v1` (no access-proxy in path)
The service carries a **fixed** `host.v1` config (`{protocol: tcp, address, port}`, **no `forward*` keys** — `forward*` requires the dialer to supply protocol/address/port, which a plain/BrowZer dial does not, producing `dst_protocol required`). The edge router hosts it via tunnel mode + a Bind policy granting the router identities. Router → backend directly.
- **Reconciler sets up:** service + role attrs, fixed `host.v1` config, Bind policy (edge-router identities → service), Dial policy, service-edge-router policy. Hosting = router tunnel; verify terminator exists, recreate if stale.
- **Use for:** BrowZer (proven to carry WSS), and any native route that doesn't need identity headers.

### BrowZer: per-app `direct` services (replaces the shared router)
Today BrowZer uses one shared `browzer-router-zt` service + an nginx demux that routes by `Host` — the source of the Host-mismatch failure and the catch-all workaround. **Instead, each BrowZer-enabled route gets its own `direct` service** with `host.v1` → its own backend. The bootstrapper target maps `vhost → that per-app service`. This eliminates the shared nginx demux, the Host-routing failure class, and the catch-all hack; each app reaches its backend straight over the overlay.

## Deployment profile & portability

Config splits by ownership:
- **Desired state** (DB, admin-managed): *what* to expose. Same everywhere.
- **Deployment profile** (deploy-time: env/file/secret): *where & how* Ziti runs. The only thing that differs between environments; read through adapters so reconciler logic never changes.

The profile abstracts four things (each hand-hacked in the current setup):

**1. Two address views** — every endpoint has a *control-plane address* (how OpenIDX/on-box clients reach it) and a *client-facing address* (advertised to browsers in the injected `zitiConfig`). The reconciler dials the control-plane address and writes the client-facing one into bootstrapper config.

| | control-plane (reconciler/SDK) | client-facing (browser) |
|---|---|---|
| controller | `ziti-controller.localtest.me:1280` | `ctrl.tdv.org:443` |
| router WSS | — | `browzer.tdv.org:3023` |
| bootstrapper | — | `browzer.tdv.org:443` |

**2. Edge-router selection** — `direct`-mode Bind policies need the router identities. The profile says how to pick them (default: all edge routers, or by role attribute). Works for 1 router (box) or N (K8s) with no code change.

**3. Credential / CA refs** — points at where admin creds and the controller CA come from (env / DB-encrypted / K8s secret), never inline. `insecure_skip_verify` is a profile flag, dev-only.

**4. Artifact-delivery adapter** — generated artifacts reach their consumer via a pluggable sink: file + reload on the box, ConfigMap + rollout in K8s. One interface, two implementations.

**Concrete profiles:**
- **`local-containers`**: control-plane = `*.localtest.me` (loopback); client-facing = `*.tdv.org` via the nginx front; CA = self-signed (insecure-skip in dev); single edge router; sink = shared volume + `nginx -s reload`.
- **`k8s-managed`**: control-plane = in-cluster service DNS; client-facing = ingress hostnames; real CA; all edge routers; sink = ConfigMap.

The connection subset (controller URL + creds) stays admin-overridable from the panel (DB-wins-else-profile).

## Admin-panel / management UX

The panel edits desired state (DB) and shows reconcile health; it never touches Ziti directly.

### Primary screen: Zero-Trust Routes
A table of proxy routes, each row carrying Ziti state and reconcile status:

| Route | Ziti | Mode | BrowZer | Status | Access |
|---|---|---|---|---|---|
| Netgraph | ✅ | `direct` | ✅ | 🟢 Synced | `https://netgraph.tdv.org` |
| Internal API | ✅ | `identity` | — | 🟡 Reconciling | `apiservice@ziti` |
| Legacy app | ✅ | `identity` | — | 🔴 Error: terminator bind failed | … |

- **Ziti toggle** + **Mode selector** (`identity`/`direct`). Selecting BrowZer auto-forces `direct` and explains inline that identity-header injection isn't available on that mode.
- **Status** column: 🟢 synced / 🟡 reconciling / 🔴 error-with-message, from the reconciler's per-object result. Replaces log-reading.
- **Access** column: the actual URL/service to use.

### Row detail drawer
Read-only view of what the reconciler built (service, `host.v1` config, policies, terminator state) plus last-reconcile time and any error. Transparency without hand-editing.

### Header strip
- **Connection**: status / version / reachable — Test · Connect · Disconnect.
- **Deployment profile**: active profile (read-only).
- **Reconciler health**: last run, # synced, # errors, drift-corrected indicator, **Force reconcile** button.

### Supporting sub-views (refactor of today's tabs)
- **BrowZer**: backend status (signer/auth/dial policies), bootstrapper health, OIDC issuer/client, per-app target list.
- **Identities & sync**: user→Ziti sync status, count wired for BrowZer auth, force-resync.

## Migration

Incremental and feature-flagged (`ZITI_RECONCILER`; off = current behavior). Each phase ships and reverts independently. The reconciler's first run is itself the migration — it converges whatever is on the box to the declared desired state.

- **Phase 1 — Reconciler skeleton, no behavior change.** Add the loop + `ensure*` functions reconciling the *existing* (SDK-Listen) model idempotently. Add `hosting_mode` to `proxy_routes` (migration; backfill `browzer_enabled → direct`, else `identity`). Single-writer serialization. Retires the regen races and stale-terminator drift; proves the loop without changing hosting.
- **Phase 2 — `direct` mode + per-app BrowZer.** Implement router `host.v1` hosting; migrate BrowZer routes to per-app `direct` services; retire the shared `browzer-router-zt` + nginx demux (and the catch-all). Bootstrapper targets regenerate to `vhost → per-app service`. Gated per-route: migrate one, verify it renders, roll forward.
- **Phase 3 — Deployment profiles.** Extract env-specifics into the profile abstraction; ship `local-containers` (codifies this box as a scripted/compose stack replacing the manual podman + `/tmp` setup) and `k8s-managed`.
- **Phase 4 — Admin UX.** Per-route mode selector, reconcile-status surfacing, reconciler health + force-reconcile.

### Carries over from prior work
- **Keep:** `sdk-golang v1.7.0` upgrade (required for v1.6.12 controller) and the bootstrapper-entrypoint EADDRINUSE fix — both independent of the reconciler.
- **Fold in / supersede:** terminator self-heal-on-reconnect and the regen-race fix become intrinsic to the reconciler (single-writer + continuous convergence), replacing the ad-hoc patches with structure.
- **Clean up:** manual experiment artifacts on the box (hand-made router Bind policy, duplicate `host.v1` config, hand-written catch-all `browzer-router.conf`, removed access-proxy Bind) — reconciled away by the first Phase-2 run.

## Known limitations

- **BrowZer + identity headers:** BrowZer routes are `direct`, so they do not get the access-proxy's `X-Forwarded-*` injection. BrowZer users are OIDC-authenticated, so the documented path is "the app reads the OIDC token the browser already holds." Automatic header injection for BrowZer needs an identity-aware hop the current Ziti hosting can't cleanly provide; deferred.
- **CSP/header stripping:** the old browzer-router stripped `Content-Security-Policy` / `X-Frame-Options` so the injected BrowZer runtime works. Going per-app `direct`, confirm during implementation that the **bootstrapper** handles CSP (it injects into the HTML stream, so it likely does); if not, that stripping moves into per-app handling.
- **Controller restart edge case:** a full controller restart can leave the SDK's channel to the router stale until a router-side reconnect. The reconciler's re-auth-triggered convergence mitigates but does not fully eliminate this Ziti-level behavior.

## Testing & verification

- **Unit:** reconciler `ensure*` functions are idempotent (run twice = no change); desired/actual diffing; profile adapter selection.
- **Convergence:** start with drifted Ziti state (missing policy, stale terminator, wrong config) → one reconcile pass corrects all; assert via mgmt API.
- **Hosting:** `identity` route reachable by a native Ziti client with `X-Forwarded-*` present; `direct` route reachable by an overlay dial (verified this session: a separate enrolled identity dialing a `host.v1` service returns 200).
- **BrowZer end-to-end:** per-app `direct` service renders the app clientlessly in a browser (the outstanding confirmation; gated Phase-2 rollout starts here).
- **Resilience:** restart access-service, restart router, restart controller → reconciler reconverges; assert no `no destination` faults persist.
- **Portability:** the same reconciler passes its convergence tests under both `local-containers` and (a stub of) `k8s-managed` profiles.
