# APISIX BrowZer edge — design

**Status:** Draft for review · **Date:** 2026-06-24

**Goal:** Replace the hand-/generated-nginx edge (`oidx-nginx` on `:443`) with
Apache APISIX as the single TLS front, with the access-service pushing routes to
APISIX's Admin API (etcd-backed) instead of generating nginx config files. Migrate
**BrowZer per-app publishing first**, then the rest of the edge, in phases —
nginx stays a fallback upstream until each surface is moved.

---

## 1. Context & current state

The OpenIDX edge today is `oidx-nginx` (host-net, `:443`), a mix of hand-written
and access-service-generated nginx config:

| Surface | Host(s) | Upstream |
|---|---|---|
| Admin console SPA + API fan-out | `openidx.tdv.org` | static + `:8001/2/3/4/5/6/7` by path |
| One-click apps (access-proxy) | `*.tdv.org` | access-proxy `:8007` |
| BrowZer bootstrapper | `browzer.tdv.org` | bootstrapper `:8445` (SNI-passthrough) |
| Ziti controller edge API | `ctrl.tdv.org` | controller `:1280` |
| **BrowZer per-app (generated)** | `netgraph/psm.tdv.org` | bootstrapper `:8445`; OIDC `form_post` → hop |

What already exists for APISIX (this is the lever):

- **Live**: `apisix-docker2_apisix_1`, `…_etcd_1`, `…_dashboard_1`, `…_oauth2-proxy_1`
  are running (3 months), **not** on `:443`. APISIX listens `:9080` (http) /
  `:9443` (ssl), Admin API `:9180` (key `edd1c9f0…`), etcd at `openidx-etcd:2379`,
  prefix `/apisix` (`deployments/docker/apisix/config.yaml`).
- **Declarative routes** for the API fan-out already authored
  (`deployments/docker/apisix/apisix.yaml`: identity/governance/provisioning/audit/…
  with `limit-req`, `cors`, `enable_websocket` for audit `/stream`).
- **Cert management to APISIX**: `internal/access/platform_certs.go`
  (`APISIXSSLConfig`, `updateAPISIXSSL`) already writes `ssls` entries.
- **Forward-auth**: `handleAuthDecide` (`context_evaluator.go`) — APISIX sends
  `X-Forwarded-Host/Uri/Method`; the access-service replies `200` + `X-Forwarded-Route`
  (allow) or `403`/redirect (deny). This is how the access-proxy wildcard enforces
  auth at the edge.
- **Route push pattern**: `load-apisix-routes.sh` →
  `PUT $ADMIN/apisix/admin/routes/<name>` with `X-API-KEY`.

**Decisions taken (review questions, 2026-06-24):** etcd + Admin API control
plane · APISIX is the `:443` front with nginx as a fallback upstream · full edge
migration, phased.

---

## 2. Target architecture

```
                       :443 (TLS terminate, *.tdv.org wildcard cert in APISIX ssls)
                                  │
                          ┌───────▼────────┐        Admin API :9180  ┌──────────────┐
   browser ──────────────►│     APISIX     │◄───── PUT routes ───────│ access-svc   │
                          │  (etcd-backed) │                         │ APISIX route │
                          └───┬───────┬────┘                         │  reconciler  │
        host=app.tdv.org  ┌───┘       └────┐ everything else         └──────────────┘
   (BrowZer route)        │                │ (catch-all, priority -100)
                ┌─────────▼──────┐   ┌──────▼─────────┐
                │ bootstrapper   │   │  oidx-nginx    │  (demoted: internal :8443,
                │  :8445 (WSS,   │   │  fallback      │   plain http upstream; serves
                │  SNI=app)      │   │  upstream      │   admin/API/oauth/ctrl until
                └────────────────┘   └────────────────┘   migrated)
   OIDC form_post  (higher-priority route, host=app + uri~signin-oidc$ → hop :80xx)
```

- **APISIX owns `:443`.** One `ssl` object holds the real `*.tdv.org` wildcard
  cert (`snis: ["*.tdv.org", "tdv.org"]`), reusing the `platform_certs` writer
  (Admin API `ssls` instead of `apisix.yaml`).
- **Per-host routes** are matched by `hosts:`. BrowZer apps get native APISIX
  routes; **unmigrated hosts fall through to a catch-all** (`uri: /*`,
  `priority: -100`) whose upstream is the demoted `oidx-nginx` — so admin console,
  OAuth, ctrl, and the `*.tdv.org` access-proxy keep working untouched.
- **The access-service is the control plane.** A new **APISIX route reconciler**
  (sibling of the Ziti reconciler) renders desired route objects from `proxy_routes`
  and `PUT`s them to the Admin API, idempotent by deterministic name, deleting
  routes for removed apps. This *replaces* the nginx vhost file generator
  (`browzer_vhosts.go`) and its poll-reload entrypoint.

---

## 3. BrowZer route model (Phase 1 — the core)

For each `ziti_enabled AND browzer_enabled AND enabled` route with hostname `H`,
service `S`, hosting_mode `M`, hop port `P`:

**(a) Overlay route → bootstrapper** (name `browzer-<slug>`):
```jsonc
{
  "name": "browzer-<slug>",
  "hosts": ["H"],
  "uri": "/*",
  "priority": 0,
  "enable_websocket": true,            // BrowZer WSS to the router/bootstrapper
  "upstream": {
    "type": "roundrobin",
    "scheme": "https",
    "pass_host": "rewrite",
    "upstream_host": "H",              // Host: H  (bootstrapper demuxes the target vhost)
    "nodes": { "127.0.0.1:8445": 1 },
    "tls": { "verify": false },        // bootstrapper cert is self-signed
    "timeout": { "connect": 60, "send": 86400, "read": 86400 }
  }
}
```

**(b) OIDC `form_post` bypass → hop** (hop-mode only, name `browzer-<slug>-oidc`,
higher priority so it wins over (a)):
```jsonc
{
  "name": "browzer-<slug>-oidc",
  "hosts": ["H"],
  "uri": "/*",
  "vars": [ ["uri", "~~", "/(signin-oidc|signout-callback-oidc)$"] ],
  "priority": 10,
  "upstream": {
    "type": "roundrobin", "scheme": "http",
    "pass_host": "rewrite", "upstream_host": "H",
    "nodes": { "127.0.0.1:<P>": 1 }   // the route's hop port (assignHopPorts)
  }
}
```

Callback suffixes come from `BROWZER_OIDC_CALLBACK_PATHS` (today's config). Only
hop-mode routes get (b) — direct-mode apps have no host-side upstream.

### 3.1 SNI to the bootstrapper — SPIKE RESOLVED (2026-06-24)

The bootstrapper demuxes the target app **by the TLS SNI** of the upstream
connection (today: nginx `proxy_ssl_server_name on; proxy_ssl_name $host`).
APISIX must present **SNI = `H`** on the upstream TLS handshake to `127.0.0.1:8445`.

Spiked against the live APISIX (**3.15.0**, host-net) by routing through it to an
SNI-echo TLS server (`return 200 "$ssl_server_name"`). Results:

| Candidate | Upstream SNI seen | Verdict |
|---|---|---|
| **`pass_host: rewrite` + `upstream_host: H`** | **`H`** | ✅ **USE THIS** |
| `upstream.tls.sni: H` | _(empty)_ | ❌ schema **accepts** the field but it does **not** set the handshake SNI in 3.15.0 — a no-op trap |
| `pass_host: pass` (SNI follows incoming `Host`) | `H` only if the request `Host` is `H` | ❌ unusable — the BrowZer runtime sends `Host: unknown`, so SNI would be `unknown` |

**Decision:** the per-app overlay route uses **`pass_host: rewrite` +
`upstream_host: H`**, which deterministically sets BOTH the upstream `Host`
header AND the TLS SNI to the app vhost, independent of the (always `unknown`)
incoming Host. This is exactly what the route model in §3 already specifies — so
**Phase 1 is unblocked**, no fallback or Lua plugin needed. (Do **not** rely on
`upstream.tls.sni`; it validates but silently does nothing here.)

### 3.2 Other BrowZer specifics

- **WSS**: `enable_websocket: true` on the overlay route (verified pattern — the
  audit `/stream` route already uses it).
- **Long-lived**: `timeout.read/send: 86400` (matches nginx `proxy_read_timeout 86400s`).
- **No auth plugin** on BrowZer routes — BrowZer's own OIDC (OpenIDX) gates overlay
  access; the edge is a transparent proxy here.

---

## 4. Component design — APISIX route reconciler

`internal/access/apisix_reconciler.go` (mirrors `ziti_reconciler.go`):

- **Desired set**: reuse `queryBrowZerRoutes` (hostname, service, hosting_mode,
  hop port via `assignHopPorts`) → render the route JSON objects above.
- **Apply**: `PUT /apisix/admin/routes/browzer-<slug>` (+ `-oidc`) with `X-API-KEY`;
  idempotent (APISIX PUT-by-name is upsert). Diff against `GET …/routes` and
  **delete** routes whose app is gone/disabled (`browzer-*` namespace only).
- **SSL**: ensure one `ssl` object with the wildcard cert (reuse/extend
  `platform_certs` to target the Admin API).
- **Triggers**: boot + on feature toggle (`RegenerateConfigs` calls it instead of
  writing vhost files) + the existing reconcile tick. Behind a flag
  `APISIX_EDGE_ENABLED` so it's opt-in and the nginx generator remains the default
  until cutover.
- **Config**: `APISIX_ADMIN_URL` (`http://127.0.0.1:9180`), `APISIX_ADMIN_KEY`,
  `APISIX_BOOTSTRAPPER_NODE` (`127.0.0.1:8445`), reuse `BROWZER_OIDC_CALLBACK_PATHS`.

This *retires* `browzer_vhosts.go` + `oidx-nginx-entrypoint.sh` once Phase 1 is
live (kept until then).

---

## 5. Phases

**Phase 0 — adopt the live APISIX, give it `:443`, nginx becomes fallback.**
- Reuse the running `apisix-docker2_apisix_1` (3.15.0, etcd-backed); bring its
  `config.yaml` under repo management and add a `:443` SSL listener.
- Put the `*.tdv.org` wildcard cert in an APISIX `ssl` object (Admin API).
- Demote `oidx-nginx` to an internal port (e.g. `:8443`, plain http or its own TLS).
- Add catch-all route (`uri:/*`, `priority:-100`, `enable_websocket`, long timeout)
  → nginx. **Verify every current host still works through APISIX→nginx** (admin
  console, API, oauth, ctrl, browzer, both BrowZer apps).
- *Rollback*: point `:443` back at nginx (stop APISIX `:443` / restore listener).

**Phase 1 — BrowZer per-app routes native in APISIX.** (after the §3.1 spike)
- Ship the route reconciler; add the per-app overlay + OIDC routes; they win over
  the catch-all by host match. Verify netgraph + psm render clientlessly and the
  psm Entra `form_post` login completes. Retire the nginx vhost generator.

**Phase 2 — admin console SPA + API fan-out.**
- Adopt the existing `apisix.yaml` routes (identity/governance/provisioning/audit/
  admin) as Admin-API route objects; SPA static via APISIX (or keep nginx serving
  `/usr/share/nginx/html` as a dedicated upstream). Move host `openidx.tdv.org`
  off the catch-all.

**Phase 3 — OAuth, ctrl, and the `*.tdv.org` access-proxy wildcard.**
- `oauth/.well-known` → `:8006`; `ctrl.tdv.org` → controller `:1280` (TLS verify
  off); `browzer.tdv.org` → bootstrapper.
- `*.tdv.org` access-proxy: route → access-proxy `:8007` with the **forward-auth**
  plugin pointing at `handleAuthDecide` (the contract already exists), replacing
  the access-service's inline auth-redirect for edge-gated apps.

**Phase 4 — reduce nginx to the SPA static upstream.** Once all *proxy* hosts have
native APISIX routes, drop the broad catch-all; `oidx-nginx` shrinks to a single
internal upstream serving the admin-console `dist` (`try_files … /index.html`) for
`openidx.tdv.org`'s SPA routes (APISIX handles that host's `/api`, `/oauth`,
`/.well-known`, `/scim`). nginx is **not** removed — APISIX isn't a static file
server.

---

## 6. Cutover, rollback, verification

- **Per phase**: a host moves from the catch-all (→nginx) to a native APISIX route
  only after its native route is verified; the catch-all is the safety net the
  whole time.
- **Rollback at any point**: native routes are `browzer-*`/per-host names —
  delete them and the catch-all serves the host via nginx again. Phase 0 rollback
  = give `:443` back to nginx.
- **Verify each route**: TLS (cert chain), the right upstream, WSS upgrade (BrowZer
  overlay), `form_post` POST → hop (psm login), forward-auth allow/deny (access-proxy),
  long-lived connections survive.
- **Adopt-or-replace the stale `apisix-docker2` stack**: confirm version
  (for §3.1), etcd prefix `/apisix`, Admin key; either adopt those containers or
  stand up a fresh APISIX bound to `:443`. (Operator step; flagged.)

---

## 7. What this buys / costs

**Buys:** one gateway (matches the documented architecture); dynamic API-driven
routes (no config-file generation, no poll-reload entrypoint, no nginx bind-mount
inode gotcha); per-route plugins (rate-limit, cors, forward-auth, observability,
mTLS) available uniformly; the OIDC bypass + access-proxy auth become first-class
route/plugin objects.

**Costs:** etcd is now load-bearing for the edge (HA/backup matters); a risky
`:443` cutover (mitigated by the nginx-fallback model); the §3.1 SNI spike is a
real unknown; APISIX is OpenResty/nginx underneath, so no *raw* capability gain —
the value is the control plane, not the data plane.

---

## 8. Resolved decisions

1. **§3.1 SNI spike — RESOLVED** (2026-06-24): `pass_host: rewrite` +
   `upstream_host: H` sets the upstream SNI on APISIX 3.15.0; `upstream.tls.sni`
   is a no-op. Phase 1 unblocked.
2. **Adopt the running APISIX, manage its config from the repo.** The live
   `apisix-docker2_apisix_1` is APISIX **3.15.0, host-net, etcd-backed**, Admin
   API `:9180` (key `add1c9f0…`), `:9080`/`:9443` up but not on `:443`. Reuse it
   (and its etcd) rather than standing up a second APISIX/etcd — Phase 0 just adds
   a `:443` SSL listener and brings its `config.yaml` + routes under repo
   management (the access-service is the route source of truth).
3. **Keep nginx as the SPA static upstream.** APISIX is not a static file server;
   the admin-console SPA (`try_files … /index.html`) stays served by a thin
   `oidx-nginx` **behind** APISIX. So nginx never fully retires — it shrinks to
   the SPA/static upstream for `openidx.tdv.org`. (Phase 4 = "reduce nginx to the
   SPA upstream", not "remove nginx".)
4. **forward-auth only for the `*.tdv.org` access-proxy hosts.** The service APIs
   (identity/governance/…) each validate their own JWT, and BrowZer routes are
   gated by BrowZer's OIDC — don't double-gate them. The APISIX `forward-auth`
   plugin (→ `handleAuthDecide`) applies only to the edge-gated access-proxy
   wildcard apps (Phase 3).
5. **etcd durability is a production follow-up, out of scope here.** The test box
   keeps the existing single-node etcd. Production hardening (3-/5-node etcd
   quorum + periodic snapshot backups) is tracked separately, not part of this
   edge migration.
