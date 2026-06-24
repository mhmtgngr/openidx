# OpenIDX Clientless Access Edge — Architecture

How OpenIDX publishes internal and external apps **clientlessly** (no VPN, no agent)
over an OpenZiti zero-trust overlay via BrowZer, and how the edge is moving from
nginx to APISIX. Reflects the live topology as of 2026-06-24.

---

## 1. Big picture — layers

```
                    ┌─────────────────────────────────────────────────┐
   Browser (any) ──►│  EDGE :443   (TLS terminate, *.tdv.org cert)     │
                    │  TODAY: oidx-nginx     IN PROGRESS: oidx-apisix   │
                    └───────────────┬─────────────────────────────────┘
            ┌───────────────────────┼───────────────────────────┐
            │ host = <app>.tdv.org  │ host = openidx.tdv.org     │ other *.tdv.org
            ▼ (clientless / dark)   ▼ (admin + APIs)             ▼
   ┌──────────────────┐    ┌──────────────────────┐    ┌──────────────────┐
   │ BrowZer          │    │ admin-console SPA +   │    │ access-proxy     │
   │ bootstrapper     │    │ /api/* fan-out to     │    │ :8007 (auth-gated │
   │ oidx-browzer:8445│    │ identity/gov/prov/    │    │ reverse proxy)   │
   │ (ONE, serves all)│    │ audit/admin/oauth     │    └──────────────────┘
   └────────┬─────────┘    └──────────────────────┘
            │ serves WASM runtime + service worker to the browser
            ▼
   ┌───────────────── OpenZiti overlay (zero-trust mesh) ─────────────────────┐
   │  controller (oidx-ziti-controller)  +  edge router (oidx-ziti-router,     │
   │  host-net, WSS for BrowZer). The browser's WASM dials a per-app Ziti       │
   │  SERVICE; the router HOSTS it via a host.v1 config (the terminator).       │
   └───────────────┬──────────────────────────────────┬──────────────────────┘
        direct mode │ (router → upstream,              │ hop mode (Host-routed /
        WASM end-to-│  end-to-end)                     │ https upstreams)
        end TLS)    ▼                                  ▼
              ┌───────────┐                     ┌──────────────────────┐
              │ netgraph  │                     │ oidx-browzer-hop     │
              │ 127.0.0.1 │                     │ nginx :8095-8110     │
              │ :8088     │                     │ per-app port:        │
              │ (dark)    │                     │ Host-rewrite → app   │
              └───────────┘                     └─────────┬────────────┘
                                                          ▼
                                                 psm (IIS/.NET, Entra OIDC)
                                                 https://192.168.152.112
```

---

## 2. Request flow — a clientless ("dark") app

Example: `https://psm.tdv.org`. psm is an external Windows/IIS app with **no public
exposure**; it is reachable only over the Ziti overlay.

1. **Browser → edge `:443`.** TLS terminates on the real `*.tdv.org` cert. The edge
   matches `host = psm.tdv.org` and forwards to the **bootstrapper** (`:8445`),
   passing the SNI through (`proxy_ssl_name = psm.tdv.org`) so the single
   bootstrapper knows which app this is.
2. **Bootstrapper → browser.** Serves an HTML shell that loads the **ziti-browzer
   WASM runtime** + a **service worker**, and runs an OIDC login against **OpenIDX's
   own OAuth**. This is BrowZer's gate: only an authenticated OpenIDX user can use
   the overlay at all.
3. **WASM dials the overlay.** The service worker then intercepts the page's
   requests and tunnels them over OpenZiti to the **per-app Ziti service**
   (`openidx-PSM`). The browser origin stays `psm.tdv.org` — cookies/CORS work.
4. **Router hosts the service.** The edge **router** is the terminator for
   `openidx-PSM` via a fixed **`host.v1`** config. For psm (Host-routed HTTPS) this
   is **hop mode**: `host.v1 → 127.0.0.1:8096` (psm's hop port).
5. **Hop → real app.** `oidx-browzer-hop` on `:8096` rewrites `Host: psm.tdv.org`
   and proxies to `https://192.168.152.112`.

**Why the hop exists:** the BrowZer WASM runtime sends a fixed **`Host: unknown`**
and **no SNI** on overlay requests. So apps cannot be demuxed by Host or SNI on the
overlay leg — only by **port**. Each Ziti service maps to its own hop port, and the
hop restores the correct `Host` before talking to the real upstream.

**netgraph** is **direct mode**: a local dark service (`127.0.0.1:8088`), so its
`host.v1` points straight at it and the router hosts it with no hop.

---

## 3. Control plane — the access-service is the brain

Everything above is **declarative**, driven off the `proxy_routes` table. The
access-service runs reconcilers that converge reality to the table:

- **Ziti reconciler** (`ZITI_RECONCILER=true`, `internal/access/ziti_reconciler.go`):
  reads `proxy_routes` (`ziti_enabled` / `browzer_enabled` / `hosting_mode` /
  `to_url`) and creates the Ziti **service**, **bind/dial policies**
  (Bind→`#ziti-routers`, Dial→`#browzer-users`), `host.v1` configs, and hosting.
  It is the **single owner** of all Ziti mutations — the admin-console one-click
  toggle only writes DB flags and lets the reconciler converge.
- **Config generators**: bootstrapper targets, the hop nginx config (per-app ports,
  Host rewrite, OIDC bypass, landing redirects), and the public per-app edge config.
- **APISIX route reconciler** (`internal/access/apisix_reconciler.go`): when
  `APISIX_EDGE_ENABLED`, pushes one route per BrowZer app to APISIX's Admin API and
  prunes stale `browzer-*` routes — replacing the generated-nginx vhosts. Prune is
  bounded to the `browzer-*` prefix and computed from the desired set, so it can
  never delete other routes and never false-prunes a still-desired app.

Toggling an app's BrowZer switch in the console flips a DB flag; the reconcilers
then create the Ziti service + hop block + edge route. No hand-config.

---

## 4. Authentication — two independent OIDC flows

```
You ──► psm.tdv.org ──► BrowZer requires OpenIDX OIDC login   (gate to the overlay)
                    └─► psm app ALSO requires Entra OIDC login (the app's own auth)
```

The app's Entra login uses `response_mode=form_post`: Microsoft does a top-level
**cross-site POST** to `…/signin-oidc`. The WASM/service-worker **cannot intercept
a cross-origin POST navigation**, so that callback lands on the bootstrapper, which
**403s all non-GET**. Fix: the edge routes the OIDC callback path **straight to the
hop** (bypassing the bootstrapper). The app validates its nonce/correlation cookies
(the browser holds them, set earlier over the overlay at the same origin), sets its
auth cookie, and 302s back to the app — the normal overlay flow then resumes.

---

## 5. The edge: nginx today, APISIX next

**Today** — `oidx-nginx` owns `:443`; the per-app vhosts + OIDC bypass are
*generated* into nginx config and hot-reloaded by a poll-reload entrypoint.

**Target** — `oidx-apisix` owns `:443`; routes are **pushed dynamically via the
Admin API** (no file generation, no reload hack), and the SNI passthrough + OIDC
bypass become first-class route objects:

```
  Browser :443 ──► oidx-apisix ──┬─ host=<app>.tdv.org → route → bootstrapper:8445
   (post-flip)                   │     (upstream SNI = app via pass_host:rewrite +
                                 │      upstream_host — proven; upstream.tls.sni is
                                 │      a no-op on APISIX 3.15.0)
                                 │   + uri ~ /signin-oidc$ → hop port (OIDC bypass)
                                 └─ everything else → catch-all (priority -100) →
                                       oidx-nginx:8443 (fallback; serves admin/API/
                                       oauth/ctrl + legacy apps unchanged)
```

This is a **separate** fresh APISIX (isolated etcd prefix `/apisix-oidx`),
deliberately **not** the existing `apisix-docker2` gateway — that instance already
serves HMDM/n8n/openvas/rguac/certmngr and has a `127.0.0.1:443` HMDM route that
would self-loop if it took `:443`.

**Cutover model (APISIX-front + nginx-fallback):** APISIX takes `:443`; nginx moves
to an internal `:8443` and becomes the catch-all upstream. Hosts migrate to native
APISIX routes phase by phase; the catch-all is the safety net for everything not yet
migrated, and rollback is "give `:443` back to nginx."

---

## 6. Component reference (live)

| Component | Address | Role |
|---|---|---|
| `oidx-nginx` | `:443` (→`:8443` post-flip) | current edge / future SPA + fallback upstream |
| `oidx-apisix` | `:9444` (→`:443` at flip), admin `:9280` | target edge, route-driven (etcd prefix `/apisix-oidx`) |
| `oidx-browzer` | `:8445` | **the** BrowZer bootstrapper (one instance, all apps) |
| `oidx-browzer-hop` | `:8095–8110` | per-app Host-rewrite hop (hop mode + OIDC callback target) |
| `oidx-browzer-router` | `:8094` | legacy shared Host-demux router (**retired**) |
| `oidx-ziti-controller` | `:1280` (mgmt) | OpenZiti control plane |
| `oidx-ziti-router` | host-net, WSS | hosts per-app services (terminators via host.v1) |
| access-service | `:8007` | control plane (reconcilers) + auth-gated access-proxy |
| identity / governance / provisioning / audit / admin / oauth | `:8001–8006` | platform APIs |

### Hosting modes

| Mode | When | Path |
|---|---|---|
| **direct** | local dark service, scheme matches | router `host.v1` → upstream directly (end-to-end WASM TLS) |
| **hop** | Host-routed / external HTTPS app (e.g. IIS/.NET) | router `host.v1` → per-app hop port → Host-rewrite → real upstream |

---

## 7. Key invariants & gotchas

- **One bootstrapper**, shared by all apps; it demuxes by the SNI the edge forwards.
  Edge → bootstrapper must pass `proxy_ssl_name = <app host>` (nginx) or
  `pass_host:rewrite`+`upstream_host` (APISIX).
- **Overlay leg carries `Host: unknown`, no SNI** → demux by **port** only; the hop
  restores the real Host. Never rely on Host/SNI on the WASM→hop leg.
- **Reconcilers own all mutations.** Don't hand-create Ziti services/policies or
  edge routes when the reconcilers are on — set the `proxy_routes` flags instead.
- **APISIX prune is `browzer-*`-only and desired-set-based** — it cannot touch
  non-OpenIDX routes and won't delete a still-desired app on a transient PUT failure.
- The fresh `oidx-apisix` is currently a **hand-run container** (not in
  compose/systemd) — productize before relying on it across reboots.
