# Publishing a service on OpenIDX (clientless, zero-trust)

How to expose any internal/external web service — e.g. `secops.tdv.org` — through
the OpenIDX clientless edge (APISIX + OpenZiti + BrowZer), with **no firewall
changes, no agent, and no requirement that the backend have a valid TLS cert**.

> TL;DR: pick a `*.tdv.org` hostname, publish the route from the admin console,
> turn on **OpenZiti + BrowZer**, choose **hop** mode for anything that's
> external/HTTPS/Host-routed (this also makes a bad upstream cert a non-issue),
> register the hostname's redirect_uri on the BrowZer OAuth client, point DNS at
> the box. The public TLS is the `*.tdv.org` wildcard — automatic for any
> subdomain.

---

## 1. Architecture (recap)

```
                         :443  (APISIX edge — TLS terminate, *.tdv.org wildcard cert)
   Browser ──────────────────┬──────────────────────────────────────────────┐
   (anywhere,                 │ host = secops.tdv.org → native APISIX route   │
    secops.tdv.org →          ▼                                                │ other hosts
    the box)        ┌──────────────────┐                                      ▼
                    │ BrowZer          │   openidx.tdv.org → SPA + APIs        access-proxy :8007
                    │ bootstrapper:8445│   browzer/ctrl.tdv.org → infra
                    │ (serves WASM)    │
                    └────────┬─────────┘
        WASM + service worker│ + WSS to the router :3023 (browser-trusted *.tdv.org cert)
                             ▼
   ┌──────────── OpenZiti overlay (controller + edge router) ───────────────────┐
   │  The browser dials a per-app Ziti SERVICE; the edge ROUTER hosts it via a   │
   │  host.v1 config. The user is authenticated to the overlay by BrowZer's own  │
   │  OIDC (OpenIDX). The app's origin (secops.tdv.org) is preserved end to end. │
   └───────────────┬──────────────────────────────────┬─────────────────────────┘
        direct mode │ (router → upstream, end-to-end    │ hop mode (external / HTTPS /
        WASM TLS)   ▼  the browser validates the cert)  ▼ Host-routed upstreams)
              ┌───────────┐                      ┌──────────────────────────┐
              │ local dark│                      │ oidx-browzer-hop (nginx)  │
              │ service   │                      │ per-app port: Host-rewrite│
              │ 127.0.0.1 │                      │ + proxy_ssl_verify OFF →  │
              └───────────┘                      │ tolerates ANY upstream cert│
                                                 └─────────┬─────────────────┘
                                                           ▼ secops backend (any cert / http)
```

**Control plane:** you only ever set flags on the `proxy_routes` row (via the admin
console). The access-service reconcilers converge everything else:
- **Ziti reconciler** → creates the Ziti service, bind/dial/SERP policies, the
  `host.v1` config, and router hosting.
- **APISIX reconciler** → creates the public edge route `browzer-<slug>` (and prunes
  stale ones).
- **config generators** → bootstrapper targets + the per-app hop nginx config.

Full detail: `docs/OPENIDX_CLIENTLESS_EDGE_ARCHITECTURE.md`.

---

## 2. Add `secops.tdv.org` — step by step

### 2.1 Create the proxy route (admin console)
**Access → Proxy Routes → Add route** (or **Applications → Publish**):
- **Name:** `secops`
- **Public host (from_url):** `https://secops.tdv.org`
- **Upstream (to_url):** the real backend, e.g. `https://192.168.x.y` (HTTPS),
  `http://192.168.x.y:8080` (HTTP), or `http://127.0.0.1:9000` (local/dark).
- **Hosting mode:** see §3. Use **hop** for external/HTTPS/Host-routed apps,
  **direct** for a local dark service with a browser-trusted cert (or HTTP).

### 2.2 Turn on OpenZiti + BrowZer
On the route's action bar, flip **OpenZiti** then **BrowZer** (BrowZer depends on
Ziti). That sets `ziti_enabled` / `browzer_enabled` and triggers the reconcilers,
which create the Ziti service + the APISIX route + the hop block (if hop mode).

### 2.3 Register the redirect_uri on the BrowZer OAuth client
BrowZer authenticates the user to the overlay via OpenIDX OIDC. Each published
host must be an allowed redirect target on the **`browzer-client`** OAuth client:
add `https://secops.tdv.org/` (and the BrowZer callback path it uses). **Admin →
Applications/OAuth clients → `browzer-client` → Redirect URIs.** *(Missing this →
the BrowZer login bounces.)*

### 2.4 Point DNS / hosts at the box
`secops.tdv.org` must resolve to this box for the user's browser:
- Production: a DNS A/CNAME record for `secops.tdv.org`.
- Test machine without DNS: `…/etc/hosts` → `<box-ip>  secops.tdv.org`, or Chrome
  `--host-resolver-rules`.

### 2.5 Verify
```bash
# public TLS + bootstrap (expect 200, x-powered-by: BrowZer)
curl -skI --resolve secops.tdv.org:443:<box-ip> https://secops.tdv.org/ | grep -iE 'HTTP|x-powered-by'
# the reconciler created the route:
curl -s -H "X-API-KEY: <key>" http://127.0.0.1:9280/apisix/admin/routes | grep browzer-secops
```
Then load `https://secops.tdv.org` in a browser → OpenIDX login → the app renders.

---

## 3. Hosting mode: direct vs hop

| Use **hop** when… | Use **direct** when… |
|---|---|
| Upstream is **external** / on another host | Upstream is **local/dark** (`127.0.0.1`) |
| Upstream is **HTTPS** (esp. with a self-signed/expired/wrong-host cert) | Upstream presents a **browser-trusted** cert, or is plain HTTP |
| App is **Host-routed** (vhost-sensitive, IIS/.NET, etc.) | App doesn't care about the Host header |
| App has its **own external OIDC** (form_post callbacks) | Simple app, no nested OIDC |

**Why hop is the safe default:** the BrowZer runtime sends a fixed `Host: unknown`
and no SNI on overlay requests. The hop rewrites the `Host` to `secops.tdv.org`
and proxies to the real upstream — and for HTTPS upstreams it uses
`proxy_ssl_verify off`, so it tolerates **any** upstream certificate state.

---

## 4. Certificates — every case

There are **two** TLS legs. Keep them separate in your head.

### Leg A — Browser ⇄ Edge (public)
Always the real **`*.tdv.org` wildcard** cert, presented by:
- the **APISIX edge** on `:443`,
- the **BrowZer bootstrapper** behind it,
- the **router's WSS listener** on `:3023` (via `transport.wss.identity`).

→ **Any `*.tdv.org` subdomain is automatically covered. No per-app cert, ever.**
This is why you should publish services under `*.tdv.org`.

*(If you must use a non-`*.tdv.org` name: add that cert to the APISIX `ssl` object
**and** the router's `transport.wss.identity` — more work; prefer `*.tdv.org`.)*

### Leg B — Edge/Hop ⇄ Upstream (the backend's own cert)
This is where "**the service hasn't got a valid certificate**" matters. Pick by
the upstream's cert state:

| Upstream cert state | What to do | Why |
|---|---|---|
| **Self-signed / expired / wrong hostname / untrusted CA** | **hop mode**, `to_url=https://…` | The hop connects with `proxy_ssl_verify off` — it does **not** validate the upstream cert, so a bad cert just works. |
| **No TLS (HTTP only)** | any mode, `to_url=http://…` | No cert involved. Hop proxies `http→upstream`. |
| **Valid, browser-trusted cert** | **direct** or hop | Direct works because the browser (end-to-end WASM TLS) trusts it. |
| **Valid cert but local/dark service** | **direct**, `to_url=https://…` | End-to-end WASM TLS straight to the dark upstream. |

**Critical rule:** for an HTTPS upstream with an **invalid** cert, use **hop**, not
direct. In **direct** mode the BrowZer WASM does end-to-end TLS and the **browser**
validates the upstream cert — an invalid one is rejected by the browser. The hop is
the layer that absorbs bad upstream certs.

**Security note:** `proxy_ssl_verify off` means the hop trusts the upstream
blindly. That's fine for internal/dark services on a trusted segment (the
zero-trust boundary is the overlay + the user's IdP auth, not the upstream TLS).
For a stricter posture, terminate the upstream's TLS properly (give the backend a
real cert and use direct, or pin the upstream CA at the hop).

### Leg C — The app's OWN login (nested OIDC, e.g. Entra)
If `secops` runs its own external IdP login with `response_mode=form_post`
(cross-site POST to `…/signin-oidc`): **do nothing special.** Once BrowZer's WSS
overlay is healthy, its service worker tunnels that callback over the overlay and
the app's session cookie stays in context. **Do NOT add an edge "OIDC bypass" for
the callback** — it routes the callback off-overlay and the session cookie won't
be seen → login loop. (`BROWZER_OIDC_CALLBACK_PATHS` is empty by default for this
reason; only set it as a fallback if the overlay genuinely can't carry the POST.)

---

## 5. Troubleshooting (symptoms seen in practice)

| Symptom | Cause | Fix |
|---|---|---|
| **502** on the app | service SDK-hosted with no `host.v1`, or proxy sent plain HTTP to a `:443` upstream | use **hop** mode; let the reconciler own hosting (don't imperatively host) |
| Redirect to **`http://unknown:<port>/…`** | upstream emitted an absolute redirect; nginx default `proxy_redirect` rewrote it using `Host: unknown` | hop config already sets `proxy_redirect off` (regenerate if hand-edited) |
| BrowZer **1007 — No WSS-Enabled Routers** | router has no `wss` edge listener | add the `wss:0.0.0.0:3023` listener (see `deployments/apisix-edge/ziti-router/`) |
| BrowZer **1016 — certificates issue** on the WSS | router WSS presented the ziti cert, not a browser-trusted one | set `transport.wss.identity` → the `*.tdv.org` cert (not `alt_server_certs`) |
| App **login loop** after its own IdP login | edge OIDC `form_post` bypass set the session cookie off-overlay | leave `BROWZER_OIDC_CALLBACK_PATHS=""`; let the overlay carry the callback |
| BrowZer login bounces immediately | host's redirect_uri not on the `browzer-client` OAuth client | add `https://<host>/` to the client's redirect URIs |
| `secops.tdv.org` doesn't resolve | no DNS/hosts entry | add DNS record or `/etc/hosts` |

---

## 6. What you do vs what's automatic

| You | Automatic (reconcilers/edge) |
|---|---|
| Add the proxy route + pick hosting mode | Ziti service + bind/dial/SERP policies + `host.v1` |
| Toggle OpenZiti + BrowZer | APISIX edge route `browzer-<slug>` + bootstrapper target |
| Register redirect_uri on `browzer-client` | hop nginx block (hop mode) + landing redirect |
| DNS/hosts → the box | Public `*.tdv.org` TLS on edge + bootstrapper + WSS |
| (only if non-`*.tdv.org`) add the app's edge cert | — |
