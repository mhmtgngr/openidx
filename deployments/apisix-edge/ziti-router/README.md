# OpenZiti edge router — BrowZer WSS configuration

The BrowZer browser runtime connects to the overlay over a **WSS (secure
WebSocket) edge listener** on the router. If the router has no WSS listener, the
BrowZer runtime fails with **`code: 1007 — No WSS-Enabled Routers found`**.

This captures the WSS-specific router config that the OpenZiti quickstart image's
bootstrap does **not** generate, so it survives router recreation. Reference:
`config.reference.yml` (the live `/persistent/config.yml`).

## What BrowZer requires on the router

1. **A second `edge` listener bound to `wss`** (alongside the normal `tls` edge
   listener). From `config.reference.yml`:
   ```yaml
   listeners:
     - binding: edge
       address: tls:0.0.0.0:3022          # normal edge (SDK clients, e.g. access-proxy)
       options: { advertise: ziti-router.localtest.me:3022, ... }
     - binding: edge
       address: wss:0.0.0.0:3023          # BrowZer WSS
       options: { advertise: browzer.tdv.org:3023, ... }
     - binding: tunnel
       options: { mode: host }
   ```
   plus the `ws:` options block (writeTimeout/readTimeout/idleTimeout).

2. **A browser-trusted server cert for the WSS advertise host**, via
   `identity.alt_server_certs` — the real `*.tdv.org` GlobalSign cert:
   ```yaml
   identity:
     cert:        "router.cert"                       # ziti-CA client identity (enrolled)
     server_cert: "/persistent/router.server.chain.cert"
     key:         "/persistent/router.key"
     ca:          "/persistent/router.cas"
     alt_server_certs:
       - server_cert: "/persistent/tdv-fullchain.pem" # *.tdv.org cert -> valid for browzer.tdv.org
         server_key:  "/persistent/tdv-key.pem"
   ```

## Gotcha: the enrolled cert can't carry `browzer.tdv.org`

`ziti router enroll` does **not** honor `edge.csr.sans` — the enrolled server
cert's SANs are auto-derived from `ZITI_ROUTER_ADVERTISED_ADDRESS` + defaults
(`localhost`, the container hostname, `127.0.0.1`, `::1`,
`ziti-router.localtest.me`). So you **cannot** get `browzer.tdv.org` into the
enrolled cert, and the `wss` advertise `browzer.tdv.org:3023` would fail config
load with *"identity is not valid for provided host: browzer.tdv.org"*. That is
exactly why `alt_server_certs` (the real `*.tdv.org` cert) is required — the WSS
listener presents it for the `browzer.tdv.org` SNI; BrowZer validates the overlay
against the ziti CA, the browser validates the WSS TLS against the public cert.

## Identity persistence (so recreate ≠ re-enroll)

Run with `ZITI_HOME=/persistent` and the named volume `oidx_ziti_router_cfg:/persistent`
so the enrolled identity (`router.cert/key/cas/server.chain.cert`) + `config.yml`
+ the alt cert live in the volume. Then **`podman start` (reboot) reuses the
identity** — only a wiped volume forces re-enrollment. (See the parent README's
"router hardening" note.)

## Bring-up / repair

`./setup-router-wss.sh` applies the cert + WSS config to the volume and runs the
router with the canonical command. **Prerequisite (one-time, or if the volume is
wiped):** enroll first —
```bash
# on the controller: issue a token for the edge-router
podman exec oidx-ziti-controller ziti edge re-enroll edge-router oidx-router \
  --jwt-output-file /tmp/oidx-router.jwt
podman cp oidx-ziti-controller:/tmp/oidx-router.jwt /home/cmit/oidx-runtime/oidx-ziti/oidx-router.jwt
chmod 644 /home/cmit/oidx-runtime/oidx-ziti/oidx-router.jwt
# then run once with enrollment on + the /jwt mount (see setup-router-wss.sh --enroll)
```

### Canonical run command (steady state — already enrolled)
```bash
podman run --replace -d --name oidx-ziti-router --network host \
  -e ZITI_HOME=/persistent \
  -e ZITI_CTRL_ADVERTISED_ADDRESS=ziti-controller.localtest.me -e ZITI_CTRL_ADVERTISED_PORT=1280 \
  -e ZITI_ROUTER_ADVERTISED_ADDRESS=ziti-router.localtest.me -e ZITI_ROUTER_PORT=3022 \
  -e ZITI_BOOTSTRAP=true -e ZITI_BOOTSTRAP_ENROLLMENT=false -e ZITI_BOOTSTRAP_CONFIG=false \
  -e PFXLOG_NO_JSON=true \
  -v oidx_ziti_router_cfg:/persistent \
  docker.io/openziti/ziti-router:latest
```
`ZITI_BOOTSTRAP_CONFIG=false` is critical — it stops the bootstrap from
regenerating `config.yml` and wiping the WSS listener / `alt_server_certs`.

## Verify
```bash
ss -ltn | grep 3023                                  # WSS listening
podman exec oidx-ziti-controller ziti edge list edge-routers   # oidx-router online=true
```
Then load `https://browzer.tdv.org`-fronted apps (psm/netgraph) in a browser and
confirm no `1007`.

## Caveats
- **Cert renewal:** `alt_server_certs` points at a **copy** in the volume
  (`/persistent/tdv-fullchain.pem`). Re-sync it when the GlobalSign `*.tdv.org`
  cert renews, else the WSS TLS cert expires.
- **`:3023` reachability:** the router is host-net and binds `:3023` directly;
  `browzer.tdv.org` must resolve to this box and `:3023` be reachable from clients
  (independent of the APISIX `:443` edge).
