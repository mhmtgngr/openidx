# OpenIDX APISIX edge — deployment runbook

Reference deployment of the OpenIDX `:443` edge on **Apache APISIX**, as run on the
tdv.org box. APISIX is the single TLS edge; the access-service pushes per-app
BrowZer routes dynamically via the Admin API; nginx is reduced to the admin-console
SPA static upstream. See `docs/OPENIDX_CLIENTLESS_EDGE_ARCHITECTURE.md` for the
full architecture.

> **Adapt before reuse:** paths here are this box's (`/home/cmit/oidx-runtime`,
> `*.tdv.org`). Replace `CHANGE_ME_*` placeholders (admin key, secrets) and the
> hostnames/paths for your environment. **Never commit real secrets.**

## Topology

```
Browser ─https:443─► APISIX (oidx-apisix, host-net, etcd prefix /apisix-oidx)
   ├─ <app>.tdv.org           → bootstrapper :8445 (SNI per app; reconciler-managed)
   │    + /…/signin-oidc POST  → hop port (OIDC form_post bypass; reconciler-managed)
   ├─ openidx.tdv.org /api/*  → backend services :8001–8007
   │                 /oauth,/.well-known → :8006 · /scim → :8003
   │                 /* (SPA) → nginx :8443 (static)
   ├─ browzer.tdv.org → :8445 · ctrl.tdv.org → :1280
   └─ *.tdv.org       → access-proxy :8007 (auth enforced by the proxy)
```

Ports: APISIX `:443` (edge TLS) / `:9444` (pre-cutover test) / `:9081` (http) /
`:9280` (Admin API). nginx `:8443` (SPA, internal). Shared **etcd** at
`127.0.0.1:2379` with a dedicated prefix `/apisix-oidx` (isolated from any other
APISIX on the same etcd).

## Files

| File | Purpose |
|------|---------|
| `config.yaml` | APISIX instance config (traditional/etcd role, `:443`+admin listeners, prefix `/apisix-oidx`). Set a real `admin_key`. |
| `seed-edge-routes.sh` | Idempotent seeder for the **static** routes (openidx APIs, oauth/scim, browzer/ctrl, `*.tdv.org` access-proxy) + the `*.tdv.org` SSL object. Run only to bootstrap or if etcd is reset. |
| `oidx-common.env.example` | Template for the backend services' shared `EnvironmentFile`. |
| `systemd/*.service` | User units for the access-service + the 6 backend services (`Restart=always`, `EnvironmentFile`, `ExecStart` from `/home/cmit/oidx-runtime/bin`). |

The **per-app BrowZer routes** (`browzer-<app>-tdv-org[-oidc]`) are NOT seeded here —
the access-service's APISIX reconciler creates/prunes them from `proxy_routes`
when `APISIX_EDGE_ENABLED=true` (see `internal/access/apisix_reconciler.go`).

## Bring-up

1. **APISIX**: `podman run -d --name oidx-apisix --network host -v <repo>/deployments/apisix-edge/config.yaml:/usr/local/apisix/conf/config.yaml:ro docker.io/apache/apisix:latest` (point `etcd.host` at a running etcd; pick a unique `prefix`).
2. **TLS + static routes**: `APISIX_ADMIN_KEY=… ./seed-edge-routes.sh`.
3. **Backend services**: copy `oidx-common.env.example` → `~/.config/oidx/common.env` (real values); install the `systemd/*.service` units to `~/.config/systemd/user/`; `systemctl --user daemon-reload && systemctl --user enable --now oidx-access oidx-identity oidx-governance oidx-provisioning oidx-audit oidx-admin-api oidx-oauth`.
4. **BrowZer routes**: set `APISIX_EDGE_ENABLED=true`, `APISIX_ADMIN_URL`, `APISIX_ADMIN_KEY`, `APISIX_BOOTSTRAPPER_NODE` in the access-service env — the reconciler pushes them on start.
5. **nginx (SPA upstream)** on `:8443` and the bootstrapper/hop/ziti containers: enable as `podman generate systemd --name <c>` user units (start-existing) so they return on reboot under `loginctl enable-linger`.
6. **OpenZiti edge router — BrowZer WSS**: the router needs a `wss` edge listener + `alt_server_certs` (the `*.tdv.org` cert) for the clientless BrowZer path, which the quickstart bootstrap does NOT generate. See [`ziti-router/README.md`](ziti-router/README.md) + `ziti-router/setup-router-wss.sh`. Without it the BrowZer runtime errors `1007 — No WSS-Enabled Routers found`.

## Cutover model (APISIX-front + nginx-fallback)

During migration APISIX took `:443` while nginx moved to `:8443`, with a low-priority
catch-all route (`uri:/*`, `priority:-100`) → nginx as the safety net. Hosts were
migrated to native routes one phase at a time (BrowZer → admin/API → infra →
access-proxy); the catch-all was removed once every host had a native route, and
nginx trimmed to the SPA block. **Rollback** at any point: delete the offending
native route (traffic falls back to nginx) or, for a full revert, return `:443` to
nginx and stop APISIX's `:443` listener.

## Security notes

- `config.yaml` ships `admin_key: CHANGE_ME_ADMIN_KEY` and `allow_admin: 0.0.0.0/0` —
  set a strong key and tighten `allow_admin` for anything but a single-host dev box.
- `oidx-common.env.example` holds only placeholders. Keep the real env file outside
  the repo (this deployment uses `~/.config/oidx/common.env`).
