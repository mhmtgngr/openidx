# OpenIDX edge — one edge, not two

Roadmap item #7. OpenIDX ships two things that can act as the HTTP edge:

- **APISIX** (`oidx-apisix`, `:443`) — the production edge on the box.
- **`gateway-service`** (`cmd/gateway-service`, `:8008`) — a thin Go reverse
  proxy, an *alternative* edge for deployments that don't run APISIX.

Running **both** means two routing tables that drift, two sets of failure modes,
and `gateway-service` binding `*:8008` for no reason. On the box, APISIX is
authoritative and **`gateway-service` was in nobody's request path** — verified:
the APISIX seed (`oidx-apisix/seed-edge-routes.sh`) routes every path **directly**
to the service ports, with **zero** references to `:8008`; nothing connected to
`:8008`; no config referenced it.

## The routing (APISIX → services, direct)

| Path (host `openidx.tdv.org`) | → upstream |
|---|---|
| `/api/v1/identity/*` | `127.0.0.1:8001` |
| `/api/v1/governance/*` | `127.0.0.1:8002` |
| `/api/v1/provisioning/*`, `/scim/*` | `127.0.0.1:8003` |
| `/api/v1/audit/*` (ws) | `127.0.0.1:8004` |
| `/api/*` (admin) | `127.0.0.1:8005` |
| `/oauth/*`, `/.well-known/*` | `127.0.0.1:8006` |
| `/api/v1/access/*` (ws) | `127.0.0.1:8007` |
| `/*` (SPA) | `oidx-nginx:8443` |
| `*.tdv.org` `/*` (published apps) | `127.0.0.1:8007` (access-proxy) |

`gateway-service` (`:8008`) is **not** in this table.

## What changed on the box

`oidx-gateway.service` was **stopped and disabled** (won't return on boot).
Verified after: APISIX `:443` → 200 and all 7 services healthy — nothing
depended on `:8008`. The `:8008` scrape target was dropped from
`deployments/monitoring/prometheus.yml`.

Rollback (if ever needed): `systemctl --user enable --now oidx-gateway.service`.

## Guidance: pick one edge

`gateway-service` is **kept in the codebase** — it's a valid edge for a
deployment that doesn't run APISIX (e.g. a simpler single-binary front). But run
**one** edge, never both: either APISIX (recommended, and what the box uses) **or**
`gateway-service`. If you adopt `gateway-service` as your edge, don't also expose
the service ports through APISIX, and vice-versa.
