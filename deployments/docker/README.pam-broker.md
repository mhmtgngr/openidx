# PAM dedicated session brokers

Stands up the two dedicated Guacamole brokers the PAM connection manager routes
to **per connection** (each entry's `reach_mode`), isolated from the shared
BrowZer Guacamole:

| Broker | Services | Target hop |
|---|---|---|
| **direct** | `pam-guacd` + `pam-guacamole` | guacd dials the target `host:port` directly |
| **ziti** | `pam-guacd-ziti` + `pam-guacamole-ziti` + `pam-ziti-tunnel` | guacd dials a loopback port the `ziti-tunnel` carries over the OpenZiti overlay to an edge-router-hosted terminator — **no inbound target exposure** |

Both brokers use the Guacamole JDBC/Postgres auth extension (a dedicated
`pam-guac-postgres` with two databases) so OpenIDX holds a real REST admin
credential — the shared stack's header-auth is why it can't be reused. A single
`pam_recordings` volume is shared by both `guacd`s and the access-service so the
recording + retention pipeline has an on-disk substrate.

The access-service picks the broker at connect time via `brokerFor(reach_mode)`;
a `ziti` connection is never launched through the direct broker (it can't see the
overlay loopback ports) or vice-versa.

## Docker Compose

```bash
# 1. Generate secrets (adds GUACAMOLE_ZITI_ADMIN_PASSWORD + PAM_GUAC_DB_PASSWORD).
./scripts/generate-secrets.sh

# 2. Bring the stack up with the broker overlay layered on the base compose.
cd deployments/docker
docker compose -f docker-compose.yml -f docker-compose.pam-broker.yml up -d
```

This overrides the access-service's `GUACAMOLE_URL` to point at `pam-guacamole`,
sets `GUACAMOLE_ZITI_URL` to `pam-guacamole-ziti`, sets
`GUACAMOLE_RECORDING_PATH=/recordings`, and mounts the shared `pam_recordings`
volume. **Direct-mode brokered launches now work end-to-end.**

Broker web consoles (for debugging): direct `:8086`, ziti `:8087`.

## Kubernetes (Helm)

Disabled by default. Enable and supply the broker secrets:

```bash
helm upgrade --install openidx deployments/kubernetes/helm/openidx \
  --set pamBroker.enabled=true \
  --set secrets.pamGuacDbPassword=<pw> \
  --set secrets.guacamoleAdminPassword=<pw> \
  --set secrets.guacamoleZitiAdminPassword=<pw>
```

This renders the two broker Deployments + Services, the ziti-tunnel sidecar (in
the ziti guacd pod), a **ReadWriteMany** `pam-recordings` PVC (mounted into both
`guacd`s and the access-service), and injects the `GUACAMOLE_*` / `GUACAMOLE_ZITI_*`
env into the access-service. The brokers expect a Postgres reachable at
`pamBroker.db.hostname` with the Guacamole schema in `guac_direct` + `guac_ziti`
(load `init-guacamole.sql` into each). When `pamBroker.enabled=false` (default)
nothing changes for existing deployments.

## Enabling Ziti reach on a connection

1. In the admin console (**PAM → Connections**), toggle **Ziti** on a session
   entry — OpenIDX provisions a per-entry Ziti service (`openidx-pam-<id>`,
   host.v1 → target, Bind → `#ziti-routers`, Dial → `#pam-broker-dialers`) and
   allocates a broker loopback port.
2. The `pam-ziti-tunnel` must run an enrolled identity carrying the
   `#pam-broker-dialers` role so it may dial those services.

### Enrolling the ziti-tunnel identity

Create an identity with the `pam-broker-dialers` role attribute and enroll it:

- **Compose:** mount an enrolled identity at
  `pam_ziti_identity:/ziti-identity/pam-broker.json`, or drop a one-time
  enrollment JWT at `/ziti-identity/pam-broker.jwt` and the entrypoint enrolls it.
- **Helm:** set `pamBroker.zitiTunnel.identitySecret` to a Secret containing
  `pam-broker.json`.

### The loopback-binding last mile

OpenIDX's reach mode uses proxy-loopback ports (host.v1 services, no
`intercept.v1`), so the tunnel must **proxy** each service→port pair. The current
mapping is served by the access-service at
`GET /api/v1/access/pam/broker/ziti-bindings` (admin-guarded) and logged by the
tunnel entrypoint for visibility. The exact tunneler proxy invocation is
OpenZiti-tunneler-version specific and is centralized in
`pam-ziti-tunnel-entrypoint.sh` — override that command for your tunneler build.
**Toggling a new ziti entry changes the binding set; restart the tunnel (or wire
the planned reconciler) to pick it up.** This is the remaining operational
step to make ziti-reach traffic flow; direct-reach needs none of it.

## Files

- `docker-compose.pam-broker.yml` — the compose overlay (postgres, both brokers, tunnel, access-service overrides, volumes).
- `init-pam-guac.sh` — creates `guac_direct` + `guac_ziti` and loads the Guacamole schema.
- `pam-ziti-tunnel-entrypoint.sh` — enrolls + runs the ziti-tunnel.
- `../kubernetes/helm/openidx/templates/pam-broker.yaml` — the Helm manifests.
- Design: `../../docs/superpowers/specs/2026-07-12-pam-dedicated-access-ziti-design.md`.
