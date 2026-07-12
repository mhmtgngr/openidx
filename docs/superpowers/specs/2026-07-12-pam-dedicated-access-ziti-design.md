# PAM dedicated brokered access + OpenZiti target hop — design

> Design spec. Turns PAM brokered RDP/SSH/VNC launches (the current 503) into a **dedicated,
> self-owned session broker**, and adds **OpenZiti as a zero-trust data plane for the target
> hop** so guacd reaches RDP/SSH/VNC over the overlay instead of dialing the target directly.
> Follows the M1–M5 PAM foundations and the merged RDM-parity connection manager (#437).

## Context — why the 503, and why not the shared stack

`handlePamConnect` (`internal/access/pam_launch.go:220`) and `handleGuacamoleConnect`
(`internal/access/guacamole.go:439`) return **503 `Guacamole is not configured`** whenever
`s.guacamoleClient == nil`, which is exactly when `GUACAMOLE_URL` is unset. On the reference box
`GUACAMOLE_URL` is unset for the access-service, so every brokered launch 503s. This is a
**deployment-topology gap, not a code bug** — the injection/approval/recording/ledger code is all
present and unit-tested.

The box *does* run a Guacamole stack, but it is the **shared BrowZer front-door** deployment:

- It authenticates end-users via **header-auth (trusted proxy) + LDAP**, not the username/password
  REST login OpenIDX's `GuacamoleClient` uses (`POST /api/tokens`, `guacamole.go:125`).
- OpenIDX has **no REST admin credential** for it, and guessing/resetting one or repointing it
  risks breaking the running BrowZer topology (the `guacamole-zbr-proxy` + WASM tunnel shim in
  `deployments/docker/docker-compose.yml:820-1101`).

So PAM must **not** hijack the shared stack. The decision (confirmed): **stand up a dedicated
Guacamole owned by OpenIDX PAM**, isolated from the BrowZer front door — and, since the reference
platform is already an OpenZiti overlay, make the target hop **zero-trust over Ziti**.

### What already exists (reuse, do not rebuild)

| Capability | Where | State |
|---|---|---|
| Guacamole REST client (create/update/delete conn, force-terminate, share, active sessions) | `internal/access/guacamole.go` | Production |
| Server-side credential injection into brokered sessions | `pam_launch.go` `buildPamGuacParams` / `handlePamConnect` | Merged (#437) |
| Approval gate, session ledger, recording params, retention/legal-hold | `guacamole_sessions.go`, `remote_support_retention.go` | Production |
| Full OpenZiti provisioning: service / identity / Bind+Dial policy / `host.v1` config / terminator CRUD | `internal/access/ziti.go` `ZitiManager` (`CreateService`, `EnsureServicePolicy`, `CreateHostV1ConfigFixed`, `SetupZitiForRoute`) | Production |
| SDK dial + bind data plane (`zitiCtx.Dial`, `zitiCtx.Listen`) | `ziti.go:908`, `ziti.go:255` | Production |
| Declarative Ziti reconciler (DB = desired state → controller) | `ziti_reconciler.go` | Production (default) |
| Per-app loopback **port allocator** (hop ports) | `browzer_targets.go:257` `assignHopPorts` | Production — template for Ziti-mode intercept ports |

### Gaps this design closes

- **No dedicated broker.** guacd/guacamole exist only in dev compose; in prod they're `restart:"no"`
  behind the `ziti` profile; **absent entirely from Kubernetes/Helm**.
- **No shared recording volume.** guacd has zero `volumes:`; access-service mounts none for
  recordings — so the M3/M4 recording write→purge contract has no on-disk substrate.
- **Target hop is not zero-trust.** guacd connects **directly** to `remote_host:remote_port`
  (`provisionGuacamoleForRoute`, `guacamole.go:647`), so every RDP/SSH/VNC target must be
  network-reachable from guacd and expose an inbound listening port to the broker network.
- **Hard 503 UX.** The launcher can't tell a broker is missing until it clicks Connect and gets 503.

## Goals / non-goals

**Goals**
1. A **dedicated PAM session broker** (guacd + Guacamole REST, JDBC/Postgres auth) owned by
   OpenIDX, isolated from the shared BrowZer stack, with its own admin credential and a **shared
   recording volume** — so `direct`-mode brokered launches work end-to-end.
2. **OpenZiti reach mode**: guacd reaches the target **over the overlay** (no inbound target
   exposure), provisioned from the existing `ZitiManager`, selectable **per PAM entry**.
3. Graceful degradation: the UI knows whether a broker exists and which reach modes it supports;
   Connect never dead-ends on a bare 503.
4. Deploy artifacts for **both** docker-compose and Helm (close the k8s gap).

**Non-goals**
- Replacing Guacamole with a bespoke RDP/SSH gateway.
- Touching the shared BrowZer Guacamole or its header-auth/LDAP flow.
- Ziti/BrowZer for the *web-UI* front door (already solved); this spec is about the **target hop**.

## Architecture

```
                         OpenIDX access-service (PAM)
                                    │  1. resolve credential from vault (server-side)
                                    │  2. ensure Guacamole connection (inject creds)
                                    │  3. return connect URL only
                                    ▼
   browser ──HTTPS──▶  Dedicated PAM Guacamole (REST + web)  ──▶  guacd
   (HTML5 RDP/SSH/VNC)   JDBC/Postgres auth, own admin cred          │
                                                                     │ reach_mode
                                          ┌──────────────────────────┴───────────────────────┐
                                          ▼ direct                                            ▼ ziti
                              guacd ──TCP──▶ target:port                    guacd ──▶ 127.0.0.1:<port> (ziti-tunnel, proxy mode)
                              (target reachable, inbound port)                         │  dial Ziti service pam-<entry_id>
                                                                                       ▼
                                                                    edge router hosts host.v1 {tcp, target, port}
                                                                                       ▼
                                                                                   target:port
                                                                    (NO inbound exposure — target/router dials out)
```

### The dedicated broker

A new **`pam-broker`** deployment unit, separate from the BrowZer Guacamole:

- **`pam-guacd`** — `guacamole/guacd`, plus (for Ziti mode) a colocated **`ziti-tunnel`** in
  **proxy mode** enrolled as a dedicated Ziti identity `pam-broker` (role `#pam-broker-dialers`).
- **`pam-guacamole`** — `guacamole/guacamole` with the **JDBC/Postgres auth extension** so OpenIDX
  holds a real REST `guacadmin` credential (the shared stack's header-auth is why we can't reuse it).
  Its schema lives in a dedicated `pam_guacamole` database (reuse the `init-guacamole.sql` pattern).
- **Shared `pam_recordings` volume** mounted into **both** `pam-guacd` (`recording-path` target) and
  **access-service** (retention sweeper + transcript reads) — closes the missing-volume gap.
- access-service points `GUACAMOLE_URL` at **this** web app (`http://pam-guacamole:8080/guacamole`),
  `GUACAMOLE_RECORDING_PATH=/recordings`, and a dedicated `GUACAMOLE_ADMIN_PASSWORD`.

Nothing here touches the shared `guacamole`/`guacd`/`guacamole-zbr-proxy` services.

### OpenZiti reach mode (the zero-trust target hop)

The crux of "add OpenZiti support." Today guacd → **direct TCP** → target. We add a per-entry
**`reach_mode`** of `ziti`, where guacd reaches the target **over the overlay**:

**Provisioning (access-service, reusing `ZitiManager`)** — at entry-create or lazily at first connect:
1. `CreateHostV1ConfigFixed(ctx, "pam-<entry>-hostv1", target_host, target_port)` → a `host.v1`
   pinned to `{protocol:tcp, address:target_host, port:target_port}`.
2. `createServiceWithConfigID(ctx, "pam-<entry_id>", ["#pam-<entry_id>"], hostV1ID)` → the Ziti
   service for this target.
3. `EnsureServicePolicy` **Bind** `#pam-<entry_id>` → `#ziti-routers` (edge-router-hosted, matching
   the existing BrowZer `direct` hosting mode — no software on the target network beyond an edge
   router), and **Dial** `#pam-<entry_id>` → `#pam-broker-dialers` (only the PAM broker identity
   may dial it).
4. `EnsureServiceEdgeRouterPolicy` + role attributes as `SetupZitiForRoute` already does.

**Connect-time wiring (`handlePamConnect`, ziti mode):**
- The `pam-guacd` sidecar tunneler binds a **stable loopback port** per service (allocated by a
  `assignHopPorts`-style allocator; persisted as `pam_entries.ziti_intercept_port`).
- access-service sets the Guacamole connection's `hostname=127.0.0.1`, `port=<ziti_intercept_port>`
  instead of the real target. Everything else — credential injection, recording, approval — is
  **unchanged**.
- guacd opens RDP/SSH/VNC to `127.0.0.1:<port>`; the tunneler dials Ziti service `pam-<entry_id>`;
  the edge router's `host.v1` terminator opens the final TCP leg to `target:port`.

**Result:** the target exposes **no inbound RDP/SSH port to the broker network** — the edge router
(or a target-side tunneler) dials outbound to the controller. Mutual-TLS, end-to-end encrypted
overlay. Each PAM entry is its own Ziti service with a Dial policy scoped to the single broker
identity → per-target least privilege; deleting the entry tears down its service + policies.

**Why proxy-mode loopback (not intercept.v1/tproxy) as the default:** proxy mode needs no
`NET_ADMIN`/tproxy/DNS inside the guacd container, mirrors the existing hop-port allocator, and
keeps the guacd image close to stock. `intercept.v1` + tproxy (address `pam-<id>.ziti`, no port
allocation) is a cleaner future option once the broker runs with tunneler DNS.

## Data model — migration vNN

Additive columns on `pam_entries` (org-scoped table already under the v37 RLS belt; idempotent
`ADD COLUMN IF NOT EXISTS`):

- `reach_mode VARCHAR(16) NOT NULL DEFAULT 'direct'` — `direct` | `ziti`.
- `ziti_service_name VARCHAR(255)` — the provisioned service name (NULL until provisioned).
- `ziti_intercept_port INTEGER` — the broker-side loopback port (NULL for `direct`).

No new tables. `direct` is the default so every existing entry is unchanged.

## Config

- Reuse `GUACAMOLE_URL` / `GUACAMOLE_ADMIN_USER` / `GUACAMOLE_ADMIN_PASSWORD` /
  `GUACAMOLE_RECORDING_PATH` (`config.go:131-135`) — now pointed at the **dedicated** broker.
- Reuse the existing Ziti connection (`ZitiCtrlURL`/admin/identity) and `ZitiProvider` already wired
  into access-service — the PAM reach mode calls the same `s.ziti()` manager.
- New: `PAM_BROKER_ZITI_INTERCEPT_BASE_PORT` (default e.g. `14000`) for the loopback allocator, and
  a `pam-broker` Ziti identity/role for the tunneler.

## Graceful degradation (kill the bare 503)

- New `GET /api/v1/access/pam/broker/status` → `{ available: bool, reach_modes: ["direct","ziti"] }`
  (`available = s.guacamoleClient != nil`; `ziti` present when `s.ziti() != nil`).
- `handlePamConnect` returns a **structured** 503 `{ error, code: "broker_unconfigured" }` instead of
  a bare string, so the UI can render an explainer and disable Connect on session entries when no
  broker exists — rather than dead-ending on click.
- Connections page: gray the Connect button + "Ask an admin to configure a session broker" when
  `available=false`; show a "via Ziti" badge on `ziti`-mode entries.

## Deploy artifacts

**docker-compose** (a `pam-broker` overlay file, opt-in): `pam-guacd` (+ `ziti-tunnel` sidecar),
`pam-guacamole` (JDBC/Postgres, `pam_guacamole` DB), a named `pam_recordings` volume mounted into
`pam-guacd` **and** access-service, and access-service env `GUACAMOLE_URL=http://pam-guacamole:8080/
guacamole`, `GUACAMOLE_RECORDING_PATH=/recordings`, `GUACAMOLE_ADMIN_PASSWORD=<dedicated>`.

**Helm** (closes the k8s gap): a `pam-broker` sub-chart — guacd Deployment, guacamole Deployment +
Service, an **RWX PVC** `pam-recordings` mounted into guacd and access-service, and the `GUACAMOLE_*`
env on the access-service Deployment. Ziti mode adds the tunneler as a guacd sidecar container with
the enrolled `pam-broker` identity mounted from a Secret.

## Security model

- **Zero inbound target exposure** in `ziti` mode — the overlay terminator dials out; no listening
  RDP/SSH reachable from the broker network. This is the headline zero-trust gain.
- **Credential still injected server-side** — unchanged; the plaintext never reaches the browser
  and never rides the client leg.
- **Per-target least privilege** — one Ziti service + Dial policy per PAM entry, scoped to the single
  `pam-broker` dialer identity. Entry delete → service/policy teardown (extend `handlePamDeleteEntry`).
- **Isolation** — dedicated broker with its own admin credential and DB; the shared BrowZer stack is
  untouched. Recording/retention/legal-hold inherit the existing pipeline once the volume is wired.

## Phased plan

- **P0 — graceful UX (small, ship first):** `broker/status` endpoint + structured 503 code +
  Connections-page capability handling. No deploy dependency.
- **P1 — dedicated broker (`direct` works for real):** compose `pam-broker` overlay + Helm sub-chart
  + shared recording volume; point `GUACAMOLE_URL` at it. Verifies the whole injection/recording path.
- **P2 — OpenZiti reach mode:** `reach_mode`/`ziti_service_name`/`ziti_intercept_port` migration;
  connect-time service provisioning via `ZitiManager`; guacd tunneler sidecar + loopback allocator;
  entry-delete teardown.
- **P3 — hardening/options:** `intercept.v1`+tproxy alternative; optional target-side tunneler hosting
  (vs edge-router); per-org broker pools.

## Verification

- Unit: reach-mode param wiring (guacd `hostname/port` = loopback in ziti mode, real target in
  direct); `broker/status` capability shape; Ziti provisioning idempotency (reuses `ZitiManager`
  tests' patterns).
- Integration: compose `pam-broker` up → provision an RDP entry → Connect opens a session with the
  password injected → recording lands on the shared volume → retention sweeper sees it. Ziti mode:
  target with **no inbound RDP rule**, only an edge-router `host.v1` → Connect still succeeds over
  the overlay; force-terminate + audit trail intact.
- Gates: `go build/vet`, `gofmt`, `orgscope -fail ./internal`, unit/race, `tsc` + frontend build.

## Open decisions (need a call before P2)

1. **Ziti client leg:** proxy-mode loopback ports (recommended — container-friendly, mirrors hop
   allocator) vs `intercept.v1` + tproxy DNS.
2. **Target-side hosting:** edge-router-hosted `host.v1` (recommended — no target-side software) vs a
   tunneler on/near the target (finer origin control, more to deploy).
3. **Provisioning timing:** provision the Ziti service at **entry-create** (fail fast, steady state)
   vs **lazily at first connect** (no orphan services for never-launched entries).

## Critical files (anchors)

- 503 branch: `internal/access/pam_launch.go:220`; direct-target provisioning today:
  `internal/access/guacamole.go:647`.
- Ziti provisioning to reuse: `internal/access/ziti.go` (`CreateHostV1ConfigFixed:1955`,
  `createServiceWithConfigID:2030`, `EnsureServicePolicy:1141`, `SetupZitiForRoute:1349`),
  `ziti_reconciler.go` (declarative convergence), `browzer_targets.go:257` (`assignHopPorts`).
- Broker config: `internal/common/config/config.go:131-135`; wiring: `cmd/access-service/main.go:283`.
- Deploy: `deployments/docker/docker-compose.yml:813-867` (existing guac services to NOT reuse),
  `deployments/docker/init-guacamole.sql` (schema pattern), `deployments/kubernetes/helm/openidx/`
  (add `pam-broker`).
