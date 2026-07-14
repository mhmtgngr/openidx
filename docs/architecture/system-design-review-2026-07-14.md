# OpenIDX — System Design Review & Advice

> A grounded review of the OpenIDX system as actually deployed (single-VM, rootless podman + `systemd --user`) — structure, traffic flow, and how to make it more correct, simpler, more available, faster, and more secure. Dated 2026-07-14.

**What prompted this:** you want to step back from feature work and look at the whole system — structure, how traffic flows, and how to make it more correct, simpler, more available, faster, and more secure — and have a document to think with.

---

## 1. Current state (what you actually run)

**Topology on the box (one Azure VM, rootless podman + `systemd --user`):**

```
Browser / API client
      │  https://*.tdv.org:443
      ▼
┌───────────────┐   :443 edge, TLS, routes by path/host
│  oidx-apisix  │───────────────────────────────────────────────┐
└───────┬───────┘                                                │
        │ /api/v1/identity   → :8001   /oauth,/.well-known → :8006│
        │ /api/v1/governance → :8002   /api/v1/access      → :8007│
        │ /api/v1/provision  → :8003   /api/* (admin)       → :8005│
        │ /api/v1/audit      → :8004   /* (SPA)  → oidx-nginx :8443│
        ▼                                                         ▼
  8 Go services (:8001–8008)  ── all read/write ──►  ONE Postgres (oidx-pg)
  identity/governance/provisioning/audit/admin/oauth/access/gateway
        │                                            Redis (1)  · Elasticsearch (1)
        ├─ OPA (:8281, optional authz)
        ├─ Guacamole PAM brokers ×2 (direct :10090 + ziti)
        └─ OpenZiti controller + router  →  BrowZer clientless data plane
```

**Key characteristics:**
- **8 services, 1 database.** Services are separate processes but share one Postgres schema (v87) and the `openidx_app` RLS role. They do **not** call each other over HTTP in the hot path — they meet at the database.
- **Multi-tenant via Postgres RLS.** Every pooled connection is stamped with `app.org_id` at checkout (`internal/common/database/rls.go`); tenant resolved from subdomain / JWT / `X-Org-ID` (`internal/common/middleware/tenant_resolver.go`). Fail-closed (no org → no rows).
- **Two overlapping edges.** `oidx-apisix` (:443, the real edge) **and** a `gateway-service` (:8008) that is a second reverse proxy. On the box, APISIX is authoritative; gateway-service is largely redundant.
- **Everything is single-instance.** Postgres, Redis, Elasticsearch, APISIX, nginx, the Ziti controller/router, and each Guacamole broker are all one-of. The VM itself is the ultimate SPOF.
- **Good bones already present:** RLS everywhere, JWKS RS256-pinned auth with a 1h cache, OPA fail-closed-in-prod, async (non-blocking) audit logging, per-connection RLS caching, graceful shutdown, `/health/{live,ready}` with dependency checks, OTel tracing hooks, versioned migrations.

---

## 2. The one structural insight that frames everything

**You have a "distributed monolith": micro-*services*, but a mono-*database*.** That's a legitimate, pragmatic choice — but be deliberate about it, because it drives the other dimensions:

- ✅ **Keep it** for now. Splitting the DB per service would be a huge amount of work for a product at this stage and would *cost* you the thing RLS gives you cheaply (one consistent tenant boundary). The shared DB is your biggest simplicity asset.
- ⚠️ **But stop pretending the 8 services are independent.** They deploy together, migrate together, and fail together (shared DB). Two honest options:
  1. **Lean in (recommended):** treat them as one logical app with 8 entrypoints. One release train, one migration gate, one health dashboard. This is basically what the box already does — just make it explicit.
  2. **Selective split later:** only carve out a service to its own store when it has a *genuinely* different scaling/availability profile (audit/event ingestion is the usual first candidate — high write volume, eventual consistency OK).

Everything below assumes option 1.

---

## 3. Recommendations by dimension

### A. Simplicity — remove moving parts (highest simplicity ROI)
1. **Collapse the double edge.** Pick APISIX as the *only* edge and retire `gateway-service` from the request path (or vice-versa), so there's exactly one place that knows the routing table. Two proxies = two configs that drift (you've already hit inode/routing drift this session). *Effort: M · Impact: high (fewer failure modes, one mental model).*
2. **One Guacamole broker unless you truly need two.** The direct + ziti brokers double the surface (two admin creds, two RemoteIpValve configs, two per-user account sets after the change you just shipped). Keep the second only for genuinely overlay-only targets; otherwise route ziti-reach through the direct broker's guacd over the tunnel. *Effort: M · Impact: medium.*
3. **Kill the `localtest.me` addresses in anything a remote party touches.** The Ziti controller advertising `ziti-controller.localtest.me:1280` already bit you (agent enrollment). Give the controller a real, resolvable name so you don't carry per-client `/etc/hosts` hacks. *Effort: M · Impact: medium (removes a whole class of "works on box, not remotely" bugs).*
4. **One canonical deployment definition.** The `docker-compose.pam-broker.yml` has drifted from the ad-hoc `podman run` containers. Make the compose/systemd units the *source of truth* so a rebuild reproduces the box. *Effort: M · Impact: high for disaster recovery.*

### B. Traffic flow & fast responses
1. **Keep external calls off the hot path.** OPA, Guacamole, and Ziti calls are synchronous on request paths today, some with a **60s** timeout. Any of them being slow stalls user requests. Fixes: short timeouts (≤2–3s), a per-dependency circuit breaker (you already have one for OPA — extend the pattern), and cache OPA decisions with a short TTL keyed on (subject, resource, action). *Effort: M · Impact: high tail-latency win.*
2. **Cache the hot lookups you already miss on.** JWKS (have 1h ✓), org lookup (30s ✓), and **role/permission resolution** — make sure the permission resolver is Redis-cached with a short TTL + explicit invalidation on role change, not re-queried per request. *Effort: S–M.*
3. **Keyset (cursor) pagination for the big lists.** Audit events and SCIM users use OFFSET/LIMIT; deep offsets get slow at scale. Switch the high-cardinality endpoints to keyset (`WHERE (ts,id) < ($1,$2) ORDER BY ts DESC, id DESC LIMIT n`). *Effort: M · Impact: audit/search stays fast as data grows.*
4. **Right-size the DB pool.** `DB_MAX_CONNS=25` per service × 8 services = up to 200 connections into one Postgres — but only if they all saturate. Set pool sizes from measured concurrency and cap total below Postgres `max_connections`; consider a **pgbouncer** (transaction pooling) in front so 8 services share a bounded pool. *Effort: S–M · Impact: prevents connection-exhaustion stalls.*
5. **Serve the SPA with far-future caching + hashed assets** (you already code-split). Make sure `oidx-nginx` sets long `Cache-Control` on hashed chunks and `no-cache` on `index.html`. *Effort: S.*

### C. Integrity (correctness of data & side-effects)
1. **Transactional outbox for audit + webhooks + external side-effects.** Today audit is dual-written (PG authoritative, ES best-effort) and webhooks fire inline. A crash between "DB commit" and "emit event/webhook" loses the event. Pattern: write the event to an `outbox` table *in the same transaction* as the state change, then a relay worker publishes to ES / webhooks / SIEM with at-least-once delivery + retries. This is the single biggest integrity upgrade for a compliance product. *Effort: M–L · Impact: high (audit you can trust; no lost/duplicated webhooks).*
2. **Idempotency keys on mutating public APIs** (SCIM create, PAM connect, provisioning). Store `(org_id, idempotency_key) → response`; replay returns the first result. Kills double-provisioning on client retries. *Effort: M.*
3. **Make RLS un-bypassable by construction.** You already run as non-owner `openidx_app` with FORCE RLS ✓. Add a CI check (extend your `orgscope` tool) that *fails the build* on any query to a tenant table lacking either an `org_id` predicate or an `//orgscope:ignore` with a reason — you already have the tool; make it a required gate. *Effort: S · Impact: high (prevents the classic cross-tenant leak).*
4. **Migration safety rail.** One shared DB means a bad migration halts everything. Adopt expand→migrate→contract (never drop/rename in the same release that stops using a column), and gate deploys on "migrations applied == binary expects." *Effort: S process change.*

### D. Availability (survive failures)
> On a single VM, true HA needs more than one host — but you can remove the *cheap* SPOFs and make the VM recover cleanly.
1. **Postgres is the crown jewel — protect it first.** Minimum: automated `pg_dump`/PITR (WAL archiving) with tested restore. Next step when ready: a warm standby (streaming replication) or move to managed Postgres. *Effort: S (backups) → L (HA).* **Do the backups this week.**
2. **Make Redis optional-degrade, not required.** Rate limiting and token revocation hard-depend on Redis today. Add a fail-open-with-alarm path (or a small in-process fallback) so a Redis blip doesn't take down auth. *Effort: M.*
3. **Reboot-safety audit.** You've been hardening systemd units piecemeal; do one pass confirming *every* container + service + the etcd APISIX depends on comes back on a cold boot, with a documented boot order. (etcd → apisix, pg → migrate → services.) *Effort: S–M · Impact: high — turns "reboot = incident" into a non-event.*
4. **Health checks that gate traffic.** Ensure APISIX routes honor `/health/ready` (don't send traffic to a service whose DB is down) and that readiness flips *unready* on dependency loss, not just at boot. *Effort: S.*

### E. Security (you've already done a lot this session)
1. **Just shipped ✓:** per-user Guacamole identities (no admin token in the browser), real-client-IP logging, per-user read-only monitoring. Good.
2. **Secrets off disk.** `run-access.sh` carries plaintext creds (Guacamole admin pw, etc.) inline. Move to a secrets file with `0600` at minimum, ideally a real secret store (you already have the `vault`/`secretcrypt` primitives in-repo). Rotate the ones that have been in plaintext. *Effort: M · Impact: high.*
3. **Service-to-datastore, not service-to-service, is your trust boundary — make it mTLS.** Postgres already supports TLS in your pool config; enforce `verify-full` + client certs so a foothold on the box can't just `psql` in. Same for Redis. *Effort: M.*
4. **Sign the release artifacts / supply chain.** You added Authenticode for the Windows client ✓; extend the mindset to the server (image digests pinned, SBOM, the CodeQL gate you already run kept required). *Effort: S–M.*
5. **Finish the `localtest.me`/self-signed cleanups** (controller advert address, any dev certs presented to real clients) — these are security-adjacent (cert trust) as well as simplicity. *Effort: M.*
6. **Rate-limit + lockout on the auth surface** (oauth login, MFA) independent of Redis availability. *Effort: S–M.*

### F. "Record & make it better" — observability (so you can *see* the above)
You have OTel hooks and per-check health latency, but no unified metrics/SLO view. This is what lets you tell whether the changes above actually help.
1. **Metrics:** expose Prometheus `/metrics` on every service (RED: rate/errors/duration per route + DB pool gauges + external-call latency). *Effort: M.*
2. **Tracing:** you have `otelgin` — wire an exporter (even a local Tempo/Jaeger) so a slow request shows *which* hop (OPA? Guacamole? DB?) hurt. *Effort: S–M.*
3. **A handful of SLOs + alerts:** p99 auth latency, error rate per service, DB connection saturation, cert-days-remaining (you already compute it), Redis/PG up. *Effort: S.*
4. **Structured audit → SIEM via the outbox** (ties to C.1): reliable, queryable security record. *Effort: folded into C.1.*

---

## 4. Prioritized roadmap

| # | Item | Dimension | Effort | Impact | Do when |
|---|------|-----------|--------|--------|---------|
| 1 | Automated Postgres backups + tested restore (+ WAL/PITR) | Availability | S | 🔴 critical | **now** |
| 2 | Reboot-safety pass + documented boot order | Availability | S–M | 🔴 high | now |
| 3 | Secrets off disk (0600 / secret store) + rotate | Security | M | 🔴 high | now |
| 4 | `orgscope` as a required CI gate | Integrity | S | high | now |
| 5 | Short timeouts + circuit breakers + OPA decision cache | Perf | M | high | soon |
| 6 | Transactional outbox (audit + webhooks) | Integrity | M–L | high | soon |
| 7 | Collapse double edge (APISIX only) | Simplicity | M | high | soon |
| 8 | Metrics `/metrics` + a few SLOs + tracing exporter | Observability | M | high | soon |
| 9 | pgbouncer + right-size pools | Perf/Avail | S–M | medium | soon |
| 10 | Redis fail-open-with-alarm | Availability | M | medium | next |
| 11 | Keyset pagination on audit/SCIM lists | Perf | M | medium | next |
| 12 | mTLS PG/Redis (`verify-full` + client certs) | Security | M | medium | next |
| 13 | Idempotency keys on mutating APIs | Integrity | M | medium | next |
| 14 | One canonical deploy definition (retire drift) | Simplicity | M | high-DR | next |
| 15 | Kill `localtest.me` external addresses / cert cleanup | Simplicity/Sec | M | medium | next |
| 16 | Single Guacamole broker (if feasible) | Simplicity | M | medium | later |
| 17 | Postgres warm standby / managed PG (true HA) | Availability | L | high | later |
| 18 | Carve out audit to its own store (if write volume grows) | Structure | L | situational | later |

**Suggested first sprint (all low-effort, high-safety):** #1, #2, #3, #4 — backups, reboot-safety, secrets, and the RLS CI gate. None change product behavior; all sharply reduce "3am incident" risk.

---

## 5. What NOT to do (avoid over-engineering)
- ❌ Don't split the shared database into per-service DBs now — you'd lose the RLS tenant boundary and gain distributed-transaction pain for no current benefit.
- ❌ Don't adopt Kubernetes just for HA yet — a warm Postgres standby + backups + reboot-safety gets you most of the resilience at a fraction of the operational cost on your single-VM reality.
- ❌ Don't add a message broker (Kafka/NATS) yet — the transactional *outbox* (a table + a relay goroutine) gives you reliable events without a new system to run.
- ❌ Don't microservice-split further — 8 services on 1 DB is already at the edge of worth-it; more boundaries = more overhead, not less.

---

## How to use this
Pick a cut line from the roadmap. The suggested first sprint (#1–#4: backups, reboot-safety, secrets off disk, `orgscope` CI gate) is all low-effort/high-safety and changes no product behavior. Any row can become its own implementation plan + PR.
