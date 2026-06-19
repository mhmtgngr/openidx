# OpenIDX Architecture & HA Review — Performance, Security, Availability

**Scope:** the production Kubernetes / EKS path (Helm + Terraform). Analysis only.
**Headline question:** *is one nginx enough, or should there be more?* → **No, run more than one** (see §2).

**Overall verdict:** the design is ~70% production-grade. The Kubernetes path
already has multi-replica services, HPA, PDB, pod anti-affinity, health probes,
multi-AZ EKS, ElastiCache failover, distributed rate-limiting, RLS, and full
observability. The gaps are specific and fixable — and the single biggest one is
**not** the edge (§3, background-job singletons).

Each section is scored: 🟢 Good · 🟡 Adequate · 🔴 Needs work.

---

## 1. Current topology

```
                          ┌─────────── today: THREE proxy layers ───────────┐
Client ──TLS──> nginx edge ───> APISIX gateway ───> gateway-service (Go) ───> microservices
                (TLS term,      (routing, rate-      (JWT, rate-limit;          (2–3 replicas each)
                 sec headers,    limit, CORS,         MOSTLY BYPASSED)
                 gzip)           forward-auth)
                                                                                    │
                              ┌──────────────────────────────┬────────────────────┤
                              ▼                              ▼                     ▼
                        RDS PostgreSQL                 ElastiCache Redis      OpenSearch
                        (single-AZ by default)         (3-node failover)      (external)
```

Services: identity 8001 · governance 8002 · provisioning 8003 · audit 8004 ·
admin-api 8005 · oauth 8006 · access 8007 · gateway 8008, plus the admin-console SPA.

- Edge nginx: `deployments/docker/nginx/nginx.conf`
- APISIX gateway: `deployments/docker/apisix/` (routes + `limit-req`, CORS, forward-auth, prometheus)
- gateway-service: `cmd/gateway-service`, `internal/gateway/` (JWT/JWKS, Redis rate-limit, tenant header)
- Helm: `deployments/kubernetes/helm/openidx/` · Terraform: `deployments/terraform/`

---

## 2. The edge / nginx answer 🟡

**Yes — there should be more than one nginx.** nginx is stateless (TLS
termination + routing only), so the correct production pattern is:

```
Route53 → AWS NLB (L4, multi-AZ, the ONE stable entry) → N≥2 ingress/nginx replicas (AZ-spread) → services
```

The NLB is the single stable IP/DNS target; the nginx/ingress pods behind it are
cattle — any one can die and the NLB routes around it. **One nginx is both a
single point of failure and a throughput ceiling.** Today's test box (one nginx
container) is fine for testing but must not be the production shape.

What the repo has and what to make explicit:
- `templates/ingress.yaml` defines Ingress resources but **assumes** a
  cluster-provided ingress controller — it pins neither the controller's replica
  count nor the cloud-LB type. Make it explicit: ingress-controller Deployment
  **≥2 replicas + HPA + `topologySpreadConstraints` across AZs**, fronted by an
  **AWS NLB** (annotation `service.beta.kubernetes.io/aws-load-balancer-type: nlb`).

**Architectural smell — three proxy layers.** Requests can traverse
nginx → APISIX → gateway-service before reaching a service. That is two hops too
many: extra latency, three things to scale/secure/observe, and `gateway-service`
is already bypassed for most routes. **Collapse to two layers:**

```
AWS NLB  →  ONE L7 API gateway (APISIX)  →  services
```

Pick **APISIX** as the single gateway (it already does TLS, `limit-req`, CORS,
forward-auth, prometheus). Run it **≥2 replicas with a clustered etcd** (compose
ships a single etcd — a SPOF for gateway config). Remove `gateway-service` from
the hot path unless a concrete request-aggregation need justifies it; its JWT and
rate-limit duties belong in APISIX. (If you prefer nginx-ingress as the L7 entry,
that's also fine — the point is *one* L7 gateway, not three layers.)

> **Bottom line:** more nginx — yes, ≥2 behind an NLB — but the higher-value move
> is *fewer layers*: NLB + one gateway, horizontally scaled.

---

## 3. Availability 🔴 (the real risks live here, not at the edge)

**P0 — Background-job singletons with no leader election.** ~7 critical loops run
on *every* replica with no coordination, so at the prod 2–3 replicas they
**already double/triple-run today** and get worse as you scale:

| Loop | File | Effect at N replicas |
|------|------|----------------------|
| Session-expiry sweep | `internal/oauth/session_worker.go` | revokes each session N× |
| Campaign scheduler | `internal/governance/service.go` | triggers each campaign N× |
| Continuous verifier | `internal/access/continuous_verify.go` | re-verifies sessions N× |
| Grace-period enforcer | `internal/access/agent_api.go` | escalates identities N× |
| Webhook delivery + retry | `cmd/oauth-service/main.go` | **duplicate webhook deliveries** |
| Directory / LDAP sync | `cmd/identity-service/main.go` | N concurrent syncs of same directory |

**Fix direction:** introduce **leader election** — a Kubernetes `Lease`
(`k8s.io/client-go/tools/leaderelection`) or a Redis lock (the cache layer at
`internal/common/cache/redis.go` already supports distributed locks) — so exactly
one replica owns each loop. Alternatively, extract all background loops into a
dedicated **worker Deployment with `replicas: 1`** (or K8s `CronJob`s), leaving
the API Deployments purely request-serving. This is the **#1 item** — it's a
correctness bug that scaling makes worse, and it's invisible until you look.

**P0 — RDS is not Multi-AZ.** Terraform `rds` defaults `multi_az = false`
(`deployments/terraform/.../rds/variables.tf`) and the root module doesn't
override it → the database is a single-AZ SPOF. Set **`multi_az = true`** for
prod (synchronous standby, automatic failover).

**P1 — Data-tier redundancy.** ElastiCache prod is healthy (3-node, automatic
failover, multi-AZ). Ensure prod **never** falls back to the in-cluster single
Redis (Helm `redis.sentinel.enabled = false`) — always point at managed
ElastiCache. OpenSearch is external (good) but unmanaged by Terraform — bring it
under IaC. Add a **read replica** for read-heavy audit/governance traffic.

**P1 — Deployment hardening (default `values.yaml`).** Add **startup probes**
(slow-start safety), **`topologySpreadConstraints`** to spread replicas across
AZs (anti-affinity is node-level only today), and an explicit RollingUpdate
strategy (`maxUnavailable: 0`, `maxSurge: 1`) for zero-downtime deploys. Use a
**per-AZ HA NAT gateway** in prod (Terraform uses a single NAT for dev). PDBs and
NetworkPolicy are already present 🟢.

---

## 4. Performance (fast response) 🟡

- **Edge — enable HTTP/2** (not set in `nginx.conf`) and **brotli** (only gzip
  today, level 6); keepalive/`tcp_nopush`/`tcp_nodelay` already tuned 🟢.
- **SPA static assets — add a CDN.** The admin-console build is served straight
  from nginx with no edge cache. Put it behind **CloudFront**: long-lived
  immutable caching for hashed `assets/*`, `no-cache` for `index.html`. Biggest
  perceived-latency win for end users, and it offloads the edge.
- **Database connections.** Pool is 25 max / 5 min per instance
  (`internal/common/database/database.go`). With many replicas × pools you can
  exhaust RDS `max_connections` — front Postgres with **PgBouncer** (transaction
  pooling) and route read-heavy queries to a **read replica**.
- **Caching.** Redis cache layer (5-min TTL, metrics, locks) and in-memory JWKS
  cache exist 🟢. HTTP response caching is currently only on the audit-stats route
  (APISIX `proxy-cache`) — widen it to other cacheable GETs (dashboard, discovery).
- **Profiling.** Audit and governance queries are the likely N+1 hotspots — add
  query timing/`pg_stat_statements` review before scaling reads.

---

## 5. Security 🟢 (strong baseline) / 🟡 (edge gaps)

**Solid today:** TLS ≥ 1.2 (`internal/common/tlsutil`), defense-in-depth security
headers at both nginx and Go (`internal/common/middleware/security.go`: CSP, HSTS,
X-Frame-Options, Permissions-Policy), distributed rate-limiting that
**fails closed on auth paths** (`internal/common/middleware/ratelimit.go`),
per-org RLS belt, cryptographic secret generation
(`scripts/generate-secrets.sh`), startup production-config validation, and the
OpenZiti zero-trust overlay for app access.

**Gaps:**
- **No WAF.** Add **AWS WAF** (managed OWASP rule set) at the NLB/ALB for L7
  protection (SQLi/XSS/bot/rate rules) the app shouldn't have to self-enforce.
- **Inter-service mTLS disabled** (`serviceTLS.enabled = false`). East-west
  traffic is plaintext inside the cluster. Either enable in-mesh mTLS (a service
  mesh or the existing TLS plumbing) or rely explicitly on the OpenZiti overlay +
  NetworkPolicy and document that decision.
- **APISIX admin key hardcoded** in `deployments/docker/apisix/config.yaml` →
  move to a Kubernetes Secret / Vault; rotate.
- **In-memory rate-limit fallback** (`internal/governance/zt_policy_handler.go`)
  diverges per replica when Redis is down → each replica permits the full quota
  (≈N× bypass). Force-Redis (fail-closed) everywhere security-sensitive.
- **Single etcd** behind APISIX → cluster it (3 nodes) so gateway config isn't a
  SPOF, and so config writes survive a node loss.

---

## 6. Target architecture + prioritized roadmap

```
                    ┌─────────────────────────────────────────────────────────┐
 Route53 ─────────> │ AWS NLB (L4, multi-AZ)  +  AWS WAF                       │
                    └─────────────────────────────┬───────────────────────────┘
                                                  ▼
                           APISIX gateway  (≥2 replicas, etcd cluster)   ← ONE L7 gateway
                                                  ▼
            microservices (2–3 replicas · HPA · PDB · anti-affinity · AZ topology spread)
                                                  │
                ┌─────────────────────────────────┼──────────────────────────────┐
                ▼                                 ▼                              ▼
        RDS PostgreSQL Multi-AZ            ElastiCache Redis (3-node)        OpenSearch
        (+ read replica, PgBouncer)        (failover, encrypted)            (managed)

   singleton worker Deployment (replicas=1, leader-elected) ── owns ALL background loops
   admin-console SPA ── served via CloudFront CDN
   OpenZiti overlay ── zero-trust access to published internal apps
```

**Roadmap (by priority):**

- **P0 (correctness / SPOF — do first):**
  1. Leader election (or a `replicas:1` worker Deployment) for the §3 background loops.
  2. RDS `multi_az = true`.
  3. Explicit ingress HA: ≥2 controller replicas behind an AWS NLB.
- **P1 (resilience / hardening):**
  4. Collapse the three proxy layers → NLB + APISIX (drop gateway-service from the hot path).
  5. AWS WAF at the edge.
  6. Force-Redis rate limiting (remove the divergent in-memory fallback on security paths).
  7. APISIX etcd cluster + move the admin key to a secret.
  8. CloudFront in front of the SPA.
- **P2 (scale / polish):**
  9. RDS read replica + PgBouncer; profile audit/governance N+1.
  10. HTTP/2 + brotli at the edge.
  11. Inter-service mTLS (or documented OpenZiti+NetworkPolicy stance).
  12. Startup probes + `topologySpreadConstraints` + explicit RollingUpdate in default values.

---

## 7. Scorecard

| Dimension | Score | One-line |
|-----------|-------|----------|
| Availability | 🔴 Needs work | Background-job singletons + single-AZ RDS undercut the otherwise-good multi-replica K8s setup. |
| Performance | 🟡 Adequate | Good pooling/caching/keepalive; missing CDN, HTTP/2, read replicas. |
| Security | 🟢 / 🟡 | Strong app-layer baseline; edge WAF, mTLS, secret-managed APISIX, force-Redis RL outstanding. |
| Edge / "more nginx" | 🟡 | Run ≥2 behind an NLB **and** collapse three proxy layers to one gateway. |

The roadmap items are intentionally not implemented here — each P0/P1 becomes a
follow-up task when you choose to act on it.
