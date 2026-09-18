# Operator Guide

This is the short manual for the person who installs, upgrades and keeps an
OpenIDX deployment honest. It condenses the deployment reference, the
hardening checklist, the readiness programme's controls and the global-scale
plan into what an operator has to know, in the order an operator meets it.
Every claim names the file or job that settles it, so it can be re-checked;
where a thing is not proven, this page says so instead of implying it.

It is not the history. The six-thousand-line
[`PROJECT-READINESS-GUIDE.md`](https://github.com/mhmtgngr/openidx/blob/main/docs/PROJECT-READINESS-GUIDE.md)
records how each control came to be and what it found on the way; the
[global-scale plan](https://github.com/mhmtgngr/openidx/blob/main/docs/plans/2026-09-13-global-scale-cell-architecture-plan.md)
records what is open and why. Read those when you need the reasoning. Read
this when you need to run the thing.

---

## 1. What you are running

Nine Go services, one console, a policy engine, an optional network overlay
and one data store under FORCE row-level security. Every service serves
`GET /health` (full report), `GET /health/ready` (readiness: database and
Redis) and `GET /health/live`, and exposes Prometheus metrics at
`GET /metrics`.

| Service | Port | What it does | Availability plane |
|---|---|---|---|
| `oauth-service` | 8006 | The identity provider: OAuth 2.0 / OIDC, token minting, JWKS, SAML | ISSUE |
| `identity-service` | 8001 | Users, groups, roles, MFA, the login surface, the portal | ISSUE and ADMIN (splittable, §7) |
| `governance-service` | 8002 | Access reviews, entitlements, PAM vault and grants, SoD | ADMIN |
| `provisioning-service` | 8003 | SCIM in and out, directory sync, joiner/mover/leaver | ADMIN |
| `audit-service` | 8004 | Tamper-evident audit trail, SIEM forwarding, usage metering | EVENT |
| `admin-api` | 8005 | Console back end: dashboards, settings, reports | ADMIN |
| `access-service` | 8007 | ZTNA: device enrolment and posture, kill switch, access proxy, kiosk, remote support | ADMIN (its verify paths touch no database) |
| `gateway-service` | 8008 | API gateway: rate limiting, forward-auth, routing | ISSUE |
| `verify-service` | 8010 | Serves `/.well-known/jwks.json` and holds nothing: no database, no Redis | VERIFY |
| `event-relay` | none | Drains the outbox table into the broker; runs only with a broker configured | worker |

The planes matter because they fail differently. ISSUE is the login path
and must stay up; ADMIN is the console and is the first plane shed under
load; EVENT is the audit stream; VERIFY is the tier that keeps answering
while everything else is down. The chart can pin each plane to its own
Postgres role with its own query budget (§7), and split identity into two
Deployments so shedding ADMIN buys something.

Around them: OPA (governance fails closed while it has no policies),
PostgreSQL, Redis (three roles, §7), Elasticsearch or OpenSearch for audit
search, and optionally the OpenZiti fabric (controller, routers, BrowZer)
that lets an internal application be published with no inbound firewall
rule. The React console and end-user portal live in `web/admin-console`.

---

## 2. Choose an install path

| Path | For | Start here |
|---|---|---|
| Docker Compose, one box | evaluation, a single-VM production install | [Docker Compose](docker.md), then the production overlay `deployments/docker/docker-compose.prod.yml` |
| Helm, bundled data plane | a first cluster, staging | [Kubernetes](kubernetes.md) with the chart's default values |
| Helm, managed data plane | production | `deployments/kubernetes/helm/openidx/values-prod.yaml`, secrets from an external store, [AWS via Terraform](aws.md) for the infrastructure |
| A cell | multi-region production | the production values plus `deployments/kubernetes/cells/<id>.yaml`, deployed by the release wave (§8) |

Hardware floor for the full single-box stack: eight to ten gigabytes of
memory and four cores. It is about forty containers.

Prerequisites: Helm 3.14 or newer, kubectl matching the cluster, Terraform
1.7 or newer if you provision with it, a DNS zone for the public hostnames,
and a TLS story (the deployment reference uses cert-manager with Let's
Encrypt). The chart runs its own migrations as a post-install and
pre-upgrade hook Job; there is no out-of-band schema step.

Every tagged release publishes the chart as a cosign-signed OCI artifact and
the images under `ghcr.io/mhmtgngr/openidx/<service>:vX.Y.Z`. Never run
`latest` in production. Verification recipes are in
[`RELEASING.md`](https://github.com/mhmtgngr/openidx/blob/main/docs/RELEASING.md);
signing starts at v1.34.0.

---

## 3. What you must supply before the first boot

### 3.1 Secrets

For Compose, `scripts/generate-secrets.sh` writes a `.env` with random
values for everything below; Compose refuses to start without them. For
Helm in production, `externalSecrets.enabled=true` pulls them from your
secret store under `externalSecrets.remoteKeyPrefix` (default
`openidx/prod`):

| Store key | Becomes | Notes |
|---|---|---|
| `database-url` | `DATABASE_URL` | full DSN; `sslmode=verify-full` in production |
| `redis-url` | `REDIS_URL` | `rediss://` scheme in production |
| `encryption-key` | `ENCRYPTION_KEY` | 32 random bytes or more. It encrypts the OAuth signing key at rest: **losing it costs every outstanding token** |
| `postgres-password`, `redis-password` | `POSTGRES_PASSWORD`, `REDIS_PASSWORD` | the datastore credentials |
| `database-read-url` | `DATABASE_READ_URL` | only with `externalSecrets.readReplica=true` (§7) |
| `redis-ratelimit-url`, `redis-revocation-url` | the two Redis roles | only with `externalSecrets.redisRoles=true` (§7) |
| `database-url-issue`, `-admin`, `-event` | per-plane DSNs | only with `database.planeRoles.enabled=true` (§7) |

Also required by the production gate and not in the chart's defaults:
`ACCESS_SESSION_SECRET` (32 random bytes or more) and `AUDIT_CHAIN_SECRET`
(without it the audit hash chain does not run and the trail carries no
tamper evidence). With the bundled data plane the chart `required`s
`secrets.postgresPassword`, `secrets.redisPassword` and
`secrets.encryptionKey` and refuses to render without them.

Rotation is a policy, not a validator check: rotate the JWT signing key at
most every ninety days, and when a key-encryption key is retired run
`cmd/rekey` (dry run by default) so nothing stays sealed under the old one.

### 3.2 The production gate

Set `APP_ENV=production` (the chart's `global.environment` defaults to it)
and every service runs `ValidateProduction()` at boot. It refuses to start,
and the log names exactly what is wrong, when any of these hold:

| Setting | Must be |
|---|---|
| `ACCESS_SESSION_SECRET`, `ENCRYPTION_KEY`, `AUDIT_CHAIN_SECRET` | set, random, 32 bytes or more, not a `change-me` default |
| `DATABASE_SSL_MODE` | `require`, `verify-ca` or `verify-full` |
| `REDIS_TLS_ENABLED` | `true`, with `REDIS_TLS_SKIP_VERIFY=false` |
| `TLS_ENABLED` | `true` (inter-service TLS) |
| `CSRF_ENABLED` | `true` |
| `CORS_ALLOWED_ORIGINS`, `AUDIT_STREAM_ALLOWED_ORIGINS` | explicit origin lists, never `*`, never empty |
| `DEBUG_OTP_IN_RESPONSE`, `DEV_ADMIN_BYPASS`, `ZITI_INSECURE_SKIP_VERIFY` | `false` |
| `ZITI_ADMIN_PASSWORD`, `GUACAMOLE_ADMIN_PASSWORD` | not the built-in defaults |
| `ACCESS_PROXY_DOMAIN` | a name the outside can resolve; a loopback value issues vendor-access links that point at the recipient's own machine |
| `PAM_REQUIRE_ZTNA=enforce` | only with `GUACAMOLE_ZITI_PUBLIC_URL` set and different from `GUACAMOLE_PUBLIC_URL` |

One gate lives in the database rather than in configuration: the seed
creates `admin` with the published password `Admin@123`, and in production
identity and oauth **refuse to start** while an enabled account still
authenticates with it. Rotate it on first login (console, Users, admin, Set
password). The full list with reasons is
[`SECURITY-HARDENING.md`](https://github.com/mhmtgngr/openidx/blob/main/docs/SECURITY-HARDENING.md);
the settings reference is [Configuration Reference](configuration.md).

### 3.3 Decide the tenancy mode

| | Single tenant | Multi tenant |
|---|---|---|
| `DEFAULT_ORG_FALLBACK` (`config.defaultOrgFallback`) | `true` | `false`: an unresolved request sees no rows |
| `TENANT_BASE_DOMAIN` (`config.tenantBaseDomain`) | empty | your base domain; tenants resolve from `tenant.<base>` and get a per-tenant token issuer |
| `DEFAULT_ORG_ID` | the seeded organization `00000000-0000-0000-0000-000000000010` | unused |

Get this wrong and a fresh install logs in and shows empty lists. That is
the isolation working, not a bug; `scripts/org-doctor.sh` prints which of
the two causes it is.

---

## 4. First install and first verification

Helm, from the chart in the tree:

```bash
cd deployments/kubernetes/helm/openidx
helm dependency build
helm upgrade --install openidx . -n openidx --create-namespace -f values-prod.yaml --wait
```

A fresh install with the bundled PostgreSQL **and** the transaction pooler
turned on needs two passes: the role pgcat logs in as is created by a
post-install hook, `--wait` holds post-install hooks until every Deployment
is Ready, and pgcat exits when its login is refused. Install once with
`--set pgcat.enabled=false` (the services take the direct DSN and the hooks
run), then upgrade with the pooler on; the bootstrap hook is pre-upgrade too
and sets the pooler's credential before pgcat starts. Do not zero only the
pooler: every pooled service waits for the pooler's port in an init
container, so with the pooler at zero replicas they never become Ready and
`--wait` deadlocks the same way. The deadlock was measured by the
`kind-cell` job in `.github/workflows/helm.yml`, which takes the other
working shape (pooler and every pooled service at zero in pass one); the
`pgcat.enabled=false` pass is reasoned from the hook phases and checked by
render, not run live.

Then, in order:

1. `kubectl -n openidx get pods`: everything Running and Ready. A crash loop
   that says `production security validation failed` lists the offending
   setting in the same log line.
2. `kubectl -n openidx logs job/openidx-migrate`: the migration Job
   succeeded. The schema count is the proof it did the work:
   `SELECT count(*) FROM schema_migrations` is in the high hundreds, not zero.
3. The runtime role is least-privileged:
   `SELECT rolcanlogin, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'openidx_app'`
   must read `true, false, false`. A superuser or a `BYPASSRLS` role ignores
   row-level security entirely, **even with FORCE**, and the tenant boundary
   becomes decorative. RDS master users are not superusers; self-managed
   Postgres must connect the services as a dedicated `NOSUPERUSER
   NOBYPASSRLS` role. The local Compose stack connects as a superuser, so
   isolation there is advisory only.
4. The belt is on: `\d+ users` in psql shows `Force row security: on` and a
   `pol_users_org_scope` policy whose predicate names `app.org_id`, not
   `true`.
5. Sign in as `admin`, rotate the password, enrol MFA, create a second
   administrator. Without the rotation the production gate stops the next
   restart of identity and oauth.
6. `make smoke-test` against the deployment drives the machine grant, the
   browser login and the console's contract with the back end.

The same sequence for Compose is the README quick start plus
`docker compose -f deployments/docker/docker-compose.yml -f deployments/docker/docker-compose.prod.yml up -d`.

---

## 5. What is enforced, and how to check it in a minute

The programme that produced this platform hunted one defect class: a
control that displays without enforcing. Each row is a control an operator
relies on, where it is enforced, and the one-line check.

| Control | Enforced at | Check |
|---|---|---|
| Tenant isolation | Postgres `FORCE ROW LEVEL SECURITY` on every organization-scoped table, keyed on `app.org_id` set per request; the application layer scopes every query too, and `tools/orgscope` blocks a merge that forgets | as `openidx_app` with no organization on the connection, `SELECT count(*) FROM users` is 0 |
| Production configuration | `ValidateProduction()` at boot | a deliberately insecure setting refuses to start and names itself |
| App assignment as a grant | `/oauth/authorize` and the access proxy, when `ACCESS_ASSIGNMENT_ENFORCE=true` | an unassigned user is refused at authorize; the assignment report shows no unintended `would_deny` rows before you flip it |
| Session and token revocation | `revoked_session:*` markers in Redis at refresh and userinfo; every sever path (kill switch, leaver, review revoke) calls one revocation package | revoke a test session in the console; the refresh dies and `/oauth/introspect` reads `active: false` |
| MFA policy | `IsMFARequired` in the OAuth login path | a policy user is challenged; an exempt user is not |
| Device trust | posture verdict becomes the `device-trusted` overlay attribute the Tier-2 dial policies require; only the device's own credential may report its posture | an untrusted device is denied the dial; an anonymous `POST /agent/report` is 401 |
| Privileged reveal | `allow_reveal` and the grant ACL in the governance handler, and the reveal lands in the audit trail naming who and what | an ungranted user, and an administrator on an entry with `allow_reveal=false`, are both refused |
| Audit integrity | a hash chain over sealed rows, keyed by `AUDIT_CHAIN_SECRET` | edit a sealed row directly and the verify endpoint reports `intact: false` naming the event; restore it and the chain is whole |
| Configuration is real | `tools/deadconfig`: every settable field is read by something, and every documented variable is bound | the merge-blocking register is empty |
| Cell correctness | the issuer stamps `cell` into access tokens; every guarded service answers `421 Misdirected Request` with `X-OpenIDX-Cell` to a token for a tenant placed elsewhere | `openidx cell show <org>` names the tenant's cell; a token minted for it is served by that cell and refused by another |

The invariant behind the table: the place a person sees a grant and the
place the system enforces it use the same predicate. Anything visible in the
console without a row in this table is a defect to wire or remove.

---

## 6. Upgrade and rollback

Versioning: MAJOR for incompatible API, configuration or migration changes;
MINOR for compatible features; PATCH for fixes. Migrations are forward-only
in operation. Take a database snapshot before a MAJOR upgrade.

```bash
# bump image.tag in values-prod.yaml to the new vX.Y.Z, then
helm upgrade openidx . -n openidx -f values-prod.yaml --wait
# a deployed service reports the version
curl -s https://api.example/health | jq .version
# roll back the release
helm rollback openidx -n openidx
```

The pre-upgrade hooks run the role bootstrap and the migrations before any
new pod rolls, so a new binary never meets an old schema. `helm rollback`
rolls the manifests back; it does not roll the schema back. For that:

```bash
DATABASE_URL=... go run ./cmd/migrate status    # what is applied
DATABASE_URL=... go run ./cmd/migrate down      # one step, as the database owner
```

Every migration in the registry applies and rolls back on a real Postgres in
CI (`internal/migrations`), so a `down` is a tested path, but it is one step
at a time and it runs as the owner role, never as `openidx_app`.

Two upgrades have their own runbooks and are not a plain `helm upgrade`:
crossing the v37 tenant-isolation boundary on an existing single-tenant
install
([`multitenancy-upgrade-runbook.md`](https://github.com/mhmtgngr/openidx/blob/main/docs/multitenancy-upgrade-runbook.md):
backfill, then NOT NULL and foreign keys, then FORCE), and the managed-data-plane
cutover
([`tier3b-cutover-runbook.md`](https://github.com/mhmtgngr/openidx/blob/main/docs/tier3b-cutover-runbook.md)).

Do not set `AUTO_MIGRATE=true` on the services in Kubernetes: concurrent
replicas racing the migrations is why the hook Job exists.

---

## 7. Scale knobs, in the order to turn them on

Each of these is a value in `deployments/kubernetes/helm/openidx/values.yaml`
with its reasoning beside it. Each renders alone and the lint job proves
every unsafe combination is refused; the `kind-cell` job proves they work
together on a live cluster (§9). Turn them on one at a time, in this order,
and read the interlock messages when the chart refuses.

1. **`config.rlsMode=local`.** The tenant scope moves from the pooled
   connection to the transaction. Behaviour-preserving, and the
   precondition for the pooler. Run it for a period with the isolation
   suite green before step 2.
2. **`pgcat.enabled=true`** with `pgcat.password` and `pgcat.adminPassword`.
   The chart refuses this while `rlsMode` is `session`: a transaction pooler
   with session-scoped tenant state hands one tenant's scope to the next
   client, and that was measured
   (`docs/evidence/2026-09-13-rls-transaction-pooling.md`), not theorised. It
   also refuses a zero prepared-statement cache. The chart repoints the
   eight request-serving services at the pooler; the migration Job, the
   bootstrap hook and the backup keep the direct DSN. The Postgres backend
   budget becomes `replicaCount x poolSize`, constant under autoscaling.
   Fresh install: two passes (§4).
3. **The read replica.** Managed: store `database-read-url` and set
   `externalSecrets.readReplica=true`, as a second step after the store has
   the key, or the whole secret sync fails. Bundled:
   `postgresql.architecture=replication`, `readReplicas.replicaCount`, and
   `database.bundledReadReplica=true`; the chart refuses the last without
   the first. Read-mostly, lag-tolerant queries move to the replica; writes
   and security-critical reads stay on the primary; losing the replica is a
   degradation with a breaker, not an outage. Watch
   `OpenIDXReadReplicaOffloadLost`.
4. **`identityService.planeSplit.enabled=true`.** Two Deployments,
   `-identity-auth` serving the login surface and `-identity-admin` the
   rest, with the Ingress rules generated from the same route table the
   process registers. Pin each half to its own node pool with `nodeSelector`
   and `tolerations` under `planeSplit.auth` and `planeSplit.admin`; a
   tainted pool needs both.
5. **`database.planeRoles.enabled=true`.** Each plane connects as its own
   Postgres role carrying a server-side statement timeout: 2 s for ISSUE,
   10 s for ADMIN, 30 s for EVENT. Mutually exclusive with the pooler by
   design, and it requires `database.statementTimeout` empty because a
   connection parameter beats the role's setting silently. Give the three
   roles a password on the server first; the migration creates them
   passwordless.
6. **Redis per loss profile.** `redis.roles.rateLimitUrl` and
   `redis.roles.revocationUrl` (or `externalSecrets.redisRoles=true`): rate
   limit counters on an instance an attacker may fill, revocation markers
   on one that never evicts. An unset role aliases `REDIS_URL`.
7. **`config.cellId`.** Every service in the cell reads it from the shared
   ConfigMap; the issuer stamps it into tokens; the guards refuse foreign
   tokens with 421. Empty is a single-cell install and changes nothing.
   Place tenants with `openidx cell place` and read them back with
   `openidx cell show`; the directory is the `org_cells` table and the edge
   routes from it.
8. **`verifyService.enabled=true`** and send `/.well-known/jwks.json` there
   at the edge. It is the tier that keeps verifying tokens while the
   database is down; turning it on changes nothing until the edge route
   exists.

Autoscaling: `autoscaling.*` per service with HPA behaviour tuned, or KEDA
with the per-pod request-rate and outbox-lag triggers under `keda.*`. The
lint job asserts exactly one authority per Deployment.

---

## 8. Cells and the release wave

A cell is `values-prod.yaml` plus `deployments/kubernetes/cells/<id>.yaml`,
which is the only place a cell's `config.cellId` is set. The release
workflow deploys nothing until the repository variable `CELL_ROLLOUT` is
`"true"`; with it, the wave runs `canary-1`, then `eu-1`, then `us-1`, each
as `helm upgrade --install --atomic` in the GitHub environment `cell-<id>`
that holds that cell's `KUBECONFIG` and a required reviewer. A cell that
does not come up is rolled back and the cells after it are not attempted.
After each upgrade the job reads `CELL_ID` back from the deployed ConfigMap
and refuses a cell that does not answer with its own name. Adding a cell is
a values file, an environment and a job; `scripts/check-release-rollout.sh`
holds the wave's shape.

The functional half of a cell is measured on kind by the `kind-cell` job
(§9). The load half has never been measured: no cell has run with traffic.

---

## 9. Backup, restore, and the drills

`cmd/backup` is the tool; the chart runs it as a CronJob when
`backup.enabled=true` with a PVC or S3 destination.

```text
backup create [name]    backup list    backup verify <file>    backup restore <file>
DATABASE_URL  BACKUP_DIR  BACKUP_ENCRYPTION_KEY  BACKUP_RETENTION_COUNT (7)
BACKUP_S3_BUCKET  BACKUP_S3_REGION  BACKUP_S3_ENDPOINT  BACKUP_S3_ACCESS_KEY  BACKUP_S3_SECRET_KEY
```

A backup that has not been restored is a hope. `backup verify` checks
integrity; a monthly restore into a scratch database is the control. The
recovery procedures, including point-in-time recovery and full platform
rebuild, are in
[`disaster-recovery.md`](https://github.com/mhmtgngr/openidx/blob/main/docs/disaster-recovery.md).

Drills, and what each proves:

| Target | Proves | Needs |
|---|---|---|
| `make smoke-test` | the stack answers end to end: machine grant, browser login, console contract | a running stack |
| `make ha-drill` | the verify path survives a JWKS or database outage by serving stale keys | a running stack |
| `make dr-game-day` | the restore procedure's self-test | nothing live; the real drill is operator-run |
| `make k8s-chaos` | the chaos drill's static half: PDBs, spread, anti-affinity | a rendered chart; the live half needs a cluster |
| `make ddos-drill` | the six k6 scenarios parse and the runbook matches them | nothing live; the game day itself needs a cell and traffic |
| `make dark-drill` | dark services are reachable by an authorised identity and by nobody else | the seeded edge routes; the live variant needs the overlay |
| `kind-cell` (CI) | pooler, local RLS, replica, plane split and 421 work together | runs on every chart change |

---

## 10. Observability and the alerts that matter

Every service exports `/metrics`; `monitoring.serviceMonitor.enabled` wires
scraping and the chart ships PrometheusRules. Traces are OTLP when
`TRACING_ENABLED=true`. The Compose stack brings Prometheus, Grafana and
Jaeger; Grafana has no default password and Compose refuses to start
without `GRAFANA_ADMIN_PASSWORD`.

Alerts, grouped by what to do:

| Alert | Means | Do |
|---|---|---|
| `ServiceDown`, `ServiceHighRestartRate`, `DeploymentReplicasUnavailable` | a service is not serving | read the pod log; a production-gate refusal names its cause |
| `HighAuthFailureRate`, `TokenRefreshFailures` | logins or refreshes failing at volume | check the issuer's health and the JWKS alerts before assuming an attack |
| `JWKSRefreshFailing`, `JWKSServingStale`, `JWKSStaleNearExpiry` | verifiers cannot fetch keys and are living on the cache | restore the issuer; the stale window is the time you have |
| `ForwardedClientIPDiscarded` | the ingress hop is not in `OIDX_TRUSTED_PROXIES`; every request resolves to the ingress address and shares one rate-limit bucket | set `config.trustedProxies` to the pod CIDR; never `*` |
| `OpenIDXRateLimitOnLocalFallback` | the rate-limit Redis is unreachable; replicas count locally and divide the quota by `RATE_LIMIT_REPLICA_HINT` | restore Redis; the fallback is a degradation, not a bypass |
| `OpenIDXReadReplicaOffloadLost`, `OpenIDXReadReplicaFlapping` | reads fell back to the primary behind a breaker | fix the replica; the primary is carrying the read load meanwhile |
| `OpenIDXPoolerClientsWaiting`, `OpenIDXPoolerNoRedundancy` | the pooler's pool is saturated, or one replica is left | raise `pgcat.poolSize` within `max_connections`, or restore the second replica |
| `ZitiControllerQuorumAtRisk`, `ZitiRouterNoRedundancy` | the overlay's Raft majority or its only data path is one loss away | the controller wants three; the router wants two |
| `OpenIDXEdgeCidrSyncFailed` | the edge provider's address ranges stopped syncing; trusted hops are going stale | check the CronJob; the last good list is still in force |
| `CircuitBreakerOpen`, `HighRequestsInFlight`, `HighRequestLatency`, `HighErrorRate` | a dependency is failing or the admission controller is shedding | find the dependency; ADMIN sheds first by design |

---

## 11. The recurring controls

Run these monthly and after every incident, and write a dated row in
`docs/evidence/operational.md`. A row with no date has not been done, and
today none has: no live deployment has run them yet. The release-gate
controls that CI runs on every push are listed with their job names in
`docs/evidence/release-gate.md`.

Identity and session:

- Default administrator rotated; at least two administrators; MFA on all of
  them.
- Revoke a test session in the console; the refresh dies. Kill-switch a test
  user; IAM, PAM and the overlay all report severed.
- Every MFA factor the console offers is deliverable: a real SMS, a real
  email code, a push approval end to end.
- Oldest JWT signing key age is ninety days or less.

The access model:

- Pick three users. My Apps and Network, Access 360, the assignment report
  and an actual launch or dial all agree.
- Revoke a grant in an access review; portal, proxy and overlay drop it
  within the sweep interval.

Platform:

- Every service Ready; every service scraped; an alert reaches a human.
- A test administrator action appears in the audit table and in the SIEM
  forwarder, and chain verification passes.
- The backup ran in the last day and the latest restore-verify passed.
- No `latest` image tags in the production values; every service pinned to
  the release tag. Digest pinning is not done anywhere in this repository
  yet, chart or Dockerfiles, so there is no box to tick for it.
- Grafana and the other observability endpoints are not open with default
  credentials.

---

## 12. Troubleshooting, the six you will actually hit

| Symptom | Cause | Fix |
|---|---|---|
| Pod crash loops with `production security validation failed` | the gate (§3.2) | the log line names the setting |
| Logged in, every list is empty, or `organization context required` | no tenant resolved under the belt | `scripts/org-doctor.sh`; set `DEFAULT_ORG_FALLBACK=true` for single tenant, or fix the base domain |
| `helm install --wait` times out on a fresh install with the pooler on; pgcat in `CrashLoopBackOff` or the services stuck in `Init:0/1`; Postgres log says `Role "openidx_app" does not exist` | the hook that creates the role is held by `--wait` | install with `--set pgcat.enabled=false`, then upgrade with it on (§4) |
| identity or oauth refuse to start after an upgrade with a message about the default administrator | `Admin@123` still authenticates | rotate the seeded account |
| A background job processes nothing, no errors | it queries without an organization context and the belt hides every row | the job must carry a tenant or `orgctx.WithBypassRLS`; it is a code defect, report it with the job's name |
| `421 Misdirected Request` with `X-OpenIDX-Cell` | the token's tenant is placed in another cell | correct the edge routing or the placement (`openidx cell show <org>`); the header names the cell that answered, not the one that should have |
| Migration Job fails on a fresh install with `permission denied to create role` | the bootstrap hook did not run or `migrations.roleBootstrap.enabled` is off | with an external database, the migration DSN must be able to `CREATE ROLE`, or create `openidx_app` first |

More in [Troubleshooting](../troubleshooting.md).

---

## 13. What is not done, and not claimed

Say these to a customer before they find them:

- **No cell has run with traffic.** Every switch in §7 works together on
  kind; load, failover timing and the canary bake between waves are
  unmeasured. The k6 game day, the chaos drill's live half and the
  multi-region runbooks wait on a real cell in a real cloud account.
- **The operator-run controls have no dated rows.** §11 has been designed
  and never executed against a live deployment.
- **Per-cell key management** (OpenBao or KMS) is a code half: keys name
  their cell and a foreign cell's key cannot verify here, but the key
  encryption key still comes from `ENCRYPTION_KEY`.
- **Three Redis roles need three instances**, which the bundled chart does
  not provide; managed caches do.
- **Two product decisions are open**: may one external account link to a
  user in two tenants (the last two tables outside the tenant belt), and
  what the per-tenant enrolment quota is (the column to count on exists
  since migration v197, the number does not).
- **Terraform** has an AWS root (EKS, RDS, ElastiCache, OpenZiti) and an
  Azure root (AKS, Flexible Server, Redis, Key Vault) under
  `deployments/terraform/`. Neither has been applied from this repository;
  other clouds are values files and a cluster you bring.

---

## 14. Where to go deeper

| Question | Document |
|---|---|
| The full deployment reference, Terraform to Helm to verify | [`DEPLOYMENT.md`](https://github.com/mhmtgngr/openidx/blob/main/docs/DEPLOYMENT.md) |
| Every enforced setting, with reasons | [`SECURITY-HARDENING.md`](https://github.com/mhmtgngr/openidx/blob/main/docs/SECURITY-HARDENING.md) |
| The tenant boundary in depth | [`SECURITY-TENANCY.md`](https://github.com/mhmtgngr/openidx/blob/main/docs/SECURITY-TENANCY.md) |
| Threat model and control mapping for an auditor | [`THREAT-MODEL.md`](https://github.com/mhmtgngr/openidx/blob/main/docs/THREAT-MODEL.md), [`COMPLIANCE-CONTROL-MAPPING.md`](https://github.com/mhmtgngr/openidx/blob/main/docs/COMPLIANCE-CONTROL-MAPPING.md) |
| Cutting and verifying a release | [`RELEASING.md`](https://github.com/mhmtgngr/openidx/blob/main/docs/RELEASING.md) |
| Recovery procedures | [`disaster-recovery.md`](https://github.com/mhmtgngr/openidx/blob/main/docs/disaster-recovery.md) |
| Under a volumetric attack | [`runbooks/ddos-under-attack.md`](https://github.com/mhmtgngr/openidx/blob/main/docs/runbooks/ddos-under-attack.md) |
| Taking services dark behind the overlay | [`GOING_DARK_RUNBOOK.md`](https://github.com/mhmtgngr/openidx/blob/main/docs/GOING_DARK_RUNBOOK.md) |
| Why each control exists and what it found | [`PROJECT-READINESS-GUIDE.md`](https://github.com/mhmtgngr/openidx/blob/main/docs/PROJECT-READINESS-GUIDE.md) |
| What is still open at scale, and why | [the global-scale plan](https://github.com/mhmtgngr/openidx/blob/main/docs/plans/2026-09-13-global-scale-cell-architecture-plan.md) |

If this page and the code disagree, the code is right and this page has
rotted: fix the page in the same change.
