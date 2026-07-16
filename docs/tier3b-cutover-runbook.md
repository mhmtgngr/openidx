# Tier 3b Cutover Runbook — single-VM prod → EKS (always-available path)

Status: **scoped, ready to execute in staging first.** This is the operational
sequence to move an existing single-box OpenIDX production onto the EKS/managed
path that Terraform + Helm already describe (see
`docs/architecture/always-available-auth-plan.md` §Tier 3b). It is a cutover
runbook, not new architecture: the application is already Tier 3b-ready (verify
survives a DB outage via serve-stale JWKS, the issue path degrades cleanly and
self-recovers on RDS failover, and the read-replica seam is wired end to end).

The guiding principle from the availability work: **the verify path is
DB-independent**, so already-issued tokens keep validating throughout the
cutover. We exploit that to make the move low-risk — data and the issue path move
under a short, controlled window while verification never stops.

---

## 0. Preconditions (block the cutover until all true)

- [ ] `make dr-game-day` passes locally (drill logic is green), and the **live**
      DR game-day (`scripts/dr-game-day.sh --base-url <staging> --trigger
      --provider rds ...`) has been run once against staging with a PASS verdict.
- [ ] `make ha-drill` passes on the release commit (all availability guarantees +
      pool-safety guards hold).
- [ ] `helm template openidx deployments/kubernetes/helm/openidx -f
      values-prod.yaml` renders clean, and the image tag in values is the release
      you intend to cut over to.
- [ ] Terraform `plan` for the target account/region is reviewed and applied for
      everything **except** the DNS flip (VPC, EKS, RDS Multi-AZ + read replica,
      ElastiCache). See gaps in §1.
- [ ] A tested Postgres dump/restore path exists and a **restore** has been
      rehearsed (not just a dump). Backups are the rollback of last resort.
- [ ] Rollback owner, comms channel, and a hard "abort by" time are agreed.

---

## 1. Close the two open infra gaps first

These are the only Tier 3b items the plan lists as still open. Do them **before**
the cutover window, in staging then prod.

### 1a. OpenSearch under Terraform (audit search backend)

`values-prod.yaml` points `config.elasticsearchUrl` at
`https://opensearch.prod.internal:9200`, but there is **no OpenSearch Terraform
module** yet — today that endpoint must be provisioned out of band. Close the gap:

- Add a `modules/opensearch` (AWS OpenSearch Service domain: 3 data nodes across
  the 3 AZs, dedicated master nodes, encryption at rest + node-to-node, access
  policy scoped to the EKS node SG / IRSA role, `AdvancedSecurityOptions` on).
- Output the domain endpoint; set `config.elasticsearchUrl` to it (or keep the
  stable `opensearch.prod.internal` CNAME and point it at the domain).
- **Not on the critical auth path.** Audit ingestion has an outbox and Postgres
  remains the source of truth, so OpenSearch can even come up *after* the auth
  cutover. Sequence it first only to avoid a scramble later.

Acceptance: `curl -s $ES/_cluster/health` is `green`; audit read/report/export
endpoints return data; audit ingestion drains its outbox.

### 1b. Activate the RDS read replica (Tier 1.6 seam)

Terraform already provisions one read replica in prod (`read_replica_count = 1`)
and exposes `rds_reader_endpoints`; the chart already supports the read pool. It
is **not yet switched on** because `values-prod.yaml` does not set
`externalSecrets.readReplica`. To activate (do this after the app is healthy on
the primary, as a follow-on — it is an optimization, not a correctness change):

1. Store the reader endpoint from Terraform output `rds_reader_endpoints` as the
   secret `<remoteKeyPrefix>/database-read-url`
   (`postgres://...@<reader-endpoint>/openidx?sslmode=verify-full`).
2. Set `externalSecrets.readReplica: true` in `values-prod.yaml` (renders the
   `DATABASE_READ_URL` key in `templates/secrets.yaml`).
3. `helm upgrade`. Confirm read-mostly endpoints (dashboards, `List` paths) still
   work and that the primary's read load drops. The pool-safety guards
   (`make ha-drill`) already prove writes and security-critical reads stay on the
   primary, so replica lag cannot weaken a security decision.

Acceptance: pods pick up `DATABASE_READ_URL`; `Reader()`-backed queries succeed;
a forced replica pause does not break logins (writes/security reads unaffected).

---

## 2. Stand up the EKS stack in parallel (no traffic yet)

The new stack runs alongside the live VM; nothing is cut over yet.

1. `terraform apply` the platform (VPC, EKS across 3 AZs, RDS Multi-AZ + replica,
   ElastiCache with failover). Follow `docs/DEPLOYMENT.md` Steps 1–3 for
   bootstrap, kubectl, ingress, cert-manager, External Secrets Operator, and
   secret material.
2. `helm install` (or `upgrade --install`) with `values-prod.yaml`, but with the
   ingress host set to a **staging/shadow DNS name** (e.g.
   `auth-eks.openidx.example.com`) so real users are untouched.
3. Point the new stack's `DATABASE_URL` at the **same data** users will land on
   after cutover — see §3 for the data strategy. For a first rehearsal, point it
   at a restored copy of prod.
4. Verify on the shadow host (`docs/DEPLOYMENT.md` Step 5 + the multi-tenancy
   smoke). Run the DR game-day against the shadow host with `--trigger`.

Gate: shadow stack green (login, refresh, userinfo, JWKS, per-tenant branding,
cross-org isolation) and the DR game-day PASSES against it.

---

## 3. Data cutover strategy (the only part with a real window)

Two options; pick per RTO/RPO tolerance.

### 3a. Logical replication (near-zero downtime, preferred)

1. Provision RDS as the target; set up **logical replication** from the VM
   Postgres to RDS (publication on the VM, subscription on RDS), or use AWS DMS.
2. Let it reach steady state (replication lag ~0).
3. In the window: stop writes on the VM (put the VM app in maintenance / scale to
   zero), let the last changes drain to RDS, verify row counts / sequences, then
   promote RDS to standalone (drop the subscription).
4. Flip the EKS stack's `DATABASE_URL` to RDS (already the case if it was pointed
   at RDS all along) and proceed to §4.

RPO ≈ 0, downtime = the drain + DNS TTL. **Verify keeps working the whole time**
(DB-independent), so "downtime" only affects new logins/refreshes.

### 3b. Dump/restore (simplest, larger window)

1. In the window: quiesce writes on the VM, `pg_dump`, `pg_restore` into RDS,
   verify.
2. Flip `DATABASE_URL`, proceed to §4.

RPO ≈ 0 (writes quiesced) but downtime = dump+restore duration. Use only if the
DB is small or the window is generous.

Redis holds only cache + rate-limit + revocation state and is disposable; do not
migrate it. ElastiCache starts empty and rebuilds. (Active refresh-token
revocations, if any, should be short-lived given the access-token TTL; note any
in-flight ones in the comms.)

---

## 4. Traffic cutover (DNS) — exploit the DB-independent verify path

Order matters. Because verification does not touch the DB, cut the **verify**
surfaces first; they are the safest and the highest-blast-radius if wrong.

1. Lower DNS TTL on `auth.` / `api.` to 60s **at least a full old-TTL ahead** of
   the window (do this a day before).
2. In the window, after §3 promotes RDS:
   - Point `auth.openidx.example.com` (issuer + JWKS) at the EKS ingress. JWKS and
     token *validation* are served correctly immediately; existing tokens keep
     validating on both stacks (same signing keys — ensure the EKS stack has the
     same `encryption-key`/signing material via External Secrets).
   - Point `api.openidx.example.com` at the EKS ingress.
3. Watch, per the DR game-day's contract:
   - `/health/live` stays 200 on EKS (verify path).
   - `/health/ready` green once pods reach RDS.
   - login + refresh succeed against the EKS stack.
   - `openidx_jwks_serve_stale_total` flat (issuer healthy).
4. Keep the old VM running (drained of new traffic but able to serve) until DNS
   fully propagates and metrics are clean for one steady-state interval.

---

## 5. Post-cutover

- [ ] Activate the read replica (§1b) as a follow-on `helm upgrade`.
- [ ] Run `make ha-drill` against the release and the DR game-day against **prod**
      EKS (observe-only, or `--trigger` in a maintenance window) to prove failover
      on the real stack.
- [ ] Confirm HPA/PDB/anti-affinity are in effect (`kubectl get hpa,pdb`; pods
      spread across 3 AZs).
- [ ] Confirm OpenSearch green and audit search working (§1a).
- [ ] Decommission the VM only after 24–48h of clean metrics and one successful
      backup/restore drill against the new RDS.

---

## 6. Rollback

- **Before DNS flip:** trivial — tear down / ignore the EKS stack; the VM never
  stopped serving.
- **During/after DNS flip, data still consistent on the VM:** point `auth.`/`api.`
  DNS back at the VM. Verify never broke; new logins resume on the VM. Only writes
  made on RDS during the window are at risk — with logical replication (§3a) there
  should be none divergent if you promoted cleanly; with dump/restore, any RDS
  writes after the flip must be reconciled or accepted as lost on rollback (keep
  the window short and low-write).
- **Data corruption on RDS:** restore from the rehearsed backup (precondition §0).

---

## Why this is low-risk

The always-available-auth work makes the verify path independent of the database,
so **token validation never depends on which stack or DB is live**. That turns a
scary "move the auth system" cutover into "move the data and the issue path under
a short window, while verification keeps running." The DR game-day
(`scripts/dr-game-day.sh`) already encodes and checks exactly the invariant this
cutover leans on (verify stays up, issue path recovers), so run it at every gate.
