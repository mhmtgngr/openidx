# OpenIDX Disaster Recovery Runbook

## Recovery Targets

| Metric | Target | Notes |
|--------|--------|-------|
| **RPO** (Recovery Point Objective) | 1 hour | Maximum acceptable data loss |
| **RTO** (Recovery Time Objective) | 4 hours | Maximum downtime to full recovery |

## Backup Schedule

| Component | Method | Frequency | Retention |
|-----------|--------|-----------|-----------|
| PostgreSQL | `cmd/backup` (`pg_dump -Fc`, gzip, optional AES-256, optional S3) | Every 6 hours (cron) | `BACKUP_RETENTION_COUNT` |
| Elasticsearch | Snapshot API (not yet automated — use the ES snapshot procedure below) | Daily | 14 days |
| Redis | Not backed up (ephemeral cache) | N/A | Rebuilt on restart |
| Kubernetes etcd | Managed by cloud provider or `etcdctl snapshot save` | Daily | 7 days |

### The backup tool

PostgreSQL backups are taken by the `cmd/backup` CLI (`go build -o backup ./cmd/backup`):

```
backup create [name]    # dump + gzip (+encrypt/S3 if configured)
backup restore <file>   # restore a backup (pulls from S3 if not local)
backup list             # list backups
backup verify <file>    # checksum verification
```

It is configured via environment variables: `DATABASE_URL`, `BACKUP_DIR`,
`BACKUP_RETENTION_COUNT`, `BACKUP_ENCRYPTION_KEY` (optional), and for offsite
copies `BACKUP_S3_BUCKET` / `BACKUP_S3_REGION` / `BACKUP_S3_ENDPOINT` /
`BACKUP_S3_ACCESS_KEY` / `BACKUP_S3_SECRET_KEY`. When an S3 bucket is set, each
backup is uploaded there and `restore` will fetch it from S3 if it isn't found
locally.

### Recommended Cron Entries

```cron
# PostgreSQL backup every 6 hours (offsite copy via BACKUP_S3_* env)
0 */6 * * * DATABASE_URL=... BACKUP_DIR=/var/backups/openidx BACKUP_RETENTION_COUNT=120 /opt/openidx/backup create >> /var/log/openidx-backup.log 2>&1
```

On Kubernetes, schedule this as a `CronJob` running the backup image with the
same env (tracked as a follow-up to ship a chart `CronJob` template).

---

## Procedure 1: PostgreSQL Recovery

### 1A. Full Database Restore

```bash
# 1. Identify the most recent backup
backup list

# 2. Stop services that write to the database
kubectl scale deployment --replicas=0 -l app.kubernetes.io/part-of=openidx

# 3. Restore (fetches from S3 automatically if not present locally)
export DATABASE_URL=... BACKUP_DIR=/var/backups/openidx
backup restore openidx_YYYYMMDD_HHMMSS.sql.gz

# 4. Run pending migrations (if any)
# Migrations are applied automatically on service startup

# 5. Restart services
kubectl scale deployment --replicas=2 -l app.kubernetes.io/part-of=openidx
```

### 1B. Point-in-Time Recovery (WAL-based)

If WAL archiving is enabled (recommended for production):

```bash
# 1. Stop PostgreSQL
# 2. Restore base backup
# 3. Configure recovery.conf with target time
# 4. Start PostgreSQL — it replays WAL to the target timestamp
```

### 1C. Single Table Recovery

```bash
# Restore to a temporary database, then copy the table
PGDATABASE=openidx_temp ./scripts/restore-postgres.sh backup.dump
psql -c "INSERT INTO openidx.table SELECT * FROM openidx_temp.table WHERE ..."
dropdb openidx_temp
```

---

### 1D. Failover Game-Day (RDS Multi-AZ / Patroni)

Multi-AZ RDS provides *automatic* failover to a synchronous standby, but failover
is only trustworthy if it is **rehearsed**. Run this in staging quarterly and
after any DB/driver upgrade.

**What "good" looks like:**
- The verify path (validating already-issued JWTs) is **unaffected** — it does not
  touch Postgres (in-memory JWKS + serve-stale, see the always-available-auth plan).
- The issue path (login/refresh) returns clean, retryable errors for a few
  seconds, then recovers **without any service restart** as pgxpool re-dials the
  promoted primary.

**Drill (runnable):** `scripts/dr-game-day.sh` drives this end-to-end — a
synthetic auth canary that probes `/health/live` (verify path, must stay 200)
and `/health/ready` (issue path, may 503 briefly then must self-recover), then
prints a pass/fail verdict against the two "good" criteria above.

```bash
# Self-test (no infra): stands up a local mock that simulates a failover window
# and runs the whole canary/verdict logic against it, so the drill itself is
# verified and can't silently rot. This is what `make dr-game-day` runs.
make dr-game-day
#   or: scripts/dr-game-day.sh --self-test

# Live staging — observe only (you trigger failover in another terminal):
scripts/dr-game-day.sh --base-url https://staging.openidx.example

# Live staging — the script triggers failover for you and grades the result:
scripts/dr-game-day.sh --base-url https://staging.openidx.example \
    --trigger --provider rds --rds-instance openidx-staging
# Patroni:
scripts/dr-game-day.sh --base-url https://staging.openidx.example \
    --trigger --provider patroni --patroni-cluster openidx --patroni-standby pg-1
```

The script asserts, and exits non-zero on violation:
- `/health/live` stayed **200 for the entire window** (verify path is DB-free —
  a single non-200 is a broken always-available guarantee).
- If `/health/ready` dropped, it **recovered on its own within budget** (pgxpool
  re-dialed the promoted primary) — no `kubectl rollout`, no pod restarts.

Under the hood it triggers the same failover the manual runbook did:
```bash
#   RDS:      aws rds reboot-db-instance --db-instance-identifier openidx-prod --force-failover
#   Patroni:  patronictl switchover openidx --candidate <standby> --force
```
Expectations while it runs:
- connect attempts fail FAST (~5s `DB_CONNECT_TIMEOUT`), not hang for minutes
- `/health/ready` flips to 503 on affected replicas → LB drains new logins
- `/health/live` stays 200 → pods are NOT killed/restarted
- within ~1 pool `HealthCheckPeriod` (60s) new acquires reach the new primary
- the canary's login success rate recovers on its own (no `kubectl rollout`)

After the drill, confirm no restarts and steady state:
```bash
kubectl get pods -l app.kubernetes.io/name=openidx   # RESTARTS column unchanged
```

**If the pool does NOT recover without a restart**, that is a regression — check
that `DB_CONNECT_TIMEOUT` is set (a hung dial with no timeout is the classic
cause) and that `HealthCheckPeriod` is evicting dead conns. See
`internal/common/database/database.go` and `docs/architecture/db-pooling.md`.

---

## Procedure 2: Elasticsearch Recovery

```bash
# 1. List available snapshots
curl -s http://localhost:9200/_snapshot/openidx-backups/_all | python3 -m json.tool

# 2. Close target indices
curl -X POST "http://localhost:9200/openidx-audit-*/_close"

# 3. Restore snapshot
curl -X POST "http://localhost:9200/_snapshot/openidx-backups/snapshot_YYYYMMDD_HHMMSS/_restore" \
  -H 'Content-Type: application/json' \
  -d '{"indices": "openidx-audit-*", "ignore_unavailable": true}'

# 4. Verify
curl -s http://localhost:9200/_cat/indices/openidx-audit-*?v
```

If Elasticsearch is lost entirely and no snapshot exists, audit data in PostgreSQL remains the source of truth. The audit service can re-index from PG on startup.

---

## Procedure 3: Redis Recovery

Redis is used as a cache and rate-limiter store. Data loss is acceptable.

**Recovery steps:**
1. Deploy a new Redis instance (or let Sentinel promote a replica)
2. Services automatically reconnect via retry logic
3. Rate limit counters and session caches rebuild organically
4. No manual intervention needed beyond ensuring Redis is reachable

**With Sentinel:**
- Sentinel automatically promotes a replica to master
- Services using `NewRedisFromConfig` with Sentinel failover reconnect transparently
- Monitor via: `redis-cli -p 26379 SENTINEL masters`

---

## Procedure 4: Kubernetes Recovery

### 4A. Full Cluster Rebuild

```bash
# 1. Provision new cluster
terraform apply -var-file=production.tfvars

# 2. Restore etcd (if self-managed)
etcdctl snapshot restore /path/to/etcd-snapshot.db

# 3. Deploy OpenIDX
helm install openidx deployments/kubernetes/helm/openidx -f values-prod.yaml

# 4. Restore PostgreSQL backup (fetches from S3 if not local)
backup restore <latest-backup>

# 5. Restore Elasticsearch snapshot (see the ES snapshot procedure above)
```

### 4B. Single Service Recovery

```bash
# Rollback to previous version
helm rollback openidx <revision>

# Or redeploy a specific service
kubectl rollout restart deployment/<service-name>
```

### 4C. PersistentVolume Recovery

If PVs are backed by cloud snapshots (EBS, Azure Disk):

```bash
# 1. Create a volume from the snapshot
# 2. Create a PV pointing to the new volume
# 3. Bind it to the existing PVC
# 4. Restart the pod
```

---

## Procedure 5: Complete Platform Recovery (Bare Metal)

Order of operations for a full platform rebuild:

1. **Infrastructure**: PostgreSQL, Redis, Elasticsearch
2. **Configuration**: OPA policies, APISIX routes
3. **Data**: Restore PostgreSQL backup, ES snapshot
4. **Services**: Deploy all OpenIDX services via Helm
5. **Verification**: Run the checklist below
6. **DNS/Ingress**: Update DNS to point to new cluster

---

## Post-Recovery Verification Checklist

- [ ] All pods are Running and Ready (`kubectl get pods`)
- [ ] Health endpoints return 200 for all services
- [ ] Readiness endpoints report all dependencies healthy
- [ ] Admin console loads and authenticates successfully
- [ ] User login flow works end-to-end (OAuth → token → API)
- [ ] Audit events are being written (check `/api/v1/audit/events`)
- [ ] Prometheus is scraping metrics from all services
- [ ] Grafana dashboards show data
- [ ] Rate limiting is functional (check Redis connectivity)
- [ ] Review a sample of restored data for integrity
