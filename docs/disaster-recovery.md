# OpenIDX Disaster Recovery Runbook

## Recovery Targets

| Metric | Target | Notes |
|--------|--------|-------|
| **RPO** (Recovery Point Objective) | 1 hour | Maximum acceptable data loss |
| **RTO** (Recovery Time Objective) | 4 hours | Maximum downtime to full recovery |

## Backup Schedule

| Component | Method | Frequency | Retention |
|-----------|--------|-----------|-----------|
| PostgreSQL | `pg_dump -Fc` via `scripts/backup-postgres.sh` | Every 6 hours (cron) | 30 days |
| Elasticsearch | Snapshot API via `scripts/backup-elasticsearch.sh` | Daily | 14 days |
| Redis | Not backed up (ephemeral cache) | N/A | Rebuilt on restart |
| Kubernetes etcd | Managed by cloud provider or `etcdctl snapshot save` | Daily | 7 days |

### Recommended Cron Entries

```cron
# PostgreSQL backup every 6 hours
0 */6 * * * PGPASSWORD=<password> /opt/openidx/scripts/backup-postgres.sh >> /var/log/openidx-backup.log 2>&1

# Elasticsearch snapshot daily at 02:00
0 2 * * * /opt/openidx/scripts/backup-elasticsearch.sh >> /var/log/openidx-es-backup.log 2>&1
```

---

## Procedure 1: PostgreSQL Recovery

### 1A. Full Database Restore

```bash
# 1. Identify the most recent backup
ls -lt backups/postgres/

# 2. Stop services that write to the database
kubectl scale deployment --replicas=0 -l app.kubernetes.io/part-of=openidx

# 3. Restore
export PGPASSWORD=<password>
./scripts/restore-postgres.sh backups/postgres/openidx_YYYYMMDD_HHMMSS.dump

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
helm install openidx deployments/kubernetes/helm/openidx -f values-production.yaml

# 4. Restore PostgreSQL backup
./scripts/restore-postgres.sh <latest-backup>

# 5. Restore Elasticsearch snapshot
./scripts/backup-elasticsearch.sh  # (restore procedure above)
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
