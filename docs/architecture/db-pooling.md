# OpenIDX DB connection pooling

Roadmap item #9. OpenIDX runs ~8 services against **one** Postgres, so the fleet
must fit under `max_connections`.

## The sizing problem

Each service holds its own pgx pool (`internal/common/database/database.go`).
The old default was `DB_MAX_CONNS=25` → **8 × 25 = up to 200** connections vs a
typical `max_connections=100`. At idle that's fine (the box sits ~40), but a load
spike across services exhausts Postgres → `FATAL: too many clients` for everyone.

## The fix (right-sizing)

Defaults lowered to **`DB_MAX_CONNS=10`, `DB_MIN_CONNS=2`** per service:

| | per service | fleet (×8) |
|---|---|---|
| max | 10 | 80 |
| min (idle) | 2 | 16 |

`80 < 100` leaves ~20 for migrations, admin/psql, and monitoring. Both are
env-overridable — raise `DB_MAX_CONNS` for a genuinely hot service **and** bump
Postgres `max_connections` to keep the fleet total under it. The
`OpenIDXDBPoolSaturation` alert (`deployments/monitoring/alerts.yml`) fires when a
service holds >80% of its pool, so you size from evidence, not guesswork.

## ⚠️ Why NOT pgbouncer (in transaction mode)

The obvious next step — front Postgres with a **transaction-pooling** pgbouncer so
the services share a small bounded pool — **would break tenant isolation** here.

OpenIDX enforces multi-tenancy with RLS driven by a **session GUC** set at pool
checkout (`internal/common/database/rls.go`):

```go
select set_config('app.org_id', $1, false)   // false = SESSION scope, not SET LOCAL
```

Transaction pooling multiplexes many clients over few backend connections and
**does not preserve session state** across transactions — the `app.org_id` set at
checkout would apply to the wrong backend (or be lost), so a query could run
under another tenant's org_id or none. That's a cross-tenant data leak.

Options if pooling is ever truly needed at scale:
1. **Right-size pools** (what we do) — sufficient for this scale.
2. **Session-mode** pgbouncer — safe (1:1 client↔backend for the session), but
   gives little multiplexing benefit; mostly a connection gate.
3. Refactor RLS to set the GUC as **`SET LOCAL` inside every transaction** — then
   transaction pooling is safe, but it's an invasive change touching every query
   path and is out of scope until scale demands it.

**Do not add a transaction-pooling pgbouncer without doing (3) first.**
