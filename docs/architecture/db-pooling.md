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

## Update 2026-09-13 — option (3) exists, behind a flag

Option 3 above is implemented (global-scale plan task 2.1a,
`internal/common/database/tx.go`). `RLS_MODE` selects how the tenant scope
reaches Postgres:

| `RLS_MODE` | Where the scope lives | Transaction pooling |
|---|---|---|
| `session` (default) | the pooled connection, stamped at checkout (`rls.go`) | **unsafe** — the warning above stands |
| `local` | the transaction, `set_config(..., true)` inside it (`tx.go`) | safe: Postgres resets it at COMMIT |

In `local` mode the checkout hook stamps nothing and every query runs inside a
scoped transaction, through `db.WithTx` / `db.Query` / `db.QueryRow` / `db.Exec`.
The default is unchanged, so an existing deployment behaves exactly as before
until it opts in.

Measured against a real Postgres as a non-superuser role
(`internal/common/database/rls_local_test.go`, CI job `rls-isolation`), on a
pool restricted to **one connection** so every tenant reuses the same backend —
the shape a transaction pooler creates:

- two tenants alternating 25 times each see only their own rows;
- 200 concurrent readers across two tenants produce zero cross-tenant reads;
- after a scoped transaction commits the connection carries **no** scope, so an
  unscoped query sees zero rows rather than the previous tenant's — this is the
  property that makes pooling safe;
- a cross-tenant write is refused by `WITH CHECK`, and the bypass marker does
  not outlive its transaction either.

The suite refuses to run as a superuser (Postgres exempts superusers from every
policy, so it would pass vacuously), and both mutations of the scope statement —
making it session-scoped, and omitting it — turn it red.

**Still do not put pgcat in front until** `RLS_MODE=local` has run on a canary
cell for two weeks and `tools/orgscope` enforces that no query reaches the pool
outside a scoped wrapper (task 2.1b). The flag makes the transport safe; the
linter is what makes it complete.
