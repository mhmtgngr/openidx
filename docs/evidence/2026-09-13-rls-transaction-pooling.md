# Evidence: the tenant scope behind a transaction pooler

**Date:** 2026-09-13 · **Tasks:** global-scale plan 2.1a / 2.1b, prerequisite for 2.2
**Ran against:** PostgreSQL 16.13 and PgBouncer 1.22.0 (`pool_mode=transaction`,
`default_pool_size=1`), application role `openidx_app` (not superuser, not
`BYPASSRLS`).

Everything below was executed, not reasoned about. The design
(`docs/architecture/2026-09-13-global-scale-cell-architecture-and-ddos.md`, finding
B1) predicted the leak; this is the measurement.

## 1. The leak the design predicted, reproduced

Session-scoped stamping is what `rls.go` does at pool checkout:
`set_config('app.org_id', …, false)`, outside any transaction. Behind a
transaction pooler, the backend that carries it is handed to the next client.

From a freshly restarted pooler, one client stamps and disconnects; a **different**
client then reads the setting:

| Stamp form | What the next client sees |
|---|---|
| `set_config(…, false)` — session, today's checkout hook | **`BBBB`** — the previous client's tenant |
| `set_config(…, true)` — transaction-local, `tx.go` | *(empty)* |

Under FORCE RLS the first row means the second client reads the first tenant's
data. That is the cross-tenant leak, and it is why `RLS_MODE=local` exists.

The residue is durable: a later automated run failed with
`Should be empty, but was BBBB`, still reading the GUC left on the pooled
backend by the manual experiment minutes earlier. The connection is recycled;
the session state is not cleaned.

## 2. `RLS_MODE=local` holds, through the pooler

The full isolation suite (`internal/common/database/rls_local_test.go`), run with
`TEST_POSTGRES_POOLER_DSN` pointing at PgBouncer:

| Assertion | Result |
|---|---|
| Two tenants alternating 20–25× on a shared backend | pass — each sees only its own row |
| 200 concurrent readers, two tenants, one backend | pass — zero cross-tenant reads |
| Scope after COMMIT | pass — gone; an unscoped query sees zero rows |
| Cross-tenant write | pass — refused by `WITH CHECK` |
| Bypass marker | pass — works, and does not outlive its transaction |
| Unedited `db.Pool.Query/QueryRow/Exec/Begin/SendBatch` | pass — scoped by the wrapper |
| `Raw()` | pass — deliberately unscoped, so fail-closed |

## 3. Two prerequisites this surfaced, which the plan did not mention

**3.1 The pooler must track prepared statements.** pgx caches prepared
statements. A transaction pooler that does not track them fails long before RLS
is reached:

```
ERROR: prepared statement "stmtcache_a47001a4…" already exists (SQLSTATE 42P05)
```

PgBouncer needs `max_prepared_statements > 0` (≥ 1.21; 200 was used here).
pgcat must be configured equivalently, or pgx must be forced to the simple
protocol. **Task 2.2 cannot land without this.**

**3.2 The checkout hook must be silent in local mode.** With the hook still
stamping, pgxpool gave up acquiring connections entirely behind the pooler:

```
pgxpool: too many failed attempts acquiring connection;
likely bug in PrepareConn, BeforeAcquire, or ShouldPing hook
```

`rls.go` now returns immediately when the mode is `local`, which is both correct
and required for a pooled deployment to start at all.

## 4. The tests are load-bearing

Mutating the scope statement to session scope (`true` → `false`) turns
`TestRLSLocal_ScopeDoesNotSurviveTheTransaction` red with the message naming the
consequence; removing the scope call entirely turns
`TestRLSLocal_BypassStillSeesEverything` red. Pointed at a superuser DSN the
whole suite refuses to run, because Postgres exempts superusers from every
policy and every assertion would otherwise pass with the belt cut.

## 5. What this does *not* prove

- No production or canary cell has run `RLS_MODE=local`. The plan's gate stands:
  two weeks on a canary before pgcat goes in front of anything.
- PgBouncer was the pooler here; pgcat is what the plan names for production and
  it has not been exercised.
- `default_pool_size=1` maximises the hazard deliberately. Real pool sizing and
  the connection-budget claim behind task 2.2 are unmeasured.

## Reproducing

```bash
# Postgres + a non-superuser role, then PgBouncer with pool_mode=transaction
# and max_prepared_statements = 200.
export TEST_POSTGRES_DSN="postgres://openidx_app:…@127.0.0.1:5433/openidx_rls?sslmode=disable"
export TEST_POSTGRES_POOLER_DSN="postgres://openidx_app:…@127.0.0.1:6432/openidx_rls?sslmode=disable"
RLS_MODE=local go test ./internal/common/database/ -run 'RLS|ScopedPool' -count=1 -v
```
