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

## 5. pgcat (task 2.2): what was checked, and how

The chart ships pgcat, not PgBouncer, so the two prerequisites above had to be
re-established for it. Both were checked against **pgcat v1.2.0's own source and
registry**, not against a running pooler:

| Claim | How it was checked |
|---|---|
| `ghcr.io/postgresml/pgcat:1.1.1` exists | **False.** The registry's only released tag is `v1.2.0`; everything else is a commit SHA or branch. The chart now pins `v1.2.0`. |
| `prepared_statements = true` is a `[general]` key | **False.** No such key exists in `struct General` (`src/config.rs`). pgcat does not use `deny_unknown_fields`, so it would have been ignored in silence. |
| `prepared_statements_cache_size` is pool-level, default 0 | True — `Pool::default_prepared_statements_cache_size() -> 0`. Zero means disabled, i.e. §3.1's failure on every query. The chart refuses to render a zero. |
| Every rendered key exists in pgcat's structs | True — all 22 keys of the rendered `pgcat.toml` matched `General` / `Pool` / `User` / `Shard`. |
| The image needs an explicit `command` | True — it declares `CMD ["pgcat"]` and **no** `ENTRYPOINT`, so `args` alone replaces the binary with the path to the TOML file. |

`cleanup_server_connections` (pgcat's `DISCARD ALL` between transactions, on by
default) would also clear a session GUC — PgBouncer's equivalent is not run in
transaction mode by default, which is why §1's leak was measurable. That
difference is exactly why the interlock does not rest on it: it is one
performance flag away from being off, and `RLS_MODE=local` holds either way.

## 6. What this does *not* prove

- No production or canary cell has run `RLS_MODE=local`. The plan's gate stands:
  two weeks on a canary before pgcat goes in front of anything.
- PgBouncer was the pooler measured in §1–§2. **No pgcat process has been
  started**: §5 is a source and registry audit of the configuration the chart
  generates, which is what catches a key in the wrong section — not a
  substitute for running it.
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
