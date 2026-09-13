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

### Measured behind a real pooler (2026-09-13)

`docs/evidence/2026-09-13-rls-transaction-pooling.md` records the run. Two
results worth carrying here:

1. **The leak is real and reproducible.** Behind PgBouncer in transaction mode,
   a client that stamps `app.org_id` session-scoped and disconnects leaves it on
   the backend; the *next, different* client reads that tenant's value. In
   `local` mode the same experiment leaves nothing behind. Under FORCE RLS the
   first case is a cross-tenant read.
2. **Two prerequisites the plan did not list.** pgx caches prepared statements,
   so the pooler must track them (`max_prepared_statements > 0` on PgBouncer
   ≥ 1.21, or the pgcat equivalent) or every query fails with
   `prepared statement … already exists`. And the RLS checkout hook must do
   nothing in `local` mode, or pgxpool cannot acquire a connection at all
   behind the pooler. Both are fixed in the tree; both are hard requirements
   for task 2.2.

**Still do not put pgcat in front until** `RLS_MODE=local` has run on a canary
cell for two weeks and `tools/orgscope` enforces that no query reaches the pool
outside a scoped wrapper (task 2.1b). The flag makes the transport safe; the
linter is what makes it complete.

## Update 2026-09-13 — the chart ships the pooler (task 2.2)

The Helm chart now has a `pgcat` block, **off by default**. What it changes when
turned on:

- **Who talks to whom.** The eight request-serving Deployments get a
  `DATABASE_URL` pointing at `<release>-pgcat:6432`; the migration Job, the
  bootstrap hook and the backup CronJob keep the direct DSN. None of those three
  survives transaction pooling — a migration's advisory lock is session-scoped,
  and `pg_dump` needs one session to hold its snapshot for the whole dump.
- **What bounds the connection count.** `replicaCount × poolSize` (2 × 40 by
  default), a constant. Without the pooler it is
  `services × replicas × DB_MAX_CONNS`, which autoscaling multiplies. So
  `DB_MAX_CONNS` keeps its meaning but stops being the number that protects
  Postgres; it then sizes cheap client connections to the pooler.
- **What watches it.** pgcat's Prometheus exporter is enabled and scraped;
  `OpenIDXPoolerClientsWaiting` replaces `OpenIDXDBPoolSaturation` as the alert
  that sees the wall, and `OpenIDXPoolerNoRedundancy` covers the new single
  point of failure in front of the database.

**The chart refuses to render** `pgcat.enabled=true` while `config.rlsMode` is
anything but `local` — there is no override, because the override is the thing
that makes it safe. It also refuses a `preparedStatementsCacheSize` of 0, which
is pgcat's own default and means a fleet that cannot run one query. Both
refusals, plus the routing above, are asserted in CI (`.github/workflows/
helm.yml`, "The transaction pooler is safe by construction") and each assertion
was checked by breaking the thing it guards.

The gate in the previous section still stands: `RLS_MODE=local` on a canary cell
for two weeks, and `tools/orgscope` finished, **before** anything turns this on.
Shipping the chart support is not the same as having run it — no pgcat process
has been started against OpenIDX yet (see the evidence note, §6).

## Update 2026-09-13 — per-plane roles, and why they and the pooler are exclusive (task 2.4)

Migration v189 created `openidx_issue`, `openidx_admin` and `openidx_event` —
one Postgres LOGIN role per availability plane, each `IN ROLE openidx_app` and
each carrying its own budget on the **server**: `statement_timeout` 2s / 10s /
30s, `idle_in_transaction_session_timeout` 60s / 120s / 300s. Nothing used
them: the migration provisions the roles, and a deployment opts in by pointing
a service's `DATABASE_URL` at one. `database.planeRoles.enabled` is that
switch, and it is off by default.

**Why the budget belongs to the role.** Every service connects as one role
today with no query time limit, so one expensive ADMIN or EVENT query — an
audit search, a governance report, a SCIM page with a bad predicate — is
indistinguishable to Postgres from a token exchange, and holds a backend for as
long as it likes. Once a query is *running*, the database cancelling it is the
only layer that can stop it: cancelling a Go context abandons the call while
the backend keeps burning CPU and holding its locks. Attaching the limit to the
role rather than to a DSN also means `\drds` lists it, an operator cannot lose
it by editing a secret, and it holds for a `psql` session opened as that role.

**What was measured** (`internal/migrations/plane_roles_test.go`, against a
real PostgreSQL with the **whole** migration chain applied by a NOSUPERUSER
NOCREATEROLE NOBYPASSRLS owner — the shape the bundled chart creates):

- All three roles reach **every one of 220 tables** and every sequence. This
  was the open question: the roles *inherit* their grants and hold none of
  their own, and the tables arrive across 190-odd migrations, some granting to
  `openidx_app` explicitly and the rest relying on the default privileges v53
  set. One table that got neither would be a service that starts, passes its
  health check, and answers a single endpoint with `permission denied for
  table`.
- The budgets survive `database.NewPostgres` — the pool the services actually
  open, not a bare `pgx` connection.

**The interaction that would have been silent.** `DB_STATEMENT_TIMEOUT` is sent
as a connection *runtime parameter*, and a runtime parameter **beats** the
value `ALTER ROLE ... SET` attached to the role. `values-prod.yaml` sets
`database.statementTimeout: "30s"`, so a production install that simply flipped
`planeRoles.enabled` would have handed all three planes 30 seconds, on every
service, with nothing in any log to say so. Measured: with
`DB_STATEMENT_TIMEOUT=45s` the test reports 45 000 ms for all three roles. The
chart therefore **refuses to render** `planeRoles.enabled` while
`database.statementTimeout` is set, and names the file to clear it in.

**Why pgcat and the plane roles cannot both be on.** Two reasons, and the
second is the real one:

1. Both inject `DATABASE_URL` as a pod `env` entry, so the rendered Deployment
   would carry the name twice.
2. A transaction pooler multiplexes many clients onto a few *server*
   connections, and the per-role budget is a property of the server connection
   — which pgcat opens as its own pool user, once, for everybody. Getting the
   budgets back means giving pgcat three pool users
   (`openidx_issue`/`openidx_admin`/`openidx_event`) and splitting the cell's
   backend budget three ways. That is a sizing decision with a real cost, not a
   flag, and it is not made here.

So the chart refuses the combination and says which decision is outstanding.
Six interlocks in total are asserted in CI (`.github/workflows/helm.yml`, "Each
plane connects as its own role, or none of them does"), together with the
rendered fact that all eight services take the plane their assignment names and
that the migration and bootstrap Jobs keep the owner DSN — the migration does
DDL the runtime roles do not have.

**Still not run in anger.** The roles have never served production traffic. The
assignment table starts deliberately loose: `identity-service` takes `admin`
(10s) rather than `issue` (2s), because one unsplit identity-service serves
both planes and the tighter budget would cancel legitimate console queries.
`SERVICE_PROFILE` (task 3.4) splits that process in two; the auth half moves to
`issue` when the chart renders both halves.
