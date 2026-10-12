# Runbook: from observe to enforce

A production install starts only when every authorization control enforces,
or while a declared observe window is open. This is how an install that has
been running in development mode, or with controls in observe mode, gets to
fully enforcing without anyone losing access by surprise.

The controls (variable names as the startup log and the console show them):

| Control | What it refuses when enforcing |
| --- | --- |
| `ACCESS_ASSIGNMENT_ENFORCE=true` | reaching an application that is not assigned to the user or one of their groups |
| `STEPUP_GATE=enforce` | a privileged-session launch or an admin write without a fresh second factor |
| `BOT_GATE=enforce` | a credential spray spread across many addresses, until it proves a human |
| `POSTURE_DEVICE_TRUST_GATE=enforce` | overlay reach from a device whose posture failed |
| `PAM_REQUIRE_ZTNA=enforce` | a privileged session that would dial its target off the overlay (needs `GUACAMOLE_ZITI_PUBLIC_URL`) |
| `ACCESS_API_REQUIRE_AUTH=true`, `ADMIN_API_REQUIRE_AUTH=true` | anonymous callers on the access and admin APIs |

## 1. Declare the window

In the services' environment (on the reference box: `~/.config/oidx/common.env`,
read by every `oidx-*` unit):

```
APP_ENV=production
ENFORCEMENT_OBSERVE_UNTIL=2026-10-23      # ≤ 30 days ahead
ACCESS_ASSIGNMENT_ENFORCE=false           # or leave unset
STEPUP_GATE=observe
BOT_GATE=observe
POSTURE_DEVICE_TRUST_GATE=observe
PAM_REQUIRE_ZTNA=observe
ACCESS_API_REQUIRE_AUTH=true              # these two have no observe mode: turn them on now
ADMIN_API_REQUIRE_AUTH=true
```

Restart the services. Each one logs `AUTHZ: observe window until … (N day(s)
left)` and one `AUTHZ: control not enforcing` line per open control. A service
that does not start prints the controls it refuses and this file's advice.

`APP_ENV=production` also requires real secrets, TLS to the database and Redis,
CSRF, no wildcard CORS or trusted proxies, and non-default Ziti and Guacamole
passwords. Fix those first; they do not have an observe mode.

## 2. Read what would have been refused

Console → **Security → Enforcement** (`GET /api/v1/admin/security-posture`).
For each control it shows the mode, the days left, and **would deny (7d)**:
how many times in the last week the control recorded a refusal it did not
carry out. The same rows are in the unified audit log under
`access.assignment.would_deny` and `pam.ztna.would_deny`.

- A would-deny count of 0 for a week: flip that control.
- A count above 0: open the audit rows, assign the application (or group) the
  people were reaching, or publish the privileged target on the overlay, then
  watch the count fall.

Do not extend the window because a count is still high; fix the assignments.
The window exists so that nobody is surprised, not so that nothing changes.

## 3. Flip

Set each control to `enforce` / `true`, remove `ENFORCEMENT_OBSERVE_UNTIL`, and
restart. The startup log reports `open_gates: 0, fully_enforcing: true` and the
console page shows every control green. Keep the audit query from step 2 as a
dashboard panel: once enforcing, the same actions appear as `access.decision.deny`.

## The bypass role (before `APP_ENV=production`)

Background work reads across tenants as a role with `BYPASSRLS`, not with a
session setting the application role could also set (#964). Production refuses
to start without `DATABASE_BYPASS_URL`. On the reference box, once, as the
Postgres superuser inside `oidx-pg`:

```sql
CREATE ROLE openidx_bypass LOGIN NOSUPERUSER BYPASSRLS NOCREATEDB NOCREATEROLE INHERIT IN ROLE openidx_app PASSWORD '<random>';
GRANT CONNECT ON DATABASE openidx TO openidx_bypass;
ALTER ROLE openidx BYPASSRLS;   -- the owner that runs migrations; services connect as openidx_app
```

Then in `~/.config/oidx/common.env`:

```
DATABASE_BYPASS_URL=postgres://openidx_bypass:<random>@localhost:55432/openidx
```

Restart the services; each logs that the bypass pool is open. Run
`oidx-migrate up`: migration 231 now removes the `app.bypass_rls` clause from
every policy and reports how many. Do **not** give the owner `BYPASSRLS` on an
install whose services connect as the owner.

**Helm.** From the chart after v1.42.0, the services connect as `openidx_app`
and `openidx_bypass`, never as the owner, and with the bundled PostgreSQL the
bootstrap hook creates the bypass role, sets both passwords and gives the owner
`BYPASSRLS` (`docs/docs/deployment/kubernetes.md`, "Database roles"). With
External Secrets, store `database-app-url` and `database-bypass-url` and run
the SQL above against your database yourself.

An install that already ran migration 231 while the owner lacked `BYPASSRLS`
recorded it with a NOTICE and changed nothing, so `migrate up` will not run it
again. Background work still reads through the bypass role, so nothing is
broken, but the `app.bypass_rls` clause stays in the policies. To remove it,
run the body of migration 231 (`bypassGUCLeavesPoliciesUp` in
`internal/migrations/sql_v231.go`) once with `psql` as the owner. It changes
only the policies that still mention the clause, and it fails if any policy
still mentions it afterwards.

## If the window runs out

A service started after the named day refuses with
`the observe window ended on …: set each control above to enforce`. Either flip
(step 3) or, if an application is still being assigned, declare a new window
with a date you intend to keep.

## Upgrading the reference box (`scripts/box-deploy.sh`)

Every change above reaches the box through a release deploy. Since v1.44.0 that
deploy is `scripts/box-deploy.sh`, one step at a time (it is not
`scripts/deploy-box.sh`, which deploys the docker-compose stack). Build the
seven services and `cmd/migrate` into `~/oidx-runtime/stage-<version>/` as
`oidx-<name>`, the console into `stage-<version>/dist/`, write the release to
`stage-<version>/VERSION`, then:

```
export VERSION=v1.45.0 EXPECT_SCHEMA=236     # the last migration the release ships
scripts/box-deploy.sh preflight   # stage complete? live schema (saved for rollback), owner URL present, units
scripts/box-deploy.sh rehearse    # newest backup -> throwaway postgres:16-alpine on 127.0.0.1:55499 -> migrate up
scripts/box-deploy.sh dump        # fresh pg_dump from oidx-pg (path saved for rollback)
scripts/box-deploy.sh stop
scripts/box-deploy.sh migrate     # as the owner; fails unless the live schema reaches EXPECT_SCHEMA
scripts/box-deploy.sh swap        # binaries keep .rollback-<ts>; dist is rsynced INTO the bind-mounted dir
scripts/box-deploy.sh start
scripts/box-deploy.sh verify      # /health per port, edge via SNI, schema, error lines in /tmp/oidx-logs/<svc>.log
```

The rehearsal never uses a scratch database inside `oidx-pg`: roles are
cluster-global and migrations create them. It copies the live role names
(without logins) into the throwaway container, restores, migrates with the
staged binary and removes the container (`REHEARSE_KEEP=1` keeps it). Run
`verify` again after the first five-minute background tick.

`scripts/box-deploy.sh rollback` stops the units and puts back the binaries and
console saved under the same rollback suffix (`TS`, kept in
`stage-<version>/rollback_ts`). It does not touch the database: it prints the
two ways back, `oidx-migrate down <previous schema>` as the owner or a
`pg_restore --clean --if-exists` of the pre-deploy dump. Units, binaries and
paths are overridable (`UNITS`, `BINS`, `RT`, `DIST`, see the script header).
The script never prints a database URL and refuses to run under `set -x`.

The three PAM Ziti-broker containers have no unit of their own; after a reboot
they stay stopped. `scripts/box-pam-units.sh` shows the units it would add,
and `scripts/box-pam-units.sh --apply` writes and enables them.
