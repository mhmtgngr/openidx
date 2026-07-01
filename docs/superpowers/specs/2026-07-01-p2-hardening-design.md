# P2 hardening cluster — cross-org audit, IP-threat visibility, dead DDL

Three low-severity hardening items from the v2.0 audit, plus one deliberately
deferred. One PR.

## P2-1 — Platform-admin cross-org audit silently fails under RLS

`audit/cross_org.go` `CrossOrgAuditor` records the mandatory audit row when a
platform admin crosses an org boundary. It inserts `org_id = target.ID` into the
FORCE-RLS `audit_events` table on `c.Request.Context()` (**no bypass**), and
swallows the result (`_, _ = pool.Exec(...)`).

Two problems, both realized under the `openidx_app` cutover:
1. The insert's `WITH CHECK` requires `org_id == current_setting('app.org_id')`
   or bypass. The row's `org_id` is the **target** org, generally not the
   session's resolved org → the insert is **rejected**, so cross-org accesses go
   **unaudited**. (This is a P0-2-class fail-closed, in a security audit path.)
2. The swallowed error means the failure is **invisible**.

**Fix:**
- Wrap the insert ctx in `orgctx.WithBypassRLS(c.Request.Context())` — the
  cross-org audit is legitimately cross-org (it writes the target org's row from
  a different session), so bypass is correct and safe.
- Add a `logger *zap.Logger` parameter to `CrossOrgAuditor` and **log a warning**
  when the insert fails (a mandatory audit that fails must be visible). Keep it
  best-effort (don't block the request) — matching its documented contract.
- Update the 7 call sites (`cmd/{provisioning,access,identity,admin-api,oauth,
  audit,governance}-service/main.go`), which all have `log := logger.New()` in
  scope, to `audit.CrossOrgAuditor(db.Pool, log)`.

## P2-2 — IP-threat check fails open silently on DB error

`access/context_evaluator.go` `checkIPThreat` runs `SELECT … FROM ip_threat_list
WHERE ip_address=$1` and, on **any** error, `return "", false` (not blocked).
That conflates:
- `pgx.ErrNoRows` — the IP isn't a listed threat → allow (correct, the common
  case), and
- a real DB error — unknown state, currently **silently admits** the IP.

**Fix:** distinguish them — on `pgx.ErrNoRows` allow with no log; on a real DB
error **log a warning** and still allow. Keeping the fail-**open** posture on a
transient DB error is deliberate and documented in a comment: `ip_threat_list`
is a secondary deny-list; failing **closed** would block *all* proxied traffic
on any DB blip (a worse DoS than the residual risk of admitting a listed IP
during an outage). The hardening here is **visibility**, not changing the
posture. Requires adding `errors` and `github.com/jackc/pgx/v5` imports.

## P2-3a — Delete dead oauth runtime-DDL

`EnsureConsentTable` (`oauth/consent.go:492`), `EnsureClientsTable`
(`oauth/client.go:552`), `EnsureSigningKeysTable` (`oauth/keys.go:597`) each run
`CREATE TABLE IF NOT EXISTS …` at runtime. They have **no callers** (verified),
are redundant with the migrations that own those tables, and would fail under the
non-owner `openidx_app` role if ever wired. **Delete** all three (and any
now-unused helper/imports they leave behind; confirm no test references them).

## P2-3b — `ensurePartition` / tamper-evident Store: DEFERRED (out of scope)

`audit/store.go`'s `ensurePartition` creates `audit_events_tamper_evident`
partitions at runtime (and the Store self-creates that table). This is real
runtime DDL that `openidx_app` can't execute — **but the Store is unwired**:
`audit.NewStore` has no production constructor and `audit_events_tamper_evident`
exists in **no migration or init-db**, so nothing runs this path today. Deleting
the whole (coherent, if unshipped) tamper-evident audit feature is beyond a P2
hardening pass and risky. **Action:** add a one-line note comment on the Store
that its schema/partition DDL must move to migrations before it is ever wired
(so a future integrator doesn't ship runtime DDL that breaks under `openidx_app`).
No behavioral change.

## Testing

These are error-path / dead-code changes; coverage is pragmatic:
- **Build/vet/lint/orgscope** must be clean (covers P2-3a deletion + the imports).
- **P2-1** is exercised by the existing integration `TestCrossOrgIsolation`
  (the platform-admin audited-bypass assertion) — which should now pass under an
  `openidx_app`-role DB where it previously wouldn't have recorded the row. No new
  DB unit test (the auditor needs a real pool); the bypass + log are
  inspection-simple. The 7 call-site updates are compile-checked.
- **P2-2**: the `ErrNoRows`-vs-error branch is inspection-simple and needs a live
  DB to exercise the error path; rely on build + the existing access tests. (If a
  cheap seam exists in the access test harness, add a `checkIPThreat` allow-on-
  ErrNoRows case; otherwise omit rather than build DB scaffolding for a log line.)

## Out of scope

- The tamper-evident Store rework (P2-3b — note only).
- Reverse init-db drift, LDAP `skip_tls_verify`, OPA dev fail-open (separate
  low-priority audit items).

## Verification checklist

- [ ] `CrossOrgAuditor` takes a logger, wraps ctx in `WithBypassRLS`, logs on
  insert failure; all 7 mains updated.
- [ ] `checkIPThreat` distinguishes `ErrNoRows` (silent allow) from real errors
  (logged warn, allow); comment documents the fail-open trade-off.
- [ ] The 3 oauth `Ensure*Table` functions deleted; no callers/tests broken.
- [ ] `ensurePartition`/tamper-evident Store carries a note about migrating its
  DDL before wiring.
- [ ] build / vet / gofmt / golangci-lint / orgscope green; touched-package tests
  pass.
