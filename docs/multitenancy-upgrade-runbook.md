# Single-tenant → multi-tenant upgrade runbook (v1.6 → v1.8)

This runbook activates OpenIDX's tenant isolation on an install that has been
running single-tenant. The schema groundwork (v1.6.0) and app-layer scoping
(v1.7.0) are behavior-preserving; this procedure flips enforcement on and adds
the RLS belt (v1.8.0).

## Background

- **v1.6.0** added `org_id` to all 68 tenant-scoped tables, backfilled the
  default org (`00000000-0000-0000-0000-000000000010`), and created **dormant**
  RLS policies (`USING (true)`).
- **v1.7.0** made every service query filter by `org_id` from request context,
  and added the `DEFAULT_ORG_FALLBACK` switch (default **false**), per-tenant
  JWT `iss`, and platform-admin (`super_admin`) cross-org access with audit.
- **v1.8.0** rewrites the policies to a real predicate and turns on
  `ENABLE` + `FORCE ROW LEVEL SECURITY` (migration **v37**), with the per-request
  `app.org_id` GUC set at pool checkout and an explicit `app.bypass_rls` for
  background jobs.

## Pre-flight

1. Take a database backup. Migration v37 is reversible (down restores
   `USING (true)` + RLS off) but back up regardless.
2. Confirm you are on a build that includes migration v37 and the pool RLS hook
   (`internal/common/database/rls.go`).
3. Decide tenancy mode:
   - **Staying single-tenant:** set `DEFAULT_ORG_FALLBACK=true`. Every request
     resolves to the default org; RLS scopes to it. Nothing else to do.
   - **Going multi-tenant:** leave `DEFAULT_ORG_FALLBACK=false` (the default) and
     set `TENANT_BASE_DOMAIN` (e.g. `openidx.io`) so subdomains resolve tenants
     and tokens get per-tenant `iss`.

## Procedure

1. **Roll out config** to every service:
   - `DEFAULT_ORG_FALLBACK` (`true` for single-tenant, `false` for multi-tenant),
   - `DEFAULT_ORG_ID` (defaults to the canonical default org; override only if
     your default org row differs),
   - `TENANT_BASE_DOMAIN` (multi-tenant only).
2. **Deploy the v1.8.0 build.** On startup each service auto-runs migrations; v37
   activates RLS. The migrator runs with `app.bypass_rls=on`, so the migration
   itself is not filtered.
3. **Verify** (see below).

## Verification

- `\d+ users` (psql) shows `Force row security: on` and the policy predicate is
  `… org_id = NULLIF(current_setting('app.org_id', true), '')::uuid …` (not
  `true`).
- A normal authenticated request reads only its org's data.
- Background jobs (session expiry, JIT expiry, directory sync, cert monitor,
  metrics collectors, DSAR processor, …) continue to process rows — watch logs
  for a job suddenly doing nothing, which indicates a missing `app.bypass_rls`
  wiring (it would silently see 0 rows).
- Integration ship-gate: `make dev-infra && make test-integration` →
  `TestRLSBelt` and `TestCrossOrgIsolation` pass.

## Operating with RLS on

- Any **direct SQL** an operator runs against an org-scoped table will see **no
  rows** unless the session sets scope first:
  - read one org: `SELECT set_config('app.org_id', '<org-uuid>', false);`
  - cross-org maintenance: `SELECT set_config('app.bypass_rls', 'on', false);`
- Application code never needs to do this — the pool checkout hook derives the
  GUC from `orgctx`; background code opts into bypass via
  `orgctx.WithBypassRLS(ctx)`.

## Rollback

- Run migration **v37 down** (restores `USING (true)` + `NO FORCE` + RLS
  disabled). The app-layer `org_id` filters (v1.7.0) remain, so isolation is not
  lost — only the belt. Optionally set `DEFAULT_ORG_FALLBACK=true` to revert to
  permissive resolution.

## Notes

- The app connects as the table **owner**; that is why v37 uses `FORCE` (RLS is
  otherwise skipped for the owner). If you later move to a dedicated non-owner
  application role, `FORCE` becomes optional but harmless.
- `compliance_reader` is an org-scoped read-only audit role (audit read/export
  only); assign it via `organization_members.role` for external reviewers.
