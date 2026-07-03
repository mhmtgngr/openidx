# Attestation tenant isolation (readiness W2.7)

> First item of Workstream 2 (architecture correctness). A **real cross-org data
> exposure**: `attestation_campaigns` and `attestation_items` (created by migration v54)
> have **no `org_id`**, and the handlers in `internal/admin/attestation.go` query them
> **without an org filter**. Any authenticated admin sees and acts on **every org's**
> attestation campaigns and items. Fix = add `org_id` + the v37 FORCE-RLS belt (the real
> enforcement boundary) + set `org_id` on writes + org-scope reads.

## Problem (verified)

- `internal/migrations/sql_v54.go` defines both tables with **no `org_id`** column (and they
  are mirrored the same way in `deployments/docker/init-db.sql`).
- `internal/admin/attestation.go`:
  - `handleListAttestationCampaigns` — `SELECT ... FROM attestation_campaigns ORDER BY created_at` (no org filter).
  - `handleGetAttestationCampaign` / `handleUpdateAttestationCampaign` / `handleLaunchAttestationCampaign` — `WHERE id = $1` only.
  - `handleCreateAttestationCampaign` — `INSERT ... (no org_id)`.
  - `generateAttestationItems` — inserts items with no `org_id` (it already resolves `org` via `orgctx.From` to scope the *source* tables, but the item rows themselves carry no org).
- These tables are reached via the shared RLS-configured pool (the `configureRLS` PrepareConn hook
  sets `app.org_id` from `orgctx`), so once the tables carry `org_id` and are under the belt, RLS
  enforces isolation on every statement — the same mechanism protecting `vault_secrets` etc.

## Fix

### 1. Migration v61 — `attestation_org_isolation` (`internal/migrations/sql_v61.go`, registered in `loader.go`)

For **each** of `attestation_campaigns`, `attestation_items` (plain statements only — the runner's
`splitSQL` cannot handle `DO $$` blocks, per the v56/v57 lesson):

```sql
-- add column + FK idempotently (ADD COLUMN IF NOT EXISTS guards the whole clause;
-- nullable at first so existing rows are allowed)
ALTER TABLE attestation_campaigns ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE attestation_items      ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- backfill: campaigns → oldest (primary) org; items → their parent campaign's org
UPDATE attestation_campaigns SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;
UPDATE attestation_items ai SET org_id = ac.org_id FROM attestation_campaigns ac WHERE ai.campaign_id = ac.id AND ai.org_id IS NULL;
-- any still-orphan items (campaign already gone) → oldest org, so SET NOT NULL can't fail
UPDATE attestation_items SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE attestation_campaigns ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE attestation_items      ALTER COLUMN org_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_attestation_campaigns_org ON attestation_campaigns(org_id);
CREATE INDEX IF NOT EXISTS idx_attestation_items_org     ON attestation_items(org_id);

-- v37 FORCE-RLS belt (USING + explicit WITH CHECK so INSERT/UPDATE are enforced too)
DROP POLICY IF EXISTS pol_attestation_campaigns_org_scope ON attestation_campaigns;
CREATE POLICY pol_attestation_campaigns_org_scope ON attestation_campaigns
  USING (current_setting('app.bypass_rls', true) = 'on' OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on' OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE attestation_campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE attestation_campaigns FORCE  ROW LEVEL SECURITY;
-- …same policy for attestation_items…

-- plain GRANT (openidx_app provisioned by v53; belt-and-suspenders)
GRANT SELECT, INSERT, UPDATE, DELETE ON attestation_campaigns, attestation_items TO openidx_app;
```

Down: drop the two policies, `DISABLE ROW LEVEL SECURITY`, drop the two `org_id` columns.

Idempotent (safe to re-apply): `ADD COLUMN IF NOT EXISTS`, `SET NOT NULL` (no-op if already set),
`DROP POLICY IF EXISTS` + `CREATE POLICY`, `CREATE INDEX IF NOT EXISTS`.

### 2. Mirror into `deployments/docker/init-db.sql`

Add `org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE` to both `CREATE TABLE`
definitions (matching the migrated schema on a fresh DB — init-db creates orgs before these tables,
so NOT NULL is fine as there are no pre-existing rows), the two indexes, the ENABLE/FORCE + policy
belt, and the grant. `TestInitDBParity` is table-existence-level, but mirror fully for real
migrate-vs-init parity (see W2.9).

### 3. Handlers (`internal/admin/attestation.go`) — set org on writes, scope reads

- `handleCreateAttestationCampaign`: resolve `org, err := orgctx.From(c.Request.Context())` (403 if
  absent); add `org_id` to the INSERT column list + `$…` = `org.ID`. (RLS `WITH CHECK` would reject a
  mismatched/absent org_id anyway — this makes it correct, not just non-erroring.)
- `generateAttestationItems`: it already has `org` from `orgctx.From`; add `org_id` = `org.ID` to
  every `INSERT INTO attestation_items (...)` (role / application / group / vault_access /
  rotation_policy branches).
- Reads (`handleListAttestationCampaigns`, `handleGetAttestationCampaign`,
  `handleUpdateAttestationCampaign`, `handleLaunchAttestationCampaign`, and the decision path):
  RLS already enforces isolation, but add explicit `org_id = $…` predicates (defense-in-depth) and/or
  `//orgscope:ignore` annotations as the `tools/orgscope` linter requires. Run the linter and resolve
  every finding it raises on this file — do not leave a bare unscoped query on these now-org-scoped
  tables.

## Testing

- **Unit** (`internal/migrations`): existing `TestInitDBParity` stays green.
- **Migration apply** (integration, testcontainers): v61 applies on top of init-db and on a fresh
  init-db; both tables end up with `org_id NOT NULL` + the policy present (`pg_policies`).
- **Isolation** (integration): with two orgs A and B, a campaign created under A's `app.org_id` GUC is
  **not** visible when the GUC is set to B (RLS), and an INSERT with a mismatched org_id is rejected
  by `WITH CHECK`. Prefer extending the existing RLS/integration test harness if one exists; if the
  suite requires infra not available here, note it and rely on the migration-apply + a query-shape
  unit assertion.
- **Gates**: `go build ./...`, `go vet`, `gofmt`, `go run ./tools/orgscope -fail ./internal` (must be
  clean — the whole point), `golangci-lint`, and the branch CI Required Checks green.

## Out of scope
`jit_grants` / `request_approval_chains` org_id (that's W2.10, defense-in-depth, lower priority);
column-level parity guard + `ziti_certificates` (W2.9). This item is attestation isolation only.

## Critical files
- New: `internal/migrations/sql_v61.go`; edit `internal/migrations/loader.go` (register v61),
  `deployments/docker/init-db.sql` (mirror), `internal/admin/attestation.go` (org on writes + scope reads).
- Reuse anchors: `internal/migrations/sql_v56.go` + `sql_v37.go` (belt pattern), `internal/common/orgctx`.
