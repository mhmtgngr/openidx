# PAM M2a — JIT/approval schema drift fix

> First half of milestone M2 (split from the JIT credential-checkout feature, which is
> M2b). A focused, standalone bugfix: create the two tables that Go code references but no
> migration ever created, so the referencing endpoints/workers stop returning 500s.

## Context

Two tables are written/read by production code but exist in **neither** the migration set
nor `deployments/docker/init-db.sql` — the same init-db↔migrations drift class as v38–v55,
but for tables that were *never created anywhere*:

- **`jit_grants`** — `internal/governance/jit.go` INSERTs/SELECTs/UPDATEs it across
  `RequestElevation`/`GrantElevation`/`GetActiveGrant`/`ExtendGrant`/`RevokeGrant` and the
  30-second `StartExpiryChecker` background worker. Every JIT-elevation call and the
  expiry worker error on `relation "jit_grants" does not exist`.
- **`request_approval_chains`** — `internal/governance/request.go` INSERTs it in
  `SubmitRequest` (line 166) and reads it in the escalation worker (line 435) and
  `GetRequest` (lines 543/626). So **`POST /api/v1/governance/requests` 500s today** and the
  escalation checker errors every tick.

This spec creates both tables exactly as the code expects. It is intentionally minimal:
no code changes, no new features (checkout is M2b).

## Design

New migration **v58** (`internal/migrations/sql_v58.go`, registered in `loader.go`),
mirrored verbatim into `deployments/docker/init-db.sql` so `TestInitDBParity` stays green.
Idempotent (`CREATE TABLE IF NOT EXISTS`). **Not under the v37 FORCE-RLS belt** — matching
the v42–v55 reconcile precedent and the code's actual usage:

- `jit_grants` is **not org-scoped in code** (queried by `user_id`+`role_id`+`status`; the
  only `org_id` in jit.go is on the `roles` lookup, not this table). Org isolation is
  implicit via the user/role FKs.
- `request_approval_chains` is a **child of `access_requests`** joined by `request_id`;
  its queries reach it only through the (RLS-scoped) `access_requests` parent, so it needs
  no own `org_id`/policy.

Adding `org_id` + RLS to either would require code changes and is out of scope for a
drift fix; if desired it becomes a separate hardening item.

### `jit_grants` (columns verified against jit.go INSERT/SELECT/UPDATE)

```sql
CREATE TABLE IF NOT EXISTS jit_grants (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id       UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    role_name     VARCHAR(255) NOT NULL,
    granted_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    justification TEXT NOT NULL,
    duration      VARCHAR(32) NOT NULL,          -- time.Duration.String()
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),  -- set by ExtendGrant/RevokeGrant; not in INSERT → needs default
    revoked_at    TIMESTAMPTZ,
    revoked_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    status        VARCHAR(16) NOT NULL DEFAULT 'active'  -- active|expired|revoked
);
CREATE INDEX IF NOT EXISTS idx_jit_grants_user_role ON jit_grants(user_id, role_id, status);
CREATE INDEX IF NOT EXISTS idx_jit_grants_expiry    ON jit_grants(status, expires_at);
```

Note: the INSERT supplies `(id,user_id,role_id,role_name,granted_by,justification,duration,expires_at,created_at,status)` — `updated_at` is omitted there and later UPDATEd, so its `DEFAULT NOW()` is required. `granted_by` is nullable (`ON DELETE SET NULL`) so grants survive granter deletion.

### `request_approval_chains` (columns verified against request.go)

```sql
CREATE TABLE IF NOT EXISTS request_approval_chains (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id           UUID NOT NULL UNIQUE REFERENCES access_requests(id) ON DELETE CASCADE,
    steps                JSONB NOT NULL DEFAULT '[]',
    escalate_after_hours INTEGER NOT NULL DEFAULT 24,
    escalate_to          JSONB NOT NULL DEFAULT '[]',
    escalation_due_at    TIMESTAMPTZ NOT NULL,
    current_step         INTEGER NOT NULL DEFAULT 0,
    escalation_notified  BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS idx_rac_escalation ON request_approval_chains(escalation_due_at)
    WHERE escalation_notified = false;
```

`UNIQUE (request_id)` — the code writes exactly one chain per request and updates/reads it
by `request_id`.

## Out of scope

- The JIT credential-checkout feature (M2b).
- Adding `org_id`/RLS to these tables (would need code changes).
- The `access_requests`/`access_request_approvals` `org_id` columns — those were added by
  the v34 org-id sweep (verify during implementation; if genuinely absent, add in this
  migration, but the v34/v37 belt almost certainly covered them).

## Testing

- **Integration** (`test/integration/`, matching the suite): after migrations apply, assert
  `jit_grants` and `request_approval_chains` exist with the expected columns; and a smoke
  test that an INSERT matching the code's column list succeeds (round-trips) for each.
- `TestInitDBParity` green (tables mirrored into init-db.sql).
- `go build ./...`, `go vet`, `gofmt`, `orgscope -fail ./internal` (no new queries — clean).

## Verification (box / CI)

- CI Integration Tests apply v58 cleanly; `TestInitDBParity` passes.
- Functional: `POST /api/v1/governance/requests` no longer 500s (creates a request +
  its approval chain); a JIT elevation via `JITService` inserts a `jit_grants` row and the
  expiry worker runs without error.

## Critical files

- New: `internal/migrations/sql_v58.go`; `test/integration/jit_drift_test.go`.
- Modify: `internal/migrations/loader.go` (register v58); `deployments/docker/init-db.sql`
  (mirror both tables).
- Reference (unchanged, the consumers that stop 500ing): `internal/governance/jit.go`,
  `internal/governance/jit_expiry.go`, `internal/governance/request.go`.
