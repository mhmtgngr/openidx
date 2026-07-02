# PAM M1b — Credential Rotation Engine design

> Milestone M1b of the [PAM roadmap](2026-07-02-pam-architecture-roadmap.md). Builds
> directly on the [M1 vault store](2026-07-02-pam-m1-vault-store-design.md): the engine
> generates new credential values, applies them to target systems, and stores them as
> vault versions. Scoping decisions confirmed with the user: connectors = **directory +
> generate-only**; triggers = **scheduled + on-demand + rotate-on-checkout**; safety =
> **candidate-version + verify-then-promote**; rotate-now is **admin-only**.

## Context

The vault (M1) can store and version secrets but cannot change the underlying credential
on the system that owns it, and the `credential_rotations` table
(`migrations/023_password_management.up.sql:10-19`) has been dead since it shipped. M1b
adds the rotation engine: a leader-gated scheduler + connectors that generate a new
credential, apply it to the target, verify it, and promote it in the vault — turning the
vault from passive storage into managed credentials.

OpenIDX already has the two hard pieces: **directory password write-back**
(`directory.Service.ResetPassword(ctx, directoryID, username, newPassword)` →
AD `unicodePwd` / LDAP RFC-3062 / Azure Graph) and a **proven rotation state-machine
pattern** (`internal/access/ziti_hardening.go:175-472`: `active→rotating→rotated`,
revert-on-failure, circuit breaker, `StartCertificateMonitor` 1h ticker over due rows,
leader-gated). M1b reuses both.

**Outcome:** an admin can attach a rotation policy to a vault secret; the engine rotates
it on a schedule, on demand, or when a checkout is returned — safely (no lockout, never
lose a value, `Use`/`Reveal` never return an unconfirmed credential), fully audited.

## Non-goals (out of scope for this spec)

- **SSH / database / cloud-IAM connectors** — deferred to M5. The `Rotator` interface is
  designed so they slot in without engine changes, but only `directory` and
  `generate_only` ship here.
- **Session credential injection** (M3) — a separate consumer of `vault.Use()`.
- **Break-glass / emergency rotation workflows** — later.
- **Rotate-now honoring a per-secret `rotate` grant** — admin-only is sufficient for now
  (the `rotate` grant action reserved in M1 stays reserved).

## Architecture

- **`internal/credentials`** — the engine:
  - `rotator.go` — the `Rotator` interface, `generateSecret`, and the connector registry.
  - `directory_rotator.go` — directory connector (Apply via `directory.Service`, Verify
    via LDAP bind).
  - `generate_rotator.go` — generate-only connector (no-op Apply, notify).
  - `engine.go` — `Service` with `RotateSecret(ctx, policyID)` (the state machine) + policy CRUD.
  - `scheduler.go` — leader-gated periodic pass (due-by-interval + rotate-on-checkout).
  - `handlers.go` — admin-api handlers under `/api/v1/vault/rotation-policies` and the
    per-secret rotate/history routes.
- **Additive changes to `internal/vault`** (M1b is a superset consumer):
  - `AddCandidateVersion(ctx, secretID, value, by) (int, error)` — insert a new encrypted
    version **without** bumping `current_version`.
  - `PromoteVersion(ctx, secretID, version) error` — set `current_version = version`.
  - `SecretOrg(ctx, secretID) (string, error)` — resolve a secret's `org_id` (the engine
    runs under bypass-RLS and needs the org to scope vault inserts).
- **Depends on:** `internal/directory` (ResetPassword + a bind-verify helper),
  `internal/common/leader`, `internal/common/orgctx`, `internal/access` UnifiedAudit,
  `internal/notifications` (generate-only "apply manually" notice).

### Why candidate-then-promote is safe

M1's vault already distinguishes `current_version` (what `Use`/`Reveal` return — believed
live on the target) from the latest stored version. A candidate version stored above
`current_version` is invisible to consumers until promoted. So a rotation can durably
persist the new value **before** touching the target (never lose it), change the target,
verify, and only then promote `current_version`. Any failure leaves `current_version` on
the old, still-live value; the candidate lingers for retry.

## Data model — migration v57

New Go migration `internal/migrations/sql_v57.go`, registered as version **57** in
`loader.go`. Mirrored into `deployments/docker/init-db.sql` (tables + RLS belt) so
`TestInitDBParity` stays green.

```sql
-- Rotation policy: binds a vault secret to a target + schedule.
CREATE TABLE IF NOT EXISTS credential_rotation_policies (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id            UUID NOT NULL,
    secret_id         UUID NOT NULL REFERENCES vault_secrets(id) ON DELETE CASCADE,
    connector_type    VARCHAR(32) NOT NULL,          -- directory | generate_only
    connector_config  JSONB NOT NULL DEFAULT '{}',   -- directory: {"directory_id":..,"username":..}
    generation_policy JSONB NOT NULL DEFAULT '{}',   -- {"length":24,"upper":true,"lower":true,"digits":true,"symbols":true}
    interval_seconds  INTEGER NOT NULL DEFAULT 0,     -- 0 = no time schedule
    rotate_on_checkout BOOLEAN NOT NULL DEFAULT false,
    enabled           BOOLEAN NOT NULL DEFAULT true,
    next_run_at       TIMESTAMPTZ,                    -- set when interval_seconds>0
    last_run_at       TIMESTAMPTZ,
    last_status       VARCHAR(16),                    -- succeeded | failed
    created_by        UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (secret_id)   -- one rotation policy per secret in M1b
);
CREATE INDEX IF NOT EXISTS idx_rotation_policies_due
    ON credential_rotation_policies(enabled, next_run_at) WHERE enabled;

-- Reconcile the dead credential_rotations into the run ledger (one row per attempt).
ALTER TABLE credential_rotations ALTER COLUMN service_account_id DROP NOT NULL;
ALTER TABLE credential_rotations ADD COLUMN IF NOT EXISTS org_id        UUID;
ALTER TABLE credential_rotations ADD COLUMN IF NOT EXISTS policy_id     UUID REFERENCES credential_rotation_policies(id) ON DELETE SET NULL;
ALTER TABLE credential_rotations ADD COLUMN IF NOT EXISTS secret_id     UUID REFERENCES vault_secrets(id) ON DELETE CASCADE;
ALTER TABLE credential_rotations ADD COLUMN IF NOT EXISTS version_from  INTEGER;
ALTER TABLE credential_rotations ADD COLUMN IF NOT EXISTS version_to    INTEGER;
ALTER TABLE credential_rotations ADD COLUMN IF NOT EXISTS connector_type VARCHAR(32);
ALTER TABLE credential_rotations ADD COLUMN IF NOT EXISTS trigger       VARCHAR(16);   -- scheduled | on_demand | checkout
ALTER TABLE credential_rotations ADD COLUMN IF NOT EXISTS error_message TEXT;
ALTER TABLE credential_rotations ADD COLUMN IF NOT EXISTS started_at    TIMESTAMPTZ;
ALTER TABLE credential_rotations ADD COLUMN IF NOT EXISTS completed_at  TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_credential_rotations_secret ON credential_rotations(secret_id, started_at DESC);
```

`credential_rotation_policies` goes under the **v37 FORCE-RLS belt** (org-scoped, most
sensitive). `credential_rotations` also gains the belt now that it carries `org_id`
(previously beltless and dead). `status` values used by the ledger: `rotating`,
`verifying`, `succeeded`, `failed`.

## Vault additions (in `internal/vault/store.go`)

```go
// AddCandidateVersion stores a new encrypted version WITHOUT changing current_version.
// The candidate is invisible to Use/Reveal until PromoteVersion is called. Used by the
// rotation engine so a generated value is durable before the target is touched.
func (s *Service) AddCandidateVersion(ctx context.Context, secretID string, value []byte, by string) (int, error)

// PromoteVersion sets the secret's current_version to the given version — the atomic
// "this value is now live on the target" commit.
func (s *Service) PromoteVersion(ctx context.Context, secretID string, version int) error

// SecretOrg returns a secret's org_id (bypass-RLS callers derive the org for inserts).
func (s *Service) SecretOrg(ctx context.Context, secretID string) (string, error)
```

`AddCandidateVersion` numbers the new version as `MAX(version)+1` (not
`current_version+1`) so repeated failed attempts don't collide. `Use`/`Reveal` are
unchanged — they already join on `current_version`.

## Rotator interface + connectors (`internal/credentials/rotator.go`)

```go
var ErrVerifyUnsupported = errors.New("credentials: connector cannot verify")

type Rotator interface {
    Type() string
    // Apply sets newValue as the live credential on the target.
    Apply(ctx context.Context, cfg map[string]any, newValue []byte) error
    // Verify confirms newValue is live; return ErrVerifyUnsupported to skip.
    Verify(ctx context.Context, cfg map[string]any, newValue []byte) error
}

// generateSecret builds a random value per the policy's generation_policy using crypto/rand.
func generateSecret(gp GenerationPolicy) ([]byte, error)
```

- **`directoryRotator`** (`directory_rotator.go`): `Apply` reads `cfg["directory_id"]`,
  `cfg["username"]` and calls `directory.Service.ResetPassword(ctx, directoryID, username,
  string(newValue))`. `Verify` attempts an LDAP bind as the user with `newValue` for
  `ldap`/`ad` directory types (new small helper on the LDAP connector); returns
  `ErrVerifyUnsupported` for Azure AD (Graph offers no cheap credential-verify).
- **`generateOnlyRotator`** (`generate_rotator.go`): `Apply` returns nil (nothing to set);
  `Verify` returns `ErrVerifyUnsupported`. The engine still versions + promotes and fires
  a notification instructing an admin to apply the new value wherever it's consumed.

## Engine state machine (`engine.go`, `RotateSecret(ctx, policyID, trigger)`)

Mirrors `ziti_hardening.go RotateCertificate`, using a `credential_rotations` ledger row
as the state record:

1. Load policy (+ secret). If disabled, no-op. Insert ledger row: `status='rotating'`,
   `version_from = secret.current_version`, `trigger`, `started_at=NOW()`.
2. `newValue, _ := generateSecret(policy.generation_policy)` — `defer zero(newValue)`.
3. `candidateVer := vault.AddCandidateVersion(ctx, secretID, newValue, "rotation")`.
   Set ledger `version_to = candidateVer`. (Durable before touching the target.)
4. `rotator.Apply(ctx, cfg, newValue)`. On error → ledger `status='failed'`,
   `error_message`, `completed_at`; **do not** promote (current stays on old); update
   policy `last_status='failed'`; audit `credential.rotation_failed`; return.
5. `status='verifying'`. `rotator.Verify(...)`. `ErrVerifyUnsupported` → skip. On verify
   **failure** → `status='failed'` + alert (target may hold a value the vault hasn't
   promoted — flag loudly); do not promote; return.
6. `vault.PromoteVersion(ctx, secretID, candidateVer)`. Ledger `status='succeeded'`,
   `completed_at`. Policy `last_run_at=NOW()`, `last_status='succeeded'`,
   `next_run_at = NOW()+interval` (when `interval_seconds>0`). Audit
   `credential.rotated` (details: secret_id, version_from/to, connector, trigger — never
   the value).

The whole call runs under a context carrying `WithBypassRLS` **and** the secret's org
(`orgctx.With(ctx, orgctx.Org{ID: policy.org_id})`) so vault inserts/updates get `org_id`.

## Scheduler + rotate-on-checkout (`scheduler.go`)

```go
func (s *Service) StartScheduler(ctx context.Context, rdb *redis.Client) {
    ctx = orgctx.WithBypassRLS(ctx)
    leader.RunPeriodic(ctx, rdb, s.logger, "credentials:rotation", 60*time.Second, s.tick)
}
```

Each `tick` selects due policies (annotated `//orgscope:ignore` — background cross-org):
- **Scheduled:** `enabled AND interval_seconds>0 AND (next_run_at IS NULL OR next_run_at<=NOW())`.
- **Rotate-on-checkout:** `enabled AND rotate_on_checkout` **and** a `vault_checkouts` row
  exists for the secret with `status IN ('returned','expired')` and
  `COALESCE(returned_at, leased_at) > COALESCE(policy.last_run_at, 'epoch')` — i.e. a
  checkout was concluded since the last rotation. This polls the M1 checkout ledger, so
  the vault sweeper stays decoupled from the rotation engine.

For each due policy, `RotateSecret(ctx, policyID, trigger)`. A single in-flight guard
(the `status='rotating'` ledger row / policy lock) prevents overlap; leader-gating
prevents cross-replica double-runs.

## API (admin-api, admin-guarded — same `admin.RequireAdmin()` subgroup as the vault)

| Method | Path | Notes |
|---|---|---|
| POST | `/api/v1/vault/rotation-policies` | create (body binds a secret_id + connector + schedule) |
| GET | `/api/v1/vault/rotation-policies` | list (metadata; no secrets) |
| GET/PUT/DELETE | `/api/v1/vault/rotation-policies/:id` | manage |
| POST | `/api/v1/vault/secrets/:id/rotate` | **rotate now** (admin-only); runs `RotateSecret(trigger=on_demand)` |
| GET | `/api/v1/vault/secrets/:id/rotations` | run history from the ledger |

`generation_policy` and `connector_config` are validated on write (e.g. directory type
requires `directory_id`+`username`; length ≥ 8).

## Cross-cutting

- **Multi-tenancy/RLS:** both tables org-scoped + FORCE RLS (v37 belt). Engine runs under
  bypass with the policy's org injected for vault writes.
- **Secret hygiene:** generated values live only as `[]byte`, zeroed via `defer`; never
  logged; never in audit/ledger details; the ledger stores versions + status, not values.
- **Safety invariants:** `current_version` only advances after a successful (and, where
  supported, verified) target apply; a failed apply never changes what `Use`/`Reveal`
  return; candidate versions are retryable.
- **Config:** `CREDENTIALS_ROTATION_SCHEDULER_INTERVAL_SECONDS` (default 60),
  `CREDENTIALS_ROTATION_DEFAULT_LENGTH` (default 24). Scheduler started in `cmd/admin-api`
  alongside the vault sweeper.

## Testing

- **Unit (`internal/credentials`):**
  - `generateSecret`: honors length/charset; entropy (no repeats across calls); rejects length<8.
  - state machine with a mock `Rotator`: Apply-ok+Verify-ok → PromoteVersion called, ledger
    `succeeded`; Apply-fail → no promote, ledger `failed`, current unchanged; Verify-fail →
    no promote, ledger `failed`; `ErrVerifyUnsupported` → promote proceeds.
  - rotate-on-checkout selection SQL picks a secret whose checkout concluded after
    `last_run_at` and skips one that didn't.
  - generate_only: Apply no-op → promote + notification fired.
- **Integration (testcontainers/live DB, matching the suite):** v57 applies on init-db and
  on top; directory rotation end-to-end against a mock LDAP connector (Apply resets,
  Verify binds); `Use` returns the new value only after promotion; RLS isolation; ledger
  rows written; `TestInitDBParity` green.
- **Gates:** `go build`, `go vet`, `gofmt`, `orgscope -fail ./internal`, golangci-lint,
  govulncheck, `go test ./internal/credentials/... ./internal/vault/...`.

## Verification (end-to-end, box)

1. Store a secret representing a directory service account; create a `directory` rotation
   policy (`interval_seconds=3600`) bound to it.
2. `POST …/secrets/:id/rotate` → 200; `credential_rotations` has a `succeeded` row with
   `version_from=1,version_to=2`; the directory account's password is changed; `Use`/reveal
   returns the new value; version 1 still decrypts.
3. Break the target (bad directory creds) → rotate → ledger `failed`, `current_version`
   unchanged, reveal still returns the old (live) value.
4. Set `rotate_on_checkout=true`; reveal + let the lease expire → within a scheduler tick a
   `checkout`-triggered rotation runs.
5. Second org cannot see the policy or ledger (RLS).

## Critical files

- New: `internal/credentials/{rotator.go,directory_rotator.go,generate_rotator.go,engine.go,scheduler.go,handlers.go}` + `*_test.go`; `internal/migrations/sql_v57.go`; `test/integration/rotation_test.go`.
- Modify: `internal/vault/store.go` (AddCandidateVersion/PromoteVersion/SecretOrg),
  `internal/migrations/loader.go` (register v57), `deployments/docker/init-db.sql`
  (policies table + ledger columns + RLS belt), `internal/common/config/config.go`
  (`CREDENTIALS_*`), `internal/directory/ldap.go` (bind-verify helper),
  `cmd/admin-api/main.go` (construct engine, register routes, start scheduler).
- Reuse: `directory.Service.ResetPassword` (`internal/directory/service.go:137`),
  the rotation state-machine pattern (`internal/access/ziti_hardening.go:175-472`),
  `leader.RunPeriodic`, `orgctx`, `access.UnifiedAuditService.RecordEvent`.
```
