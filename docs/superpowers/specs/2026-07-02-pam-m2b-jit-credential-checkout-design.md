# PAM M2b — JIT credential checkout

> Second half of milestone M2 (M2a shipped the schema drift-fix). Builds
> approval-gated, time-boxed checkout of a vault credential on top of the existing
> access-request/approval workflow. Decisions confirmed with the user: reuse
> `access_requests` (new resource type), reveal-to-requester under a lease with
> auto-return, rotate-on-return via M1b.

## Context

The vault (M1) stores and reveals secrets; the rotation engine (M1b) rotates them on a
schedule or when a checkout concludes; and the governance service (M2a fixed its schema)
runs a mature request → multi-step approval → fulfill workflow. M2b joins them: a user
requests temporary access to a privileged credential, an approver grants it, and the user
retrieves the plaintext for a bounded window — after which access auto-revokes and the
credential rotates.

**Key architectural resolution:** `access_requests`/`fulfillRequest` live in
`internal/governance` (governance-service, :8002); the vault lives in `internal/vault`
(wired into admin-api, :8005). `internal/vault` is a **library over the shared Postgres +
KEK**, not a network service, so governance-service instantiates its **own**
`vault.Service` (same `ENCRYPTION_KEY`/`VAULT_KEK` via the shared config) and calls it
in-process — no cross-service HTTP. This requires governance-service to carry the same
vault KEK config as admin-api (a deployment note).

## Design

**No new table.** The `access_requests` row *is* the checkout record:
`resource_type='vault_credential'`, `resource_id=<vault_secrets.id>`, `expires_at` = the
checkout window. Checkout state = `access_requests.status`
(`pending → approved → fulfilled → expired`). This reuses the entire approval/escalation
machinery and the `jit_expiry` sweeper.

### Flow

1. **Request** — `POST /api/v1/governance/requests` with `resource_type:"vault_credential"`,
   `resource_id:<secret_id>`, `justification`, `duration`. `SubmitRequest` creates the
   request + approval chain (existing). **Validation:** reject if the secret isn't visible
   under the requester's org (a `SELECT 1 FROM vault_secrets WHERE id=$1` under the request
   context — RLS scopes it) → 400.

2. **Approve** — existing multi-step approval → `status='approved'` → `fulfillRequest`.

3. **Fulfill** — new `case "vault_credential"` in `workflows.go fulfillRequest`:
   - `vault.AddGrant(Grant{SecretID, PrincipalType:"user", PrincipalID:requester,
     Actions:["reveal"], ExpiresAt:&request.ExpiresAt})` — a **time-boxed reveal grant**
     that is the authorization to retrieve, and auto-expires with the window (the vault's
     `hasGrant` checks `expires_at > NOW()`).
   - Audit `jit_credential.checkout_granted`. Mark `access_requests.status='fulfilled'`.

4. **Retrieve** — new `POST /api/v1/governance/requests/:id/credential`: verify the request
   belongs to the caller, is `resource_type='vault_credential'`, `status='fulfilled'`, and
   `expires_at > NOW()`; then `vault.Reveal(secretID, requesterID, roles, reason:"JIT
   checkout <reqID>", isAdmin:false)`. The grant from step 3 satisfies `Reveal`; the vault
   records the reveal in `vault_checkouts` + audits `vault.reveal`. Returns the plaintext
   once per call within the window (the requester already holds it — re-reads are
   acceptable and audited). Response body zeroed after write, as in M1.

5. **Auto-return (expiry)** — `jit_expiry.go` already sweeps `fulfilled` `access_requests`
   past `expires_at`. Add a `vault_credential` branch: mark `status='expired'`, and
   **rotate-on-return** — `UPDATE credential_rotation_policies SET next_run_at = NOW()
   WHERE secret_id = $1 AND rotate_on_checkout = true` so the M1b scheduler rotates the
   secret on its next tick. Audit `jit_credential.checkout_expired`. (The reveal grant
   auto-expires via its `expires_at`; no explicit revoke needed on the timeout path.)

6. **Explicit return** — new `POST /api/v1/governance/requests/:id/return` (requester ends
   early): `vault.RevokeGrantForPrincipal(secretID,"user",requester)` for immediate
   deauthorization, mark `status='expired'`, bump the rotation policy as in step 5, audit
   `jit_credential.checkout_returned`.

### Vault additions (`internal/vault/store.go`)

- `RevokeGrantForPrincipal(ctx, secretID, principalType, principalID string) error` —
  `DELETE FROM vault_access_grants WHERE secret_id=$1 AND principal_type=$2 AND
  principal_id=$3`. Used by the explicit-return path (the timeout path relies on the
  grant's `expires_at`). Small, additive.

### Governance wiring

- `cmd/governance-service/main.go`: build `vault.KeyringFromConfig(vault.KeyConfig{...cfg})`
  → `vault.NewService(db, ring, unifiedAudit, ttl, log)` (fail-closed on missing KEK,
  matching admin-api), inject into `governance.NewService(...)` so `fulfillRequest`,
  `jit_expiry`, and the new handlers can call it.
- `internal/governance/service.go`: hold the `*vault.Service`; register the two new routes
  in the existing admin/auth-guarded `/api/v1/governance` group.

## Out of scope

- Session credential injection (M3) — a different consumer of `vault.Use()`.
- SSH/DB/cloud rotation connectors (M5).
- A dedicated checkout table / parallel approval flow (we reuse `access_requests`).

## Testing

- **Unit:** `RevokeGrantForPrincipal` deletes the right row; the `vault_credential`
  validation rejects a missing secret; the `fulfillRequest` case calls `AddGrant` with the
  window `expires_at` (via a vault port/mock).
- **Integration (`test/integration/`):** end-to-end — seed org+user+secret+rotation policy;
  submit a `vault_credential` request; approve; assert a time-boxed reveal grant exists;
  retrieve returns the secret value; after marking the request expired via the jit_expiry
  path, the grant no longer authorizes and the rotation policy's `next_run_at` is bumped;
  RLS: a different org can't request/retrieve another org's secret.
- Gates: `go build`, `go vet`, `gofmt`, `orgscope -fail ./internal`, `go test`,
  `golangci-lint`, integration compiles under `-tags=integration`.

## Verification (box / CI)

Request a `vault_credential` for a test secret → approve → `POST …/requests/:id/credential`
returns the value → wait past `expires_at` (or `POST …/return`) → retrieve now 403s and the
secret's rotation policy fires on the next scheduler tick.

## Critical files

- Modify: `internal/governance/workflows.go` (`fulfillRequest` case + SubmitRequest
  validation + retrieve/return handlers), `internal/governance/jit_expiry.go`
  (`vault_credential` expiry branch + rotate-on-return), `internal/governance/service.go`
  (hold vault.Service + route registration), `cmd/governance-service/main.go` (construct +
  inject vault.Service), `internal/vault/store.go` (`RevokeGrantForPrincipal`).
- Reuse: `vault.AddGrant`/`Reveal`/`Grant` (`internal/vault/store.go`), the
  `SubmitRequest`/approval/`fulfillRequest` flow (`internal/governance/{request.go,workflows.go}`),
  the `jit_expiry` sweeper (`internal/governance/jit_expiry.go`), M1b rotate-on-checkout
  (`internal/credentials/scheduler.go` — already polls; we just wake it via `next_run_at`).
- New: `test/integration/jit_checkout_test.go`.
