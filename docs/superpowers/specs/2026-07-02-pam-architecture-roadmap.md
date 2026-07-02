# OpenIDX PAM (Privileged Access Management) — architecture & phased roadmap

> System-design roadmap. Feasibility assessment + bottom-up/top-down architecture,
> decomposed into milestones. Each milestone gets its own spec → plan → PR cycle.
> Milestone 1 (credential vault + rotation engine) is the agreed lead.

## Context

The question: *is it possible to add PAM to OpenIDX — credential **vault**, automated
**password rotation**, **remote-support** brokering, session **recording** — designed
bottom-up and top-down?*

**Finding: yes, and OpenIDX is already ~70% of a PAM product.** A read-only survey
across four subsystems shows the hard infrastructure already exists; what's missing is
*connective tissue*, not foundations. PAM here is an **assembly-and-completion** effort,
not greenfield.

### What already exists (reuse, do not rebuild)

| Capability | Where | State |
|---|---|---|
| AES-256-GCM encrypter + **keyring with key-rotation** | `internal/mfa/encrypter.go`, `internal/access/recording_crypto.go` | Production; used for TOTP, Ziti admin pw, recordings |
| Directory **password write-back** (AD `unicodePwd`, LDAP RFC-3062, Azure Graph) | `internal/directory/ldap.go:212-339`, `azure_ad.go:241-277`, `service.go:114-174` | Production |
| **Rotation pattern** (monitor→state-machine `active→rotating→rotated`→audit, circuit breaker) | `internal/access/ziti_hardening.go:175-472` | Production — the template for the rotation engine |
| **Leader-gated schedulers** (cluster-safe periodic jobs) | `internal/oauth/session_worker.go`, `internal/directory/scheduler.go`, `internal/common/leader` | Production |
| Guacamole SSH/RDP/VNC **session brokering** + pooling | `internal/access/guacamole.go` | MVP |
| WebRTC **remote-support** broker (view/interactive, TURN mint) | `internal/access/remote_support_api.go` | Phase-4 MVP |
| Encrypted **session recording** + **retention** + **legal holds** | `internal/access/remote_support_recording.go`, `remote_support_retention.go`, `remote_support_legal_hold.go` | Phase-4 MVP — mature |
| **JIT / approvals**: temp-access links, `access_requests`+multi-step `approval_policies`, expiry worker | `internal/access/temp_access.go`, `internal/governance/request.go`, `workflows.go`, `jit_expiry.go` | Production |
| OPA + inline **policy DSL**, tamper-evident **audit** | `internal/governance/policy.go`, `internal/access/unified_audit.go`, `internal/audit` | Production |

### Gaps PAM must close

- **No general-purpose secret vault.** Secrets are encrypted ad-hoc per feature; several
  sit **plaintext** with `-- TODO: encrypt at rest`: `oauth_clients.client_secret`,
  `identity_providers.client_secret`, webhook secrets, `guacamole_connection_pool.token`.
- **`credential_rotations` table exists but is dead** (`migrations/023_password_management.up.sql:10-19`)
  — no engine, no policies, no connectors beyond directory.
- **No credential injection** into brokered sessions — Guacamole uses shared admin creds;
  users would see target passwords.
- **No pre-session approval gate / live monitor / force-terminate-with-reason** on privileged sessions.
- **Recording is video-only** — no keystroke/command transcript.
- **Schema drift bug:** `jit_grants` and `request_approval_chains` are referenced by code
  (`governance/jit.go`, `request.go:166`) but **absent from migrations** → latent 500s.

## Design — two views

### Bottom-up (foundations → up)

```
Layer 0  Crypto & keyring        reuse AES-256-GCM + keyring rotation (recording_crypto.go pattern)
Layer 1  Vault store             new: encrypted per-secret storage, versioned, KEK/DEK envelope
Layer 2  Checkout/lease          new: time-bound checkout, auto-revoke, audit — model on temp_access + jit_expiry
Layer 3  Rotation engine         new: policies + scheduler (leader.RunPeriodic) + state machine (ziti_hardening pattern)
Layer 3  Target connectors       reuse directory write-back; new interface CredentialRotator (SSH/DB/cloud later)
Layer 4  Session broker          extend Guacamole/WebRTC to inject vaulted creds without reveal
Layer 5  Governance glue         gate checkout/session on access_requests + approval_policies + OPA + device-trust
Layer 6  Audit & recording       bind every checkout/session to unified_audit + existing recording/retention/hold
```

### Top-down (product capabilities → user journeys)

- **Secrets & service accounts:** store/rotate privileged credentials (DB, service-account,
  API, admin) with per-secret RBAC and audited checkout.
- **Just-in-time privileged access:** request → approve → **checkout a time-boxed credential
  or session** → auto-revoke + rotate-on-return.
- **Privileged session:** broker RDP/SSH/web via Guacamole/Ziti with **credential injected
  server-side**, recorded, retained, legal-holdable — user never learns the password.
- **Break-glass:** emergency checkout (reuse MFA-bypass + notification hooks) with mandatory
  recording + post-hoc review.
- **Assurance:** existing attestation campaigns extend to privileged entitlements + vault-access review.

## Phased roadmap (each milestone = its own spec → plan → PR series)

**M1 — Credential vault + rotation engine (lead; foundation).** New `internal/vault` pkg +
`internal/credentials` rotation service. Encrypted `vault_secrets` (envelope-encrypted,
versioned) + `vault_secret_versions`; wire the dead `credential_rotations` table; rotation
policies + leader-gated scheduler cloning the `ziti_hardening` state machine; first connector =
directory write-back (already built). Fold the plaintext-secret TODOs (oauth/idp/webhook/guac)
into vault-backed storage. Detailed at roadmap level below.

**M2 — JIT credential checkout + fix drift.** Add the missing `jit_grants` /
`request_approval_chains` migrations (closes the latent-500 bug), then build approval-gated,
time-boxed **checkout** on top of `access_requests`/`approval_policies`, with `jit_expiry`-style
auto-revoke and **rotate-on-return**.

**M3 — Credential injection into brokered sessions.** Guacamole/WebRTC pull the target
credential from the vault server-side (never sent to the browser); pre-session **approval gate**
+ **force-terminate-with-reason**; bind session to recording.

**M4 — Session assurance.** Keystroke/command **transcript** alongside video; live monitor;
extend attestation to privileged entitlements + vault-access reviews.

**M5 — Connector expansion.** `CredentialRotator` implementations for SSH, PostgreSQL/MySQL,
cloud IAM — behind the M1 interface.

## M1 detail (roadmap level — full plan in a later cycle)

- **Schema (new Go migration `internal/migrations/sql_vNN.go`, registered in `loader.go`,
  org-scoped + RLS per the `sql_v37.go` belt, guarded by `TestInitDBParity`):**
  - `vault_secrets(id, org_id, name, type, owner_id, rotation_policy_id, current_version, metadata, created/updated)`
  - `vault_secret_versions(id, secret_id, version, ciphertext, key_id, created_by, created_at)`
    — envelope: DEK per secret, wrapped by KEK from the `ENCRYPTION_KEY` keyring.
  - `vault_access_grants(secret_id, principal, actions[read|use|rotate], expires_at)` — checkout RBAC.
  - `credential_rotation_policies(id, org_id, target_type, interval, rotate_on_checkout bool, connector_config)`;
    wire existing `credential_rotations` as the audit ledger.
- **Packages:** `internal/vault` (store + envelope crypto — reuse the `recording_crypto.go`
  keyring approach), `internal/credentials` (rotation service). Rotation scheduler via
  `leader.RunPeriodic`; per-target execution via a `CredentialRotator` interface whose first
  impl delegates to `internal/directory` `ResetPassword`.
- **State machine & audit:** copy `ziti_hardening.go` `active→rotating→rotated`/revert-on-failure
  + `unified_audit` events (`vault.checkout`, `credential.rotate`).
- **API/UI:** admin-api CRUD for secrets/policies; admin-console page under the existing
  access/governance nav (pattern: the Device-Trust-Approval page).
- **Migrate the plaintext TODOs** to vault-backed reads (oauth/idp secrets, webhook secrets,
  guac pool token) — removes the standing `-- TODO: encrypt` findings.

## Cross-cutting

- **Multi-tenancy/RLS:** every new table gets `org_id` + the v37 FORCE-RLS policy belt; queries
  via `orgctx`; background jobs use `orgctx.WithBypassRLS` (as the `ziti_hardening` monitor does).
- **Key management:** reuse the recordings **keyring** model (active-key-id + retained decrypt
  keys) so vault DEKs rotate without re-encrypting history.
- **init-db ↔ migrations parity:** honor `TestInitDBParity`; do not reintroduce the known init-db drift.
- **Release discipline:** feature branch off `main`; per-PR go-ahead before any merge; branch
  protection (Required Checks green) gates merges; never commit secrets / use `CHANGE_ME`.

## Verification (per milestone, at execution time)

- Unit: envelope encrypt/decrypt round-trip incl. key rotation; rotation state-machine transitions;
  checkout expiry/auto-revoke.
- Integration (testcontainers Postgres): migrations apply on init-db and on top of it;
  `TestInitDBParity` green; RLS isolation between orgs.
- Gates: `go build ./...`, `go vet`, `gofmt`, `go run ./tools/orgscope -fail ./internal`,
  `golangci-lint`, `govulncheck`, `go test` (unit/race/integration).
- Live (box): rotate a directory service-account credential end-to-end via a policy; check the
  `credential_rotations` ledger + `unified_audit_events`; confirm the plaintext-secret columns
  now read from vault.

## Critical files (reuse anchors)

- Crypto/keyring: `internal/access/recording_crypto.go`, `internal/mfa/encrypter.go`
- Rotation template: `internal/access/ziti_hardening.go:175-472`; schedulers: `internal/common/leader`, `internal/oauth/session_worker.go`
- Directory write-back: `internal/directory/{ldap.go,azure_ad.go,service.go}`
- Dead table to wire: `migrations/023_password_management.up.sql:10-19` (`credential_rotations`)
- Session broker: `internal/access/guacamole.go`, `remote_support_*.go`
- Governance glue: `internal/governance/{request.go,workflows.go,jit.go,jit_expiry.go,policy.go}`, `internal/access/temp_access.go`
- Drift to fix (M2): missing `jit_grants` / `request_approval_chains` migrations
- Migration mechanics: `internal/migrations/loader.go`, `sql_v37.go` (RLS belt), `initdb_parity_test.go`
