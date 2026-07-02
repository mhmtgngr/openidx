# PAM M1 — Credential Vault (store) design

> Milestone M1 of the [PAM roadmap](2026-07-02-pam-architecture-roadmap.md), scoped to
> **the vault store only**: encrypted secret storage + envelope crypto + versioning +
> per-secret access grants + checkout/reveal + audit. The **rotation engine** is a
> sibling spec (M1b) that depends on this. Scoping decisions confirmed with the user:
> vault-store-only; both use-only and reveal-with-audit access; KEK reuses the
> `ENCRYPTION_KEY` keyring; migrating existing plaintext secrets is a deferred follow-up.

## Context

OpenIDX has ad-hoc, per-feature encryption (TOTP secrets, Ziti admin password, session
recordings) but **no general-purpose secret vault**. Several privileged secrets sit
plaintext with `-- TODO: encrypt at rest` (`oauth_clients.client_secret`,
`identity_providers.client_secret`, webhook secrets, `guacamole_connection_pool.token`),
and the `credential_rotations` table (`migrations/023_password_management.up.sql:10-19`)
is dead. PAM needs a vault as its foundation: everything above it (JIT credential
checkout, credential injection into brokered sessions, rotation) reads and writes through it.

This spec builds that vault store. It deliberately reuses OpenIDX's proven crypto and
multi-tenancy machinery rather than introducing new infrastructure.

**Outcome:** a tenant-isolated, envelope-encrypted secret store where a privileged
credential can be stored once, versioned, granted to principals, consumed
server-side (`use`) by internal callers, or revealed once to a human with a reason and
a heavy audit trail — and where the plaintext never touches disk unencrypted, a log
line, or a list/get response.

## Non-goals (explicitly out of scope for this spec)

- **Rotation** — no policies, scheduler, connectors, or `credential_rotations` wiring. That is M1b.
- **Migrating existing plaintext secrets** (oauth/idp/webhook/guac) into the vault — deferred follow-up.
- **Session credential injection** (Guacamole/WebRTC) — M3; it will call `vault.Use()`.
- **External KMS** (AWS KMS / Vault transit) — the KEK abstraction leaves room, but only
  the local-keyring impl ships here.

## Architecture

- **`internal/vault`** — the store package. No HTTP. Contains:
  - `crypto.go` — the KEK keyring + per-version AEAD, mirroring
    `internal/access/recording_crypto.go`.
  - `store.go` — `Service` with the Go API (`Store`, `NewVersion`, `Use`, `Reveal`,
    `List`, `Get`, `Delete`, grant management, checkout queries).
  - `sweeper.go` — leader-gated expiry of stale checkouts / reveal leases.
- **admin-api handlers** — `internal/admin` (or a small `internal/vault/handlers.go`
  registered by admin-api) exposing `/api/v1/vault/*`. Handlers are thin; logic lives in
  `vault.Service`.
- **Consumers (future, not built here):** M1b rotation and M3 session broker call
  `vault.Service.Use(ctx, secretID)` in-process.

### Data flow

```
create/new-version:  value ──HTTP──▶ handler ──▶ Service.Store
                       └─ derive key = HKDF(KEK[activeID], "openidx-vault-v1:"+secretID+":"+version)
                       └─ AES-256-GCM seal ──▶ vault_secret_versions.ciphertext (framed)   [plaintext discarded]

use (internal):      Service.Use(ctx, secretID) ──▶ load current version ──▶ HKDF(KEK[key_id],…) ──▶ GCM open
                       └─ returns []byte in-process only; records vault_checkouts(mode=use) + audit

reveal (human):      POST /secrets/:id/reveal {reason} ──▶ require `reveal` grant ──▶ GCM open
                       └─ returns plaintext ONCE; records vault_checkouts(mode=reveal, reason) + audit
```

## Data model — migration v56

New Go migration `internal/migrations/sql_v56.go`, registered as version **56** in
`internal/migrations/loader.go` `allMigrations()` (v55 is current highest). All four
tables are org-scoped and placed **under the v37 RLS belt** (they hold the most
sensitive data in the system, so full tenant isolation is mandatory): `org_id UUID NOT
NULL` + a `pol_<table>_org_scope` policy matching v37's predicate
(`app.bypass_rls='on' OR org_id = NULLIF(current_setting('app.org_id', true),'')::uuid`)
+ `ENABLE` + `FORCE ROW LEVEL SECURITY`. The **same DDL is added to
`deployments/docker/init-db.sql`** so `TestInitDBParity` stays green. DDL is idempotent
(`IF NOT EXISTS`).

```sql
-- vault_secrets: the secret's identity + metadata. Never holds a value.
CREATE TABLE IF NOT EXISTS vault_secrets (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         UUID NOT NULL,
    name           VARCHAR(255) NOT NULL,
    type           VARCHAR(32)  NOT NULL DEFAULT 'generic', -- password|api_key|ssh_key|generic
    description    TEXT,
    owner_id       UUID REFERENCES users(id) ON DELETE SET NULL,
    metadata       JSONB NOT NULL DEFAULT '{}',
    current_version INTEGER NOT NULL DEFAULT 0,
    created_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name)
);

-- vault_secret_versions: the ONLY place ciphertext lives. Append-only per version.
CREATE TABLE IF NOT EXISTS vault_secret_versions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL,
    secret_id   UUID NOT NULL REFERENCES vault_secrets(id) ON DELETE CASCADE,
    version     INTEGER NOT NULL,
    key_id      SMALLINT NOT NULL,          -- which KEK in the ring protected this version
    ciphertext  BYTEA NOT NULL,             -- framed: keyid(1)|nonce(12)|ct+tag
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (secret_id, version)
);

-- vault_access_grants: who may use/reveal a secret.
CREATE TABLE IF NOT EXISTS vault_access_grants (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         UUID NOT NULL,
    secret_id      UUID NOT NULL REFERENCES vault_secrets(id) ON DELETE CASCADE,
    principal_type VARCHAR(32) NOT NULL,     -- user|role|service_account
    principal_id   UUID NOT NULL,
    actions        TEXT[] NOT NULL DEFAULT '{}', -- subset of {use, reveal} (rotate reserved for M1b)
    granted_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at     TIMESTAMPTZ,              -- NULL = no expiry
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (secret_id, principal_type, principal_id)
);

-- vault_checkouts: lease + audit ledger for every use/reveal.
CREATE TABLE IF NOT EXISTS vault_checkouts (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL,
    secret_id     UUID NOT NULL REFERENCES vault_secrets(id) ON DELETE CASCADE,
    secret_version INTEGER NOT NULL,
    principal_id  UUID,                      -- user (reveal) or service_account (use); NULL for system use
    mode          VARCHAR(16) NOT NULL,      -- use|reveal
    reason        TEXT,                      -- required for reveal
    leased_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ,               -- reveal leases expire; use is point-in-time
    returned_at   TIMESTAMPTZ,
    status        VARCHAR(16) NOT NULL DEFAULT 'active' -- active|returned|expired
);
CREATE INDEX IF NOT EXISTS idx_vault_versions_secret ON vault_secret_versions(secret_id, version DESC);
CREATE INDEX IF NOT EXISTS idx_vault_grants_secret   ON vault_access_grants(secret_id);
CREATE INDEX IF NOT EXISTS idx_vault_checkouts_secret ON vault_checkouts(secret_id, leased_at DESC);
CREATE INDEX IF NOT EXISTS idx_vault_checkouts_active ON vault_checkouts(status, expires_at) WHERE status = 'active';
```

## Crypto — envelope, mirroring `recording_crypto.go`

`internal/vault/crypto.go` reuses the recording keyring design verbatim in spirit:

- **`vaultKeyring`** — `map[byte][]byte` of 32-byte KEKs + `activeID`, built by a
  `newVaultKeyring(multiForm, activeID, singleKey)` that is a copy of
  `newRecordingKeyring` (`recording_crypto.go:143`). `masterFor(id)` errors on a retired id.
- **Per-version key derivation** — `HKDF-SHA256(KEK[id], salt=nil,
  info="openidx-vault-v1:"+secretID+":"+strconv(version))` → 32 bytes → `aes.NewCipher`
  → `cipher.NewGCM`. Identical construction to `newRecordingAEAD`
  (`recording_crypto.go:73`), only the info string differs.
- **Framing** — reuse the `keyid(1)|len(4)|nonce(12)|ct+tag` frame (a secret value is a
  single frame). Fresh random 12-byte nonce per seal (never counter-derived — same
  invariant as recordings, `recording_crypto.go:28-30`).
- **KEK rotation** — new versions seal under `activeID`; existing versions keep their
  stored `key_id` and decrypt as long as that KEK stays in the ring. No re-encryption on
  rotation. Retire a KEK only after every version it protected is deleted.

### Key source (config) — reuse `ENCRYPTION_KEY`

New config in `internal/common/config/config.go` mirroring the recordings keys
(`recordings_encryption_key` / `recordings_encryption_keys` / `..._active_key_id`):

- `VAULT_KEK` (single 32-byte base64 key → id 0), or
- `VAULT_KEKS` (`"id:base64key,..."`) + `VAULT_ACTIVE_KEK_ID`.
- **Default:** when none are set, seed the ring with the existing 32-byte `ENCRYPTION_KEY`
  as id 0. This satisfies "reuse the ENCRYPTION_KEY keyring" while still allowing a
  dedicated, independently-rotatable vault KEK later.

**Fail closed:** if the ring ends up empty (no `ENCRYPTION_KEY` and no `VAULT_*`), the
vault service returns an error at construction and its routes are not registered — the
vault never silently stores plaintext.

## Go API (`vault.Service`)

```go
// Store creates a new secret (version 1). value is zeroed after sealing.
func (s *Service) Store(ctx context.Context, in StoreInput) (*Secret, error)
// NewVersion appends a new encrypted version and bumps current_version. (Manual rotation;
// automated rotation calls this from M1b.)
func (s *Service) NewVersion(ctx context.Context, secretID string, value []byte, by string) (int, error)
// Use decrypts the current version for an internal caller (rotation, session broker).
// Returns plaintext IN-PROCESS ONLY. Records a use checkout + audit. Never exposed over HTTP.
func (s *Service) Use(ctx context.Context, secretID string) ([]byte, error)
// Reveal decrypts for a human. Requires a `reveal` grant + non-empty reason. Records a
// reveal checkout (with reason) + audit and opens a short lease.
func (s *Service) Reveal(ctx context.Context, secretID, principalID, reason string) ([]byte, error)
func (s *Service) List(ctx context.Context) ([]SecretMeta, error)          // metadata only
func (s *Service) Get(ctx context.Context, secretID string) (*SecretDetail, error) // meta + version history, NO value
func (s *Service) Delete(ctx context.Context, secretID string) error       // cascade-drops versions = crypto-erase
func (s *Service) AddGrant(ctx context.Context, g Grant) (grantID string, err error)
func (s *Service) RemoveGrant(ctx context.Context, grantID string) error // matches DELETE .../grants/:grantId
func (s *Service) Checkouts(ctx context.Context, secretID string) ([]Checkout, error)
```

**Authorization:** `Use`/`Reveal` check `vault_access_grants` for a non-expired grant
carrying the required action for the calling principal (or org-admin override, matching
how other admin-api resources treat admins). `Use` additionally accepts a **system**
caller (M1b/M3) running under `orgctx.WithBypassRLS`, which bypasses the grant check but
still records a checkout row with `principal_id = NULL` and a `system=true` audit detail.

## HTTP surface (admin-api, admin-guarded)

| Method | Path | Notes |
|---|---|---|
| POST | `/api/v1/vault/secrets` | create; body `{name,type,description,value,metadata}` — value sealed server-side, never stored/logged/echoed |
| GET | `/api/v1/vault/secrets` | list metadata (no values) |
| GET | `/api/v1/vault/secrets/:id` | metadata + version history (no values) |
| PUT | `/api/v1/vault/secrets/:id/version` | new version (manual rotation) |
| DELETE | `/api/v1/vault/secrets/:id` | crypto-erase |
| POST | `/api/v1/vault/secrets/:id/reveal` | body `{reason}` (required) → plaintext once; requires `reveal` grant; audited |
| POST | `/api/v1/vault/secrets/:id/grants` | add grant |
| DELETE | `/api/v1/vault/secrets/:id/grants/:grantId` | remove grant |
| GET | `/api/v1/vault/secrets/:id/checkouts` | audit trail |

There is **no `use` HTTP endpoint** — `use` is Go-internal only, so a browser/API client
can never pull raw plaintext except through the reason-gated, audited `reveal` path.

## Cross-cutting

- **Multi-tenancy/RLS:** all queries run under the per-request `app.org_id` GUC set at
  pool checkout from `orgctx` (`internal/common/database`). System `Use()` callers use
  `orgctx.WithBypassRLS`. Every table is FORCE-RLS'd (the app connects as table owner),
  matching the v37 belt.
- **Audit:** reuse `UnifiedAuditService.RecordEvent(ctx, "vault", eventType, "", userID,
  ip, details)` → `unified_audit_events`. Event types: `vault.secret_created`,
  `vault.secret_version`, `vault.reveal`, `vault.use`, `vault.grant_added`,
  `vault.grant_removed`, `vault.secret_deleted`. Reveal details carry the reason
  (the value never appears in details).
- **Secret hygiene:** plaintext `[]byte` is zeroed after sealing; value fields are never
  put on a struct that gets logged; zap logging of request bodies is suppressed on vault
  routes; list/get DTOs have no value field at all.
- **Sweeper:** `vault.sweeper` runs via `leader.RunPeriodic(ctx, rdb, logger,
  "vault:checkout-expiry", 60*time.Second, …)` (the `oauth/session_worker.go` pattern),
  flipping `active` checkouts past `expires_at` to `expired`.
- **Reveal-lease TTL:** default 5 minutes (config `VAULT_REVEAL_LEASE_TTL`). The lease is
  advisory audit state (the plaintext is already returned once); it bounds how long a
  reveal is considered "outstanding" for review dashboards.

## Testing

- **Unit (`internal/vault`):**
  - envelope round-trip: seal → open returns original; wrong KEK id fails; tampered
    ciphertext fails GCM auth.
  - KEK rotation: seal under active id 0 → add id 1 as active → new version uses id 1,
    old version (id 0) still opens; drop id 0 from ring → old version errors clearly.
  - `newVaultKeyring` parsing (single, multi, bad-length, bad-base64, active-id-not-present) —
    mirror the recording keyring tests.
  - authz: `Use`/`Reveal` denied without grant; `Reveal` denied with empty reason;
    expired grant denied.
  - hygiene: `List`/`Get` DTOs contain no value; a `Reveal` records a checkout with the reason.
- **Integration (testcontainers Postgres, `-tags=integration`):**
  - migration v56 applies cleanly both on a fresh `init-db.sql` cluster and stacked on top
    of the migration set; `TestInitDBParity` green.
  - RLS isolation: org A cannot read/reveal/use org B's secret (query under A's GUC
    returns nothing); `WithBypassRLS` system `Use` works.
- **Gates:** `go build ./...`, `go vet ./...`, `gofmt -l`, `go run ./tools/orgscope -fail
  ./internal`, `golangci-lint run`, `govulncheck ./...`, `go test ./internal/vault/...`
  and the integration suite.

## Verification (end-to-end, box)

1. `POST /api/v1/vault/secrets` with a test password → 201, no value echoed; row in
   `vault_secrets` (current_version=1) + one `vault_secret_versions` row with non-empty
   `ciphertext` and a `key_id`.
2. `psql` confirms the ciphertext bytes are not the plaintext.
3. `GET …/secrets/:id` → metadata + version history, **no value**.
4. Grant `reveal` to the admin user; `POST …/reveal {reason:"break-glass test"}` → returns
   the value once; `vault_checkouts` has a `mode=reveal` row with the reason;
   `unified_audit_events` has a `vault.reveal` event.
5. `PUT …/version` → current_version=2; reveal now returns the new value; version 1 row
   still decrypts.
6. `DELETE` → secret + versions gone; subsequent reveal 404s.
7. Second org's admin cannot see the secret (RLS).

## Critical files

- New: `internal/vault/{crypto.go,store.go,sweeper.go}`, `internal/vault/*_test.go`,
  `internal/migrations/sql_v56.go`, admin-api vault handlers + route registration.
- Modify: `internal/migrations/loader.go` (register v56), `deployments/docker/init-db.sql`
  (add the four tables + RLS belt), `internal/common/config/config.go` (`VAULT_*` keys +
  `ENCRYPTION_KEY` default), `internal/migrations/initdb_parity_test.go` (auto-covers new tables).
- Reuse: `internal/access/recording_crypto.go` (keyring + AEAD pattern),
  `internal/common/leader` + `internal/oauth/session_worker.go` (sweeper),
  `internal/access/unified_audit.go` `RecordEvent` (audit),
  `internal/common/orgctx` + `internal/common/database` (RLS GUC / bypass),
  `internal/migrations/sql_v37.go` (RLS belt predicate to copy).
```
