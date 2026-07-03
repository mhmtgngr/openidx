# Encrypt plaintext secrets at rest (backlog)

> Backlog initiative. Three secret columns are stored in cleartext and used for
> outbound authentication / signing, so they must be **recoverable-encrypted** at rest.
> `oauth_clients.client_secret` is **already secure** (SHA-256 hash, constant-time compare,
> never re-returned) — out of scope; its `-- TODO: Encrypt` init-db comment is stale.

## Scope (verified via code map)

| Table.column | Used for | Services touching it | Treatment |
|---|---|---|---|
| `identity_providers.client_secret` | outbound OIDC token exchange (`oauth2.Config.Exchange`) | identity, oauth, access | **ENCRYPT** |
| `webhook_subscriptions.secret` | HMAC-SHA256 signing of outbound deliveries | webhooks | **ENCRYPT** |
| `guacamole_connection_pool.token` | Guacamole session auth token (returned to client) | access | **ENCRYPT** |
| `oauth_clients.client_secret` | client auth (validate only) | oauth | already **HASHED** — skip |

All three already have `json:"-"` on their struct field (not exposed in API responses).

## Design

### Shared helper — `internal/common/secretcrypt`
AES-256-GCM keyed by the 32-byte `ENCRYPTION_KEY` (the same key every service already loads and
that TOTP secrets + the Ziti admin password already use). Exported so identity/webhooks/access can
import it (the `internal/vault` keyring type is unexported and can't be reused directly).

- `New(key string) (*Cipher, error)` — requires a 32-byte key.
- `Encrypt(plaintext string) (string, error)` → `"encv1:" + base64(nonce‖ciphertext‖tag)`.
- `Decrypt(stored string) (string, error)` → **prefix-aware**: a value carrying the `encv1:` tag is
  decrypted; an untagged value is returned **as-is** (legacy plaintext passthrough), so reads work
  during rollout with mixed rows. No error on legacy values (documented).
- `IsEncrypted(stored string) bool`.

Rotation is out of scope (the reference box has no separate `VAULT_KEK`; `ENCRYPTION_KEY` is the
key). The `encv1:` version tag leaves room for a future keyring-backed `encv2:`.

### Rollout — lazy, no flag-day
- **Writes** always `Encrypt`. **Reads** always go through `Decrypt` (handles tagged + legacy).
- Columns widen to `TEXT` (ciphertext exceeds `VARCHAR(255)`), via a migration per table.
- **Existing rows** are backfilled by a throwaway `cmd/` tool run on the box (same technique as the
  vault/rotation smoke tools) — a SQL migration can't run Go's AES. Until backfilled, legacy rows
  read fine via the passthrough; any create/update re-encrypts them.

### Decomposition (each its own PR: spec→implement→review→CI→merge)
1. **`secretcrypt` helper + unit tests** (this PR — foundation; no schema/service change).
2. **webhook_subscriptions.secret** — widen to TEXT (migration + init-db); encrypt on create,
   decrypt in `Publish`/`deliverWebhook`/`PingSubscription` before `computeSignature`.
3. **identity_providers.client_secret** — widen to TEXT; encrypt on create/update
   (`identity/service.go`), decrypt on read (`GetIdentityProvider`, `ListIdentityProviders`,
   `access/multi_idp.go loadIDPByRoute`, `oauth/service.go handleFederatedLogin`).
4. **guacamole_connection_pool.token** — widen to TEXT; encrypt in `savePooledConnection`, decrypt
   in the DB-read path of `GetPooledConnection` (in-memory cache may stay plaintext for same-process
   reuse). Column already `VARCHAR(500)` → still widen to TEXT for ciphertext.

Each table PR: migration (widen column, mirror init-db, `TestInitDBColumnParity` stays green — the
column type change doesn't add/remove columns so parity is unaffected), wire the service's
`secretcrypt.Cipher` from `cfg.EncryptionKey`, encrypt-on-write + decrypt-on-read, unit tests.

## Testing
- Helper: roundtrip; output carries the `encv1:` tag; legacy (untagged) passthrough; wrong-key and
  tampered-ciphertext fail; `IsEncrypted`.
- Per table PR: a service-level test that a stored secret round-trips and that a legacy plaintext row
  still reads. `go build`, `go vet`, `gofmt`, `orgscope`, parity guards green.

## Out of scope
`oauth_clients.client_secret` (already hashed); KEK rotation; the other backlog items (compose
tenant-isolation, prod-compose hardening, leaked-key rotation, connectors).

## Critical files
- New: `internal/common/secretcrypt/secretcrypt.go` (+ test). Reuse anchor: `internal/mfa/encrypter.go`.
- Later PRs: `internal/webhooks/service.go`, `internal/identity/service.go`,
  `internal/access/multi_idp.go`, `internal/oauth/service.go`, `internal/access/guacamole.go`,
  migrations `sql_v65+`, `deployments/docker/init-db.sql`.
