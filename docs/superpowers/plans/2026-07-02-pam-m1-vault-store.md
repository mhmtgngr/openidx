# PAM M1 — Credential Vault (store) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the tenant-isolated, envelope-encrypted credential vault store for OpenIDX PAM — storage, versioning, per-secret access grants, internal `use`, reason-gated `reveal`, and a checkout audit ledger — with plaintext never persisted, logged, or listed.

**Architecture:** New `internal/vault` package (crypto + store + sweeper) mirroring the proven `internal/access/recording_crypto.go` keyring; four org-scoped tables under the v37 FORCE-RLS belt (migration v56); admin-api HTTP handlers; reuse of `leader.RunPeriodic`, `orgctx`, and `unified_audit`. No rotation (M1b) and no plaintext-secret migration (deferred).

**Tech Stack:** Go 1.25, pgx v5, `golang.org/x/crypto/hkdf`, AES-256-GCM, Gin, zap, Viper, testcontainers.

**Spec:** `docs/superpowers/specs/2026-07-02-pam-m1-vault-store-design.md`

---

## File structure

- `internal/vault/crypto.go` — KEK keyring + per-version AEAD (seal/open). No DB, no deps beyond stdlib+hkdf.
- `internal/vault/crypto_test.go` — round-trip, rotation, keyring parsing.
- `internal/vault/store.go` — `Service` struct + `Store/NewVersion/Get/List/Delete`, grant mgmt, `Use/Reveal`, `Checkouts`.
- `internal/vault/store_test.go` — unit tests for authz/hygiene with a stubbed pool where feasible; DB-backed cases live in the integration suite.
- `internal/vault/sweeper.go` — leader-gated checkout/reveal-lease expiry.
- `internal/vault/handlers.go` — Gin handlers + `RegisterRoutes`.
- `internal/migrations/sql_v56.go` — migration v56 (DDL + RLS belt + grants).
- `internal/migrations/loader.go` — register v56 (modify).
- `deployments/docker/init-db.sql` — add the four tables + RLS belt (modify; keeps `TestInitDBParity` green).
- `internal/common/config/config.go` — `Vault*` config fields + env bindings (modify).
- `test/integration/vault_test.go` — migration-apply, RLS isolation, e2e (new).
- Service wiring: whichever service already mounts admin-api routes (grep `RegisterRoutes` in `cmd/admin-api` / `internal/admin`) — construct `vault.Service`, register routes, start sweeper (modify).

---

## Task 1: Vault crypto (keyring + AEAD)

**Files:**
- Create: `internal/vault/crypto.go`
- Test: `internal/vault/crypto_test.go`

This mirrors `internal/access/recording_crypto.go` but derives per-**secret-version** keys and stores the `key_id` in its own column (not framed), so the ciphertext blob is just `nonce|ct+tag`.

- [ ] **Step 1: Write the failing test**

```go
package vault

import (
	"bytes"
	"testing"
)

func testKey(b byte) []byte { k := make([]byte, 32); for i := range k { k[i] = b }; return k }

func TestSealOpenRoundTrip(t *testing.T) {
	r := &keyring{keys: map[byte][]byte{0: testKey(1)}, activeID: 0}
	pt := []byte("s3cr3t-p@ss")
	keyID, blob, err := r.Seal("secret-abc", 1, pt)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if keyID != 0 {
		t.Fatalf("keyID=%d want 0", keyID)
	}
	if bytes.Contains(blob, pt) {
		t.Fatal("plaintext leaked into ciphertext blob")
	}
	got, err := r.Open(keyID, "secret-abc", 1, blob)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("open=%q want %q", got, pt)
	}
}

func TestOpenWrongContextFails(t *testing.T) {
	r := &keyring{keys: map[byte][]byte{0: testKey(1)}, activeID: 0}
	_, blob, _ := r.Seal("secret-abc", 1, []byte("x"))
	if _, err := r.Open(0, "secret-abc", 2, blob); err == nil { // wrong version → wrong derived key
		t.Fatal("expected auth failure on version mismatch")
	}
	if _, err := r.Open(0, "other", 1, blob); err == nil {
		t.Fatal("expected auth failure on secretID mismatch")
	}
}

func TestKeyRotation(t *testing.T) {
	r := &keyring{keys: map[byte][]byte{0: testKey(1)}, activeID: 0}
	_, blobV1, _ := r.Seal("s", 1, []byte("v1val"))
	// Rotate: add key id 1, make it active.
	r.keys[1] = testKey(2)
	r.activeID = 1
	idV2, blobV2, _ := r.Seal("s", 2, []byte("v2val"))
	if idV2 != 1 {
		t.Fatalf("new version keyID=%d want 1", idV2)
	}
	// Old version still opens under retained key 0.
	if got, err := r.Open(0, "s", 1, blobV1); err != nil || string(got) != "v1val" {
		t.Fatalf("old version decrypt failed: %v %q", err, got)
	}
	if got, _ := r.Open(1, "s", 2, blobV2); string(got) != "v2val" {
		t.Fatal("new version decrypt failed")
	}
	// Retire key 0 → old version errors clearly.
	delete(r.keys, 0)
	if _, err := r.Open(0, "s", 1, blobV1); err == nil {
		t.Fatal("expected retired-key error")
	}
}

func TestNewKeyring(t *testing.T) {
	// single raw form (base64 of 32 bytes)
	single := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // 32 zero bytes b64
	r, err := newKeyring("", 0, single)
	if err != nil || r == nil || !r.Enabled() {
		t.Fatalf("single keyring: %v", err)
	}
	// unset → nil ring, no error (caller applies ENCRYPTION_KEY default / fail-closed)
	r2, err := newKeyring("", 0, "")
	if err != nil || r2 != nil {
		t.Fatalf("empty keyring should be (nil,nil): %v", err)
	}
	// bad length
	if _, err := newKeyring("", 0, "QUJD"); err == nil {
		t.Fatal("expected bad-length error")
	}
	// multi form + active id not present
	if _, err := newKeyring("0:"+single, 5, ""); err == nil {
		t.Fatal("expected active-id-missing error")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vault/ -run TestSeal -v`
Expected: FAIL — package/functions undefined.

- [ ] **Step 3: Write minimal implementation**

```go
// Package vault provides an envelope-encrypted, tenant-isolated store for
// privileged credentials (the PAM credential vault). Each secret version is
// sealed with a per-version key derived via HKDF-SHA256 from a key-encryption
// key (KEK) held in an in-memory keyring, then AES-256-GCM encrypted. The KEK
// id is stored alongside the ciphertext so KEKs rotate without re-encrypting
// history: new versions seal under the active id, old versions keep theirs and
// decrypt as long as their KEK remains in the ring.
//
// This mirrors internal/access/recording_crypto.go; the only differences are
// the derivation context (secretID:version) and that the key id lives in its
// own DB column rather than framed into the blob.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/hkdf"
)

const kekLen = 32 // AES-256

const (
	nonceLen = 12 // AES-GCM standard nonce
	tagLen   = 16 // AES-GCM tag
)

// keyring holds the KEKs: an active id used for new seals plus any retained
// ids kept so older versions still decrypt.
type keyring struct {
	keys     map[byte][]byte
	activeID byte
}

func (r *keyring) Enabled() bool { return r != nil && len(r.keys) > 0 }

func (r *keyring) masterFor(id byte) ([]byte, error) {
	k, ok := r.keys[id]
	if !ok {
		return nil, fmt.Errorf("vault KEK id %d not in keyring (retired or never configured)", id)
	}
	return k, nil
}

// deriveGCM derives the per-version AEAD from a KEK. The info string binds the
// key to (secretID, version) so a blob can never be replayed under a different
// secret or version.
func deriveGCM(master []byte, secretID string, version int) (cipher.AEAD, error) {
	if len(master) != kekLen {
		return nil, fmt.Errorf("vault KEK must be %d bytes, got %d", kekLen, len(master))
	}
	info := []byte("openidx-vault-v1:" + secretID + ":" + strconv.Itoa(version))
	kdf := hkdf.New(sha256.New, master, nil, info)
	derived := make([]byte, 32)
	if _, err := io.ReadFull(kdf, derived); err != nil {
		return nil, fmt.Errorf("hkdf read: %w", err)
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, fmt.Errorf("aes new cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

// Seal encrypts plaintext under the active KEK. Returns the KEK id (to store in
// the key_id column) and blob = nonce(12) | ciphertext+tag.
func (r *keyring) Seal(secretID string, version int, plaintext []byte) (byte, []byte, error) {
	master, err := r.masterFor(r.activeID)
	if err != nil {
		return 0, nil, err
	}
	gcm, err := deriveGCM(master, secretID, version)
	if err != nil {
		return 0, nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return 0, nil, fmt.Errorf("nonce random: %w", err)
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	blob := make([]byte, nonceLen+len(ct))
	copy(blob, nonce)
	copy(blob[nonceLen:], ct)
	return r.activeID, blob, nil
}

// Open decrypts a blob produced by Seal under the KEK identified by keyID.
func (r *keyring) Open(keyID byte, secretID string, version int, blob []byte) ([]byte, error) {
	if len(blob) < nonceLen+tagLen {
		return nil, errors.New("vault ciphertext too short")
	}
	master, err := r.masterFor(keyID)
	if err != nil {
		return nil, err
	}
	gcm, err := deriveGCM(master, secretID, version)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, blob[:nonceLen], blob[nonceLen:], nil)
}

// newKeyring builds a ring from config. multiForm is comma-separated
// "id:base64key" entries (activeID selects the write key); otherwise singleKey
// (base64 of 32 bytes) loads as id 0 active. Returns (nil,nil) when neither is
// set so the caller can apply the ENCRYPTION_KEY default or fail closed.
func newKeyring(multiForm string, activeID int, singleKey string) (*keyring, error) {
	multiForm = strings.TrimSpace(multiForm)
	if multiForm == "" {
		if strings.TrimSpace(singleKey) == "" {
			return nil, nil
		}
		raw, err := decodeKEK(singleKey)
		if err != nil {
			return nil, fmt.Errorf("vault_kek: %w", err)
		}
		return &keyring{keys: map[byte][]byte{0: raw}, activeID: 0}, nil
	}
	ring := &keyring{keys: make(map[byte][]byte)}
	for _, entry := range strings.Split(multiForm, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		idStr, keyStr, ok := strings.Cut(entry, ":")
		if !ok {
			return nil, fmt.Errorf("vault_keks: entry %q is not id:base64key", entry)
		}
		id, err := strconv.Atoi(strings.TrimSpace(idStr))
		if err != nil || id < 0 || id > 255 {
			return nil, fmt.Errorf("vault_keks: id %q must be 0-255", idStr)
		}
		raw, err := decodeKEK(keyStr)
		if err != nil {
			return nil, fmt.Errorf("vault_keks: id %d: %w", id, err)
		}
		ring.keys[byte(id)] = raw
	}
	if len(ring.keys) == 0 {
		return nil, errors.New("vault_keks: no valid entries")
	}
	if activeID < 0 || activeID > 255 {
		return nil, fmt.Errorf("vault_active_kek_id %d must be 0-255", activeID)
	}
	if _, ok := ring.keys[byte(activeID)]; !ok {
		return nil, fmt.Errorf("vault_active_kek_id %d not present in vault_keks", activeID)
	}
	ring.activeID = byte(activeID)
	return ring, nil
}

func decodeKEK(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("not valid base64: %w", err)
	}
	if len(raw) != kekLen {
		return nil, fmt.Errorf("must decode to %d bytes, got %d", kekLen, len(raw))
	}
	return raw, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vault/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/vault/crypto.go internal/vault/crypto_test.go
git commit -m "feat(vault): envelope crypto — HKDF+AES-256-GCM keyring with KEK rotation"
```

---

## Task 2: Config fields + keyring constructor

**Files:**
- Modify: `internal/common/config/config.go`
- Create/append: `internal/vault/config.go`
- Test: `internal/vault/config_test.go`

- [ ] **Step 1: Add config fields.** In the `Config` struct near the recordings keys (`config.go:262-271`), add:

```go
	// Vault (PAM credential vault) key-encryption keys. Same shape as the
	// recordings keyring. When all three are empty the vault falls back to
	// EncryptionKey as KEK id 0 (raw 32-byte string, not base64). If that is
	// also unusable the vault service fails closed and does not register.
	VaultKEK          string `mapstructure:"vault_kek"`
	VaultKEKs         string `mapstructure:"vault_keks"`
	VaultActiveKEKID  int    `mapstructure:"vault_active_kek_id"`
	VaultRevealLeaseTTLSeconds int `mapstructure:"vault_reveal_lease_ttl_seconds"`
```

In the env binding map (near `config.go:639`, `"encryption_key": "ENCRYPTION_KEY"`), add:

```go
		"vault_kek":                       "VAULT_KEK",
		"vault_keks":                      "VAULT_KEKS",
		"vault_active_kek_id":             "VAULT_ACTIVE_KEK_ID",
		"vault_reveal_lease_ttl_seconds":  "VAULT_REVEAL_LEASE_TTL_SECONDS",
```

Set a viper default for the TTL (find the `SetDefault` block): `v.SetDefault("vault_reveal_lease_ttl_seconds", 300)`.

- [ ] **Step 2: Write the failing test** (`internal/vault/config_test.go`):

```go
package vault

import "testing"

func TestKeyringFromConfig_DefaultsToEncryptionKey(t *testing.T) {
	// 32-byte raw ENCRYPTION_KEY, no VAULT_* set → id 0 default.
	r, err := KeyringFromConfig(KeyConfig{EncryptionKey: string(make([]byte, 32))})
	if err != nil || r == nil || !r.Enabled() {
		t.Fatalf("expected default ring from ENCRYPTION_KEY: %v", err)
	}
}

func TestKeyringFromConfig_FailsClosed(t *testing.T) {
	if _, err := KeyringFromConfig(KeyConfig{}); err == nil {
		t.Fatal("expected fail-closed error when no KEK available")
	}
	// ENCRYPTION_KEY of wrong length is also fail-closed.
	if _, err := KeyringFromConfig(KeyConfig{EncryptionKey: "too-short"}); err == nil {
		t.Fatal("expected fail-closed on short ENCRYPTION_KEY")
	}
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `go test ./internal/vault/ -run TestKeyringFromConfig -v`
Expected: FAIL — `KeyringFromConfig`/`KeyConfig` undefined.

- [ ] **Step 4: Implement** (`internal/vault/config.go`):

```go
package vault

import "fmt"

// KeyConfig is the subset of app config the vault keyring needs. Kept local so
// internal/vault does not import internal/common/config.
type KeyConfig struct {
	KEK           string // VAULT_KEK (base64, 32 bytes)
	KEKs          string // VAULT_KEKS ("id:base64,...")
	ActiveKEKID   int    // VAULT_ACTIVE_KEK_ID
	EncryptionKey string // ENCRYPTION_KEY (raw 32-byte string) — fallback KEK id 0
}

// KeyringFromConfig builds the vault KEK ring. Precedence: explicit VAULT_*
// keys, else the raw ENCRYPTION_KEY as id 0. Fails closed when neither yields a
// usable 32-byte key — the vault never silently stores plaintext.
func KeyringFromConfig(cfg KeyConfig) (*keyring, error) {
	r, err := newKeyring(cfg.KEKs, cfg.ActiveKEKID, cfg.KEK)
	if err != nil {
		return nil, err
	}
	if r != nil {
		return r, nil
	}
	if len(cfg.EncryptionKey) != kekLen {
		return nil, fmt.Errorf("vault: no VAULT_KEK/VAULT_KEKS set and ENCRYPTION_KEY is not %d bytes; refusing to start (fail-closed)", kekLen)
	}
	return &keyring{keys: map[byte][]byte{0: []byte(cfg.EncryptionKey)}, activeID: 0}, nil
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `go test ./internal/vault/ -v && go build ./...`
Expected: PASS + build OK.

- [ ] **Step 6: Commit**

```bash
git add internal/common/config/config.go internal/vault/config.go internal/vault/config_test.go
git commit -m "feat(vault): VAULT_* KEK config with ENCRYPTION_KEY fallback (fail-closed)"
```

---

## Task 3: Migration v56 (four tables + RLS belt)

**Files:**
- Create: `internal/migrations/sql_v56.go`
- Modify: `internal/migrations/loader.go`
- Modify: `deployments/docker/init-db.sql`

- [ ] **Step 1: Create the migration** (`internal/migrations/sql_v56.go`):

```go
package migrations

// Migration v56 — PAM credential vault store (M1). Four org-scoped tables under
// the v37 FORCE-RLS belt: vault_secrets (metadata, no value), vault_secret_versions
// (the only ciphertext home), vault_access_grants (use/reveal), vault_checkouts
// (lease + audit ledger). Idempotent. Rotation (credential_rotation_policies) is
// intentionally NOT here — that is M1b. The same DDL is mirrored into
// deployments/docker/init-db.sql so TestInitDBParity stays green.
var vaultStoreUp = `-- Migration 056: PAM credential vault store.
CREATE TABLE IF NOT EXISTS vault_secrets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL,
    name            VARCHAR(255) NOT NULL,
    type            VARCHAR(32)  NOT NULL DEFAULT 'generic',
    description     TEXT,
    owner_id        UUID REFERENCES users(id) ON DELETE SET NULL,
    metadata        JSONB NOT NULL DEFAULT '{}',
    current_version INTEGER NOT NULL DEFAULT 0,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name)
);

CREATE TABLE IF NOT EXISTS vault_secret_versions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL,
    secret_id   UUID NOT NULL REFERENCES vault_secrets(id) ON DELETE CASCADE,
    version     INTEGER NOT NULL,
    key_id      SMALLINT NOT NULL,
    ciphertext  BYTEA NOT NULL,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (secret_id, version)
);

CREATE TABLE IF NOT EXISTS vault_access_grants (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         UUID NOT NULL,
    secret_id      UUID NOT NULL REFERENCES vault_secrets(id) ON DELETE CASCADE,
    principal_type VARCHAR(32) NOT NULL,
    principal_id   UUID NOT NULL,
    actions        TEXT[] NOT NULL DEFAULT '{}',
    granted_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at     TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (secret_id, principal_type, principal_id)
);

CREATE TABLE IF NOT EXISTS vault_checkouts (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         UUID NOT NULL,
    secret_id      UUID NOT NULL REFERENCES vault_secrets(id) ON DELETE CASCADE,
    secret_version INTEGER NOT NULL,
    principal_id   UUID,
    mode           VARCHAR(16) NOT NULL,
    reason         TEXT,
    leased_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at     TIMESTAMPTZ,
    returned_at    TIMESTAMPTZ,
    status         VARCHAR(16) NOT NULL DEFAULT 'active'
);

CREATE INDEX IF NOT EXISTS idx_vault_versions_secret  ON vault_secret_versions(secret_id, version DESC);
CREATE INDEX IF NOT EXISTS idx_vault_grants_secret    ON vault_access_grants(secret_id);
CREATE INDEX IF NOT EXISTS idx_vault_checkouts_secret ON vault_checkouts(secret_id, leased_at DESC);
CREATE INDEX IF NOT EXISTS idx_vault_checkouts_active ON vault_checkouts(status, expires_at) WHERE status = 'active';

-- v37-style RLS belt: fail-closed org predicate + FORCE (app connects as owner).
DROP POLICY IF EXISTS pol_vault_secrets_org_scope ON vault_secrets;
CREATE POLICY pol_vault_secrets_org_scope ON vault_secrets
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE vault_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault_secrets FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_vault_secret_versions_org_scope ON vault_secret_versions;
CREATE POLICY pol_vault_secret_versions_org_scope ON vault_secret_versions
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE vault_secret_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault_secret_versions FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_vault_access_grants_org_scope ON vault_access_grants;
CREATE POLICY pol_vault_access_grants_org_scope ON vault_access_grants
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE vault_access_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault_access_grants FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_vault_checkouts_org_scope ON vault_checkouts;
CREATE POLICY pol_vault_checkouts_org_scope ON vault_checkouts
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE vault_checkouts ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault_checkouts FORCE  ROW LEVEL SECURITY;

-- Grant DML to the runtime app role when present (matches v53).
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openidx_app') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON
      vault_secrets, vault_secret_versions, vault_access_grants, vault_checkouts
      TO openidx_app;
  END IF;
END $$;
`

var vaultStoreDown = `-- Migration 056 down.
DROP TABLE IF EXISTS vault_checkouts CASCADE;
DROP TABLE IF EXISTS vault_access_grants CASCADE;
DROP TABLE IF EXISTS vault_secret_versions CASCADE;
DROP TABLE IF EXISTS vault_secrets CASCADE;
`
```

- [ ] **Step 2: Register in `loader.go`.** After the v55 entry (`loader.go:399`), before the closing `}`:

```go
		{
			Version:     56,
			Name:        "vault_store",
			Description: "PAM credential vault store (M1): vault_secrets, vault_secret_versions, vault_access_grants, vault_checkouts — org-scoped under the v37 FORCE-RLS belt. Envelope ciphertext lives only in vault_secret_versions. Rotation (credential_rotation_policies) is deferred to M1b. Idempotent; mirrored into init-db.sql so TestInitDBParity stays green.",
			UpSQL:       vaultStoreUp,
			DownSQL:     vaultStoreDown,
		},
```

- [ ] **Step 3: Mirror into `init-db.sql`.** Append the four `CREATE TABLE IF NOT EXISTS` blocks (only the tables + indexes — the RLS belt lives in the docker-compose init via the same file if the belt is present there; match how v54/v55 tables were added: tables + indexes verbatim). Place them near the other access/PAM tables. This satisfies `TestInitDBParity`.

- [ ] **Step 4: Verify parity + build**

Run: `go build ./... && go test ./internal/migrations/ -run TestInitDBParity -v`
Expected: PASS (no missing/extra tables reported).

- [ ] **Step 5: Commit**

```bash
git add internal/migrations/sql_v56.go internal/migrations/loader.go deployments/docker/init-db.sql
git commit -m "feat(migrations): v56 — PAM vault store tables under the RLS belt"
```

---

## Task 4: Store core — Service + Store/NewVersion/Get/List/Delete

**Files:**
- Create: `internal/vault/store.go`
- Test: covered by integration suite (Task 10); add a unit test for DTO hygiene here.

- [ ] **Step 1: Write the failing hygiene test** (`internal/vault/store_test.go`):

```go
package vault

import (
	"encoding/json"
	"strings"
	"testing"
)

// SecretMeta / SecretDetail must have NO field that could carry a plaintext value.
func TestDTOsHaveNoValueField(t *testing.T) {
	for _, v := range []interface{}{SecretMeta{}, SecretDetail{}, VersionMeta{}} {
		b, _ := json.Marshal(v)
		if strings.Contains(strings.ToLower(string(b)), "\"value\"") ||
			strings.Contains(strings.ToLower(string(b)), "\"ciphertext\"") ||
			strings.Contains(strings.ToLower(string(b)), "\"plaintext\"") {
			t.Fatalf("DTO %T exposes a value/ciphertext field: %s", v, b)
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/vault/ -run TestDTOs -v`
Expected: FAIL — types undefined.

- [ ] **Step 3: Implement** (`internal/vault/store.go`):

```go
package vault

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// Auditor is the subset of the unified audit service the vault uses. Satisfied
// by *access.UnifiedAuditService.RecordEvent.
type Auditor interface {
	RecordEvent(ctx context.Context, source, eventType, routeID, userID, actorIP string, details map[string]interface{}) error
}

// Service is the credential vault store.
type Service struct {
	db            *database.PostgresDB
	ring          *keyring
	audit         Auditor
	logger        *zap.Logger
	revealLeaseTTL time.Duration
}

func NewService(db *database.PostgresDB, ring *keyring, audit Auditor, revealLeaseTTL time.Duration, logger *zap.Logger) (*Service, error) {
	if ring == nil || !ring.Enabled() {
		return nil, errors.New("vault: keyring not enabled; refusing to start (fail-closed)")
	}
	if revealLeaseTTL <= 0 {
		revealLeaseTTL = 5 * time.Minute
	}
	return &Service{db: db, ring: ring, audit: audit, logger: logger.With(zap.String("component", "vault")), revealLeaseTTL: revealLeaseTTL}, nil
}

// ---- DTOs (deliberately carry no value/ciphertext) ----

type SecretMeta struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Type           string    `json:"type"`
	Description    string    `json:"description,omitempty"`
	CurrentVersion int       `json:"current_version"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type VersionMeta struct {
	Version   int       `json:"version"`
	KeyID     int       `json:"key_id"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type SecretDetail struct {
	SecretMeta
	Versions []VersionMeta `json:"versions"`
}

type StoreInput struct {
	Name        string
	Type        string
	Description string
	Value       []byte
	Metadata    map[string]interface{}
	OwnerID     string
	CreatedBy   string
}

func (s *Service) orgID(ctx context.Context) (string, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return "", err
	}
	return org.ID, nil
}

// Store creates a new secret at version 1. The plaintext is sealed and zeroed;
// it is never persisted, logged, or returned.
func (s *Service) Store(ctx context.Context, in StoreInput) (*SecretMeta, error) {
	orgID, err := s.orgID(ctx)
	if err != nil {
		return nil, err
	}
	if in.Type == "" {
		in.Type = "generic"
	}
	secretID := uuid.New().String()
	keyID, blob, err := s.ring.Seal(secretID, 1, in.Value)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	zero(in.Value)

	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var meta SecretMeta
	err = tx.QueryRow(ctx, `
		INSERT INTO vault_secrets (id, org_id, name, type, description, owner_id, metadata, current_version, created_by)
		VALUES ($1,$2,$3,$4,$5,NULLIF($6,'')::uuid,$7,1,NULLIF($8,'')::uuid)
		RETURNING id, name, type, COALESCE(description,''), current_version, created_at, updated_at
	`, secretID, orgID, in.Name, in.Type, in.Description, in.OwnerID, jsonOrEmpty(in.Metadata), in.CreatedBy).
		Scan(&meta.ID, &meta.Name, &meta.Type, &meta.Description, &meta.CurrentVersion, &meta.CreatedAt, &meta.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO vault_secret_versions (org_id, secret_id, version, key_id, ciphertext, created_by)
		VALUES ($1,$2,1,$3,$4,NULLIF($5,'')::uuid)
	`, orgID, secretID, int(keyID), blob, in.CreatedBy); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	s.recordAudit(ctx, "vault.secret_created", in.CreatedBy, map[string]interface{}{"secret_id": secretID, "name": in.Name})
	return &meta, nil
}

// NewVersion appends an encrypted version and bumps current_version.
func (s *Service) NewVersion(ctx context.Context, secretID string, value []byte, by string) (int, error) {
	orgID, err := s.orgID(ctx)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	var next int
	if err := tx.QueryRow(ctx,
		`UPDATE vault_secrets SET current_version = current_version + 1, updated_at = NOW()
		 WHERE id = $1 RETURNING current_version`, secretID).Scan(&next); err != nil {
		return 0, err
	}
	keyID, blob, err := s.ring.Seal(secretID, next, value)
	if err != nil {
		return 0, err
	}
	zero(value)
	if _, err := tx.Exec(ctx,
		`INSERT INTO vault_secret_versions (org_id, secret_id, version, key_id, ciphertext, created_by)
		 VALUES ($1,$2,$3,$4,$5,NULLIF($6,'')::uuid)`, orgID, secretID, next, int(keyID), blob, by); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	s.recordAudit(ctx, "vault.secret_version", by, map[string]interface{}{"secret_id": secretID, "version": next})
	return next, nil
}

func (s *Service) List(ctx context.Context) ([]SecretMeta, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, type, COALESCE(description,''), current_version, created_at, updated_at
		FROM vault_secrets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SecretMeta
	for rows.Next() {
		var m SecretMeta
		if err := rows.Scan(&m.ID, &m.Name, &m.Type, &m.Description, &m.CurrentVersion, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Service) Get(ctx context.Context, secretID string) (*SecretDetail, error) {
	var d SecretDetail
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, name, type, COALESCE(description,''), current_version, created_at, updated_at
		FROM vault_secrets WHERE id = $1`, secretID).
		Scan(&d.ID, &d.Name, &d.Type, &d.Description, &d.CurrentVersion, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Pool.Query(ctx,
		`SELECT version, key_id, COALESCE(created_by::text,''), created_at
		 FROM vault_secret_versions WHERE secret_id = $1 ORDER BY version DESC`, secretID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var v VersionMeta
		if err := rows.Scan(&v.Version, &v.KeyID, &v.CreatedBy, &v.CreatedAt); err != nil {
			return nil, err
		}
		d.Versions = append(d.Versions, v)
	}
	return &d, rows.Err()
}

// Delete removes the secret and (via cascade) all its versions — the only copy
// of the ciphertext — so the secret is cryptographically unrecoverable.
func (s *Service) Delete(ctx context.Context, secretID string) error {
	ct, err := s.db.Pool.Exec(ctx, `DELETE FROM vault_secrets WHERE id = $1`, secretID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	s.recordAudit(ctx, "vault.secret_deleted", "", map[string]interface{}{"secret_id": secretID})
	return nil
}

var ErrNotFound = errors.New("vault: secret not found")

func (s *Service) recordAudit(ctx context.Context, eventType, userID string, details map[string]interface{}) {
	if s.audit == nil {
		return
	}
	if err := s.audit.RecordEvent(ctx, "vault", eventType, "", userID, "", details); err != nil {
		s.logger.Warn("vault audit failed", zap.String("event", eventType), zap.Error(err))
	}
}

func zero(b []byte) { for i := range b { b[i] = 0 } }
```

Add `jsonOrEmpty` (marshal metadata to JSONB text, default `{}`) in the same file:

```go
func jsonOrEmpty(m map[string]interface{}) string {
	if len(m) == 0 {
		return "{}"
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}
```

(add `"encoding/json"` to imports.)

- [ ] **Step 4: Run to verify it passes + build**

Run: `go test ./internal/vault/ -run TestDTOs -v && go build ./...`
Expected: PASS + build OK.

- [ ] **Step 5: Commit**

```bash
git add internal/vault/store.go internal/vault/store_test.go
git commit -m "feat(vault): Service core — Store/NewVersion/List/Get/Delete with envelope seal"
```

---

## Task 5: Access grants + authorization

**Files:**
- Modify: `internal/vault/store.go`

- [ ] **Step 1: Add grant types + methods.**

```go
type Grant struct {
	SecretID      string   `json:"secret_id"`
	PrincipalType string   `json:"principal_type"` // user|role|service_account
	PrincipalID   string   `json:"principal_id"`
	Actions       []string `json:"actions"`        // subset of {use, reveal}
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	GrantedBy     string   `json:"-"`
}

func (s *Service) AddGrant(ctx context.Context, g Grant) (string, error) {
	orgID, err := s.orgID(ctx)
	if err != nil {
		return "", err
	}
	id := uuid.New().String()
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO vault_access_grants (id, org_id, secret_id, principal_type, principal_id, actions, granted_by, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,'')::uuid,$8)
		ON CONFLICT (secret_id, principal_type, principal_id)
		DO UPDATE SET actions = EXCLUDED.actions, expires_at = EXCLUDED.expires_at
		RETURNING id`, id, orgID, g.SecretID, g.PrincipalType, g.PrincipalID, g.Actions, g.GrantedBy, g.ExpiresAt)
	if err != nil {
		return "", err
	}
	s.recordAudit(ctx, "vault.grant_added", g.GrantedBy, map[string]interface{}{
		"secret_id": g.SecretID, "principal": g.PrincipalType + ":" + g.PrincipalID, "actions": g.Actions})
	return id, nil
}

func (s *Service) RemoveGrant(ctx context.Context, grantID string) error {
	ct, err := s.db.Pool.Exec(ctx, `DELETE FROM vault_access_grants WHERE id = $1`, grantID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	s.recordAudit(ctx, "vault.grant_removed", "", map[string]interface{}{"grant_id": grantID})
	return nil
}

// hasGrant reports whether principalID holds a non-expired grant carrying action
// on secretID. userRoles lets a user match role-type grants.
func (s *Service) hasGrant(ctx context.Context, secretID, principalID string, userRoles []string, action string) (bool, error) {
	var ok bool
	err := s.db.Pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM vault_access_grants
			WHERE secret_id = $1
			  AND $2 = ANY(actions)
			  AND (expires_at IS NULL OR expires_at > NOW())
			  AND (
			    (principal_type IN ('user','service_account') AND principal_id::text = $3)
			    OR (principal_type = 'role' AND principal_id::text = ANY($4))
			  )
		)`, secretID, action, principalID, userRoles).Scan(&ok)
	return ok, err
}
```

- [ ] **Step 2: Build + vet**

Run: `go build ./... && go vet ./internal/vault/...`
Expected: OK.

- [ ] **Step 3: Commit**

```bash
git add internal/vault/store.go
git commit -m "feat(vault): access grants + grant-based authorization check"
```

---

## Task 6: Use + Reveal + checkout ledger

**Files:**
- Modify: `internal/vault/store.go`

- [ ] **Step 1: Add the decryption helper + Use + Reveal.**

```go
// decryptCurrent loads and decrypts the current version. Internal only.
func (s *Service) decryptCurrent(ctx context.Context, secretID string) (int, []byte, error) {
	var version, keyID int
	var blob []byte
	err := s.db.Pool.QueryRow(ctx, `
		SELECT v.version, v.key_id, v.ciphertext
		FROM vault_secret_versions v
		JOIN vault_secrets s ON s.id = v.secret_id AND s.current_version = v.version
		WHERE v.secret_id = $1`, secretID).Scan(&version, &keyID, &blob)
	if err != nil {
		return 0, nil, err
	}
	pt, err := s.ring.Open(byte(keyID), secretID, version, blob)
	if err != nil {
		return 0, nil, fmt.Errorf("decrypt: %w", err)
	}
	return version, pt, nil
}

// Use returns the current plaintext to an INTERNAL Go caller (rotation engine,
// session broker). Never exposed over HTTP. System callers (WithBypassRLS) skip
// the grant check but are still recorded. Callers must zero the returned slice.
func (s *Service) Use(ctx context.Context, secretID string) ([]byte, error) {
	if !orgctx.IsBypassRLS(ctx) {
		return nil, errors.New("vault: Use requires a system (bypass-RLS) context")
	}
	version, pt, err := s.decryptCurrent(ctx, secretID)
	if err != nil {
		return nil, err
	}
	s.recordCheckout(ctx, secretID, version, "", "use", "", nil)
	s.recordAudit(ctx, "vault.use", "", map[string]interface{}{"secret_id": secretID, "system": true})
	return pt, nil
}

// Reveal returns the current plaintext to a human, requiring a `reveal` grant
// and a non-empty reason. Heavily audited; opens a short lease.
func (s *Service) Reveal(ctx context.Context, secretID, principalID string, userRoles []string, reason string, isAdmin bool) ([]byte, error) {
	if reason == "" {
		return nil, errors.New("vault: reveal requires a reason")
	}
	if !isAdmin {
		ok, err := s.hasGrant(ctx, secretID, principalID, userRoles, "reveal")
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrForbidden
		}
	}
	version, pt, err := s.decryptCurrent(ctx, secretID)
	if err != nil {
		return nil, err
	}
	exp := time.Now().Add(s.revealLeaseTTL)
	s.recordCheckout(ctx, secretID, version, principalID, "reveal", reason, &exp)
	s.recordAudit(ctx, "vault.reveal", principalID, map[string]interface{}{
		"secret_id": secretID, "version": version, "reason": reason})
	return pt, nil
}

var ErrForbidden = errors.New("vault: principal lacks the required grant")

func (s *Service) recordCheckout(ctx context.Context, secretID string, version int, principalID, mode, reason string, expires *time.Time) {
	orgID, err := s.orgID(ctx)
	if err != nil {
		// System Use runs under bypass with no org; derive from the secret row.
		_ = s.db.Pool.QueryRow(ctx, `SELECT org_id FROM vault_secrets WHERE id = $1`, secretID).Scan(&orgID)
	}
	if _, err := s.db.Pool.Exec(ctx, `
		INSERT INTO vault_checkouts (org_id, secret_id, secret_version, principal_id, mode, reason, expires_at)
		VALUES ($1,$2,$3,NULLIF($4,'')::uuid,$5,NULLIF($6,''),$7)`,
		orgID, secretID, version, principalID, mode, reason, expires); err != nil {
		s.logger.Warn("vault checkout record failed", zap.Error(err))
	}
}

type Checkout struct {
	ID        string     `json:"id"`
	Version   int        `json:"secret_version"`
	Principal string     `json:"principal_id,omitempty"`
	Mode      string     `json:"mode"`
	Reason    string     `json:"reason,omitempty"`
	LeasedAt  time.Time  `json:"leased_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Status    string     `json:"status"`
}

func (s *Service) Checkouts(ctx context.Context, secretID string) ([]Checkout, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, secret_version, COALESCE(principal_id::text,''), mode, COALESCE(reason,''), leased_at, expires_at, status
		FROM vault_checkouts WHERE secret_id = $1 ORDER BY leased_at DESC LIMIT 200`, secretID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Checkout
	for rows.Next() {
		var c Checkout
		if err := rows.Scan(&c.ID, &c.Version, &c.Principal, &c.Mode, &c.Reason, &c.LeasedAt, &c.ExpiresAt, &c.Status); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
```

- [ ] **Step 2: Build + vet + orgscope**

Run: `go build ./... && go vet ./internal/vault/... && go run ./tools/orgscope -fail ./internal/vault`
Expected: OK. (If orgscope flags the `recordCheckout` bypass fallback SELECT, annotate that line with `//orgscope:ignore system Use has no request org; org_id derived from the secret row`.)

- [ ] **Step 3: Commit**

```bash
git add internal/vault/store.go
git commit -m "feat(vault): Use (internal) + reason-gated Reveal + checkout ledger"
```

---

## Task 7: Checkout sweeper

**Files:**
- Create: `internal/vault/sweeper.go`

- [ ] **Step 1: Implement** (mirrors `internal/oauth/session_worker.go`):

```go
package vault

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/leader"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// StartSweeper marks active checkouts past their expires_at as expired. Leader-
// gated so it runs once per interval cluster-wide. Runs under bypass-RLS since
// it sweeps across all orgs.
func (s *Service) StartSweeper(ctx context.Context, rdb *redis.Client) {
	ctx = orgctx.WithBypassRLS(ctx)
	s.logger.Info("Starting vault checkout sweeper")
	leader.RunPeriodic(ctx, rdb, s.logger, "vault:checkout-expiry", 60*time.Second, s.expireCheckouts)
}

func (s *Service) expireCheckouts(ctx context.Context) {
	ct, err := s.db.Pool.Exec(ctx,
		//orgscope:ignore background ticker expiring reveal leases across all orgs; no request/tenant context
		`UPDATE vault_checkouts SET status = 'expired'
		 WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at <= NOW()`)
	if err != nil {
		s.logger.Error("vault checkout sweep failed", zap.Error(err))
		return
	}
	if n := ct.RowsAffected(); n > 0 {
		s.logger.Info("Expired vault reveal leases", zap.Int64("count", n))
	}
}
```

- [ ] **Step 2: Build + orgscope**

Run: `go build ./... && go run ./tools/orgscope -fail ./internal/vault`
Expected: OK.

- [ ] **Step 3: Commit**

```bash
git add internal/vault/sweeper.go
git commit -m "feat(vault): leader-gated checkout/reveal-lease expiry sweeper"
```

---

## Task 8: admin-api HTTP handlers

**Files:**
- Create: `internal/vault/handlers.go`

**First** grep an existing admin-api handler set to copy the exact router group, auth middleware, and org/user extraction idiom (e.g., `grep -rn "RegisterRoutes" internal/admin internal/access | head`; look at how `c` yields the current user id and how admin-guard middleware is applied). Match that idiom; the code below shows intent.

- [ ] **Step 1: Implement handlers + RegisterRoutes.**

```go
package vault

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// RegisterRoutes mounts the vault API under an already-admin-guarded group.
// The caller passes a group that has tenant-resolution + admin auth applied
// (same middleware the other admin-api resources use).
func (s *Service) RegisterRoutes(g *gin.RouterGroup) {
	v := g.Group("/vault/secrets")
	v.POST("", s.handleCreate)
	v.GET("", s.handleList)
	v.GET("/:id", s.handleGet)
	v.PUT("/:id/version", s.handleNewVersion)
	v.DELETE("/:id", s.handleDelete)
	v.POST("/:id/reveal", s.handleReveal)
	v.POST("/:id/grants", s.handleAddGrant)
	v.DELETE("/:id/grants/:grantId", s.handleRemoveGrant)
	v.GET("/:id/checkouts", s.handleCheckouts)
}

type createReq struct {
	Name        string                 `json:"name" binding:"required"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Value       string                 `json:"value" binding:"required"`
	Metadata    map[string]interface{} `json:"metadata"`
	OwnerID     string                 `json:"owner_id"`
}

func (s *Service) handleCreate(c *gin.Context) {
	var req createReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	meta, err := s.Store(c.Request.Context(), StoreInput{
		Name: req.Name, Type: req.Type, Description: req.Description,
		Value: []byte(req.Value), Metadata: req.Metadata,
		OwnerID: req.OwnerID, CreatedBy: currentUserID(c),
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, meta) // meta carries no value
}

func (s *Service) handleList(c *gin.Context) {
	out, err := s.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"secrets": out})
}

func (s *Service) handleGet(c *gin.Context) {
	d, err := s.Get(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, d)
}

func (s *Service) handleNewVersion(c *gin.Context) {
	var req struct{ Value string `json:"value" binding:"required"` }
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	v, err := s.NewVersion(c.Request.Context(), c.Param("id"), []byte(req.Value), currentUserID(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"version": v})
}

func (s *Service) handleDelete(c *gin.Context) {
	if err := s.Delete(c.Request.Context(), c.Param("id")); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.Status(http.StatusNoContent)
}

func (s *Service) handleReveal(c *gin.Context) {
	var req struct{ Reason string `json:"reason" binding:"required"` }
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "reason is required"})
		return
	}
	pt, err := s.Reveal(c.Request.Context(), c.Param("id"), currentUserID(c), currentUserRoles(c), req.Reason, isAdmin(c))
	if err != nil {
		if err == ErrForbidden {
			c.JSON(http.StatusForbidden, gin.H{"error": "not permitted"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// Returned once. Do not log the body.
	c.JSON(http.StatusOK, gin.H{"value": string(pt)})
	zero(pt)
}

func (s *Service) handleAddGrant(c *gin.Context) {
	var g Grant
	if err := c.ShouldBindJSON(&g); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	g.SecretID = c.Param("id")
	g.GrantedBy = currentUserID(c)
	id, err := s.AddGrant(c.Request.Context(), g)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

func (s *Service) handleRemoveGrant(c *gin.Context) {
	if err := s.RemoveGrant(c.Request.Context(), c.Param("grantId")); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.Status(http.StatusNoContent)
}

func (s *Service) handleCheckouts(c *gin.Context) {
	out, err := s.Checkouts(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"checkouts": out})
}
```

Provide `currentUserID(c)`, `currentUserRoles(c)`, `isAdmin(c)` by matching the existing admin-api idiom discovered in the grep (e.g., values set on the gin context by the auth middleware — `c.GetString("user_id")`, a roles slice, an `is_admin` flag). Put them at the bottom of `handlers.go`.

- [ ] **Step 2: Build + vet**

Run: `go build ./... && go vet ./internal/vault/...`
Expected: OK.

- [ ] **Step 3: Commit**

```bash
git add internal/vault/handlers.go
git commit -m "feat(vault): admin-api handlers + route registration"
```

---

## Task 9: Service wiring (construct, register, start sweeper, fail-closed)

**Files:**
- Modify: the service that mounts admin-api routes (found via grep in Task 8).

- [ ] **Step 1: Wire it up** where the service builds its dependencies and router:

```go
ring, err := vault.KeyringFromConfig(vault.KeyConfig{
	KEK: cfg.VaultKEK, KEKs: cfg.VaultKEKs, ActiveKEKID: cfg.VaultActiveKEKID,
	EncryptionKey: cfg.EncryptionKey,
})
if err != nil {
	logger.Fatal("vault keyring unavailable (fail-closed)", zap.Error(err))
}
vaultSvc, err := vault.NewService(db, ring,
	unifiedAudit, // *access.UnifiedAuditService satisfies vault.Auditor
	time.Duration(cfg.VaultRevealLeaseTTLSeconds)*time.Second, logger)
if err != nil {
	logger.Fatal("vault service init failed", zap.Error(err))
}
vaultSvc.RegisterRoutes(adminGroup) // the admin-guarded router group
go vaultSvc.StartSweeper(ctx, redisClient)
```

If the mounting service does not already construct a `*access.UnifiedAuditService`, either construct one (`access.NewUnifiedAuditService(db, logger)`) or pass `nil` (audit is best-effort; `recordAudit` no-ops on nil). Prefer constructing it.

- [ ] **Step 2: Build the whole tree + vet + gofmt + orgscope**

Run:
```bash
go build ./... && go vet ./... && gofmt -l internal/vault && go run ./tools/orgscope -fail ./internal
```
Expected: build OK, `gofmt -l` prints nothing, orgscope clean.

- [ ] **Step 3: Commit**

```bash
git add -- <the wired service file(s)>
git commit -m "feat(vault): wire vault service into admin-api (fail-closed) + start sweeper"
```

---

## Task 10: Integration tests (migration apply, RLS isolation, e2e)

**Files:**
- Create: `test/integration/vault_test.go` (build tag `//go:build integration`, matching the suite's convention — confirm with an existing file in `test/integration/`).

- [ ] **Step 1: Write the tests.** Model connection/bootstrapping on an existing `test/integration/*_test.go` (testcontainers Postgres + run migrations). Cover:

```go
//go:build integration

package integration

// TestVaultMigrationApplies: fresh init-db.sql cluster AND migrate-on-top both
// end with the four vault_* tables present and RLS enabled+forced.
// TestVaultRoundTrip: with app.org_id GUC set to org A, Store a secret; a direct
//   SELECT of ciphertext != plaintext; Reveal (admin) returns the value; NewVersion
//   bumps and old version still decrypts; Delete removes it.
// TestVaultRLSIsolation: Store under org A; set GUC to org B → List/Get return
//   nothing and Reveal 404/forbidden; set app.bypass_rls=on → Use returns it.
```

Write each as a real test using the suite's DB helper. Assert:
- table existence + `relrowsecurity`/`relforcerowsecurity` true via `pg_class`.
- `SELECT ciphertext FROM vault_secret_versions` bytes do not contain the plaintext.
- cross-org SELECT under a different `app.org_id` GUC returns 0 rows.

- [ ] **Step 2: Run**

Run: `go test -tags=integration ./test/integration/ -run TestVault -v`
Expected: PASS (requires Docker for testcontainers).

- [ ] **Step 3: Commit**

```bash
git add test/integration/vault_test.go
git commit -m "test(vault): migration-apply, RLS isolation, and e2e integration tests"
```

---

## Final verification (whole feature)

```bash
go build ./...
go vet ./...
gofmt -l internal/vault
go run ./tools/orgscope -fail ./internal
golangci-lint run
govulncheck ./...
go test ./internal/vault/... -v
go test ./internal/migrations/ -run TestInitDBParity -v
go test -tags=integration ./test/integration/ -run TestVault -v   # Docker required
```

Then the manual box walkthrough from the spec's Verification section (create → confirm ciphertext-at-rest → get shows no value → grant+reveal with reason → audit event present → new version → delete → cross-org isolation).

## Self-review notes (addressed)

- **No plaintext egress:** the only value-returning paths are internal `Use` (bypass-RLS Go callers) and reason-gated `Reveal`; `List`/`Get` DTOs carry no value field (unit-asserted in Task 4).
- **Type consistency:** `RemoveGrant(ctx, grantID)` matches the `DELETE …/grants/:grantId` route (Task 5/8); `Reveal` signature is identical in store (Task 6) and handler (Task 8).
- **Fail-closed:** `KeyringFromConfig` (Task 2) and `NewService` (Task 4) both error when no KEK; Task 9 turns that into `logger.Fatal`.
- **RLS/orgscope:** every query runs under the request GUC; the two cross-org background/system reads are annotated `//orgscope:ignore`.
- **Parity:** Task 3 mirrors DDL into `init-db.sql`; `TestInitDBParity` is run in Task 3 and final verification.
```
