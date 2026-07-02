# PAM M1b — Credential Rotation Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a rotation engine that generates new credential values, applies them to target systems, verifies, and promotes them as the vault's current version — on a schedule, on demand, or when a checkout concludes — safely and fully audited.

**Architecture:** New `internal/credentials` package (engine + `Rotator` interface + directory/generate-only connectors + leader-gated scheduler + admin-api handlers), building on the M1 vault via three additive vault methods (candidate-version + promote). Migration v57 adds `credential_rotation_policies` and reconciles the dead `credential_rotations` table into a run ledger. Mirrors the `internal/access/ziti_hardening.go` rotation state machine.

**Tech Stack:** Go 1.25, pgx v5, `crypto/rand`, Gin, zap, Viper, `leader.RunPeriodic`.

**Spec:** `docs/superpowers/specs/2026-07-02-pam-m1b-rotation-engine-design.md`
**Depends on:** the M1 vault (`internal/vault`) — this branch is stacked on `pam/vault-store-spec`.

---

## File structure

- `internal/vault/store.go` — MODIFY: add `AddCandidateVersion`, `PromoteVersion`, `SecretOrg`.
- `internal/credentials/rotator.go` — `Rotator` interface, `ErrVerifyUnsupported`, `GenerationPolicy`, `generateSecret`, connector registry.
- `internal/credentials/directory_rotator.go` — directory connector.
- `internal/credentials/generate_rotator.go` — generate-only connector.
- `internal/credentials/engine.go` — `Service`: `RotateSecret` state machine + policy CRUD.
- `internal/credentials/scheduler.go` — leader-gated periodic pass.
- `internal/credentials/handlers.go` — admin-api handlers + `RegisterRoutes`.
- `internal/credentials/*_test.go` — unit tests.
- `internal/migrations/sql_v57.go` + `loader.go` (register) + `deployments/docker/init-db.sql` (mirror).
- `internal/common/config/config.go` — `CREDENTIALS_*` fields.
- `internal/directory/{service.go,ldap.go}` — MODIFY: add `VerifyPassword` (+ `ErrVerifyUnsupported`).
- `cmd/admin-api/main.go` — construct engine, register routes, start scheduler.
- `test/integration/rotation_test.go` — v57 apply, directory e2e, RLS, ledger.

---

## Task 1: Vault additions (candidate + promote + org)

**Files:** Modify `internal/vault/store.go`. Test: integration (Task 10) — add a compile-time-safe unit note here.

- [ ] **Step 1: Add the three methods.**

```go
// AddCandidateVersion stores a new encrypted version WITHOUT bumping current_version.
// The candidate is invisible to Use/Reveal (which join on current_version) until
// PromoteVersion runs. Version number = MAX(version)+1 so repeated failed rotations
// don't collide. Used by the rotation engine to make a generated value durable before
// touching the target. value is zeroed by the caller.
func (s *Service) AddCandidateVersion(ctx context.Context, secretID string, value []byte, by string) (int, error) {
	orgID, err := s.orgID(ctx)
	if err != nil {
		return 0, err
	}
	var next int
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT COALESCE(MAX(version),0)+1 FROM vault_secret_versions WHERE secret_id = $1`, secretID).Scan(&next); err != nil {
		return 0, err
	}
	keyID, blob, err := s.ring.Seal(secretID, next, value)
	if err != nil {
		return 0, err
	}
	if _, err := s.db.Pool.Exec(ctx,
		`INSERT INTO vault_secret_versions (org_id, secret_id, version, key_id, ciphertext, created_by)
		 VALUES ($1,$2,$3,$4,$5,NULLIF($6,'')::uuid)`, orgID, secretID, next, int(keyID), blob, by); err != nil {
		return 0, err
	}
	return next, nil
}

// PromoteVersion sets a secret's current_version — the atomic "this value is now live on
// the target" commit that makes it visible to Use/Reveal.
func (s *Service) PromoteVersion(ctx context.Context, secretID string, version int) error {
	ct, err := s.db.Pool.Exec(ctx,
		`UPDATE vault_secrets SET current_version = $2, updated_at = NOW() WHERE id = $1`, secretID, version)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SecretOrg returns a secret's org_id. Background/bypass callers (the rotation engine)
// use it to inject the org into their context for scoped vault writes.
func (s *Service) SecretOrg(ctx context.Context, secretID string) (string, error) {
	var org string
	err := s.db.Pool.QueryRow(ctx, `SELECT org_id FROM vault_secrets WHERE id = $1`, secretID).Scan(&org)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return org, err
}
```

- [ ] **Step 2: Build + existing tests.**

Run: `go build ./... && go test ./internal/vault/... && go vet ./internal/vault/... && go run ./tools/orgscope -fail ./internal/vault`
Expected: all pass/clean. (`pgx` + `errors` already imported in store.go from M1.)

- [ ] **Step 3: Commit**

```bash
git add internal/vault/store.go
git commit -m "feat(vault): AddCandidateVersion/PromoteVersion/SecretOrg for rotation"
```

---

## Task 2: Migration v57 (policies + ledger reconcile)

**Files:** Create `internal/migrations/sql_v57.go`; modify `loader.go`, `deployments/docker/init-db.sql`.

- [ ] **Step 1: Create `internal/migrations/sql_v57.go`** with the DDL from the spec's "Data model — migration v57" (both the `credential_rotation_policies` CREATE + indexes, the `credential_rotations` ALTERs, and the RLS belt for both tables). Add the belt exactly as v56 does (copy the `pol_<t>_org_scope` policy + `ENABLE`/`FORCE` pattern for `credential_rotation_policies` and `credential_rotations`, plus the `GRANT ... TO openidx_app` DO-block). Wrap the `credential_rotations` ALTERs so they are idempotent (`ADD COLUMN IF NOT EXISTS`; the `DROP NOT NULL` is idempotent). Down: `DROP TABLE credential_rotation_policies`; leave `credential_rotations` columns (down is best-effort — note it).

- [ ] **Step 2: Register v57 in `loader.go`** after the v56 entry, Name `credential_rotation`, Description summarizing the policies table + ledger reconcile + RLS belt.

- [ ] **Step 3: Mirror into `init-db.sql`** — add `credential_rotation_policies` CREATE + indexes, the `credential_rotations` reconcile columns (as `ADD COLUMN IF NOT EXISTS` + `ALTER COLUMN ... DROP NOT NULL`), and the RLS belt for both (init-db.sql now carries the vault belt from M1's fix, so match that). Grep how M1's vault belt was added to init-db.sql and follow it exactly.

- [ ] **Step 4: Parity + build.**

Run: `go build ./... && go test ./internal/migrations/ -run TestInitDBParity -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/migrations/sql_v57.go internal/migrations/loader.go deployments/docker/init-db.sql
git commit -m "feat(migrations): v57 — rotation policies + credential_rotations ledger reconcile"
```

---

## Task 3: Config fields

**Files:** Modify `internal/common/config/config.go`.

- [ ] **Step 1: Add fields** near the vault fields:

```go
	CredentialsRotationSchedulerIntervalSeconds int `mapstructure:"credentials_rotation_scheduler_interval_seconds"`
	CredentialsRotationDefaultLength            int `mapstructure:"credentials_rotation_default_length"`
```

Env bindings: `"credentials_rotation_scheduler_interval_seconds": "CREDENTIALS_ROTATION_SCHEDULER_INTERVAL_SECONDS"`, `"credentials_rotation_default_length": "CREDENTIALS_ROTATION_DEFAULT_LENGTH"`. Viper defaults: `60` and `24` respectively (match the existing SetDefault style).

- [ ] **Step 2: Build.** `go build ./...` → OK.
- [ ] **Step 3: Commit** `git commit -am "feat(config): CREDENTIALS_ROTATION_* settings"` (stage only config.go).

---

## Task 4: Rotator interface + generator

**Files:** Create `internal/credentials/rotator.go`, `internal/credentials/rotator_test.go`.

- [ ] **Step 1: Write the failing test** (`rotator_test.go`):

```go
package credentials

import (
	"bytes"
	"testing"
)

func TestGenerateSecretLengthAndCharset(t *testing.T) {
	v, err := generateSecret(GenerationPolicy{Length: 20, Lower: true, Digits: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 20 {
		t.Fatalf("len=%d want 20", len(v))
	}
	for _, c := range v {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			t.Fatalf("char %q outside requested charset", c)
		}
	}
}

func TestGenerateSecretRejectsShort(t *testing.T) {
	if _, err := generateSecret(GenerationPolicy{Length: 4}); err == nil {
		t.Fatal("expected error for length < 8")
	}
}

func TestGenerateSecretDefaultsAndEntropy(t *testing.T) {
	a, _ := generateSecret(GenerationPolicy{}) // defaults: len 24, all classes
	b, _ := generateSecret(GenerationPolicy{})
	if len(a) != 24 {
		t.Fatalf("default len=%d want 24", len(a))
	}
	if bytes.Equal(a, b) {
		t.Fatal("two generated secrets identical — not random")
	}
}
```

- [ ] **Step 2: Run → fails** (undefined). `go test ./internal/credentials/ -run TestGenerate -v`.

- [ ] **Step 3: Implement `rotator.go`:**

```go
// Package credentials implements the PAM credential rotation engine: it generates new
// credential values, applies them to target systems through Rotator connectors, verifies
// them, and promotes them as the vault's current version.
package credentials

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

// ErrVerifyUnsupported signals a connector cannot verify a credential is live; the engine
// treats it as "skip verification" (not a failure).
var ErrVerifyUnsupported = errors.New("credentials: connector cannot verify")

// Rotator applies (and optionally verifies) a new credential value on a target system.
type Rotator interface {
	Type() string
	Apply(ctx context.Context, cfg map[string]any, newValue []byte) error
	Verify(ctx context.Context, cfg map[string]any, newValue []byte) error
}

// GenerationPolicy controls generateSecret. Zero value → length 24, all character classes.
type GenerationPolicy struct {
	Length  int  `json:"length"`
	Upper   bool `json:"upper"`
	Lower   bool `json:"lower"`
	Digits  bool `json:"digits"`
	Symbols bool `json:"symbols"`
}

const (
	setUpper  = "ABCDEFGHJKLMNPQRSTUVWXYZ" // no I/O
	setLower  = "abcdefghijkmnopqrstuvwxyz"
	setDigits = "23456789"
	setSym    = "!@#$%^&*()-_=+"
)

// generateSecret builds a cryptographically-random value per gp using crypto/rand.
func generateSecret(gp GenerationPolicy) ([]byte, error) {
	if gp.Length == 0 {
		gp.Length = 24
	}
	if gp.Length < 8 {
		return nil, fmt.Errorf("generation length must be >= 8, got %d", gp.Length)
	}
	var charset []byte
	if gp.Upper {
		charset = append(charset, setUpper...)
	}
	if gp.Lower {
		charset = append(charset, setLower...)
	}
	if gp.Digits {
		charset = append(charset, setDigits...)
	}
	if gp.Symbols {
		charset = append(charset, setSym...)
	}
	if len(charset) == 0 { // no class requested → use all
		charset = []byte(setUpper + setLower + setDigits + setSym)
	}
	out := make([]byte, gp.Length)
	max := big.NewInt(int64(len(charset)))
	for i := range out {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil, fmt.Errorf("rand: %w", err)
		}
		out[i] = charset[n.Int64()]
	}
	return out, nil
}
```

- [ ] **Step 4: Run → pass.** `go test ./internal/credentials/ -v`; `go build ./...`; `gofmt -l internal/credentials`; `go vet ./internal/credentials/...`.

- [ ] **Step 5: Commit** `git add internal/credentials/rotator.go internal/credentials/rotator_test.go && git commit -m "feat(credentials): Rotator interface + crypto/rand secret generator"`.

---

## Task 5: Connectors (directory + generate-only) + directory VerifyPassword

**Files:** Create `internal/credentials/directory_rotator.go`, `internal/credentials/generate_rotator.go`; modify `internal/directory/service.go` + `internal/directory/ldap.go`.

- [ ] **Step 1: Add `VerifyPassword` to the directory service.** First read `internal/directory/service.go:137` (`ResetPassword`) and `internal/directory/ldap.go:214-246` to match the connector-dispatch idiom. Add:

```go
// internal/directory/service.go
// ErrVerifyUnsupported means this directory type cannot cheaply verify a credential
// (e.g. Azure AD via Graph). Callers treat it as "skip verification".
var ErrVerifyUnsupported = errors.New("directory: password verify unsupported for this type")

// VerifyPassword confirms username/password authenticates against the directory. For
// ldap/ad it performs a bind; for azure it returns ErrVerifyUnsupported.
func (s *Service) VerifyPassword(ctx context.Context, directoryID, username, password string) error {
	// dispatch on directory type exactly like ResetPassword does; for ldap/ad call the
	// LDAP connector's VerifyBind; for azure return ErrVerifyUnsupported.
}
```

Add a `VerifyBind(username, password string) error` to the LDAP connector in `ldap.go` that opens a fresh connection and binds as the user (reuse the connector's dial/TLS setup used by `ResetPassword`; a successful bind = nil, invalid creds = error). Keep it minimal and close the conn.

- [ ] **Step 2: Implement `directory_rotator.go`:**

```go
package credentials

import (
	"context"
	"errors"
	"fmt"

	"github.com/openidx/openidx/internal/directory"
)

type directoryRotator struct{ dir *directory.Service }

func (d *directoryRotator) Type() string { return "directory" }

func (d *directoryRotator) Apply(ctx context.Context, cfg map[string]any, newValue []byte) error {
	dirID, _ := cfg["directory_id"].(string)
	user, _ := cfg["username"].(string)
	if dirID == "" || user == "" {
		return fmt.Errorf("directory connector requires directory_id and username")
	}
	return d.dir.ResetPassword(ctx, dirID, user, string(newValue))
}

func (d *directoryRotator) Verify(ctx context.Context, cfg map[string]any, newValue []byte) error {
	dirID, _ := cfg["directory_id"].(string)
	user, _ := cfg["username"].(string)
	err := d.dir.VerifyPassword(ctx, dirID, user, string(newValue))
	if errors.Is(err, directory.ErrVerifyUnsupported) {
		return ErrVerifyUnsupported
	}
	return err
}
```

- [ ] **Step 3: Implement `generate_rotator.go`:**

```go
package credentials

import "context"

// generateOnlyRotator rotates the vault value but applies nothing to a target — for
// secrets consumed somewhere the engine can't reach (e.g. a shared API key). The engine
// promotes immediately and fires an "apply manually" notification.
type generateOnlyRotator struct{}

func (generateOnlyRotator) Type() string { return "generate_only" }
func (generateOnlyRotator) Apply(ctx context.Context, cfg map[string]any, newValue []byte) error {
	return nil
}
func (generateOnlyRotator) Verify(ctx context.Context, cfg map[string]any, newValue []byte) error {
	return ErrVerifyUnsupported
}
```

- [ ] **Step 4: Build + vet.** `go build ./... && go vet ./internal/credentials/... ./internal/directory/...`.
- [ ] **Step 5: Commit** the four files: `git commit -m "feat(credentials): directory + generate-only connectors; directory VerifyPassword"`.

---

## Task 6: Engine — RotateSecret state machine + policy CRUD

**Files:** Create `internal/credentials/engine.go`, `internal/credentials/engine_test.go`.

- [ ] **Step 1: Write the failing state-machine test** using a mock Rotator (the engine must accept an injectable `Rotator` per connector type). The test exercises: Apply-ok+Verify-ok → PromoteVersion called + ledger `succeeded`; Apply-fail → no promote + ledger `failed`; Verify-fail → no promote + `failed`; `ErrVerifyUnsupported` → promote proceeds. Since the engine writes to the vault + ledger (DB), structure the test to inject a small `vaultPromoter` interface + a `ledger` interface so the state logic is unit-testable without a DB:

```go
package credentials

import (
	"context"
	"errors"
	"testing"
)

type fakeVault struct {
	candidate int
	promoted  int
}
func (f *fakeVault) AddCandidateVersion(ctx context.Context, secretID string, v []byte, by string) (int, error) {
	f.candidate = 2
	return 2, nil
}
func (f *fakeVault) PromoteVersion(ctx context.Context, secretID string, version int) error {
	f.promoted = version
	return nil
}

type fakeRotator struct{ applyErr, verifyErr error }
func (f fakeRotator) Type() string { return "fake" }
func (f fakeRotator) Apply(ctx context.Context, cfg map[string]any, v []byte) error  { return f.applyErr }
func (f fakeRotator) Verify(ctx context.Context, cfg map[string]any, v []byte) error { return f.verifyErr }

func TestRotateOutcome(t *testing.T) {
	cases := []struct {
		name              string
		apply, verify     error
		wantPromoted      bool
		wantStatus        string
	}{
		{"ok", nil, nil, true, "succeeded"},
		{"apply-fail", errors.New("x"), nil, false, "failed"},
		{"verify-fail", nil, errors.New("x"), false, "failed"},
		{"verify-unsupported", nil, ErrVerifyUnsupported, true, "succeeded"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fv := &fakeVault{}
			status, promoted := runRotation(context.Background(),
				fakeRotator{applyErr: tc.apply, verifyErr: tc.verify},
				fv, GenerationPolicy{Length: 12}, map[string]any{})
			if promoted != tc.wantPromoted {
				t.Fatalf("promoted=%v want %v", promoted, tc.wantPromoted)
			}
			if status != tc.wantStatus {
				t.Fatalf("status=%q want %q", status, tc.wantStatus)
			}
		})
	}
}
```

- [ ] **Step 2: Run → fails.**

- [ ] **Step 3: Implement `engine.go`.** Extract the pure decision core `runRotation` (used by the test) and wrap it with the DB-backed `RotateSecret`. Define the collaborator interfaces so the core is testable:

```go
package credentials

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// vaultPort is the subset of *vault.Service the engine needs.
type vaultPort interface {
	AddCandidateVersion(ctx context.Context, secretID string, value []byte, by string) (int, error)
	PromoteVersion(ctx context.Context, secretID string, version int) error
	SecretOrg(ctx context.Context, secretID string) (string, error)
}

type Auditor interface {
	RecordEvent(ctx context.Context, source, eventType, routeID, userID, actorIP string, details map[string]interface{}) error
}

type Service struct {
	db        *database.PostgresDB
	vault     vaultPort
	rotators  map[string]Rotator // keyed by Type()
	audit     Auditor
	logger    *zap.Logger
	defaultLen int
}

func NewService(db *database.PostgresDB, v vaultPort, rotators []Rotator, audit Auditor, defaultLen int, logger *zap.Logger) *Service {
	m := make(map[string]Rotator, len(rotators))
	for _, r := range rotators {
		m[r.Type()] = r
	}
	if defaultLen == 0 {
		defaultLen = 24
	}
	return &Service{db: db, vault: v, rotators: m, audit: audit, defaultLen: defaultLen, logger: logger.With(zap.String("component", "credentials"))}
}

func zero(b []byte) { for i := range b { b[i] = 0 } }

// runRotation is the pure, DB-free decision core: generate → candidate → apply → verify →
// promote. Returns the terminal ledger status and whether the candidate was promoted.
func runRotation(ctx context.Context, r Rotator, v interface {
	AddCandidateVersion(ctx context.Context, secretID string, value []byte, by string) (int, error)
	PromoteVersion(ctx context.Context, secretID string, version int) error
}, gp GenerationPolicy, cfg map[string]any) (status string, promoted bool) {
	newValue, err := generateSecret(gp)
	if err != nil {
		return "failed", false
	}
	defer zero(newValue)
	candidate, err := v.AddCandidateVersion(ctx, "", newValue, "rotation") // secretID injected by RotateSecret via closure in real path
	if err != nil {
		return "failed", false
	}
	if err := r.Apply(ctx, cfg, newValue); err != nil {
		return "failed", false
	}
	if err := r.Verify(ctx, cfg, newValue); err != nil && !errors.Is(err, ErrVerifyUnsupported) {
		return "failed", false
	}
	if err := v.PromoteVersion(ctx, "", candidate); err != nil {
		return "failed", false
	}
	return "succeeded", true
}
```

NOTE for implementer: the pure `runRotation` above uses `""` for secretID for testability; in the real `RotateSecret` you will pass the actual `secretID` — refactor `runRotation` to take `secretID string` and have the test pass a dummy. Keep the test asserting promote/status outcomes. Then implement the DB-backed wrapper:

```go
// RotateSecret runs one rotation for a policy, recording a credential_rotations ledger
// row through the state machine. trigger ∈ {scheduled,on_demand,checkout}.
func (s *Service) RotateSecret(ctx context.Context, policyID, trigger string) error {
	// 1. Load policy (+ secret_id, connector_type, connector_config, generation_policy,
	//    interval_seconds, org_id, current secret version) — SELECT ... FROM
	//    credential_rotation_policies JOIN vault_secrets. If !enabled, return nil.
	// 2. ctx = orgctx.With(orgctx.WithBypassRLS(ctx), orgctx.Org{ID: policy.OrgID}).
	// 3. Insert ledger row: status='rotating', version_from=current, trigger, started_at=NOW(); capture runID.
	// 4. rot := s.rotators[policy.ConnectorType]; if nil → fail the run ("unknown connector").
	// 5. Run the generate→candidate→apply→verify→promote sequence (the runRotation logic),
	//    updating the ledger row: version_to=candidate; on apply/verify failure set
	//    status='failed'+error_message+completed_at and update policy last_status='failed';
	//    on success set status='succeeded'+completed_at, policy last_run_at=NOW(),
	//    last_status='succeeded', next_run_at = NOW()+interval (if interval_seconds>0).
	// 6. For generate_only, after promote, fire a notification ("apply the new value manually").
	// 7. Audit: RecordEvent(ctx,"vault","credential.rotated" | "credential.rotation_failed",
	//    "", "", "", {"secret_id":..,"policy_id":..,"version_from":..,"version_to":..,
	//    "connector":..,"trigger":..}). NEVER include the value.
}
```

Also implement policy CRUD used by handlers: `CreatePolicy`, `ListPolicies`, `GetPolicy`, `UpdatePolicy`, `DeletePolicy` (org-scoped via orgctx; validate connector_config for `directory` requires `directory_id`+`username`; `interval_seconds>=0`; generation length default from `s.defaultLen`).

- [ ] **Step 4: Run tests + build + orgscope.** `go test ./internal/credentials/ -v && go build ./... && go vet ./internal/credentials/... && go run ./tools/orgscope -fail ./internal/credentials` (annotate the RotateSecret loading query / scheduler-invoked paths with `//orgscope:ignore` where they run under bypass with org derived from the policy row).

- [ ] **Step 5: Commit** `git commit -m "feat(credentials): rotation engine state machine + policy CRUD"`.

---

## Task 7: Scheduler (interval + rotate-on-checkout)

**Files:** Create `internal/credentials/scheduler.go`.

- [ ] **Step 1: Implement** (mirrors `internal/oauth/session_worker.go`):

```go
package credentials

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/leader"
	"github.com/openidx/openidx/internal/common/orgctx"
)

func (s *Service) StartScheduler(ctx context.Context, rdb *redis.Client, interval time.Duration) {
	ctx = orgctx.WithBypassRLS(ctx)
	if interval <= 0 {
		interval = 60 * time.Second
	}
	s.logger.Info("Starting credential rotation scheduler")
	leader.RunPeriodic(ctx, rdb, s.logger, "credentials:rotation", interval, s.tick)
}

func (s *Service) tick(ctx context.Context) {
	ids, err := s.dueUnsafe(ctx)
	if err != nil {
		s.logger.Error("rotation scheduler due-scan failed", zap.Error(err))
		return
	}
	for _, p := range ids {
		if err := s.RotateSecret(ctx, p.policyID, p.trigger); err != nil {
			s.logger.Error("scheduled rotation failed", zap.String("policy_id", p.policyID), zap.Error(err))
		}
	}
}

type duePolicy struct {
	policyID string
	trigger  string
}

// dueUnsafe returns policies whose interval is due OR whose rotate_on_checkout is set and a
// checkout concluded since last_run_at. Runs under bypass (background, cross-org).
func (s *Service) dueUnsafe(ctx context.Context) ([]duePolicy, error) {
	rows, err := s.db.Pool.Query(ctx,
		//orgscope:ignore background rotation scheduler scans due policies across all orgs; no request/tenant context
		`SELECT p.id,
		        CASE WHEN p.interval_seconds > 0 AND (p.next_run_at IS NULL OR p.next_run_at <= NOW())
		             THEN 'scheduled' ELSE 'checkout' END AS trigger
		 FROM credential_rotation_policies p
		 WHERE p.enabled AND (
		   (p.interval_seconds > 0 AND (p.next_run_at IS NULL OR p.next_run_at <= NOW()))
		   OR (p.rotate_on_checkout AND EXISTS (
		         SELECT 1 FROM vault_checkouts c
		         WHERE c.secret_id = p.secret_id
		           AND c.status IN ('returned','expired')
		           AND COALESCE(c.returned_at, c.leased_at) > COALESCE(p.last_run_at, 'epoch'::timestamptz)))
		 )
		 LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []duePolicy
	for rows.Next() {
		var d duePolicy
		if err := rows.Scan(&d.policyID, &d.trigger); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
```

- [ ] **Step 2: Build + orgscope.** `go build ./... && go run ./tools/orgscope -fail ./internal/credentials`.
- [ ] **Step 3: Commit** `git commit -m "feat(credentials): leader-gated scheduler (interval + rotate-on-checkout)"`.

---

## Task 8: admin-api handlers

**Files:** Create `internal/credentials/handlers.go`.

- [ ] **Step 1: Implement** the handlers + `RegisterRoutes(g *gin.RouterGroup)`. Reuse the M1 vault handler idiom exactly (read `internal/vault/handlers.go` for the `currentUserID`/`isAdmin` helpers and the error-mapping style — `errors.Is(ErrNotFound)`→404 etc.). Routes:

```go
func (s *Service) RegisterRoutes(g *gin.RouterGroup) {
	g.POST("/vault/rotation-policies", s.handleCreatePolicy)
	g.GET("/vault/rotation-policies", s.handleListPolicies)
	g.GET("/vault/rotation-policies/:id", s.handleGetPolicy)
	g.PUT("/vault/rotation-policies/:id", s.handleUpdatePolicy)
	g.DELETE("/vault/rotation-policies/:id", s.handleDeletePolicy)
	g.POST("/vault/secrets/:id/rotate", s.handleRotateNow)      // admin-only (group is RequireAdmin)
	g.GET("/vault/secrets/:id/rotations", s.handleRotationHistory)
}
```

`handleRotateNow`: look up the policy for the secret (`:id`); 404 if none; call `s.RotateSecret(ctx, policyID, "on_demand")`; return the resulting ledger row / status. `handleRotationHistory`: SELECT from `credential_rotations WHERE secret_id=$1 ORDER BY started_at DESC LIMIT 200` (never returns values). Policy DTOs never include secret values.

- [ ] **Step 2: Build + vet.** `go build ./... && go vet ./internal/credentials/...`.
- [ ] **Step 3: Commit** `git commit -m "feat(credentials): admin-api rotation-policy + rotate-now + history handlers"`.

---

## Task 9: Service wiring

**Files:** Modify `cmd/admin-api/main.go`.

- [ ] **Step 1: Wire it** in the same admin-guarded block where the vault is mounted (after `vaultSvc.RegisterRoutes(vaultGroup)`). Reuse the `vaultGroup` (already `admin.RequireAdmin()`-guarded) and the `unifiedAudit`, `db`, `log`, `ctx`, `redis.Client`, `cfg` already in scope:

```go
	dirRotator := &... // construct directoryRotator{dir: directoryService}
	rotators := []credentials.Rotator{ /* directory rotator */, generateOnlyRotator{} }
	credSvc := credentials.NewService(db, vaultSvc, rotators, unifiedAudit, cfg.CredentialsRotationDefaultLength, log)
	credSvc.RegisterRoutes(vaultGroup)
	go credSvc.StartScheduler(ctx, redis.Client,
		time.Duration(cfg.CredentialsRotationSchedulerIntervalSeconds)*time.Second)
```

DISCOVER: whether `cmd/admin-api` already constructs a `*directory.Service` (grep `directory.NewService`/`directoryService`). If yes, reuse it for the directory rotator. If not, construct one following its constructor signature (read `internal/directory/service.go`), or — if the directory service needs config not available here — register only the `generate_only` rotator and log that the directory connector is unavailable, and report this back so we can decide. Since `vaultSvc` (a `*vault.Service`) must satisfy `credentials.vaultPort`, confirm it exposes `AddCandidateVersion`/`PromoteVersion`/`SecretOrg` (Task 1) — it does.

- [ ] **Step 2: Full build + gates.** `go build ./... && go vet ./... && gofmt -l cmd/admin-api/main.go internal/credentials && go run ./tools/orgscope -fail ./internal`.
- [ ] **Step 3: Commit** `git commit -m "feat(credentials): wire rotation engine into admin-api + start scheduler"`.

---

## Task 10: Integration tests

**Files:** Create `test/integration/rotation_test.go` (build tag `//go:build integration`, matching the suite; reuse the M1 `vault_test.go` helpers: `integrationDB`, `seedOrg`, the RLS role pool, `requireForceRLS`).

- [ ] **Step 1: Write tests:**
  - `TestRotationMigrationApplies` — v57 tables/columns exist; `credential_rotation_policies` and `credential_rotations` are FORCE-RLS.
  - `TestRotateNowDirectory` — seed a secret + a `directory` policy pointing at a **mock/stub directory** (inject a fake Rotator via the engine constructor, OR — if the suite tests through the real directory.Service — use a test LDAP container if available; otherwise use a fake Rotator registered under type `directory`). Assert: `RotateSecret` creates a `succeeded` ledger row with `version_from=1,version_to=2`; the secret's `current_version` becomes 2; `vault.Reveal` returns the new value; version 1 still decrypts.
  - `TestRotateFailureKeepsCurrent` — fake Rotator whose Apply errors → ledger `failed`, `current_version` stays 1, reveal returns the old value.
  - `TestRotateOnCheckoutSelection` — a returned/expired checkout after `last_run_at` makes `dueUnsafe` return the policy with trigger `checkout`.
  - `TestRotationRLSIsolation` — org B cannot see org A's policy/ledger.

- [ ] **Step 2: Compile + run.** `go test -c -tags=integration ./test/integration/ -o /dev/null` (must compile). Run `go test -tags=integration ./test/integration/ -run 'TestRotation|TestRotate' -v` when a DB is available; else report compile-only + CI.
- [ ] **Step 3: Commit** `git commit -m "test(credentials): rotation migration/e2e/RLS integration tests"`.

---

## Final verification

```bash
go build ./... && go vet ./... && gofmt -l internal/credentials internal/vault cmd/admin-api/main.go
go run ./tools/orgscope -fail ./internal
golangci-lint run && govulncheck ./...
go test ./internal/credentials/... ./internal/vault/...
go test ./internal/migrations/ -run TestInitDBParity
go test -c -tags=integration ./test/integration/ -o /dev/null
```

## Self-review notes (addressed)

- **No plaintext egress:** generated values are `[]byte`, `defer zero`'d, never logged, never in ledger/audit details; no HTTP endpoint returns a rotated value (reveal via the vault only).
- **Safety:** `PromoteVersion` runs only after a successful Apply (+Verify unless unsupported); failure paths leave `current_version` on the old value; candidate versions are retryable — asserted in Task 6 (unit) and Task 10 (`TestRotateFailureKeepsCurrent`).
- **Type consistency:** engine `vaultPort` matches the Task 1 vault method signatures; `Rotator` is identical across rotator.go/connectors/engine; handlers reuse the M1 `ErrNotFound`/`errors.Is` mapping.
- **RLS/orgscope:** policy/ledger tables org-scoped + FORCE (v57); engine runs under bypass with the policy's org injected for vault writes; the scheduler due-scan is annotated `//orgscope:ignore`.
- **Parity:** Task 2 mirrors DDL into init-db.sql; `TestInitDBParity` gated in Task 2 + final.
```
