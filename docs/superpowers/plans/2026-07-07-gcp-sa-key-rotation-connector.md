# GCP service-account key rotation connector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `gcp_sa` PAM rotation connector that rotates a GCP service-account key, on the existing engine `Minter`/`PostRotateCleaner` seam, verified by mocked unit tests.

**Architecture:** Mirrors `internal/credentials/aws_iam_rotator.go`. The connector implements `Minter` (create a new SA key via the IAM API, return its JSON), `Verify` (mint an OAuth token from the new key, retrying), `PostRotateCleaner` (delete all USER_MANAGED keys but the newest), and `ConfigValidator`. The google IAM client (builder-chain API) is wrapped behind a narrow `gcpKeyAPI` interface + a token-check func field, both injectable so tests run without network.

**Tech Stack:** Go 1.25, `google.golang.org/api/iam/v1` + `google.golang.org/api/option` (new deps), `golang.org/x/oauth2/google` (existing dep) for verify. React/Vitest for the UI task.

**PR shape:** one PR (backend + UI), like the AWS connector (#335).

---

### Task 1: `gcp_sa` connector + deps

**Files:**
- Create: `internal/credentials/gcp_sa_rotator.go`
- Test: `internal/credentials/gcp_sa_rotator_test.go`
- Modify: `go.mod` / `go.sum`

- [ ] **Step 1: Add the GCP API dependency**

Run:
```bash
cd /home/cmit/openidx
go get google.golang.org/api/iam/v1@latest
go get google.golang.org/api/option@latest
```
Expected: `go.mod` gains `google.golang.org/api`. (`golang.org/x/oauth2` is already present.)

- [ ] **Step 2: Write the failing connector tests**

Create `internal/credentials/gcp_sa_rotator_test.go`:

```go
package credentials

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	iam "google.golang.org/api/iam/v1"
)

// staticVaultGCP satisfies vaultUser with a fixed admin SA-key JSON.
type staticVaultGCP struct{ val []byte }

func (s staticVaultGCP) Use(context.Context, string) ([]byte, error) {
	return append([]byte(nil), s.val...), nil
}

// fakeGCPKeyAPI is an injectable gcpKeyAPI.
type fakeGCPKeyAPI struct {
	keys       []*iam.ServiceAccountKey
	createErr  error
	deleted    []string
	createName string
}

func (f *fakeGCPKeyAPI) ListKeys(context.Context, string) ([]*iam.ServiceAccountKey, error) {
	return f.keys, nil
}
func (f *fakeGCPKeyAPI) CreateKey(context.Context, string) (*iam.ServiceAccountKey, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	name := f.createName
	if name == "" {
		name = "projects/p/serviceAccounts/sa@p.iam.gserviceaccount.com/keys/NEW"
	}
	keyFile, _ := json.Marshal(map[string]string{
		"type": "service_account", "client_email": "sa@p.iam.gserviceaccount.com", "private_key_id": "NEW",
	})
	return &iam.ServiceAccountKey{
		Name:           name,
		KeyType:        "USER_MANAGED",
		PrivateKeyData: base64.StdEncoding.EncodeToString(keyFile),
		ValidAfterTime: "2026-07-07T00:00:00Z",
	}, nil
}
func (f *fakeGCPKeyAPI) DeleteKey(_ context.Context, name string) error {
	f.deleted = append(f.deleted, name)
	return nil
}

func adminSAJSON() []byte {
	b, _ := json.Marshal(map[string]string{
		"type": "service_account", "client_email": "admin@p.iam.gserviceaccount.com", "private_key": "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n",
	})
	return b
}

func newTestGCPRotator(api *fakeGCPKeyAPI, check func(context.Context, []byte) error) *gcpSARotator {
	r := &gcpSARotator{vault: staticVaultGCP{val: adminSAJSON()}}
	r.newAPI = func(context.Context, []byte) (gcpKeyAPI, error) { return api, nil }
	r.check = check
	r.verifyRetries = 3
	r.verifyDelay = 0
	return r
}

func gcpCfg() map[string]any {
	return map[string]any{"service_account_email": "sa@p.iam.gserviceaccount.com", "admin_secret_id": "sec-admin"}
}

func okCheck(context.Context, []byte) error { return nil }

func TestGCPSA_MintReturnsDecodedKeyJSON(t *testing.T) {
	f := &fakeGCPKeyAPI{}
	r := newTestGCPRotator(f, okCheck)
	val, err := r.Mint(context.Background(), gcpCfg())
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	var kf map[string]string
	if err := json.Unmarshal(val, &kf); err != nil {
		t.Fatalf("Mint returned non-JSON key file: %v (%s)", err, val)
	}
	if kf["type"] != "service_account" || kf["private_key_id"] != "NEW" {
		t.Errorf("minted key = %v, want the newly created SA key file", kf)
	}
}

func TestGCPSA_MintDeletesOldestAtLimit(t *testing.T) {
	keys := make([]*iam.ServiceAccountKey, 0, 10)
	for i := 0; i < 10; i++ {
		vat := "2026-07-0" + string(rune('1'+i%9)) + "T00:00:00Z"
		keys = append(keys, &iam.ServiceAccountKey{
			Name: "projects/p/serviceAccounts/sa/keys/K" + string(rune('0'+i)), KeyType: "USER_MANAGED", ValidAfterTime: vat,
		})
	}
	// Make K0 unambiguously the oldest.
	keys[0].ValidAfterTime = "2020-01-01T00:00:00Z"
	f := &fakeGCPKeyAPI{keys: keys}
	r := newTestGCPRotator(f, okCheck)
	if _, err := r.Mint(context.Background(), gcpCfg()); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if len(f.deleted) != 1 || f.deleted[0] != "projects/p/serviceAccounts/sa/keys/K0" {
		t.Errorf("deleted = %v, want [K0] (oldest, to make room at the 10-key limit)", f.deleted)
	}
}

func TestGCPSA_VerifyRetriesThenSucceeds(t *testing.T) {
	calls := 0
	check := func(context.Context, []byte) error {
		calls++
		if calls <= 2 {
			return errors.New("key not yet propagated")
		}
		return nil
	}
	r := newTestGCPRotator(&fakeGCPKeyAPI{}, check)
	if err := r.Verify(context.Background(), gcpCfg(), []byte(`{"type":"service_account"}`)); err != nil {
		t.Fatalf("Verify should succeed after retries: %v", err)
	}
	if calls != 3 {
		t.Errorf("check calls = %d, want 3 (2 fail + 1 ok)", calls)
	}
}

func TestGCPSA_VerifyFailsAfterAllRetries(t *testing.T) {
	check := func(context.Context, []byte) error { return errors.New("always fails") }
	r := newTestGCPRotator(&fakeGCPKeyAPI{}, check)
	if err := r.Verify(context.Background(), gcpCfg(), []byte(`{}`)); err == nil {
		t.Fatal("Verify should fail when every attempt fails")
	}
}

func TestGCPSA_CleanupDeletesAllButNewestUserManaged(t *testing.T) {
	f := &fakeGCPKeyAPI{keys: []*iam.ServiceAccountKey{
		{Name: "keys/OLD", KeyType: "USER_MANAGED", ValidAfterTime: "2026-07-01T00:00:00Z"},
		{Name: "keys/NEW", KeyType: "USER_MANAGED", ValidAfterTime: "2026-07-07T00:00:00Z"},
		{Name: "keys/SYS", KeyType: "SYSTEM_MANAGED", ValidAfterTime: "2026-07-09T00:00:00Z"},
	}}
	r := newTestGCPRotator(f, okCheck)
	if err := r.Cleanup(context.Background(), gcpCfg()); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if len(f.deleted) != 1 || f.deleted[0] != "keys/OLD" {
		t.Errorf("deleted = %v, want [keys/OLD] (all USER_MANAGED but newest; never SYSTEM_MANAGED)", f.deleted)
	}
}

func TestGCPSA_ValidateConfig(t *testing.T) {
	r := &gcpSARotator{}
	if err := r.ValidateConfig(map[string]any{"admin_secret_id": "s"}); err == nil {
		t.Error("want error when service_account_email missing")
	}
	if err := r.ValidateConfig(map[string]any{"service_account_email": "e"}); err == nil {
		t.Error("want error when admin_secret_id missing")
	}
	if err := r.ValidateConfig(gcpCfg()); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}
```

- [ ] **Step 3: Run to verify it fails (types undefined)**

Run: `cd /home/cmit/openidx && go test ./internal/credentials/ -run TestGCPSA -v`
Expected: compile failure — `gcpSARotator`, `gcpKeyAPI` undefined.

- [ ] **Step 4: Implement `internal/credentials/gcp_sa_rotator.go`**

Match the real `google.golang.org/api/iam/v1` types (`go build` verifies). Full implementation:

```go
package credentials

// gcp_sa_rotator.go — GCP service-account key rotation connector.
//
// Manages a DEDICATED, rotation-managed service account's USER_MANAGED keys. Mirrors
// aws_iam_rotator.go: implements Minter (create a new SA key via the IAM API and return
// its JSON key file), Verify (obtain an access token from the new key, retried for
// propagation), PostRotateCleaner (delete all USER_MANAGED keys but the newest after
// promotion), and ConfigValidator. Apply is a no-op. The stored value is the new key
// FILE JSON (base64-decoded PrivateKeyData); the admin secret is an SA key file JSON.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/oauth2/google"
	iam "google.golang.org/api/iam/v1"
	"google.golang.org/api/option"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// gcpMaxKeys is GCP's per-service-account USER_MANAGED key limit.
const gcpMaxKeys = 10

// gcpKeyAPI is the subset of the IAM key API used by the connector, wrapped so tests
// can substitute a fake (the real *iam.Service uses builder-chain calls).
type gcpKeyAPI interface {
	ListKeys(ctx context.Context, saResource string) ([]*iam.ServiceAccountKey, error)
	CreateKey(ctx context.Context, saResource string) (*iam.ServiceAccountKey, error)
	DeleteKey(ctx context.Context, keyName string) error
}

// gcpSAConf holds the parsed, validated fields from a gcp_sa connector_config map.
type gcpSAConf struct {
	serviceAccountEmail string
	adminSecretID       string
}

// gcpSAConfigFromMap parses and validates a gcp_sa connector_config map.
// Required: service_account_email, admin_secret_id.
func gcpSAConfigFromMap(cfg map[string]any) (gcpSAConf, error) {
	str := func(key string) string {
		v, _ := cfg[key].(string)
		return v
	}
	email := str("service_account_email")
	adminSecretID := str("admin_secret_id")
	switch {
	case email == "":
		return gcpSAConf{}, fmt.Errorf("gcp_sa connector: missing required field %q", "service_account_email")
	case adminSecretID == "":
		return gcpSAConf{}, fmt.Errorf("gcp_sa connector: missing required field %q", "admin_secret_id")
	}
	return gcpSAConf{serviceAccountEmail: email, adminSecretID: adminSecretID}, nil
}

// gcpSARotator rotates a service account's keys. Implements Rotator, Minter,
// PostRotateCleaner, and ConfigValidator.
type gcpSARotator struct {
	vault         vaultUser
	newAPI        func(ctx context.Context, adminJSON []byte) (gcpKeyAPI, error)
	check         func(ctx context.Context, keyJSON []byte) error
	verifyRetries int
	verifyDelay   time.Duration
}

// NewGCPSARotator returns a Rotator (also Minter/PostRotateCleaner/ConfigValidator) that
// rotates a service account's keys via the GCP IAM API. vaultUser is satisfied by *vault.Service.
func NewGCPSARotator(v vaultUser) Rotator {
	return &gcpSARotator{
		vault:         v,
		newAPI:        realGCPKeyClient,
		check:         realGCPTokenCheck,
		verifyRetries: 6,
		verifyDelay:   3 * time.Second,
	}
}

func (r *gcpSARotator) Type() string { return "gcp_sa" }

// Apply is a no-op: the Minter path mints the key directly (already live on GCP).
func (r *gcpSARotator) Apply(_ context.Context, _ map[string]any, _ []byte) error { return nil }

// ValidateConfig returns an error if cfg is missing required fields.
func (r *gcpSARotator) ValidateConfig(cfg map[string]any) error {
	_, err := gcpSAConfigFromMap(cfg)
	return err
}

func saResource(email string) string { return "projects/-/serviceAccounts/" + email }

// admin fetches the admin SA-key JSON from the vault and lightly validates it. The caller
// must zero() the returned bytes after building the API client.
func (r *gcpSARotator) admin(ctx context.Context, conf gcpSAConf) ([]byte, error) {
	raw, err := r.vault.Use(orgctx.WithBypassRLS(ctx), conf.adminSecretID)
	if err != nil {
		return nil, fmt.Errorf("gcp_sa: fetch admin secret: %w", err)
	}
	var probe struct {
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		zero(raw)
		return nil, fmt.Errorf("gcp_sa: admin secret is not valid JSON: %w", err)
	}
	if probe.ClientEmail == "" || probe.PrivateKey == "" {
		zero(raw)
		return nil, fmt.Errorf("gcp_sa: admin secret missing client_email or private_key")
	}
	return raw, nil
}

// Mint creates a new key for the target SA and returns its decoded key-file JSON. If the SA
// is at the USER_MANAGED key limit, the oldest is deleted first to make room. The previously
// live key is NOT deleted here — Cleanup handles that after promotion.
func (r *gcpSARotator) Mint(ctx context.Context, cfg map[string]any) ([]byte, error) {
	conf, err := gcpSAConfigFromMap(cfg)
	if err != nil {
		return nil, err
	}
	adminRaw, err := r.admin(ctx, conf)
	if err != nil {
		return nil, err
	}
	defer zero(adminRaw)

	api, err := r.newAPI(ctx, adminRaw)
	if err != nil {
		return nil, fmt.Errorf("gcp_sa: build IAM client: %w", err)
	}
	res := saResource(conf.serviceAccountEmail)

	keys, err := api.ListKeys(ctx, res)
	if err != nil {
		return nil, fmt.Errorf("gcp_sa: list keys for %q: %w", conf.serviceAccountEmail, err)
	}
	userKeys := userManagedKeys(keys)
	if len(userKeys) >= gcpMaxKeys {
		if oldest := oldestGCPKey(userKeys); oldest != "" {
			if err := api.DeleteKey(ctx, oldest); err != nil {
				return nil, fmt.Errorf("gcp_sa: delete oldest key to make room: %w", err)
			}
		}
	}

	key, err := api.CreateKey(ctx, res)
	if err != nil {
		return nil, fmt.Errorf("gcp_sa: create key for %q: %w", conf.serviceAccountEmail, err)
	}
	dec, err := base64.StdEncoding.DecodeString(key.PrivateKeyData)
	if err != nil {
		return nil, fmt.Errorf("gcp_sa: decode new key data: %w", err)
	}
	return dec, nil
}

// Verify obtains an access token from the newly minted key, retrying to absorb propagation lag.
func (r *gcpSARotator) Verify(ctx context.Context, _ map[string]any, newValue []byte) error {
	var lastErr error
	for i := 0; i < r.verifyRetries; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("gcp_sa: verify cancelled: %w", ctx.Err())
			case <-time.After(r.verifyDelay):
			}
		}
		if err := r.check(ctx, newValue); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return fmt.Errorf("gcp_sa: verify: key not usable after %d attempts: %w", r.verifyRetries, lastErr)
}

// Cleanup deletes all USER_MANAGED keys for the target SA except the newest. Best-effort;
// invoked after the new credential is promoted.
func (r *gcpSARotator) Cleanup(ctx context.Context, cfg map[string]any) error {
	conf, err := gcpSAConfigFromMap(cfg)
	if err != nil {
		return err
	}
	adminRaw, err := r.admin(ctx, conf)
	if err != nil {
		return err
	}
	defer zero(adminRaw)

	api, err := r.newAPI(ctx, adminRaw)
	if err != nil {
		return fmt.Errorf("gcp_sa: build IAM client: %w", err)
	}
	keys, err := api.ListKeys(ctx, saResource(conf.serviceAccountEmail))
	if err != nil {
		return fmt.Errorf("gcp_sa: cleanup list keys: %w", err)
	}
	userKeys := userManagedKeys(keys)
	if len(userKeys) <= 1 {
		return nil
	}
	newest := newestGCPKey(userKeys)
	for _, k := range userKeys {
		if k.Name == newest {
			continue
		}
		if err := api.DeleteKey(ctx, k.Name); err != nil {
			return fmt.Errorf("gcp_sa: cleanup delete key %q: %w", k.Name, err)
		}
	}
	return nil
}

// userManagedKeys filters out Google SYSTEM_MANAGED keys (which cannot be deleted).
func userManagedKeys(keys []*iam.ServiceAccountKey) []*iam.ServiceAccountKey {
	out := make([]*iam.ServiceAccountKey, 0, len(keys))
	for _, k := range keys {
		if k != nil && k.KeyType != "SYSTEM_MANAGED" {
			out = append(out, k)
		}
	}
	return out
}

func gcpKeyTime(k *iam.ServiceAccountKey) time.Time {
	t, _ := time.Parse(time.RFC3339, k.ValidAfterTime) // zero on parse error
	return t
}

// oldestGCPKey returns the Name of the key with the earliest ValidAfterTime ("" if none).
func oldestGCPKey(keys []*iam.ServiceAccountKey) string {
	var name string
	var oldest time.Time
	for _, k := range keys {
		t := gcpKeyTime(k)
		if name == "" || t.Before(oldest) {
			name = k.Name
			oldest = t
		}
	}
	return name
}

// newestGCPKey returns the Name of the key with the latest ValidAfterTime ("" if none).
func newestGCPKey(keys []*iam.ServiceAccountKey) string {
	var name string
	var newest time.Time
	for _, k := range keys {
		t := gcpKeyTime(k)
		if name == "" || t.After(newest) {
			name = k.Name
			newest = t
		}
	}
	return name
}

// realGCPKeyClient builds a gcpKeyAPI backed by the google IAM service, authenticated with
// the admin SA-key JSON.
func realGCPKeyClient(ctx context.Context, adminJSON []byte) (gcpKeyAPI, error) {
	svc, err := iam.NewService(ctx, option.WithCredentialsJSON(adminJSON))
	if err != nil {
		return nil, err
	}
	return &realGCPKeyAPI{svc: svc}, nil
}

type realGCPKeyAPI struct{ svc *iam.Service }

func (a *realGCPKeyAPI) ListKeys(ctx context.Context, saResource string) ([]*iam.ServiceAccountKey, error) {
	resp, err := a.svc.Projects.ServiceAccounts.Keys.List(saResource).KeyTypes("USER_MANAGED").Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	return resp.Keys, nil
}

func (a *realGCPKeyAPI) CreateKey(ctx context.Context, saResource string) (*iam.ServiceAccountKey, error) {
	return a.svc.Projects.ServiceAccounts.Keys.Create(saResource, &iam.CreateServiceAccountKeyRequest{}).Context(ctx).Do()
}

func (a *realGCPKeyAPI) DeleteKey(ctx context.Context, keyName string) error {
	_, err := a.svc.Projects.ServiceAccounts.Keys.Delete(keyName).Context(ctx).Do()
	return err
}

// realGCPTokenCheck obtains an access token from an SA-key JSON to confirm it is usable.
func realGCPTokenCheck(ctx context.Context, keyJSON []byte) error {
	creds, err := google.CredentialsFromJSON(ctx, keyJSON, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return fmt.Errorf("gcp_sa: parse new key: %w", err)
	}
	tok, err := creds.TokenSource.Token()
	if err != nil {
		return fmt.Errorf("gcp_sa: obtain token from new key: %w", err)
	}
	if !tok.Valid() {
		return fmt.Errorf("gcp_sa: token from new key is not valid")
	}
	return nil
}
```

NOTE for the implementer: confirm the exact `iam.ServiceAccountKey` field names (`Name`, `KeyType`, `PrivateKeyData`, `ValidAfterTime`) and that `iam.NewService`/`option.WithCredentialsJSON`/`google.CredentialsFromJSON` match the installed module versions — `go build` is the check. `golang.org/x/oauth2/google` is provided by the existing `golang.org/x/oauth2` module.

- [ ] **Step 5: Run the connector tests**

Run: `cd /home/cmit/openidx && go test ./internal/credentials/ -run TestGCPSA -v`
Expected: all 6 PASS. Fix any type/field mismatch per the compiler.

- [ ] **Step 6: `go mod tidy` + full gates**

Run: `cd /home/cmit/openidx && go mod tidy && go build ./... && go vet ./internal/credentials/ && gofmt -l internal/credentials/ && go run ./tools/orgscope -fail ./internal/credentials && go test ./internal/credentials/`
Expected: all clean; `gofmt -l` prints nothing; orgscope passes.

- [ ] **Step 7: Commit**

```bash
cd /home/cmit/openidx
git add internal/credentials/gcp_sa_rotator.go internal/credentials/gcp_sa_rotator_test.go go.mod go.sum
git commit -m "feat(credentials): gcp_sa service-account key rotation connector (mocked-SDK tested)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Register the connector

**Files:**
- Modify: `cmd/admin-api/main.go` (the `rotators := []credentials.Rotator{ … }` slice)

- [ ] **Step 1: Add to the registry**

In `cmd/admin-api/main.go`, add after `credentials.NewAWSIAMRotator(vaultSvc),`:

```go
			credentials.NewGCPSARotator(vaultSvc),
```

- [ ] **Step 2: Build + tests**

Run: `cd /home/cmit/openidx && go build ./... && go test ./cmd/admin-api/ ./internal/credentials/`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
cd /home/cmit/openidx
git add cmd/admin-api/main.go
git commit -m "feat(admin-api): register gcp_sa rotation connector

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Admin-console UI

**Files:**
- Modify: `web/admin-console/src/pages/rotation-policies.tsx` (`connectorLabels`/`connectorColors`; `CONNECTOR_FIELDS`; `SCHEMA_CONNECTORS`; dropdown)
- Test: `web/admin-console/src/pages/rotation-policies.test.tsx`

- [ ] **Step 1: Failing UI test**

Add to `rotation-policies.test.tsx` (top-level `describe`, after the AWS IAM test):

```tsx
  it('GCP Service Account connector reveals its fields and builds connector_config on submit', async () => {
    const user = userEvent.setup()
    render(<RotationPoliciesPage />, { wrapper: createWrapper() })
    await screen.findByText('Rotation Policies')

    await user.click(screen.getByRole('button', { name: /new policy/i }))
    await screen.findByText('New Rotation Policy')

    await user.click(screen.getByTestId('secret-select'))
    await user.click(screen.getByRole('option', { name: 'prod-db-password' }))

    await user.click(screen.getByTestId('connector-select'))
    await user.click(screen.getByRole('option', { name: 'GCP Service Account' }))

    expect(screen.getByTestId('cc-service_account_email')).toBeInTheDocument()
    await user.type(screen.getByTestId('cc-service_account_email'), 'rotated@proj.iam.gserviceaccount.com')
    await user.click(screen.getByTestId('cc-admin_secret_id'))
    await user.click(screen.getByRole('option', { name: 'prod-db-password' }))

    await user.click(screen.getByRole('button', { name: /create policy/i }))

    await waitFor(() => {
      expect(vi.mocked(api.vault.createPolicy)).toHaveBeenCalledWith(
        expect.objectContaining({
          connector_type: 'gcp_sa',
          connector_config: expect.objectContaining({
            service_account_email: 'rotated@proj.iam.gserviceaccount.com',
            admin_secret_id: 'sec-1',
          }),
        }),
      )
    })
  })
```

- [ ] **Step 2: Run → fail**

Run: `cd /home/cmit/openidx/web/admin-console && npx vitest run src/pages/rotation-policies.test.tsx -t "GCP Service Account"`
Expected: FAIL (no GCP option).

- [ ] **Step 3: Add the connector to schema + dropdown + labels**

In `rotation-policies.tsx`:
(a) `connectorLabels`: add `gcp_sa: 'GCP Service Account',`
(b) `connectorColors`: add `gcp_sa: 'bg-red-100 text-red-800',`
(c) `CONNECTOR_FIELDS`: add
```tsx
  gcp_sa: [
    { key: 'service_account_email', label: 'Service account email', required: true, type: 'text', placeholder: 'rotated@proj.iam.gserviceaccount.com' },
    { key: 'admin_secret_id', label: 'Admin secret (GCP SA key JSON)', required: true, type: 'secret' },
  ],
```
(d) `SCHEMA_CONNECTORS`: add `'gcp_sa'`.
(e) Dropdown: add `<SelectItem value="gcp_sa">GCP Service Account</SelectItem>` after the AWS IAM item.

- [ ] **Step 4: Run page tests → pass + build**

Run: `cd /home/cmit/openidx/web/admin-console && npx vitest run src/pages/rotation-policies.test.tsx && npm run build`
Expected: all pass; tsc + vite clean.

- [ ] **Step 5: Commit**

```bash
cd /home/cmit/openidx
git add web/admin-console/src/pages/rotation-policies.tsx web/admin-console/src/pages/rotation-policies.test.tsx
git commit -m "feat(admin-console): GCP Service Account connector in rotation-policies UI

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review

**1. Spec coverage:** `Minter`/`Verify`/`Cleanup`/`Apply`-noop/`ValidateConfig` + config-from-map (Task 1); `gcpKeyAPI` interface + real adapter + token-check func, injectable for mocked tests (Task 1); USER_MANAGED filtering + 10-key-limit make-room + delete-all-but-newest (Task 1); base64-decode PrivateKeyData → stored value (Task 1 Mint); deps (Task 1); registration (Task 2); UI (Task 3); verification = mocked tests + no box smoke (called out). ✓

**2. Placeholder scan:** No TBD/TODO. The one explicit "confirm SDK field names against the module / `go build` is the check" note concerns external google API types the implementer build-verifies; all connector logic is complete code. ✓

**3. Type consistency:** `gcpSARotator` fields (`vault`,`newAPI`,`check`,`verifyRetries`,`verifyDelay`) match `newTestGCPRotator`; `gcpKeyAPI` method set (`ListKeys`/`CreateKey`/`DeleteKey`) matches the fake + real adapter; `gcpSAConfigFromMap` keys (`service_account_email`,`admin_secret_id`) match the UI `cc-*` testids and the test assertions; `NewGCPSARotator` used in Task 2 matches Task 1; `Type()`=="gcp_sa" matches the UI dropdown value + test. Helpers `userManagedKeys`/`oldestGCPKey`/`newestGCPKey`/`saResource`/`gcpKeyTime` defined and used consistently. ✓
