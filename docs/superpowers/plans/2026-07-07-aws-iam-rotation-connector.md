# AWS IAM rotation connector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an `aws_iam` PAM rotation connector that rotates an IAM user's access keys, via a new engine "minter" seam (the provider mints the secret), verified by mocked-SDK unit tests.

**Architecture:** Two new optional engine interfaces — `Minter` (connector mints + returns the new value; engine skips `Apply`) and `PostRotateCleaner` (best-effort retire of the old credential, called after promote from `RotateSecret`). The `aws_iam` connector uses `aws-sdk-go-v2` IAM/STS behind small injectable interfaces so tests run without network. Then a UI dropdown entry (PR 2).

**Tech Stack:** Go 1.25, `aws-sdk-go-v2` (`aws`, `credentials`, `service/iam`, `service/sts`); the existing `credentials` engine; React/Vitest for the UI task.

**PR split:** Tasks 1-3 = PR 1 (backend). Task 4 = PR 2 (UI).

---

### Task 1: Engine `Minter` + `PostRotateCleaner` seam

**Files:**
- Modify: `internal/credentials/rotator.go` (add two interfaces)
- Modify: `internal/credentials/engine.go` (`runRotation` ~line 83-117; `RotateSecret` ~line 499)
- Test: `internal/credentials/engine_minter_test.go` (new)

- [ ] **Step 1: Write the failing engine test**

Create `internal/credentials/engine_minter_test.go`:

```go
package credentials

import (
	"context"
	"errors"
	"testing"
)

// fakeVault is an in-memory candidateVault.
type fakeVault struct {
	candidateVal []byte
	added        int
	promoted     int
}

func (f *fakeVault) AddCandidateVersion(_ context.Context, _ string, value []byte, _ string) (int, error) {
	f.added++
	f.candidateVal = append([]byte(nil), value...)
	return 7, nil
}
func (f *fakeVault) PromoteVersion(_ context.Context, _ string, version int) error {
	f.promoted = version
	return nil
}

// fakeMinter implements Rotator + Minter + PostRotateCleaner.
type fakeMinter struct {
	minted     []byte
	applyCalls int
	verifyErr  error
	cleaned    bool
}

func (m *fakeMinter) Type() string { return "fake_minter" }
func (m *fakeMinter) Apply(context.Context, map[string]any, []byte) error { m.applyCalls++; return nil }
func (m *fakeMinter) Verify(context.Context, map[string]any, []byte) error { return m.verifyErr }
func (m *fakeMinter) Mint(context.Context, map[string]any) ([]byte, error) {
	return append([]byte(nil), m.minted...), nil
}
func (m *fakeMinter) Cleanup(context.Context, map[string]any) error { m.cleaned = true; return nil }

func TestRunRotation_MinterPath(t *testing.T) {
	v := &fakeVault{}
	m := &fakeMinter{minted: []byte(`{"access_key_id":"AKIA","secret_access_key":"s3cr3t"}`)}

	status, promoted, ver := runRotation(context.Background(), "sec-1", m, v, GenerationPolicy{}, map[string]any{})

	if status != "succeeded" || !promoted || ver != 7 {
		t.Fatalf("got (%s, %v, %d), want (succeeded, true, 7)", status, promoted, ver)
	}
	if m.applyCalls != 0 {
		t.Errorf("Apply was called %d times on the minter path; want 0", m.applyCalls)
	}
	if string(v.candidateVal) != string(m.minted) {
		t.Errorf("candidate value = %q, want the minted value %q", v.candidateVal, m.minted)
	}
	if v.promoted != 7 {
		t.Errorf("promoted version = %d, want 7", v.promoted)
	}
}

func TestRunRotation_MinterVerifyFailureBlocksPromote(t *testing.T) {
	v := &fakeVault{}
	m := &fakeMinter{minted: []byte("x"), verifyErr: errors.New("sts denied")}

	status, promoted, ver := runRotation(context.Background(), "sec-1", m, v, GenerationPolicy{}, map[string]any{})

	if status != "failed" || promoted || ver != 7 {
		t.Fatalf("got (%s, %v, %d), want (failed, false, 7 candidate-exists)", status, promoted, ver)
	}
	if v.promoted != 0 {
		t.Errorf("promoted despite verify failure (version=%d)", v.promoted)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /home/cmit/openidx && go test ./internal/credentials/ -run TestRunRotation_Minter -v`
Expected: compile error / FAIL — `Mint` is not part of the flow yet (the fake compiles, but `runRotation` never calls `Mint`, so the candidate value won't equal the minted bytes and Apply is called).

- [ ] **Step 3: Add the two interfaces to `rotator.go`**

After the `ConfigValidator` interface block in `internal/credentials/rotator.go`, add:

```go
// Minter lets a connector mint the new credential on the target system itself and return it,
// for providers that generate the secret material (e.g. cloud IAM keys). When a Rotator also
// implements Minter, runRotation calls Mint instead of the generate-value path, uses the
// returned bytes as the candidate version, and does NOT call Apply. Verify still runs.
type Minter interface {
	Mint(ctx context.Context, cfg map[string]any) ([]byte, error)
}

// PostRotateCleaner is invoked best-effort AFTER a candidate is promoted, to retire the
// superseded credential on the target (e.g. delete the old IAM access key). Its error is
// logged but does NOT fail the rotation — the new credential is already live and promoted.
type PostRotateCleaner interface {
	Cleanup(ctx context.Context, cfg map[string]any) error
}
```

- [ ] **Step 4: Wire the minter path into `runRotation`**

In `internal/credentials/engine.go`, replace the value-generation + Apply portion of `runRotation` (the block from `var newValue []byte` through the `if err := r.Apply(...)` block, ~lines 84-107) with:

```go
	var newValue []byte
	var err error
	minter, isMinter := r.(Minter)
	switch {
	case isMinter:
		newValue, err = minter.Mint(ctx, cfg)
	default:
		if g, ok := r.(ValueGenerator); ok {
			newValue, err = g.Generate(gp)
		} else {
			newValue, err = generateSecret(gp)
		}
	}
	if err != nil {
		return "failed", false, 0
	}
	defer zero(newValue)

	// created_by is empty: rotation is a system action with no acting user, and
	// vault_secret_versions.created_by is a UUID column (AddCandidateVersion casts
	// it NULLIF($,'')::uuid), so a non-UUID marker like "rotation" would fail the
	// cast. Empty string → created_by = NULL.
	candidate, err := v.AddCandidateVersion(ctx, secretID, newValue, "")
	if err != nil {
		return "failed", false, 0
	}

	// Minted credentials are already live on the provider — skip Apply.
	if !isMinter {
		if err := r.Apply(ctx, cfg, newValue); err != nil {
			return "failed", false, candidate
		}
	}
```

(Leave the subsequent `Verify` → `PromoteVersion` → `return "succeeded"` lines unchanged.)

- [ ] **Step 5: Run the engine tests to verify they pass**

Run: `cd /home/cmit/openidx && go test ./internal/credentials/ -run 'TestRunRotation' -v`
Expected: PASS — including any pre-existing `runRotation` tests (non-minter Rotators still hit generate→Apply).

- [ ] **Step 6: Call `Cleanup` after a promoted rotation in `RotateSecret`**

In `internal/credentials/engine.go`, immediately after the `runRotation(...)` call (~line 499) and before the `// 7. Determine candidate version` block, add:

```go
	// 6a. Best-effort retire of the superseded credential (minter connectors). Runs only
	// after a successful promote, so a failed verify/promote never deletes the live old key.
	if promoted {
		if c, ok := rot.(PostRotateCleaner); ok {
			if cerr := c.Cleanup(orgCtx, p.ConnectorConfig); cerr != nil {
				s.logger.Warn("credentials: post-rotate cleanup failed (new credential is live; old may linger)",
					zap.String("policy_id", policyID),
					zap.String("connector_type", p.ConnectorType),
					zap.Error(cerr))
			}
		}
	}
```

(`zap` is already imported in engine.go — confirm; it is used by `s.logger` elsewhere in the file.)

- [ ] **Step 7: Build + vet + gofmt + full package test**

Run: `cd /home/cmit/openidx && go build ./... && go vet ./internal/credentials/ && gofmt -l internal/credentials/ && go test ./internal/credentials/`
Expected: build/vet clean, `gofmt -l` prints nothing, all tests pass.

- [ ] **Step 8: Commit**

```bash
cd /home/cmit/openidx
git add internal/credentials/rotator.go internal/credentials/engine.go internal/credentials/engine_minter_test.go
git commit -m "feat(credentials): Minter + PostRotateCleaner engine seam for provider-minted secrets

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: AWS IAM connector

**Files:**
- Create: `internal/credentials/aws_iam_rotator.go`
- Test: `internal/credentials/aws_iam_rotator_test.go`
- Modify: `go.mod` / `go.sum` (via `go mod tidy`)

- [ ] **Step 1: Add the AWS SDK dependencies**

Run:
```bash
cd /home/cmit/openidx
go get github.com/aws/aws-sdk-go-v2/service/iam@latest
go get github.com/aws/aws-sdk-go-v2/service/sts@latest
go get github.com/aws/aws-sdk-go-v2/credentials@latest
go get github.com/aws/aws-sdk-go-v2@latest
```
Expected: `go.mod` gains the `aws-sdk-go-v2` modules. (Network required — CI/box have it.)

- [ ] **Step 2: Write the failing connector tests**

Create `internal/credentials/aws_iam_rotator_test.go`. This defines fakes for the `iamAPI`/`stsAPI`
interfaces (defined in Step 3) and exercises Mint/Verify/Cleanup/config without network:

```go
package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// staticVault satisfies vaultUser with a fixed admin-cred JSON.
type staticVault struct{ val []byte }

func (s staticVault) Use(context.Context, string) ([]byte, error) {
	return append([]byte(nil), s.val...), nil
}

// fakeIAM is an injectable iamAPI.
type fakeIAM struct {
	keys        []iamtypes.AccessKeyMetadata
	created     *iamtypes.AccessKey
	deleted     []string
	createErr   error
}

func (f *fakeIAM) ListAccessKeys(context.Context, *iam.ListAccessKeysInput, ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	return &iam.ListAccessKeysOutput{AccessKeyMetadata: f.keys}, nil
}
func (f *fakeIAM) CreateAccessKey(_ context.Context, in *iam.CreateAccessKeyInput, _ ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	ak := &iamtypes.AccessKey{
		AccessKeyId:     aws.String("AKIANEW"),
		SecretAccessKey: aws.String("newsecret"),
		UserName:        in.UserName,
	}
	f.created = ak
	return &iam.CreateAccessKeyOutput{AccessKey: ak}, nil
}
func (f *fakeIAM) DeleteAccessKey(_ context.Context, in *iam.DeleteAccessKeyInput, _ ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error) {
	f.deleted = append(f.deleted, aws.ToString(in.AccessKeyId))
	return &iam.DeleteAccessKeyOutput{}, nil
}

// fakeSTS is an injectable stsAPI.
type fakeSTS struct {
	failN int // fail this many times before succeeding (eventual consistency)
	calls int
}

func (f *fakeSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	f.calls++
	if f.calls <= f.failN {
		return nil, errors.New("InvalidClientTokenId (eventual consistency)")
	}
	return &sts.GetCallerIdentityOutput{Account: aws.String("123456789012")}, nil
}

func adminJSON() []byte {
	b, _ := json.Marshal(awsCreds{AccessKeyID: "AKIAADMIN", SecretAccessKey: "adminsecret"})
	return b
}

func newTestRotator(iamFake *fakeIAM, stsFake *fakeSTS) *awsIAMRotator {
	r := &awsIAMRotator{vault: staticVault{val: adminJSON()}}
	r.newIAM = func(string, awsCreds) iamAPI { return iamFake }
	r.newSTS = func(string, awsCreds) stsAPI { return stsFake }
	// zero verify backoff in tests
	r.verifyRetries = 3
	r.verifyDelay = 0
	return r
}

func cfg() map[string]any {
	return map[string]any{"target_user": "svc-rotated", "admin_secret_id": "sec-admin", "region": "us-east-1"}
}

func TestAWSIAM_MintCreatesAndReturnsJSON(t *testing.T) {
	f := &fakeIAM{}
	r := newTestRotator(f, &fakeSTS{})
	val, err := r.Mint(context.Background(), cfg())
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	var got awsCreds
	if err := json.Unmarshal(val, &got); err != nil {
		t.Fatalf("Mint returned non-JSON: %v", err)
	}
	if got.AccessKeyID != "AKIANEW" || got.SecretAccessKey != "newsecret" {
		t.Errorf("minted creds = %+v, want the newly created key", got)
	}
}

func TestAWSIAM_MintDeletesOldestWhenTwoKeys(t *testing.T) {
	old := time.Now().Add(-48 * time.Hour)
	newer := time.Now().Add(-1 * time.Hour)
	f := &fakeIAM{keys: []iamtypes.AccessKeyMetadata{
		{AccessKeyId: aws.String("AKIAOLD"), CreateDate: &old},
		{AccessKeyId: aws.String("AKIANEWER"), CreateDate: &newer},
	}}
	r := newTestRotator(f, &fakeSTS{})
	if _, err := r.Mint(context.Background(), cfg()); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if len(f.deleted) != 1 || f.deleted[0] != "AKIAOLD" {
		t.Errorf("deleted = %v, want [AKIAOLD] (oldest, to make room)", f.deleted)
	}
}

func TestAWSIAM_VerifyRetriesThenSucceeds(t *testing.T) {
	s := &fakeSTS{failN: 2}
	r := newTestRotator(&fakeIAM{}, s)
	val, _ := json.Marshal(awsCreds{AccessKeyID: "AKIANEW", SecretAccessKey: "newsecret"})
	if err := r.Verify(context.Background(), cfg(), val); err != nil {
		t.Fatalf("Verify should succeed after retries: %v", err)
	}
	if s.calls != 3 {
		t.Errorf("STS calls = %d, want 3 (2 failures + 1 success)", s.calls)
	}
}

func TestAWSIAM_CleanupDeletesAllButNewest(t *testing.T) {
	oldest := time.Now().Add(-72 * time.Hour)
	newest := time.Now().Add(-1 * time.Hour)
	f := &fakeIAM{keys: []iamtypes.AccessKeyMetadata{
		{AccessKeyId: aws.String("AKIAOLD"), CreateDate: &oldest},
		{AccessKeyId: aws.String("AKIALIVE"), CreateDate: &newest},
	}}
	r := newTestRotator(f, &fakeSTS{})
	if err := r.Cleanup(context.Background(), cfg()); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if len(f.deleted) != 1 || f.deleted[0] != "AKIAOLD" {
		t.Errorf("deleted = %v, want [AKIAOLD] (all but newest)", f.deleted)
	}
}

func TestAWSIAM_ValidateConfig(t *testing.T) {
	r := &awsIAMRotator{}
	if err := r.ValidateConfig(map[string]any{"admin_secret_id": "s"}); err == nil {
		t.Error("want error when target_user missing")
	}
	if err := r.ValidateConfig(map[string]any{"target_user": "u"}); err == nil {
		t.Error("want error when admin_secret_id missing")
	}
	if err := r.ValidateConfig(cfg()); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd /home/cmit/openidx && go test ./internal/credentials/ -run TestAWSIAM -v`
Expected: compile failure — `awsIAMRotator`, `awsCreds`, `iamAPI`, `stsAPI` are undefined yet.

- [ ] **Step 4: Implement the connector**

Create `internal/credentials/aws_iam_rotator.go`. Match the real `aws-sdk-go-v2` types (build is the
verifier); the method-set below is the standard v2 client signature so `*iam.Client`/`*sts.Client`
satisfy `iamAPI`/`stsAPI`:

```go
package credentials

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscreds "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// awsCreds is the JSON shape of both the admin secret and the rotated value.
type awsCreds struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
}

// iamAPI / stsAPI are the minimal AWS surfaces the connector uses; *iam.Client and
// *sts.Client satisfy them, and tests inject fakes.
type iamAPI interface {
	ListAccessKeys(context.Context, *iam.ListAccessKeysInput, ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	CreateAccessKey(context.Context, *iam.CreateAccessKeyInput, ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error)
	DeleteAccessKey(context.Context, *iam.DeleteAccessKeyInput, ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error)
}
type stsAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// awsIAMConf is the parsed connector_config.
type awsIAMConf struct {
	targetUser    string
	adminSecretID string
	region        string
}

func awsIAMConfigFromMap(cfg map[string]any) (awsIAMConf, error) {
	str := func(k string) string { v, _ := cfg[k].(string); return v }
	c := awsIAMConf{
		targetUser:    str("target_user"),
		adminSecretID: str("admin_secret_id"),
		region:        str("region"),
	}
	if c.targetUser == "" {
		return awsIAMConf{}, fmt.Errorf("aws_iam connector: missing required field %q", "target_user")
	}
	if c.adminSecretID == "" {
		return awsIAMConf{}, fmt.Errorf("aws_iam connector: missing required field %q", "admin_secret_id")
	}
	if c.region == "" {
		c.region = "us-east-1"
	}
	return c, nil
}

// awsIAMRotator rotates the access keys of a dedicated, rotation-managed IAM user.
type awsIAMRotator struct {
	vault         vaultUser
	newIAM        func(region string, creds awsCreds) iamAPI
	newSTS        func(region string, creds awsCreds) stsAPI
	verifyRetries int
	verifyDelay   time.Duration
}

// NewAWSIAMRotator returns a Rotator (+ Minter, PostRotateCleaner, ConfigValidator) that rotates
// an IAM user's access keys using an admin credential resolved from the vault.
func NewAWSIAMRotator(v vaultUser) Rotator {
	return &awsIAMRotator{
		vault:         v,
		newIAM:        realIAMClient,
		newSTS:        realSTSClient,
		verifyRetries: 6,
		verifyDelay:   3 * time.Second,
	}
}

func awsConfig(region string, c awsCreds) aws.Config {
	return aws.Config{
		Region:      region,
		Credentials: awscreds.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, ""),
	}
}
func realIAMClient(region string, c awsCreds) iamAPI { return iam.NewFromConfig(awsConfig(region, c)) }
func realSTSClient(region string, c awsCreds) stsAPI { return sts.NewFromConfig(awsConfig(region, c)) }

func (r *awsIAMRotator) Type() string { return "aws_iam" }

func (r *awsIAMRotator) ValidateConfig(cfg map[string]any) error {
	_, err := awsIAMConfigFromMap(cfg)
	return err
}

// Apply is never called — the Minter path skips it (the key is minted live on AWS).
func (r *awsIAMRotator) Apply(context.Context, map[string]any, []byte) error { return nil }

// admin resolves and parses the admin AWS credential from the vault.
func (r *awsIAMRotator) admin(ctx context.Context, conf awsIAMConf) (awsCreds, error) {
	raw, err := r.vault.Use(orgctx.WithBypassRLS(ctx), conf.adminSecretID)
	if err != nil {
		return awsCreds{}, fmt.Errorf("aws_iam: resolve admin secret: %w", err)
	}
	defer zero(raw)
	var c awsCreds
	if err := json.Unmarshal(raw, &c); err != nil {
		return awsCreds{}, fmt.Errorf("aws_iam: admin secret is not {access_key_id,secret_access_key} JSON: %w", err)
	}
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return awsCreds{}, fmt.Errorf("aws_iam: admin secret missing access_key_id/secret_access_key")
	}
	return c, nil
}

// Mint deletes the oldest key if the user is already at AWS's 2-key limit, creates a new access
// key, and returns it as {access_key_id, secret_access_key} JSON. The previously-live key is
// retired later by Cleanup (post-promote).
func (r *awsIAMRotator) Mint(ctx context.Context, cfg map[string]any) ([]byte, error) {
	conf, err := awsIAMConfigFromMap(cfg)
	if err != nil {
		return nil, err
	}
	adm, err := r.admin(ctx, conf)
	if err != nil {
		return nil, err
	}
	cli := r.newIAM(conf.region, adm)

	list, err := cli.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: aws.String(conf.targetUser)})
	if err != nil {
		return nil, fmt.Errorf("aws_iam: list access keys: %w", err)
	}
	if len(list.AccessKeyMetadata) >= 2 {
		oldest := oldestKey(list.AccessKeyMetadata)
		if _, err := cli.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{
			UserName: aws.String(conf.targetUser), AccessKeyId: oldest,
		}); err != nil {
			return nil, fmt.Errorf("aws_iam: delete oldest key to make room: %w", err)
		}
	}
	out, err := cli.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: aws.String(conf.targetUser)})
	if err != nil {
		return nil, fmt.Errorf("aws_iam: create access key: %w", err)
	}
	val, err := json.Marshal(awsCreds{
		AccessKeyID:     aws.ToString(out.AccessKey.AccessKeyId),
		SecretAccessKey: aws.ToString(out.AccessKey.SecretAccessKey),
	})
	if err != nil {
		return nil, fmt.Errorf("aws_iam: marshal minted key: %w", err)
	}
	return val, nil
}

// Verify calls STS GetCallerIdentity with the newly-minted key, retrying to absorb IAM's
// eventual-consistency propagation delay.
func (r *awsIAMRotator) Verify(ctx context.Context, cfg map[string]any, newValue []byte) error {
	conf, err := awsIAMConfigFromMap(cfg)
	if err != nil {
		return err
	}
	var nk awsCreds
	if err := json.Unmarshal(newValue, &nk); err != nil {
		return fmt.Errorf("aws_iam: verify parse minted key: %w", err)
	}
	cli := r.newSTS(conf.region, nk)
	var lastErr error
	for i := 0; i < r.verifyRetries; i++ {
		if _, err := cli.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if r.verifyDelay > 0 {
			select {
			case <-time.After(r.verifyDelay):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return fmt.Errorf("aws_iam: verify GetCallerIdentity failed after %d attempts: %w", r.verifyRetries, lastErr)
}

// Cleanup deletes every access key on the target user except the newest — retiring the
// superseded key after the new one is promoted. Best-effort (engine logs errors).
func (r *awsIAMRotator) Cleanup(ctx context.Context, cfg map[string]any) error {
	conf, err := awsIAMConfigFromMap(cfg)
	if err != nil {
		return err
	}
	adm, err := r.admin(ctx, conf)
	if err != nil {
		return err
	}
	cli := r.newIAM(conf.region, adm)
	list, err := cli.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: aws.String(conf.targetUser)})
	if err != nil {
		return fmt.Errorf("aws_iam: cleanup list: %w", err)
	}
	keys := list.AccessKeyMetadata
	if len(keys) <= 1 {
		return nil
	}
	newest := newestKey(keys)
	for _, k := range keys {
		if aws.ToString(k.AccessKeyId) == aws.ToString(newest) {
			continue
		}
		if _, err := cli.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{
			UserName: aws.String(conf.targetUser), AccessKeyId: k.AccessKeyId,
		}); err != nil {
			return fmt.Errorf("aws_iam: cleanup delete %s: %w", aws.ToString(k.AccessKeyId), err)
		}
	}
	return nil
}

// oldestKey / newestKey pick access-key IDs by CreateDate. iam.types.AccessKeyMetadata is imported
// transitively via the iam package; use its AccessKeyId (*string) and CreateDate (*time.Time).
func oldestKey(keys []iamAccessKeyMeta) *string { return pickByDate(keys, false) }
func newestKey(keys []iamAccessKeyMeta) *string { return pickByDate(keys, true) }

func pickByDate(keys []iamAccessKeyMeta, newest bool) *string {
	sort.Slice(keys, func(i, j int) bool {
		ti, tj := time.Time{}, time.Time{}
		if keys[i].CreateDate != nil {
			ti = *keys[i].CreateDate
		}
		if keys[j].CreateDate != nil {
			tj = *keys[j].CreateDate
		}
		return ti.Before(tj)
	})
	if len(keys) == 0 {
		return nil
	}
	if newest {
		return keys[len(keys)-1].AccessKeyId
	}
	return keys[0].AccessKeyId
}
```

NOTE for the implementer: replace the placeholder alias `iamAccessKeyMeta` with the real type
`github.com/aws/aws-sdk-go-v2/service/iam/types.AccessKeyMetadata` (add the `iamtypes "…/service/iam/types"`
import and use `[]iamtypes.AccessKeyMetadata` in `oldestKey`/`newestKey`/`pickByDate`). The test file
already imports `iamtypes`. Confirm the exact field names (`AccessKeyId`, `CreateDate`, `SecretAccessKey`,
`AccessKeyId` on `types.AccessKey`) against the SDK — `go build`/`go vet` is the check.

- [ ] **Step 5: Run the connector tests**

Run: `cd /home/cmit/openidx && go test ./internal/credentials/ -run TestAWSIAM -v`
Expected: PASS all five. If a type/field name differs from the SDK, fix per the compiler and re-run.

- [ ] **Step 6: `go mod tidy` + full gates**

Run: `cd /home/cmit/openidx && go mod tidy && go build ./... && go vet ./internal/credentials/ && gofmt -l internal/credentials/ && go test ./internal/credentials/`
Expected: tidy resolves the AWS modules (they move from `// indirect` to direct as needed); build/vet/test clean; `gofmt -l` prints nothing.

- [ ] **Step 7: Commit**

```bash
cd /home/cmit/openidx
git add internal/credentials/aws_iam_rotator.go internal/credentials/aws_iam_rotator_test.go go.mod go.sum
git commit -m "feat(credentials): aws_iam access-key rotation connector (mocked-SDK tested)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Register the connector

**Files:**
- Modify: `cmd/admin-api/main.go` (the `rotators := []credentials.Rotator{ … }` slice)

- [ ] **Step 1: Add the connector to the registry**

In `cmd/admin-api/main.go`, add to the `rotators` slice (after `credentials.NewMySQLRotator(vaultSvc),`):

```go
			credentials.NewAWSIAMRotator(vaultSvc),
```

- [ ] **Step 2: Build + the admin-api main test fixtures**

Run: `cd /home/cmit/openidx && go build ./... && go test ./cmd/admin-api/ ./internal/credentials/`
Expected: clean. (Adding a rotator to the slice is additive; no `main_test.go` fixture asserts the exact rotator set — confirm the build + tests pass.)

- [ ] **Step 3: Commit**

```bash
cd /home/cmit/openidx
git add cmd/admin-api/main.go
git commit -m "feat(admin-api): register aws_iam rotation connector

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

*(Tasks 1-3 are PR 1. Open the PR after Task 3, noting: new engine seam + aws_iam connector, mocked-SDK tests only, NO box smoke — no AWS creds on the box.)*

---

### Task 4: Admin-console UI (PR 2)

**Files:**
- Modify: `web/admin-console/src/pages/rotation-policies.tsx` (`connectorLabels`/`connectorColors`; `CONNECTOR_FIELDS`; `SCHEMA_CONNECTORS`; dropdown `<SelectItem>`s)
- Test: `web/admin-console/src/pages/rotation-policies.test.tsx`

- [ ] **Step 1: Failing UI test**

Add to `rotation-policies.test.tsx` (top-level `describe`, after the SSH tests):

```tsx
  it('AWS IAM connector reveals its fields and builds connector_config on submit', async () => {
    const user = userEvent.setup()
    render(<RotationPoliciesPage />, { wrapper: createWrapper() })
    await screen.findByText('Rotation Policies')

    await user.click(screen.getByRole('button', { name: /new policy/i }))
    await screen.findByText('New Rotation Policy')

    await user.click(screen.getByTestId('secret-select'))
    await user.click(screen.getByRole('option', { name: 'prod-db-password' }))

    await user.click(screen.getByTestId('connector-select'))
    await user.click(screen.getByRole('option', { name: 'AWS IAM' }))

    expect(screen.getByTestId('cc-target_user')).toBeInTheDocument()
    await user.type(screen.getByTestId('cc-target_user'), 'svc-rotated')
    await user.click(screen.getByTestId('cc-admin_secret_id'))
    await user.click(screen.getByRole('option', { name: 'prod-db-password' }))

    await user.click(screen.getByRole('button', { name: /create policy/i }))

    await waitFor(() => {
      expect(vi.mocked(api.vault.createPolicy)).toHaveBeenCalledWith(
        expect.objectContaining({
          connector_type: 'aws_iam',
          connector_config: expect.objectContaining({
            target_user: 'svc-rotated',
            admin_secret_id: 'sec-1',
            region: 'us-east-1',
          }),
        }),
      )
    })
  })
```

- [ ] **Step 2: Run → fail**

Run: `cd /home/cmit/openidx/web/admin-console && npx vitest run src/pages/rotation-policies.test.tsx -t "AWS IAM"`
Expected: FAIL (no AWS IAM option).

- [ ] **Step 3: Add the connector to the schema + dropdown + labels**

In `rotation-policies.tsx`:
(a) `connectorLabels`: add `aws_iam: 'AWS IAM',`
(b) `connectorColors`: add `aws_iam: 'bg-yellow-100 text-yellow-800',`
(c) `CONNECTOR_FIELDS`: add
```tsx
  aws_iam: [
    { key: 'target_user', label: 'IAM user', required: true, type: 'text', placeholder: 'svc-rotated' },
    { key: 'admin_secret_id', label: 'Admin secret (AWS creds)', required: true, type: 'secret' },
    { key: 'region', label: 'Region', required: false, type: 'text', placeholder: 'us-east-1', default: 'us-east-1' },
  ],
```
(d) `SCHEMA_CONNECTORS`: add `'aws_iam'` to the array.
(e) Dropdown: add `<SelectItem value="aws_iam">AWS IAM</SelectItem>` after the MySQL item.

- [ ] **Step 4: Run the page tests → pass + build**

Run: `cd /home/cmit/openidx/web/admin-console && npx vitest run src/pages/rotation-policies.test.tsx && npm run build`
Expected: all pass; tsc + vite clean.

- [ ] **Step 5: Commit**

```bash
cd /home/cmit/openidx
git add web/admin-console/src/pages/rotation-policies.tsx web/admin-console/src/pages/rotation-policies.test.tsx
git commit -m "feat(admin-console): AWS IAM connector in rotation-policies UI

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review

**1. Spec coverage:** Minter + PostRotateCleaner seam (Task 1); AWS connector Mint/Verify/Cleanup/Apply-noop/ValidateConfig + config-from-map + injectable iamAPI/stsAPI + awsCreds JSON (Task 2); registration + go.mod deps (Tasks 2-3); UI dropdown/schema (Task 4); verification = mocked-SDK unit tests + no box smoke (called out). All covered. ✓

**2. Placeholder scan:** No TBD/TODO. The one deliberate placeholder alias `iamAccessKeyMeta` is explicitly flagged with instructions to replace it with `iamtypes.AccessKeyMetadata` (an external SDK type the implementer wires + build-verifies); every logic step has complete code. ✓

**3. Type consistency:** `awsCreds{AccessKeyID,SecretAccessKey}` used identically in connector + tests; `iamAPI`/`stsAPI` method signatures match `*iam.Client`/`*sts.Client`; `awsIAMRotator` fields (`vault`,`newIAM`,`newSTS`,`verifyRetries`,`verifyDelay`) match `newTestRotator`; `NewAWSIAMRotator` used in registration matches Task 3; `Minter`/`PostRotateCleaner` names consistent across engine + connector; UI `aws_iam` key + `cc-target_user`/`cc-admin_secret_id` testids match Task 4 test. ✓
