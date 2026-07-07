# AWS IAM access-key rotation connector

**Goal:** Add an `aws_iam` PAM rotation connector that rotates an IAM user's access keys — the last
deferred M5 connector (AWS-only this pass; GCP follows on the same seam). Because the provider **mints**
the secret (AWS `CreateAccessKey` returns the new key material), this needs a new engine seam: the
existing `Rotator` contract is "engine generates a value → `Apply(newValue)`", which fits neither
`Generate(gp)` (no ctx/cfg) nor `Apply` (can't return the minted value).

**Verified current state (2026-07-07):**
- Engine flow (`internal/credentials/engine.go` `runRotation`, ~line 83): generate (`ValueGenerator` or
  `generateSecret`) → `AddCandidateVersion` → `Apply` → `Verify` → `PromoteVersion`.
- Connector pattern (`ssh_key_rotator.go` etc.): a struct holding `vault vaultUser`
  (`Use(ctx, secretID) ([]byte, error)`); `New…Rotator(v vaultUser) Rotator`; `Type`/`Apply`/`Verify`
  (+ optional `ValueGenerator.Generate`, `ConfigValidator.ValidateConfig`); config parsed from
  `map[string]any` via a `…ConfigFromMap` helper; admin creds resolved via
  `r.vault.Use(orgctx.WithBypassRLS(ctx), cfg.adminSecretID)`.
- Registration: `cmd/admin-api/main.go` `rotators := []credentials.Rotator{ … }`.
- UI: `web/admin-console/src/pages/rotation-policies.tsx` `CONNECTOR_FIELDS` schema + `SCHEMA_CONNECTORS`
  + dropdown + `connectorLabels`/`connectorColors` (shipped v1.19.0).
- **No AWS SDK in `go.mod`.** No cloud creds on the box → this connector is verified by **mocked-SDK
  unit tests only**, no live box smoke.

## Design

### 1. Engine seam — `Minter` + `PostRotateCleaner` (`internal/credentials/rotator.go` + `engine.go`)
Two new **optional** interfaces (connectors that don't implement them are unaffected):

```go
// Minter lets a connector mint the new credential on the target itself and return it, for
// providers that generate the secret material (cloud IAM keys). When a Rotator also implements
// Minter, runRotation calls Mint instead of the generate-value path, uses the returned bytes as
// the candidate version, and does NOT call Apply. Verify still runs.
type Minter interface {
    Mint(ctx context.Context, cfg map[string]any) ([]byte, error)
}

// PostRotateCleaner is called best-effort AFTER a candidate is promoted, to retire the superseded
// credential on the target (e.g. delete the old IAM access key). Cleanup errors are logged and do
// NOT fail the rotation — the new credential is already live and promoted.
type PostRotateCleaner interface {
    Cleanup(ctx context.Context, cfg map[string]any) error
}
```

`runRotation` changes (minimal, preserves all existing behavior):
```go
minter, isMinter := r.(Minter)
if isMinter {
    newValue, err = minter.Mint(ctx, cfg)
} else if g, ok := r.(ValueGenerator); ok {
    newValue, err = g.Generate(gp)
} else {
    newValue, err = generateSecret(gp)
}
if err != nil { return "failed", false, 0 }
defer zero(newValue)

candidate, err := v.AddCandidateVersion(ctx, secretID, newValue, "")
if err != nil { return "failed", false, 0 }

if !isMinter {                    // minted creds are already applied by the provider
    if err := r.Apply(ctx, cfg, newValue); err != nil { return "failed", false, candidate }
}
if err := r.Verify(...); err != nil && !errors.Is(err, ErrVerifyUnsupported) {
    return "failed", false, candidate
}
if err := v.PromoteVersion(ctx, secretID, candidate); err != nil { return "failed", false, candidate }

if c, ok := r.(PostRotateCleaner); ok {
    if err := c.Cleanup(ctx, cfg); err != nil { /* engine's caller logs via the returned status; see note */ }
}
return "succeeded", true, candidate
```
`runRotation` is DB-free and returns a status triple; it has no logger. Cleanup errors are surfaced by
returning them through a new best-effort channel: `runRotation` gains a `cleanupErr error` return (or,
simpler, the caller `RotateSecret` invokes `PostRotateCleaner` after a promoted result and logs via
`s.logger`). **Decision:** do the Cleanup call in `RotateSecret` (which has `s.logger`), right after a
`promoted == true` result, so `runRotation` stays pure and the error is logged, not swallowed silently.

**Safety rationale:** Cleanup runs only after promote, so a failed verify/promote never deletes the live
old key. The new key is minted and promoted before the old one is retired.

### 2. `aws_iam` connector (`internal/credentials/aws_iam_rotator.go`)
Rotates the access keys of a single IAM user. **The target IAM user must be dedicated to
rotation** (OpenIDX owns all its access keys) — documented; Cleanup deletes every access key except the
newest. Config (`awsIAMConfigFromMap`):
- `target_user` (required) — the IAM username whose keys rotate.
- `admin_secret_id` (required) — vault secret holding the **admin** AWS creds as JSON
  `{"access_key_id":"…","secret_access_key":"…"}` (a principal with
  `iam:ListAccessKeys/CreateAccessKey/DeleteAccessKey` on the target user).
- `region` (optional, default `us-east-1`) — SDK region (IAM is global but the SDK needs one).

Stored/rotated secret **value** = JSON `{"access_key_id":"…","secret_access_key":"…"}` (same shape as
the admin secret, so a rotated key can itself later serve as an admin credential).

Testability: the AWS calls used are factored behind a tiny interface so tests inject a fake (no network):
```go
type iamAPI interface {
    ListAccessKeys(ctx, *iam.ListAccessKeysInput, ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
    CreateAccessKey(ctx, *iam.CreateAccessKeyInput, ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error)
    DeleteAccessKey(ctx, *iam.DeleteAccessKeyInput, ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error)
}
type stsAPI interface {
    GetCallerIdentity(ctx, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}
// awsIAMRotator has: vault vaultUser; newIAM func(region string, creds awsCreds) iamAPI; newSTS func(region string, creds awsCreds) stsAPI
// New…Rotator wires the real aws-sdk-go-v2 constructors; tests override newIAM/newSTS with fakes.
```

- **`Mint(ctx, cfg)`**: resolve admin creds from vault → build `iamAPI` → `ListAccessKeys(target_user)`;
  if already at the AWS max of 2, `DeleteAccessKey` on the **oldest** (`CreateDate`) to make room (a
  stale key from a prior cycle) → `CreateAccessKey(target_user)` → marshal
  `{access_key_id, secret_access_key}` JSON and return it. Does NOT delete the previously-live key here
  (that happens in Cleanup, post-promote).
- **`Verify(ctx, cfg, newValue)`**: parse the new key JSON → build `stsAPI` with the **new** creds →
  `GetCallerIdentity`. New IAM keys are eventually consistent, so retry a few times with a short backoff
  before failing. Success proves the minted key is live.
- **`Cleanup(ctx, cfg)`**: resolve admin creds → `ListAccessKeys(target_user)` → `DeleteAccessKey` every
  key except the newest (`CreateDate`) — retires the superseded key(s) after the new one is promoted.
- **`Apply`**: no-op returning nil (never called — `Minter` path skips it), documented as such.
- **`ValidateConfig(cfg)`**: `awsIAMConfigFromMap` parses/validates (required `target_user`,
  `admin_secret_id`; default `region`). Satisfies `ConfigValidator` so `CreatePolicy` accepts it.

### 3. Registration + deps
- `cmd/admin-api/main.go`: add `credentials.NewAWSIAMRotator(vaultSvc)` to the `rotators` slice.
- `go.mod`: add `github.com/aws/aws-sdk-go-v2/{config,credentials,service/iam,service/sts}` (+ transitive
  `aws-sdk-go-v2` core). `go mod tidy`.

### 4. Admin-console UI (`rotation-policies.tsx`)
- `CONNECTOR_FIELDS.aws_iam`: `target_user` (text, required), `admin_secret_id` (secret, required),
  `region` (text, optional, default `us-east-1`).
- Add `aws_iam` to `SCHEMA_CONNECTORS`, a dropdown `<SelectItem value="aws_iam">AWS IAM</SelectItem>`,
  and `connectorLabels`/`connectorColors` entries. (Reuses the v1.19.0 schema-driven rendering + tests.)

## Testing / verification
- **Engine (Go):** a fake `Rotator` implementing `Minter` (+ `PostRotateCleaner`) with an in-memory
  `candidateVault`, asserting: Mint value becomes the candidate; `Apply` is not called on the minter
  path; Verify failure blocks promote; Cleanup runs only after a successful promote and its error does
  not flip the status. Plus a regression test that a non-minter Rotator still follows generate→Apply.
- **AWS connector (Go):** inject fake `iamAPI`/`stsAPI`. Cases: Mint creates a key and returns valid JSON;
  Mint deletes the oldest when 2 keys exist; Verify calls STS with the new creds and retries on a
  transient error then succeeds; Cleanup deletes all-but-newest; `awsIAMConfigFromMap` rejects missing
  `target_user`/`admin_secret_id` and defaults `region`. No network.
- `go build ./... && go vet ./internal/credentials/ && gofmt -l && go test ./internal/credentials/…`.
- **UI:** extend `rotation-policies.test.tsx` — selecting AWS IAM reveals `target_user` + admin-secret
  picker and submit builds `connector_type: 'aws_iam'` config. `npm run build` + vitest.
- **No box smoke** (no AWS creds) — call this out in the PR and release notes; correctness rests on the
  mocked unit tests.

## Scope / risk
- Two PRs recommended: **(1) engine seam + AWS connector + registration + Go tests + go.mod**;
  **(2) UI dropdown + config fields + vitest.** Or one PR if preferred.
- Backend change is additive (new optional interfaces; existing connectors untouched). New SDK deps are
  modular (aws-sdk-go-v2 service clients). No migration, no schema change.
- Documented constraint: the target IAM user must be **dedicated** to rotation (Cleanup deletes all its
  access keys except the newest). Known limitation vs a post-promote hook alternative: Cleanup is
  best-effort; if it errors (logged), a stale old key may linger until the next cycle deletes it.
- Out of scope: GCP service-account keys (identical seam, follow-up); assuming an IAM **role** instead of
  static admin keys (could add `role_arn` later); rotating keys for more than one user per policy.

## Resolved at investigation
1. Provider-minted secrets need the new `Minter` seam; `PostRotateCleaner` (invoked from `RotateSecret`
   after promote, logged via `s.logger`) safely retires the old key without a destroy-before-promote risk.
2. Admin creds + the rotated value share the JSON `{access_key_id, secret_access_key}` shape, resolved
   via the existing `vaultUser.Use`.
3. Testability via injected `iamAPI`/`stsAPI` fakes — no network, matching the "mock-only" verification
   reality (no cloud creds on the box).
