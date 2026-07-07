# GCP service-account key rotation connector

**Goal:** Add a `gcp_sa` PAM rotation connector that rotates a Google Cloud **service-account key**,
completing the cloud-IAM rotation pair (AWS shipped in v1.21.0 / #335). It reuses the engine "minter"
seam introduced for AWS — the provider mints the secret (`serviceAccounts.keys.create` returns the key
material), so it implements `Minter` + `PostRotateCleaner`, not `Apply`.

**Verified current state (2026-07-07):**
- Engine seam (`internal/credentials/rotator.go`): `Minter{Mint(ctx,cfg)([]byte,error)}` (engine uses the
  returned bytes as the candidate, skips `Apply`, still runs `Verify`) + `PostRotateCleaner{Cleanup(ctx,cfg)}`
  (called from `RotateSecret` only after a successful promote, warn-logged best-effort).
- **Template:** `internal/credentials/aws_iam_rotator.go` — struct holds `vault vaultUser` + injectable
  client factories (`newIAM`/`newSTS`) + `verifyRetries`/`verifyDelay`; `New…Rotator(v vaultUser) Rotator`;
  `Type`/`Apply`(no-op)/`ValidateConfig`/`admin`(resolve+parse admin creds from vault)/`Mint`/`Verify`
  (retry loop)/`Cleanup`. AWS calls sit behind small interfaces (`iamAPI`/`stsAPI`) → mocked-SDK tests.
- Registered in `cmd/admin-api/main.go` `rotators` slice. UI schema in `rotation-policies.tsx`
  (`CONNECTOR_FIELDS`/`SCHEMA_CONNECTORS`/dropdown/`connectorLabels`/`connectorColors`).
- **`golang.org/x/oauth2 v0.36.0` is already a direct dep** (its `/google` subpackage does the verify
  token-mint). **`google.golang.org/api` is NOT yet a dep** — this PR adds `google.golang.org/api/iam/v1`
  + `google.golang.org/api/option`.
- **No GCP creds on the box** → verified by **mocked unit tests only**, no live smoke (same as AWS).

## Design (mirror aws_iam, for GCP)

### Connector `internal/credentials/gcp_sa_rotator.go`
Rotates the **USER_MANAGED** keys of a single, dedicated service account.

**Config (`gcpSAConfigFromMap`):**
- `service_account_email` (required) — the target SA, e.g. `rotated@proj.iam.gserviceaccount.com`.
- `admin_secret_id` (required) — vault secret holding the **admin** GCP SA key JSON (the standard
  `{"type":"service_account","private_key":…,"client_email":…,…}` key file) for a principal with
  `iam.serviceAccountKeys.{list,create,delete}` on the target SA.

The GCP IAM key API keys off the resource name `projects/-/serviceAccounts/<email>` (the `-` project
wildcard resolves via the email), so no separate project field is needed.

**Stored/rotated secret value** = the target SA's **new key file JSON** (base64-decoded from the API's
`PrivateKeyData`), directly usable by a consumer as GOOGLE_APPLICATION_CREDENTIALS.

**Testability (mirror AWS interface-injection):** define narrow interfaces the connector calls, with a
real adapter over the google client and fakes in tests (the raw `*iam.Service` uses builder chains
`.Context().Do()`, so wrap them):
```go
type gcpKeyAPI interface {
    ListKeys(ctx context.Context, saResource string) ([]*iam.ServiceAccountKey, error)   // USER_MANAGED only
    CreateKey(ctx context.Context, saResource string) (*iam.ServiceAccountKey, error)
    DeleteKey(ctx context.Context, keyName string) error
}
type gcpTokenChecker interface {
    CheckKey(ctx context.Context, keyJSON []byte) error // obtains an access token from the new key
}
// gcpSARotator{ vault vaultUser; newAPI func(adminJSON []byte) (gcpKeyAPI, error); check gcpTokenChecker; verifyRetries int; verifyDelay time.Duration }
// NewGCPSARotator wires the real iam.NewService adapter + a google.CredentialsFromJSON token checker.
```

- **`Mint(ctx,cfg)`**: resolve admin key JSON from vault → `newAPI(adminJSON)` → `ListKeys(saResource)`;
  if at the GCP 10-key limit, `DeleteKey` the oldest USER_MANAGED (by `ValidAfterTime`) to make room →
  `CreateKey(saResource)` → base64-decode `PrivateKeyData` → return the key-file JSON bytes. Does NOT
  delete the previously-live key here.
- **`Verify(ctx,cfg,newValue)`**: `check.CheckKey(ctx, newValue)` — obtain an access token from the new
  key JSON (`google.CredentialsFromJSON` + `TokenSource.Token()`), retrying `verifyRetries` times with
  `verifyDelay` (respect ctx.Done()) to absorb key-propagation lag. Success proves the minted key is live.
- **`Cleanup(ctx,cfg)`**: resolve admin → `ListKeys` → `DeleteKey` every USER_MANAGED key except the
  newest (by `ValidAfterTime`). Best-effort; retires the superseded key post-promote.
- **`Apply`**: no-op returning nil (never called — Minter path). **`Type()`** = `"gcp_sa"`.
  **`ValidateConfig`** delegates to `gcpSAConfigFromMap` (→ `ConfigValidator`, so `CreatePolicy` accepts it).
- **Secrets hygiene** (mirror AWS): `defer zero(raw)` the admin bytes; never log the key material;
  the admin/new-key JSON are Go strings/bytes handed to the google libs (document as with AWS).

### Registration + deps
- `cmd/admin-api/main.go`: add `credentials.NewGCPSARotator(vaultSvc)` to `rotators`.
- `go.mod`: add `google.golang.org/api/iam/v1` + `google.golang.org/api/option`; `golang.org/x/oauth2/google`
  is already available via the existing `golang.org/x/oauth2`. `go mod tidy`.

### UI (`rotation-policies.tsx`)
- `CONNECTOR_FIELDS.gcp_sa`: `service_account_email` (text, required), `admin_secret_id` (secret, required).
- Add `gcp_sa` to `SCHEMA_CONNECTORS`, a `<SelectItem value="gcp_sa">GCP Service Account</SelectItem>`,
  and `connectorLabels`/`connectorColors` entries.

## Testing / verification
- **Go (mocked, no network):** inject fake `gcpKeyAPI` + `gcpTokenChecker`. Cases: Mint creates a key and
  returns the base64-decoded key JSON; Mint deletes the oldest when at the 10-key limit; Cleanup deletes
  all-but-newest USER_MANAGED (and never a SYSTEM_MANAGED key); Verify retries on a transient
  token-mint error then succeeds, and fails after exhausting retries; `gcpSAConfigFromMap` rejects
  missing `service_account_email`/`admin_secret_id`.
- `go build ./... && go vet ./internal/credentials/ && gofmt -l && go run ./tools/orgscope -fail ./internal/credentials && go test ./internal/credentials/`.
- **UI:** extend `rotation-policies.test.tsx` — selecting "GCP Service Account" reveals
  `service_account_email` + the admin-secret picker and submit builds `connector_type:'gcp_sa'` config.
  `npm run build` + vitest.
- **No box smoke** (no GCP creds) — call this out in the PR/release, as with AWS.

## Scope / risk
- Single PR (backend connector + registration + Go tests + go.mod + UI), mirroring the AWS PR shape.
  Additive: reuses the existing engine seam; existing connectors untouched. No migration.
- New dep `google.golang.org/api` (moderate). Documented constraint: the target SA must be **dedicated**
  to rotation (Cleanup deletes all its USER_MANAGED keys except the newest).
- Out of scope: rotating keys for >1 SA per policy; Workload Identity Federation (keyless) — a separate,
  larger initiative; a `project` override field (the `projects/-/…` wildcard suffices).

## Resolved at investigation
1. Reuse the AWS `Minter`/`PostRotateCleaner` seam verbatim — GCP is a second connector, no engine change.
2. `golang.org/x/oauth2` is already a dep (verify token-mint); only `google.golang.org/api` is new.
3. Interface-wrap the google IAM client (builder-chain methods) behind `gcpKeyAPI` + a `gcpTokenChecker`
   so the connector is fully mock-tested without network — matching the AWS approach and the "mock-only"
   verification reality (no cloud creds on the box).
