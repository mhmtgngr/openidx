# Populate ProxySession.DeviceTrusted from known_devices (devices slice D2) — design

## Context

`ProxySession.DeviceTrusted` is **never populated** — no session constructor sets it, so it is always `false`. The consequences, all in `internal/access`:

- `buildAccessContext` (`context_evaluator.go:65`) does `ac.DeviceTrusted = session.DeviceTrusted` → always false.
- `evaluateAccessContext` then (a) **always** adds +15 risk (`!ac.DeviceTrusted`), and (b) **always denies** any route with `RequireDeviceTrust` (`context_evaluator.go:157`).
- The G1 policy engine `/evaluate` call sends `"device_trusted": session.DeviceTrusted` (`service.go:2494`), so the `conditional_access` `device_trust_required` rule G1 just activated can **never** be satisfied.
- The inline-policy DSL's `DeviceTrusted` term (`policy_dsl.go`) is likewise always false.

So device-trust enforcement is dead across every path. D2 makes it real.

### What already exists (so D2 only consumes signals)

- **`known_devices.trusted`** (bool, keyed by `user_id` + `fingerprint`) is the authoritative per-device trust flag. Rows are **created at login** by the risk service (`internal/risk/service.go:119`, `internal/risk/device.go:244`) and portal — D2 does not register devices.
- The flag is flipped to `true` by the **already-wired** device-trust approval workflow in the identity service (`internal/identity/device_trust_approval.go`; routes `/device-trust-requests[/:id/approve|reject]` in `identity/service.go:3193-3195`). This is the "D3" work, largely already done.
- The device fingerprint is `risk.ComputeDeviceFingerprint(ip, ua)` = `sha256("<ip /24 subnet>|<userAgent>")`, a **pure function in the shared `internal/risk` package**. The access proxy has `ClientIP` and `UserAgent`, so it can compute the identical value and match `known_devices`.
- Device **posture** (`device_posture_results`, the D1 bridge) is a **separate** signal already feeding `ac.PostureScore` and its own check — intentionally distinct from the `trusted` flag. A policy can require both independently.

### Settled decisions

- **Definition:** `DeviceTrusted` = a `known_devices` row exists for `(user_id, computed fingerprint)` with `trusted = true`. Per-device (not per-user), and not combined with posture (kept separate).
- **Placement:** computed per-request in `buildAccessContext`, written back to the in-memory `session` so the single value feeds the context checks, the inline DSL, and the G1 `/evaluate` call (the same `session` pointer flows through all three: `buildAccessContext → evaluateAccessContext → evaluatePolicies`, and the handler already mutates `session.RiskScore` between them).

## Design

### 1. Share the fingerprint function (`internal/risk`)

Extract the body of `(*Service).ComputeDeviceFingerprint` (`internal/risk/service.go:78`) into a new package-level function `ComputeDeviceFingerprint(ipAddress, userAgent string) string` with the identical logic. The existing method becomes a one-line delegate `return ComputeDeviceFingerprint(ipAddress, userAgent)`. No behavior change; Go permits a package-level function and a method to share a name. This lets the access service compute the fingerprint without constructing a `risk.Service`.

### 2. Device-trust reader (access)

New file `internal/access/device_trust.go` with:

```go
func (s *Service) deviceTrusted(ctx context.Context, userID, ip, userAgent string) bool
```

- Returns `false` immediately if `userID` is empty.
- `fp := risk.ComputeDeviceFingerprint(ip, userAgent)`.
- `SELECT trusted FROM known_devices WHERE user_id=$1 AND fingerprint=$2 LIMIT 1`, scanning into a bool. Follow the data-plane convention used by the sibling posture query in `buildAccessContext` (an `//orgscope:ignore` comment explaining this is the already-authenticated session user, keyed by user_id + fingerprint).
- On `pgx.ErrNoRows` or any error: return `false` (absence ⇒ not trusted; safe default). Log non-ErrNoRows errors at `Warn`.

### 3. Wire into `buildAccessContext`

Replace `context_evaluator.go:65`:

```go
// Device trust from session
ac.DeviceTrusted = session.DeviceTrusted
```

with:

```go
// Device trust: is the request's device a trusted known_device?
trusted := s.deviceTrusted(ctx, session.UserID, ac.ClientIP, ac.UserAgent)
ac.DeviceTrusted = trusted
session.DeviceTrusted = trusted // propagates to the inline DSL and the G1 /evaluate call (sends session.DeviceTrusted)
```

`ac.ClientIP` and `ac.UserAgent` are already set earlier in `buildAccessContext`.

## Testing

- **`internal/risk`** (`service_test.go` or a focused test): the new package-level `ComputeDeviceFingerprint` returns the same value as the method for representative inputs; deterministic for identical inputs; two IPs in the same /24 collapse to the same fingerprint while a different /24 or different UA differs.
- **`internal/access`** (DB-backed, testcontainers — mirror the governance `setupTestDB` pattern; create a minimal `known_devices` table in the test): for a fixed `(userID, ip, ua)` whose fingerprint is computed via `risk.ComputeDeviceFingerprint`,
  - a seeded row with `trusted=true` → `deviceTrusted` returns `true`;
  - the same row with `trusted=false` → `false`;
  - no row → `false`;
  - empty `userID` → `false` (no query).

## Live verification (on the box)

1. Compute the fingerprint for an existing browser session (or read one of the two existing `known_devices` rows for the default admin user).
2. Flip that row to `trusted=true`.
3. Confirm the device is now treated as trusted — e.g. create a `conditional_access` policy with `device_trust_required` and a route carrying its `policy_id`, then a request from that device passes where it previously failed; or assert via `/evaluate` semantics. Flip the row back to `false` afterward (leave the box's data as found).

## Out of scope (follow-on)

- Persisting `DeviceTrusted` into the `proxy_sessions` table column read by `continuous_verify` (`continuous_verify.go`) — continuous re-verification still reads the stored column, which D2 does not write. Tracked as a separate follow-on; the primary forward-auth path is fully covered by the per-request computation.
- D3 (the device-trust approval workflow) — already built and wired in the identity service.
- Device auto-registration into `known_devices` — already handled by the risk service at login.
- Combining trust with posture — left to policy composition (the engine can require both).

## Verification checklist

- `go build ./...`, `go vet ./internal/access/... ./internal/risk/...` clean; `gofmt`.
- `go test ./internal/risk/ ./internal/access/` green, including the new fingerprint-equivalence and `deviceTrusted` tests.
- Live: flipping a `known_devices` row to `trusted=true` makes the matching device trusted on the forward-auth path; flipped back afterward.
