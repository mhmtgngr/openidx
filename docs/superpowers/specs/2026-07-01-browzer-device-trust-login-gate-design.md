# Login-gated device trust for clientless (BrowZer) access

## Context

Routes published with BrowZer (clientless) access — e.g. `netgraph` — carry a
`require_device_trust` flag, but it is **not enforced**: BrowZer traffic reaches
the upstream over the Ziti overlay and never traverses the access-proxy's
HTTP forward-auth (`handleAuthDecide` → `evaluateAccessContext`), which is the
only place `require_device_trust` is checked. So an untrusted device can use any
BrowZer app regardless.

Enforcing per-route device trust *inside* the BrowZer/Ziti data path is not
feasible (native Ziti posture is endpoint-reported OS/MAC/Process/Domain/MFA —
"device trusted" is an OpenIDX DB fact, not a Ziti posture; posture checks aren't
bound to service policies here; and a browser WASM isn't a posture-reporting
endpoint). The one point OpenIDX controls in the BrowZer flow is the **OIDC
login** — and `handleLogin` (`internal/oauth/service.go:1729`) **already computes
`deviceTrusted`** for the logging-in user+device. This spec gates clientless
access there.

**Enforcement model (from brainstorming, option A):** if a login destined for
the clientless (BrowZer) OAuth client comes from an untrusted device, refuse to
complete the login (no token → no BrowZer session), and file a device-trust
request for admin approval. This is a real boundary at the only controllable
point.

**Granularity (explicit trade-off, accepted):** the gate is **per-device**
(login is per-device/session) but **per-clientless-client, not per-route** —
BrowZer authenticates one global per-user JWT with no per-service claim gate, so
an untrusted device is gated for *all* clientless access, not just the routes
that set `require_device_trust`. Non-BrowZer reverse-proxy routes are unaffected
(their `require_device_trust` is already enforced via forward-auth).

## Design

### Component 1 — opt-in config flag

Add `RequireDeviceTrustForClientless bool` to `internal/common/config/config.go`
(mapstructure `require_device_trust_for_clientless`, env
`OPENIDX_REQUIRE_DEVICE_TRUST_FOR_CLIENTLESS`, **default `false`** so existing
clientless access is unchanged until an operator opts in). The clientless client
is identified by the existing `cfg.BrowZerClientID` (default `browzer-client`).

### Component 2 — the gate in `handleLogin`

In `internal/oauth/service.go` `handleLogin`, immediately after `deviceTrusted`
is computed (~line 1729, inside the `s.riskService != nil` block, so a fingerprint
exists), insert the gate:

```go
// Device-trust gate for clientless (BrowZer) access: BrowZer's data path
// bypasses the proxy's forward-auth device-trust check, so the login is the
// only place we can enforce it. If this login is destined for the clientless
// client and the device isn't trusted, refuse to complete it and file a
// trust request (per-device; not per-route — see design doc).
clientID := oauthParams["client_id"]
if s.deviceTrustGateBlocks(clientID, deviceTrusted) {
    // Best-effort: file a trust request (dedups; may auto-approve on known IP).
    var justification = "clientless (BrowZer) access from an untrusted device"
    req, derr := s.identityService.CreateDeviceTrustRequest(c.Request.Context(),
        user.ID, fingerprint /*deviceID*/, fingerprint, deviceName(userAgent),
        "browser", clientIP, userAgent, justification)
    if derr == nil && req != nil && req.Status == "approved" {
        // Auto-approved (e.g. known corporate IP) → allow login to proceed.
        deviceTrusted = true
    } else {
        s.logger.Warn("clientless login blocked: device not trusted",
            zap.String("user_id", user.ID), zap.String("client_id", clientID))
        c.JSON(403, gin.H{
            "error":             "device_not_trusted",
            "error_description": "This device must be approved before clientless access. An approval request has been filed; try again after an administrator approves it.",
        })
        return
    }
}
```

Where `deviceTrustGateBlocks` is a small, testable helper:

```go
// deviceTrustGateBlocks reports whether a login must be blocked for clientless
// device trust: the feature is enabled, the login targets the clientless
// (BrowZer) client, and the device is not trusted.
func (s *Service) deviceTrustGateBlocks(clientID string, deviceTrusted bool) bool {
    return s.config.RequireDeviceTrustForClientless &&
        clientID != "" && clientID == s.config.BrowZerClientID &&
        !deviceTrusted
}
```

`deviceName(userAgent)` is a tiny helper returning a human label (e.g. the UA's
browser/OS, or just `"browser"` if unparsed) — reuse an existing UA helper if one
exists, else a trivial fallback.

### Component 3 — reuse the existing trust-request + approval flow

`identityService.CreateDeviceTrustRequest` (already present) handles dedup (one
pending request per user+fingerprint), honors `device_trust_settings`
auto-approval (known IP / corporate device → returns `Status:"approved"`), and
sets expiry. Admin approval via the existing device-trust approval flow flips
`known_devices.trusted=true`; the next clientless login then finds
`deviceTrusted==true` and proceeds. No new approval machinery.

## Behaviour matrix

| flag | client_id | deviceTrusted | outcome |
|---|---|---|---|
| false | any | any | login proceeds (current behavior; feature off) |
| true | browzer-client | true | login proceeds |
| true | browzer-client | false | **403 device_not_trusted** + trust request filed (unless auto-approved → proceeds) |
| true | other (admin-console, reverse-proxy) | any | login proceeds (unaffected) |

## Out of scope (deliberate)

- Per-route device trust for BrowZer (architecturally infeasible — see Context).
- Enforcing device trust for non-BrowZer routes (already done via forward-auth).
- An admin-console UI toggle / per-org `device_trust_settings` column for the flag
  (config-flag now; a settings column is a possible follow-up — would need a
  migration + init-db parity).
- MFA/step-up as the remediation (we file a trust request instead, matching the
  existing device-trust approval model).

## Testing

- **Unit:** `deviceTrustGateBlocks` truth table (feature off; matching/non-matching
  client; trusted/untrusted) — pure, no DB. This pins the decision logic.
- **Unit (helper):** `deviceName` fallback.
- The full `handleLogin` path (403 + request filed; auto-approve → proceed) needs
  the oauth Service + risk/identity services; cover via the existing oauth
  integration/login tests if present, else rely on the unit-tested helper + build.
- `go build ./...`, `go vet`, `gofmt`, `go run ./tools/orgscope -fail ./internal`,
  `go test ./internal/oauth/... ./internal/common/config/...` green.
- (Live, after deploy with the flag on) an untrusted device's BrowZer login to
  netgraph returns `device_not_trusted` + a pending `device_trust_requests` row;
  after admin approval, login + clientless access succeed.

## Verification checklist

- [ ] `RequireDeviceTrustForClientless` config flag added (default false, env-bound).
- [ ] `deviceTrustGateBlocks` helper + unit test (truth table).
- [ ] `handleLogin` gate wired after `deviceTrusted` is computed; files a request;
  auto-approve proceeds, else 403 `device_not_trusted`.
- [ ] Non-clientless logins and the flag-off case are unaffected.
- [ ] build / vet / gofmt / orgscope / touched-package tests green.
