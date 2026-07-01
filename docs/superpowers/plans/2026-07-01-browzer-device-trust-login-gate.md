# Login-gated device trust for clientless (BrowZer) access — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`).

**Goal:** When enabled, refuse to complete an OIDC login destined for the clientless (BrowZer) client from an untrusted device, and file a device-trust request — the only enforceable point for device trust on the BrowZer data path.

**Architecture:** An opt-in config flag + a small testable gate helper + a hook in `oauth handleLogin` (right after `deviceTrusted` is computed) that reuses the existing `CreateDeviceTrustRequest` approval flow. Per-device, per-clientless-client (not per-route — see spec).

**Tech Stack:** Go, oauth service, `internal/common/config`, existing device-trust approval flow.

---

## Task 1: Opt-in config flag

**Files:** Modify `internal/common/config/config.go`; Test `internal/common/config/config_test.go`

Mirror the existing `apisix_edge_enabled` flag (field ~line 151, `SetDefault` ~492, env binding ~625).

- [ ] **Step 1: Add the struct field** near the other feature flags (e.g. after `APISIXEdgeEnabled`):

```go
	// RequireDeviceTrustForClientless gates clientless (BrowZer) OIDC logins on
	// device trust: an untrusted device is refused a BrowZer session and a
	// device-trust request is filed. Off by default (opt-in). Per-device, not
	// per-route (BrowZer's data path can't carry per-route device trust).
	RequireDeviceTrustForClientless bool `mapstructure:"require_device_trust_for_clientless"`
```

- [ ] **Step 2: Default + env binding.** Add near the other `SetDefault`s:
```go
	v.SetDefault("require_device_trust_for_clientless", false)
```
and in the env-binding map (with `"apisix_edge_enabled": "APISIX_EDGE_ENABLED"` etc.):
```go
		"require_device_trust_for_clientless": "OPENIDX_REQUIRE_DEVICE_TRUST_FOR_CLIENTLESS",
```

- [ ] **Step 3: Test the binding.** Add to `config_test.go` (mirror an existing env-binding test, e.g. `TestAPISIXEdgeEnvBindings`):
```go
func TestRequireDeviceTrustForClientlessBinding(t *testing.T) {
	saved := os.Getenv("OPENIDX_REQUIRE_DEVICE_TRUST_FOR_CLIENTLESS")
	dburl := os.Getenv("DATABASE_URL")
	defer func() {
		os.Setenv("OPENIDX_REQUIRE_DEVICE_TRUST_FOR_CLIENTLESS", saved)
		os.Setenv("DATABASE_URL", dburl)
	}()
	os.Setenv("DATABASE_URL", "postgres://localhost/test")

	os.Unsetenv("OPENIDX_REQUIRE_DEVICE_TRUST_FOR_CLIENTLESS")
	cfg, err := Load("test-service")
	require.NoError(t, err)
	assert.False(t, cfg.RequireDeviceTrustForClientless, "default must be false")

	os.Setenv("OPENIDX_REQUIRE_DEVICE_TRUST_FOR_CLIENTLESS", "true")
	cfg, err = Load("test-service")
	require.NoError(t, err)
	assert.True(t, cfg.RequireDeviceTrustForClientless)
}
```

- [ ] **Step 4:** `go test ./internal/common/config/ -run TestRequireDeviceTrustForClientlessBinding -v` → PASS. Commit.

## Task 2: `deviceTrustGateBlocks` helper (TDD)

**Files:** Modify `internal/oauth/service.go`; Test `internal/oauth/device_trust_gate_test.go` (create)

- [ ] **Step 1: Write the failing test** `internal/oauth/device_trust_gate_test.go`:

```go
package oauth

import (
	"testing"

	"github.com/openidx/openidx/internal/common/config"
)

func TestDeviceTrustGateBlocks(t *testing.T) {
	cases := []struct {
		name       string
		enabled    bool
		browzerID  string
		clientID   string
		trusted    bool
		wantBlock  bool
	}{
		{"feature off", false, "browzer-client", "browzer-client", false, false},
		{"clientless + untrusted", true, "browzer-client", "browzer-client", false, true},
		{"clientless + trusted", true, "browzer-client", "browzer-client", true, false},
		{"other client untrusted", true, "browzer-client", "admin-console", false, false},
		{"empty client", true, "browzer-client", "", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Service{config: &config.Config{
				RequireDeviceTrustForClientless: tc.enabled,
				BrowZerClientID:                 tc.browzerID,
			}}
			if got := s.deviceTrustGateBlocks(tc.clientID, tc.trusted); got != tc.wantBlock {
				t.Fatalf("deviceTrustGateBlocks(%q,%v)=%v want %v", tc.clientID, tc.trusted, got, tc.wantBlock)
			}
		})
	}
}
```

- [ ] **Step 2:** `go test ./internal/oauth/ -run TestDeviceTrustGateBlocks` → FAIL (`deviceTrustGateBlocks` undefined).

- [ ] **Step 3: Implement the helper** in `service.go` (near `handleLogin`):

```go
// deviceTrustGateBlocks reports whether a login must be blocked for clientless
// device trust: the feature is enabled, the login targets the clientless
// (BrowZer) client, and the device is not trusted. See the design doc — this is
// the only enforceable point for device trust on the BrowZer data path.
func (s *Service) deviceTrustGateBlocks(clientID string, deviceTrusted bool) bool {
	return s.config.RequireDeviceTrustForClientless &&
		clientID != "" && clientID == s.config.BrowZerClientID &&
		!deviceTrusted
}
```

- [ ] **Step 4:** `go test ./internal/oauth/ -run TestDeviceTrustGateBlocks -v` → PASS (all 5 cases). Commit.

## Task 3: Wire the gate into `handleLogin`

**Files:** Modify `internal/oauth/service.go` (`handleLogin`, inside the `s.riskService != nil` block, right after `deviceTrusted = s.riskService.IsDeviceTrusted(...)` at ~line 1729)

`parseBrowserNameFromUA(userAgent)` already exists (used at ~line 2143); `clientIP`, `userAgent`, `fingerprint`, `user`, `oauthParams` are all in scope here.

- [ ] **Step 1: Insert the gate** immediately after the `deviceTrusted` assignment (before `CalculateRiskScore`, so a blocked login exits early):

```go
		// Device-trust gate for clientless (BrowZer) access. BrowZer traffic
		// bypasses the proxy's forward-auth device-trust check, so the OIDC login
		// is the only place to enforce it. When enabled, an untrusted device
		// targeting the clientless client is refused a session and a trust
		// request is filed (dedups; auto-approves on known IP/corp device).
		if s.deviceTrustGateBlocks(oauthParams["client_id"], deviceTrusted) {
			req, derr := s.identityService.CreateDeviceTrustRequest(c.Request.Context(),
				user.ID, fingerprint, fingerprint, parseBrowserNameFromUA(userAgent),
				"browser", clientIP, userAgent,
				"clientless (BrowZer) access from an untrusted device")
			if derr == nil && req != nil && req.Status == "approved" {
				// Auto-approved (e.g. known corporate IP) → treat as trusted and
				// let the login proceed.
				deviceTrusted = true
			} else {
				s.logger.Warn("clientless login blocked: device not trusted",
					zap.String("user_id", user.ID),
					zap.String("client_id", oauthParams["client_id"]))
				c.JSON(403, gin.H{
					"error":             "device_not_trusted",
					"error_description": "This device must be approved before clientless access. An approval request has been filed; try again after an administrator approves it.",
				})
				return
			}
		}
```

- [ ] **Step 2: Build + vet.** `go build ./internal/oauth/ && go vet ./internal/oauth/` → clean. (If `parseBrowserNameFromUA` signature differs, adjust the call; confirm with `grep -n "func parseBrowserNameFromUA" internal/oauth/*.go`.)

- [ ] **Step 3: Confirm no regression** in the oauth suite: `go test ./internal/oauth/` → ok.

- [ ] **Step 4: Commit.**

## Task 4: Full verification

**Files:** none

- [ ] **Step 1:** `go build ./... && go vet ./internal/oauth/... ./internal/common/config/...`
- [ ] **Step 2:** `gofmt -l internal/oauth/service.go internal/oauth/device_trust_gate_test.go internal/common/config/config.go internal/common/config/config_test.go` (empty)
- [ ] **Step 3:** `go run ./tools/orgscope -fail ./internal` (no new SQL → clean)
- [ ] **Step 4:** `go test ./internal/oauth/... ./internal/common/config/...` → ok

## Self-review notes

- **Spec coverage:** flag → Task 1; helper + truth table → Task 2; handleLogin gate → Task 3; verification → Task 4.
- **Name consistency:** `RequireDeviceTrustForClientless` (config), `deviceTrustGateBlocks(clientID, deviceTrusted)`, `s.config.BrowZerClientID` — used identically across tasks. `req.Status == "approved"` matches `DeviceTrustRequest.Status`.
- **No new schema** (config flag, not a `device_trust_settings` column) → no migration / init-db parity concern.
- **Default off** → zero behavior change until an operator sets the env var.
