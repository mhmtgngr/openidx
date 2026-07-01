# Fix clientless device-trust SSO bypass (gate handleAuthorizeCallback) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`).

**Goal:** Enforce the clientless device-trust gate on the path BrowZer actually uses (`handleAuthorizeCallback`, the server-rendered login), fixing the #268 bypass.

**Architecture:** Add the same gate (reusing `deviceTrustGateBlocks`, `CreateDeviceTrustRequest`, the `RequireDeviceTrustForClientless` flag) into `handleAuthorizeCallback`, before the login-session delete + code generation; on block re-render the login page. One-file change + reuse of existing, already-tested helpers.

**Tech Stack:** Go, oauth service, existing risk/identity/device-trust flow.

---

## Task 1: Gate `handleAuthorizeCallback`

**Files:** Modify `internal/oauth/service.go` (`handleAuthorizeCallback`, between the country-block at ~1594 and the `login_session` delete at ~1597)

All referenced symbols already exist and are in scope here: `user` (from `AuthenticateUser`), `oauthParams`, `loginSession`, `s.riskService` (`ComputeDeviceFingerprint`/`RegisterDevice`/`IsDeviceTrusted`), `s.identityService.CreateDeviceTrustRequest`, `s.deviceTrustGateBlocks` (#268), `parseBrowserNameFromUA`, `s.renderLoginPage`, `zap`.

- [ ] **Step 1: Insert the gate.** Replace:

```go
	// Country-based login blocking
	if err := s.checkCountryBlock(c.Request.Context(), c.ClientIP(), user.ID, username); err != nil {
		s.renderLoginPage(c, loginSession, "Authentication is not available from your location.")
		return
	}

	// Clean up login session
	s.redis.Client.Del(c.Request.Context(), "login_session:"+loginSession)
```

with:

```go
	// Country-based login blocking
	if err := s.checkCountryBlock(c.Request.Context(), c.ClientIP(), user.ID, username); err != nil {
		s.renderLoginPage(c, loginSession, "Authentication is not available from your location.")
		return
	}

	// Device-trust gate for clientless (BrowZer) access. BrowZer's data path
	// bypasses the proxy's forward-auth device-trust check, and this
	// server-rendered login (POST /oauth/authorize/callback) — not the JSON
	// /oauth/login — is what the BrowZer public client uses, so this is the
	// enforcement point. Mirrors the handleLogin gate (#268). Placed before the
	// login_session is deleted so a blocked user can retry the same session.
	if s.riskService != nil {
		clientIP := c.ClientIP()
		userAgent := c.GetHeader("User-Agent")
		fingerprint := s.riskService.ComputeDeviceFingerprint(clientIP, userAgent)
		// Register the device so an approval has a known_devices row to flip.
		_, _, _ = s.riskService.RegisterDevice(c.Request.Context(), user.ID, fingerprint, clientIP, userAgent, "")
		deviceTrusted := s.riskService.IsDeviceTrusted(c.Request.Context(), user.ID, fingerprint)
		if s.deviceTrustGateBlocks(oauthParams["client_id"], deviceTrusted) {
			req, derr := s.identityService.CreateDeviceTrustRequest(c.Request.Context(),
				user.ID, fingerprint, fingerprint, parseBrowserNameFromUA(userAgent),
				"browser", clientIP, userAgent,
				"clientless (BrowZer) access from an untrusted device")
			if !(derr == nil && req != nil && req.Status == "approved") {
				s.logger.Warn("clientless login blocked: device not trusted",
					zap.String("user_id", user.ID),
					zap.String("client_id", oauthParams["client_id"]))
				s.renderLoginPage(c, loginSession,
					"This device must be approved before clientless access. An approval request has been filed; try again after an administrator approves it.")
				return
			}
			// Auto-approved (e.g. known corporate IP) → fall through and issue the code.
		}
	}

	// Clean up login session
	s.redis.Client.Del(c.Request.Context(), "login_session:"+loginSession)
```

- [ ] **Step 2: Verify the `RegisterDevice` signature matches** (the plan assumes `(ctx, userID, fingerprint, clientIP, userAgent, location) (…, …, …)` — as called in `handleLogin`). Run:
```bash
grep -n "func (s \*Service) RegisterDevice" internal/risk/*.go
grep -n "s.riskService.RegisterDevice(" internal/oauth/service.go
```
If the arity/returns differ from `handleLogin`'s call, match that call exactly (same 3 blank returns or whatever it uses).

- [ ] **Step 3: Build + vet.** `go build ./internal/oauth/ && go vet ./internal/oauth/` → clean.

- [ ] **Step 4: Confirm no oauth regression.** `go test ./internal/oauth/` → ok (includes the existing `TestDeviceTrustGateBlocks`).

- [ ] **Step 5: gofmt + commit.**
```bash
gofmt -w internal/oauth/service.go
git add internal/oauth/service.go
git commit -m "fix(oauth): gate clientless device trust at authorize/callback (SSO-bypass fix)"
```

## Task 2: Full verification

**Files:** none

- [ ] `go build ./... && go vet ./internal/oauth/...`
- [ ] `gofmt -l internal/oauth/service.go` (empty)
- [ ] `go run ./tools/orgscope -fail ./internal` (no new SQL → clean)
- [ ] `go test ./internal/oauth/...` → ok

## Self-review notes

- **Spec coverage:** the single gate placement → Task 1; verification → Task 2.
- **Reuse/consistency:** `deviceTrustGateBlocks(clientID, deviceTrusted)`, `CreateDeviceTrustRequest(...)` (8 args, matches #268's call), `parseBrowserNameFromUA`, `req.Status == "approved"` — all identical to the existing #268 handleLogin gate. `RegisterDevice` call mirrors `handleLogin` (verify in Step 2).
- **Placement invariant:** gate is BEFORE `s.redis.Client.Del(login_session)` so a blocked retry reuses the same session.
- **No new config/schema;** the `RequireDeviceTrustForClientless` flag + helper already shipped in #268.
- **handleLogin gate retained** (defense-in-depth; do not remove).

## Post-merge (live re-test on the box)

After merge: rebuild + deploy the oauth binary (the box already has the flag on), restart `oidx-oauth`, re-run the `device_trust_requests` watcher, and retry an untrusted-device clientless netgraph login → expect the login page to re-render with the message + a pending request → approve → retry succeeds. (Deploy is a separate, user-authorized step.)
