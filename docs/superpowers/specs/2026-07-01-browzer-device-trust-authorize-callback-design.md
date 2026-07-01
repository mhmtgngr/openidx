# Fix the clientless device-trust SSO bypass — gate `handleAuthorizeCallback`

## Context

PR #268 added a device-trust gate for clientless (BrowZer) logins, but placed it
in `handleLogin` (`POST /oauth/login`) — the **SPA/JSON** login path (admin-console
etc.). The BrowZer public client uses the **server-rendered login page**, whose
form POSTs to **`/oauth/authorize/callback` → `handleAuthorizeCallback`**
(`service.go:1554`), which authenticates the user and issues the authorization
code directly. So #268's gate **never runs for BrowZer** — verified live: an
untrusted-device netgraph login completed (authorize → callback → token, no
`POST /oauth/login`, no `device_not_trusted`, no request filed after a 6-minute
watch).

This spec moves the enforcement to the path BrowZer actually uses.

`riskService.IsDeviceTrusted` reads `known_devices.trusted` (org-scoped) — the
same signal the access-proxy's `deviceTrusted` uses — so the gate is meaningful
and consistent.

## Design

Add the device-trust gate to `handleAuthorizeCallback`, mirroring the #268 gate
but adapted to the server-rendered flow.

**Placement:** after `AuthenticateUser` succeeds and the country-block passes,
**before** the `login_session` is deleted (`s.redis.Client.Del`, line 1597) and
before the authorization code is generated. Keeping it before the session delete
lets a blocked user retry against the same still-valid `login_session`.

```go
	// Device-trust gate for clientless (BrowZer) access. BrowZer's data path
	// bypasses the proxy's forward-auth device-trust check, and this
	// server-rendered login (POST /oauth/authorize/callback) — not the JSON
	// /oauth/login — is what the BrowZer public client uses, so this is the
	// enforcement point. Mirrors the handleLogin gate (#268).
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
```

Reuses, unchanged: the `deviceTrustGateBlocks(clientID, deviceTrusted)` helper,
the `RequireDeviceTrustForClientless` flag (already live on the box), and
`identityService.CreateDeviceTrustRequest` (dedup + auto-approval). On block the
**login page re-renders with the message** (the correct UX for a server-rendered
flow — not a JSON 403).

**Keep the `handleLogin` gate** as defense-in-depth (a JSON login of the
clientless client would still be gated). It's harmless and shares the helper.

## Behaviour

| flag | client_id | deviceTrusted | callback outcome |
|---|---|---|---|
| off | any | any | code issued (current behavior) |
| on | browzer-client | true | code issued |
| on | browzer-client | false | login page re-rendered w/ "device not trusted", request filed (unless auto-approved → code issued) |
| on | other (admin-console SPA) | any | code issued (unaffected) |

## Out of scope

- Per-route device trust for BrowZer (architecturally infeasible — prior spec).
- Removing the now-mostly-redundant `handleLogin` gate (kept as defense-in-depth).
- Enforcing at token issuance (the callback is the single code-issuance point for
  this flow; gating it is sufficient).

## Testing

- **Unit:** the decision (`deviceTrustGateBlocks`) is already covered by #268's
  truth-table test — unchanged. The new wiring in `handleAuthorizeCallback` is a
  straight reuse; the full callback path (authenticate → gate → render/allow)
  needs the oauth Service + risk/identity services (DB), so cover it via the
  existing oauth login/callback integration tests if present, else rely on the
  unit-tested helper + build/vet.
- `go build ./...`, `go vet`, `gofmt`, `go run ./tools/orgscope -fail ./internal`,
  `go test ./internal/oauth/...` green.
- **Live (box already has the flag on):** re-run the `device_trust_requests`
  watcher; an untrusted-device netgraph login now re-renders the login page with
  the message and files a **pending** request; after admin approval, the retry
  issues the code → BrowZer session → netgraph loads.

## Verification checklist

- [ ] Gate added to `handleAuthorizeCallback` before `login_session` delete / code
  generation; renders the login page on block; auto-approve falls through.
- [ ] Reuses `deviceTrustGateBlocks` + `CreateDeviceTrustRequest`; `RegisterDevice`
  called so approval has a row to flip.
- [ ] `handleLogin` gate retained.
- [ ] build / vet / gofmt / orgscope / oauth tests green.
- [ ] (live) untrusted clientless login → login-page message + pending request;
  approve → retry succeeds.
