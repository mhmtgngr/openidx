# PAM M2b — JIT Credential Checkout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Approval-gated, time-boxed checkout of a vault credential, reusing the access-request/approval workflow: request `vault_credential` → approve → fulfill grants a time-boxed reveal grant → requester retrieves the plaintext for the window → auto-return on expiry + rotate-on-return via M1b.

**Architecture:** governance-service instantiates its own in-process `vault.Service` (shared DB + KEK — `internal/vault` is a library, not a network service). `access_requests` is the checkout record (`resource_type='vault_credential'`, `resource_id=secret_id`, `expires_at`=window). No new table.

**Tech Stack:** Go 1.25, Gin, pgx v5, zap. Branch: `pam/jit-checkout` (off main).

**Spec:** `docs/superpowers/specs/2026-07-02-pam-m2b-jit-credential-checkout-design.md`

---

## File structure
- `internal/vault/store.go` — MODIFY: add `RevokeGrantForPrincipal`.
- `internal/governance/service.go` — MODIFY: `vaultSvc *vault.Service` field + `SetVaultService` setter + register 2 routes.
- `internal/governance/workflows.go` — MODIFY: `fulfillRequest` `vault_credential` case; SubmitRequest/create validation; retrieve + return handlers.
- `internal/governance/jit_expiry.go` — MODIFY: `vault_credential` expiry branch + rotate-on-return.
- `cmd/governance-service/main.go` — MODIFY: construct + inject `vault.Service` (fail-closed).
- `test/integration/jit_checkout_test.go` — NEW: e2e.

---

## Task 1: vault.RevokeGrantForPrincipal

**Files:** Modify `internal/vault/store.go`.

- [ ] **Step 1: Add the method** (near `RemoveGrant`):

```go
// RevokeGrantForPrincipal deletes any grant for (secretID, principalType, principalID).
// Used by the JIT-checkout early-return path for immediate deauthorization; the timeout
// path relies on the grant's expires_at. Org-scoped by RLS via ctx.
func (s *Service) RevokeGrantForPrincipal(ctx context.Context, secretID, principalType, principalID string) error {
	_, err := s.db.Pool.Exec(ctx,
		`DELETE FROM vault_access_grants WHERE secret_id=$1 AND principal_type=$2 AND principal_id=$3`,
		secretID, principalType, principalID)
	return err
}
```

- [ ] **Step 2:** `go build ./... && go test ./internal/vault/... && go vet ./internal/vault/... && go run ./tools/orgscope -fail ./internal/vault` (clean).
- [ ] **Step 3: Commit** `git commit -m "feat(vault): RevokeGrantForPrincipal for JIT-checkout early return"`.

---

## Task 2: Governance holds a vault.Service + wiring

**Files:** Modify `internal/governance/service.go`, `cmd/governance-service/main.go`.

- [ ] **Step 1:** In `service.go`, add `vaultSvc *vault.Service` to the `Service` struct (import `github.com/openidx/openidx/internal/vault`), and a setter:

```go
// SetVaultService injects the in-process vault used for JIT credential checkout.
func (s *Service) SetVaultService(v *vault.Service) { s.vaultSvc = v }
```

- [ ] **Step 2:** In `cmd/governance-service/main.go`, after `governanceService := governance.NewService(db, redis, cfg, log)`, construct + inject the vault (fail-closed, mirroring admin-api). Pass `nil` for the vault Auditor (governance emits its own `jit_credential.*` audit events; avoids importing internal/access here):

```go
vaultRing, err := vault.KeyringFromConfig(vault.KeyConfig{
	KEK: cfg.VaultKEK, KEKs: cfg.VaultKEKs, ActiveKEKID: cfg.VaultActiveKEKID,
	EncryptionKey: cfg.EncryptionKey,
})
if err != nil {
	log.Fatal("vault keyring unavailable (fail-closed)", zap.Error(err))
}
vaultSvc, err := vault.NewService(db, vaultRing, nil,
	time.Duration(cfg.VaultRevealLeaseTTLSeconds)*time.Second, log)
if err != nil {
	log.Fatal("vault service init failed", zap.Error(err))
}
governanceService.SetVaultService(vaultSvc)
```

(add imports: `github.com/openidx/openidx/internal/vault`, `time` if not present.)

- [ ] **Step 3:** `go build ./... && go build ./cmd/governance-service/ && go vet ./internal/governance/... && gofmt -l internal/governance cmd/governance-service/main.go`.
- [ ] **Step 4: Commit** `git commit -m "feat(governance): in-process vault.Service (fail-closed) for JIT checkout"`.

---

## Task 3: Request validation for vault_credential

**Files:** Modify `internal/governance/workflows.go` (the create-request handler / SubmitRequest path).

- [ ] **Step 1:** Find where a request is created (`handleCreateAccessRequest` → `SubmitRequest`). When `resource_type == "vault_credential"`, before creating, validate the secret is visible under the requester's org context:

```go
if body.ResourceType == "vault_credential" {
	var exists bool
	if err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT EXISTS(SELECT 1 FROM vault_secrets WHERE id=$1)`, body.ResourceID).Scan(&exists); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "validate secret"})
		return
	}
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "vault secret not found or not accessible"})
		return
	}
	// A duration/expires_at is required so the checkout window is bounded.
	if body.Duration == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "vault_credential requests require a duration"})
		return
	}
}
```

(The `SELECT` runs under the request context → RLS scopes it to the caller's org; another org's secret returns false.)

- [ ] **Step 2:** `go build ./... && go vet ./internal/governance/... && go run ./tools/orgscope -fail ./internal/governance` (the EXISTS query is request-scoped; annotate `//orgscope:ignore existence check is RLS-scoped by request ctx` only if orgscope flags it).
- [ ] **Step 3: Commit** `git commit -m "feat(governance): validate vault_credential requests (secret exists + bounded)"`.

---

## Task 4: fulfillRequest vault_credential case

**Files:** Modify `internal/governance/workflows.go` (`fulfillRequest`, switch at ~966).

- [ ] **Step 1:** Add the case after `case "application":`:

```go
	case "vault_credential":
		if s.vaultSvc == nil {
			return fmt.Errorf("vault service not configured; cannot fulfill vault_credential request %s", request.ID)
		}
		if request.ExpiresAt == nil {
			return fmt.Errorf("vault_credential request %s has no expires_at (unbounded checkout)", request.ID)
		}
		// Time-boxed reveal grant IS the authorization to retrieve; it auto-expires
		// with the checkout window (vault hasGrant checks expires_at > NOW()).
		if _, err := s.vaultSvc.AddGrant(ctx, vault.Grant{
			SecretID:      request.ResourceID,
			PrincipalType: "user",
			PrincipalID:   request.RequesterID,
			Actions:       []string{"reveal"},
			ExpiresAt:     request.ExpiresAt,
			GrantedBy:     "", // system fulfillment
		}); err != nil {
			return fmt.Errorf("grant vault reveal for request %s: %w", request.ID, err)
		}
		s.auditEvent(ctx, request.RequesterID, "jit_credential.checkout_granted", map[string]any{
			"request_id": request.ID, "secret_id": request.ResourceID, "expires_at": request.ExpiresAt,
		})
```

Use the existing audit helper the file already uses (match its name/signature — grep `auditEvent`/`recordAudit`/`insertAuditEvent` in workflows.go; adapt the call). The `default:` hard-error case stays. `request` must carry `ExpiresAt *time.Time` and `RequesterID`/`ResourceID` — confirm the `AccessRequest` struct fields (grep `type AccessRequest struct`).

- [ ] **Step 2:** `go build ./... && go vet ./internal/governance/...`.
- [ ] **Step 3: Commit** `git commit -m "feat(governance): fulfill vault_credential → time-boxed vault reveal grant"`.

---

## Task 5: Retrieve handler + route

**Files:** Modify `internal/governance/service.go` (route), `internal/governance/workflows.go` (handler).

- [ ] **Step 1:** Register in `RegisterRoutes` (inside the `gov` group, ~1497):

```go
		gov.POST("/requests/:id/credential", svc.handleRetrieveCredential)
		gov.POST("/requests/:id/return", svc.handleReturnCredential)
```

- [ ] **Step 2:** Implement `handleRetrieveCredential`:

```go
func (s *Service) handleRetrieveCredential(c *gin.Context) {
	if s.vaultSvc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "vault not configured"})
		return
	}
	reqID := c.Param("id")
	userID := c.GetString("user_id")
	ctx := c.Request.Context()

	var resourceType, resourceID, status, requester string
	var expiresAt *time.Time
	err := s.db.Pool.QueryRow(ctx,
		`SELECT resource_type, resource_id, status, requester_id, expires_at
		 FROM access_requests WHERE id=$1`, reqID).
		Scan(&resourceType, &resourceID, &status, &requester, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "request not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "load request"})
		return
	}
	if resourceType != "vault_credential" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "not a vault_credential request"})
		return
	}
	if requester != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "not your request"})
		return
	}
	if status != "fulfilled" {
		c.JSON(http.StatusConflict, gin.H{"error": "request not approved/fulfilled"})
		return
	}
	if expiresAt == nil || time.Now().After(*expiresAt) {
		c.JSON(http.StatusForbidden, gin.H{"error": "checkout window expired"})
		return
	}
	roles := c.GetStringSlice("roles")
	pt, err := s.vaultSvc.Reveal(ctx, resourceID, userID, roles, "JIT checkout "+reqID, false)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "reveal denied"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"value": string(pt)})
	for i := range pt { // do not retain plaintext
		pt[i] = 0
	}
}
```

(Confirm `time`, `errors`, `github.com/jackc/pgx/v5` imports in the file; `c.GetStringSlice("roles")` matches how the auth middleware sets roles — grep how other governance handlers read roles.)

- [ ] **Step 3:** `go build ./... && go vet ./internal/governance/... && gofmt -l internal/governance`.
- [ ] **Step 4: Commit** `git commit -m "feat(governance): retrieve endpoint reveals a checked-out credential"`.

---

## Task 6: Return handler + rotate-on-return helper

**Files:** Modify `internal/governance/workflows.go`.

- [ ] **Step 1:** Add a small helper + the return handler:

```go
// bumpRotationOnReturn wakes the M1b rotation scheduler for a secret whose policy is
// rotate_on_checkout, so the credential rotates when the checkout concludes.
func (s *Service) bumpRotationOnReturn(ctx context.Context, secretID string) {
	if _, err := s.db.Pool.Exec(ctx,
		`UPDATE credential_rotation_policies SET next_run_at = NOW()
		 WHERE secret_id = $1 AND rotate_on_checkout = true`, secretID); err != nil {
		s.logger.Warn("bump rotation on return failed", zap.String("secret_id", secretID), zap.Error(err))
	}
}

func (s *Service) handleReturnCredential(c *gin.Context) {
	if s.vaultSvc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "vault not configured"})
		return
	}
	reqID := c.Param("id")
	userID := c.GetString("user_id")
	ctx := c.Request.Context()

	var resourceType, resourceID, requester, status string
	err := s.db.Pool.QueryRow(ctx,
		`SELECT resource_type, resource_id, requester_id, status FROM access_requests WHERE id=$1`, reqID).
		Scan(&resourceType, &resourceID, &requester, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "request not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "load request"})
		return
	}
	if resourceType != "vault_credential" || requester != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "not your vault_credential request"})
		return
	}
	// Immediate deauthorization + mark expired + rotate-on-return.
	if err := s.vaultSvc.RevokeGrantForPrincipal(ctx, resourceID, "user", userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "revoke grant"})
		return
	}
	_, _ = s.db.Pool.Exec(ctx, `UPDATE access_requests SET status='expired', updated_at=NOW() WHERE id=$1`, reqID)
	s.bumpRotationOnReturn(ctx, resourceID)
	s.auditEvent(ctx, userID, "jit_credential.checkout_returned", map[string]any{
		"request_id": reqID, "secret_id": resourceID,
	})
	c.JSON(http.StatusOK, gin.H{"status": "returned"})
}
```

- [ ] **Step 2:** `go build ./... && go vet ./internal/governance/... && go run ./tools/orgscope -fail ./internal/governance` (annotate the rotation-bump UPDATE if flagged — it's request-scoped so likely fine).
- [ ] **Step 3: Commit** `git commit -m "feat(governance): return endpoint — revoke grant, expire, rotate-on-return"`.

---

## Task 7: jit_expiry vault_credential branch

**Files:** Modify `internal/governance/jit_expiry.go` (switch at ~54).

- [ ] **Step 1:** Add the case (the worker already marks the request expired + audits after the switch — match the existing structure; the branch adds the rotate-on-return bump; the reveal grant auto-expires via its expires_at, so no explicit revoke needed on timeout):

```go
		case "vault_credential":
			// Reveal grant auto-expires via its expires_at; here we only wake rotation.
			if _, err := s.db.Pool.Exec(ctx,
				//orgscope:ignore background sweep across orgs; bounded by the row being expired
				`UPDATE credential_rotation_policies SET next_run_at = NOW()
				 WHERE secret_id = $1 AND rotate_on_checkout = true`, resourceID); err != nil {
				s.logger.Warn("vault_credential rotate-on-return bump failed",
					zap.String("secret_id", resourceID), zap.Error(err))
			}
```

Confirm this slots into the existing switch (which then falls through to the shared "mark request expired + audit" logic — verify the control flow; if each case does its own expire+audit, mirror that).

- [ ] **Step 2:** `go build ./... && go vet ./internal/governance/... && go run ./tools/orgscope -fail ./internal/governance`.
- [ ] **Step 3: Commit** `git commit -m "feat(governance): jit_expiry expires vault_credential checkouts + rotate-on-return"`.

---

## Task 8: Integration test (e2e)

**Files:** Create `test/integration/jit_checkout_test.go` (`//go:build integration`, reuse `integrationDB`, `seedOrg`, `bypassExec`, and the vault helpers from `vault_test.go`/`rotation_test.go`).

- [ ] **Step 1:** Write `TestJITCredentialCheckout` at the service layer (construct a `governance.Service` with `SetVaultService`, or drive the DB directly where handler wiring is heavy). Cover:
  - Seed org + a vault secret (via `vault.Service.Store` under a bypass+org ctx) + a `rotate_on_checkout` rotation policy.
  - Insert an `access_requests` row (`resource_type='vault_credential'`, `resource_id=secret`, `status='fulfilled'`, `expires_at=NOW()+1h`, `requester_id=user`) and call `fulfillRequest` (or directly `vault.AddGrant`) to create the reveal grant.
  - Assert `vault.Reveal(secret, user, nil, "JIT", false)` returns the stored value (grant authorizes).
  - Simulate expiry: mark the request expired + run the rotate-on-return `UPDATE`; assert the rotation policy's `next_run_at` is now `<= NOW()` (rotation will fire) and that after `RevokeGrantForPrincipal`, `Reveal` is denied.
  - RLS: a second org cannot see the secret / a request for it.

- [ ] **Step 2:** `go test -c -tags=integration ./test/integration/ -o /dev/null` (compiles); run when DB present.
- [ ] **Step 3: Commit** `git commit -m "test(governance): JIT credential checkout e2e integration test"`.

---

## Final verification

```bash
go build ./... && go vet ./... && gofmt -l internal/governance internal/vault cmd/governance-service/main.go
go run ./tools/orgscope -fail ./internal
golangci-lint run && govulncheck ./...
go test ./internal/governance/... ./internal/vault/...
go test -c -tags=integration ./test/integration/ -o /dev/null
```

## Self-review notes (addressed)
- **No plaintext leak:** the only egress is the retrieve endpoint (owner-checked, window-checked, grant-gated via Reveal); the response `[]byte` is zeroed after write.
- **AuthZ:** retrieve/return verify `requester == user_id`, `resource_type='vault_credential'`, and window; the vault reveal grant is time-boxed and auto-expires; early return revokes it.
- **Rotate-on-return:** both the timeout (jit_expiry) and explicit-return paths bump the M1b rotation policy `next_run_at`; M1b's scheduler already does the rotation.
- **Fail-closed:** governance-service `log.Fatal`s if the vault KEK is unavailable; handlers 503 if `vaultSvc` is nil.
- **Types:** confirm `AccessRequest` field names (`RequesterID`/`ResourceID`/`ResourceType`/`ExpiresAt`) and the audit-helper signature during Task 4/5 by reading workflows.go; adapt calls to match.
