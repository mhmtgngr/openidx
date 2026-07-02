# PAM M3 — Privileged Session Brokering + Credential Injection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans. Steps use `- [ ]`.

**Goal:** Guacamole sessions open with the target credential injected server-side (browser never sees it), gated by pre-session approval, recorded, and force-terminable.

**Architecture:** access-service instantiates an in-process `vault.Service` (shared DB+KEK). Injection happens in `handleGuacamoleConnect` (`guacamole.go:388`). Approval + session tracking are access-local tables under the v37 RLS belt (migration v59). Recording reuses guacd-native recording + the remote-support retention/legal-hold pipeline. Credential model: vault secret = password/key; username on the connection.

**Tech Stack:** Go 1.25, Gin, pgx v5, zap, Apache Guacamole REST API. Branch `pam/session-injection` (off main).

**Spec:** `docs/superpowers/specs/2026-07-02-pam-m3-session-injection-design.md`

**Execution order:** T1 → T2 → T3 → T4 → T5 → T6 → T7 (connect-handler integration, uses T4/T6 helpers) → T8 → T9.

---

## Task 1: Migration v59

**Files:** Create `internal/migrations/sql_v59.go`; modify `loader.go`, `deployments/docker/init-db.sql`.

- [ ] **Step 1:** `sql_v59.go` — `var guacSessionsUp = `:
  - `ALTER TABLE guacamole_connections ADD COLUMN IF NOT EXISTS vault_secret_id UUID REFERENCES vault_secrets(id) ON DELETE SET NULL;` and `ADD COLUMN IF NOT EXISTS inject_username VARCHAR(255);`, `ADD COLUMN IF NOT EXISTS require_approval BOOLEAN NOT NULL DEFAULT false;`, `ADD COLUMN IF NOT EXISTS record_session BOOLEAN NOT NULL DEFAULT false;`
  - `CREATE TABLE IF NOT EXISTS guacamole_session_requests (id UUID PK default gen_random_uuid(), org_id UUID NOT NULL, connection_id UUID NOT NULL, requester_id UUID NOT NULL, reason TEXT, status VARCHAR(16) NOT NULL DEFAULT 'pending', approver_id UUID, decided_at TIMESTAMPTZ, expires_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());` + index on `(connection_id, requester_id, status)`.
  - `CREATE TABLE IF NOT EXISTS guacamole_sessions (id UUID PK default gen_random_uuid(), org_id UUID NOT NULL, connection_id UUID NOT NULL, user_id UUID, guac_session_uuid VARCHAR(255), recording_path TEXT, recording_purged_at TIMESTAMPTZ, started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), ended_at TIMESTAMPTZ, status VARCHAR(16) NOT NULL DEFAULT 'active');` + index on `(connection_id, started_at DESC)` and `(status)`.
  - RLS belt for BOTH new tables (copy v56's `pol_<t>_org_scope` pattern: `DROP POLICY IF EXISTS`; `CREATE POLICY … USING (current_setting('app.bypass_rls', true)='on' OR org_id = NULLIF(current_setting('app.org_id', true),'')::uuid)`; `ENABLE`+`FORCE ROW LEVEL SECURITY`). Grant to openidx_app as a **plain GRANT** (NO `DO $$` block — the v56/v57 splitSQL lesson): `GRANT SELECT, INSERT, UPDATE, DELETE ON guacamole_session_requests, guacamole_sessions TO openidx_app;`
  - `guacamole_connections` is NOT org-scoped/belted today — do NOT add it to the belt (only ALTER its columns).
  - Down: drop the two tables.
- [ ] **Step 2:** Register v59 in `loader.go` after v58.
- [ ] **Step 3:** Mirror into `init-db.sql` (the ALTERs + both tables + belt + plain GRANT), matching the v56/v57 placement style. Confirm `guacamole_connections` exists in init-db before the ALTERs.
- [ ] **Step 4:** `go build ./... && go test ./internal/migrations/ -run TestInitDBParity -v` (PASS); `gofmt -l`.
- [ ] **Step 5:** Commit `feat(migrations): v59 — guacamole injection columns + session-request/session tables`.

---

## Task 2: access-service vault wiring + config

**Files:** `internal/access/service.go`, `cmd/access-service/main.go`, `internal/common/config/config.go`.

- [ ] **Step 1:** `service.go`: add `vaultSvc *vault.Service` to `Service` struct (import `internal/vault`) + `func (s *Service) SetVaultService(v *vault.Service) { s.vaultSvc = v }`.
- [ ] **Step 2:** `config.go`: add `GuacamoleRecordingPath string mapstructure:"guacamole_recording_path"` + env bind `GUACAMOLE_RECORDING_PATH` + default `"/var/lib/openidx/recordings/guacamole"`. (`VAULT_*` already exist.)
- [ ] **Step 3:** `cmd/access-service/main.go`: after the access Service is built, construct + inject the vault (fail-closed, mirroring `cmd/governance-service/main.go`):
```go
vaultRing, err := vault.KeyringFromConfig(vault.KeyConfig{
	KEK: cfg.VaultKEK, KEKs: cfg.VaultKEKs, ActiveKEKID: cfg.VaultActiveKEKID, EncryptionKey: cfg.EncryptionKey,
})
if err != nil {
	log.Fatal("vault keyring unavailable (fail-closed)", zap.Error(err))
}
vaultSvc, err := vault.NewService(db, vaultRing, nil, time.Duration(cfg.VaultRevealLeaseTTLSeconds)*time.Second, log)
if err != nil {
	log.Fatal("vault service init failed", zap.Error(err))
}
accessService.SetVaultService(vaultSvc)
```
(match the real var names in main.go — read it first: the access Service var, `db`, `cfg`, logger.)
- [ ] **Step 4:** `go build ./... && go build ./cmd/access-service/ && go vet ./internal/access/... && gofmt -l`.
- [ ] **Step 5:** Commit `feat(access): in-process vault.Service (fail-closed) + recording-path config`.

---

## Task 3: Connection model fields + provisioning

**Files:** `internal/access/guacamole.go`.

- [ ] **Step 1:** Add to `GuacConnection` struct: `VaultSecretID string json:"vault_secret_id,omitempty"`, `InjectUsername string json:"inject_username,omitempty"`, `RequireApproval bool json:"require_approval"`, `RecordSession bool json:"record_session"`.
- [ ] **Step 2:** Where connections are created/updated for a route (`provisionGuacamoleForRoute` ~416, `SaveGuacConnection` ~301), persist the four new columns when provided (accept them from the route/app config or a dedicated admin endpoint `PUT /guacamole/connections/:routeId/credential` that sets `vault_secret_id`/`inject_username`/`require_approval`/`record_session`). Add that admin endpoint + handler (`handleSetGuacCredential`) — validates the secret exists (org-scoped SELECT on vault_secrets) before storing `vault_secret_id`.
- [ ] **Step 3:** `go build ./... && go vet ./internal/access/... && go run ./tools/orgscope -fail ./internal/access`.
- [ ] **Step 4:** Commit `feat(access): guacamole connection credential/approval/recording config + admin endpoint`.

---

## Task 4: Approval-request lifecycle

**Files:** Create `internal/access/guacamole_sessions.go`; modify `internal/access/service.go` (routes).

- [ ] **Step 1:** In `guacamole_sessions.go`, implement handlers + a reusable gate helper:
  - `handleRequestGuacSession` (POST `/guacamole/connections/:routeId/request`): resolve connection_id + org from the route; INSERT `guacamole_session_requests` (status='pending', requester=user, reason, expires_at=NOW()+configurable e.g. 1h); return the request id.
  - `handleApproveGuacSession` / `handleDenyGuacSession` (POST `/guacamole/session-requests/:id/approve|deny`, admin): UPDATE status + approver_id + decided_at (org-scoped).
  - `handleListGuacSessionRequests` (GET, admin): list pending for the org.
  - `func (s *Service) checkAndConsumeApproval(ctx, connectionID, userID string) (bool, error)`: `UPDATE guacamole_session_requests SET status='consumed' WHERE connection_id=$1 AND requester_id=$2 AND status='approved' AND (expires_at IS NULL OR expires_at>NOW()) AND id = (SELECT id … ORDER BY created_at DESC LIMIT 1) RETURNING id` → true if a row was consumed. (Single-use.)
  - Audit each transition to `unified_audit_events` (`guacamole.session_requested/approved/denied`).
- [ ] **Step 2:** Register routes in `service.go RegisterRoutes` (admin ones behind `svc.requireAdminRole()`, matching the ziti settings idiom).
- [ ] **Step 3:** `go build ./... && go vet ./internal/access/... && go run ./tools/orgscope -fail ./internal/access` (annotate any genuinely cross-org query; these are request-scoped so should be clean).
- [ ] **Step 4:** Commit `feat(access): guacamole pre-session approval request/approve/consume`.

---

## Task 5: Force-terminate + list active sessions

**Files:** `internal/access/guacamole.go` (client methods), `internal/access/guacamole_sessions.go` (handlers), `internal/access/service.go` (routes).

- [ ] **Step 1:** Add `GuacamoleClient` methods:
  - `ListActiveSessions(ctx) ([]GuacActiveSession, error)` — GET `/api/session/data/<dataSource>/activeConnections` (returns a map of active-connection UUID → {connectionIdentifier, username, startDate, remoteHost}). Reuse `apiRequest`.
  - `TerminateSession(ctx, activeConnID string) error` — Guacamole kills an active connection via `PATCH /api/session/data/<dataSource>/activeConnections` with body `[{"op":"remove","path":"/<activeConnID>"}]`. Reuse `apiRequest`.
- [ ] **Step 2:** Handlers in `guacamole_sessions.go`: `handleListActiveGuacSessions` (GET `/guacamole/sessions`, admin) and `handleTerminateGuacSession` (POST `/guacamole/sessions/:id/terminate`, admin, body `{reason}`) → call `TerminateSession`, mark any matching `guacamole_sessions` row `status='terminated', ended_at=NOW()`, audit `guacamole.session_terminated` with reason. Mirror `handleDeleteZitiSession` (`ziti_session_handlers.go:114`).
- [ ] **Step 3:** Routes in `service.go` (admin-guarded). Build/vet/gofmt/orgscope.
- [ ] **Step 4:** Commit `feat(access): guacamole force-terminate + active-session listing`.

---

## Task 6: Session tracking + retention sweep

**Files:** `internal/access/guacamole_sessions.go` (a `recordGuacSession` helper), `internal/access/remote_support_retention.go` (extend sweep).

- [ ] **Step 1:** `func (s *Service) recordGuacSession(ctx, connectionID, userID, recordingPath string) (string, error)`: INSERT a `guacamole_sessions` row (status='active', started_at=NOW()) returning id. Called by the connect handler when `record_session`.
- [ ] **Step 2:** Extend the retention sweeper (`remote_support_retention.go sweepExpiredRecordings`) to ALSO sweep `guacamole_sessions` recordings: select finalized/ended guacamole_sessions with a `recording_path`, not purged, past the effective retention (reuse `recording_retention_policies` + the legal-hold check), delete the recording file, set `recording_purged_at=NOW()`. Reuse the existing helpers/log/audit. (If the sweeper's structure makes a shared helper awkward, add a parallel `sweepExpiredGuacRecordings` invoked from the same ticker.)
- [ ] **Step 3:** Build/vet/gofmt/orgscope (the sweep is a background bypass job — annotate `//orgscope:ignore` like the existing remote-support sweep).
- [ ] **Step 4:** Commit `feat(access): track guacamole sessions + retention sweep for recordings`.

---

## Task 7: handleGuacamoleConnect integration (injection + gate + recording)

**Files:** `internal/access/guacamole.go`.

- [ ] **Step 1:** Rework `handleGuacamoleConnect` to (order matters):
```go
func (s *Service) handleGuacamoleConnect(c *gin.Context) {
	if s.guacamoleClient == nil { /* 503 */ }
	routeID := c.Param("routeId")
	userID := c.GetString("user_id")
	ctx := c.Request.Context()

	// Load the connection + its PAM config.
	var connID, protocol, hostname, secretID, injectUser string
	var port int
	var requireApproval, recordSession bool
	err := s.db.Pool.QueryRow(ctx,
		`SELECT guacamole_connection_id, protocol, hostname, port,
		        COALESCE(vault_secret_id::text,''), COALESCE(inject_username,''),
		        require_approval, record_session
		 FROM guacamole_connections WHERE route_id=$1`, routeID).
		Scan(&connID, &protocol, &hostname, &port, &secretID, &injectUser, &requireApproval, &recordSession)
	if err != nil { /* 404 */ }

	// Approval gate.
	if requireApproval {
		ok, err := s.checkAndConsumeApproval(ctx, connID, userID)
		if err != nil { /* 500 */ }
		if !ok { c.JSON(403, gin.H{"error":"session requires approval"}); return }
	}

	// Build injected params (server-side only).
	params := map[string]string{}
	if secretID != "" && s.vaultSvc != nil {
		bctx := orgctx.WithBypassRLS(ctx)
		cred, err := s.vaultSvc.Use(bctx, secretID)
		if err != nil { c.JSON(403, gin.H{"error":"credential unavailable"}); return }
		if injectUser != "" { params["username"] = injectUser }
		// secret type decides field: password vs private-key.
		params["password"] = string(cred)
		for i := range cred { cred[i] = 0 } // zero plaintext
		s.audit(ctx, "guacamole.credential_injected", map[string]any{"route_id":routeID,"secret_id":secretID,"user_id":userID})
	}
	// Recording params (guacd-native).
	if recordSession {
		params["recording-path"] = s.cfg.GuacamoleRecordingPath
		params["recording-name"] = connID + "-" + <ts/uuid>
		params["recording-include-keys"] = "true"
		_, _ = s.recordGuacSession(ctx, connID, userID, s.cfg.GuacamoleRecordingPath)
	}
	if len(params) > 0 {
		if err := s.guacamoleClient.UpdateConnection(connID, connID, protocol, hostname, port, params); err != nil {
			c.JSON(500, gin.H{"error":"prepare session"}); return
		}
	}
	c.JSON(200, gin.H{"connect_url": s.guacamoleClient.GetConnectionURL(connID), "connection_id": connID, "route_id": routeID})
}
```
Adapt: the audit helper name (grep the file for the existing `unified_audit`/`RecordEvent` usage — use whatever the access Service already calls; `s.cfg` field access — confirm the Service holds cfg or pass recording path another way; the secret "type" (password vs private-key) — read from `vault_secrets.type` if you want ssh_key→`private-key`, else default `password`). Keep the credential `[]byte` zeroed; never log/return it.
- [ ] **Step 2:** `go build ./... && go vet ./internal/access/... && go run ./tools/orgscope -fail ./internal && gofmt -l internal/access`.
- [ ] **Step 3:** Commit `feat(access): inject vault credentials + approval gate + recording on connect`.

---

## Task 8: Unit tests

**Files:** `internal/access/guacamole_test.go` (extend or create).

- [ ] **Step 1:** Pure-logic tests where feasible without a live Guacamole/DB: the param-building (secret→password, ssh_key→private-key, username from config), the recording-param assembly (only when record_session), and any pure helper. For DB-backed logic (approval consume) prefer the integration test (Task 9). Where the connect handler is too integrated to unit-test, extract the param-building into a small pure function `buildInjectedParams(secretType, injectUser string, cred []byte, record bool, recPath, recName string) map[string]string` and unit-test that.
- [ ] **Step 2:** `go test ./internal/access/... && go vet && gofmt -l`.
- [ ] **Step 3:** Commit `test(access): unit tests for injected-param building`.

---

## Task 9: Integration test

**Files:** `test/integration/guacamole_injection_test.go` (`//go:build integration`).

- [ ] **Step 1:** Reuse suite helpers (`integrationDB`, `seedOrg`, `bypassExec`, vault-service ctor). Cover:
  - v59 applied: `guacamole_session_requests` + `guacamole_sessions` exist and are FORCE-RLS; `guacamole_connections` has the four new columns.
  - Approval round-trip at the DB layer: insert a connection + a `guacamole_session_requests` (approved), call `checkAndConsumeApproval` → true + row now `consumed`; second call → false (single-use); expired approved request → false.
  - `recordGuacSession` inserts a `guacamole_sessions` row; the retention sweep purges it past retention (mark ended + old started_at + a retention policy), skips it under legal hold.
  - RLS: org B can't see org A's session requests / sessions.
- [ ] **Step 2:** `go test -c -tags=integration ./test/integration/ -o /dev/null` (compiles); run if DB present.
- [ ] **Step 3:** Commit `test(access): guacamole injection/approval/retention integration test`.

---

## Final verification
```bash
go build ./... && go vet ./... && gofmt -l internal/access internal/migrations cmd/access-service/main.go
go run ./tools/orgscope -fail ./internal
golangci-lint run && govulncheck ./...
go test ./internal/access/... && go test ./internal/migrations/ -run TestInitDBParity
go test -c -tags=integration ./test/integration/ -o /dev/null
```

## Self-review notes (addressed)
- **No credential egress:** the credential is fetched via `Use` (bypass), injected into the Guacamole connection params server-side, and the `[]byte` is zeroed; it never appears in the HTTP response, logs, or audit details. The browser gets only the connect token.
- **Approval single-use:** `checkAndConsumeApproval` consumes the request atomically (UPDATE … RETURNING); expired/denied/consumed → no access.
- **Force-terminate audited with reason;** recordings inherit the existing retention + legal-hold.
- **RLS:** new tables FORCE-RLS; connect-time `Use` uses bypass+conn org; migration uses a plain GRANT (no `DO $$`), mirrored to init-db, parity green.
- **Fail-closed:** access-service `log.Fatal`s on missing KEK; connections without `vault_secret_id`/`require_approval`/`record_session` behave exactly as today.
