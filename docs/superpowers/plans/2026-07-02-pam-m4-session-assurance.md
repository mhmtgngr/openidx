# PAM M4 — Session Assurance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans. Steps use `- [ ]`.

**Goal:** Transcripts + live monitor + session-end detection for brokered Guacamole sessions, attestation of privileged (vault/rotation) entitlements, and a fix for the M3 recording-purge data-loss bug.

**Tech Stack:** Go 1.25, Gin, pgx v5, Apache Guacamole REST + `guaclog`. Branch `pam/session-assurance` (off main). **Spec:** `docs/superpowers/specs/2026-07-02-pam-m4-session-assurance-design.md`

**Execution order:** T1 → T2 → T3 → T4 → T5 → T6 → T7.

---

## Task 1: Migration v60 + recording full-file-path fix (data-loss)

**Files:** `internal/migrations/sql_v60.go`, `loader.go`, `deployments/docker/init-db.sql`; `internal/access/guacamole.go`, `internal/access/guacamole_sessions.go`, `internal/access/remote_support_retention.go`.

- [ ] **Step 1:** `sql_v60.go` (`guacTranscriptUp`/`Down`): `ALTER TABLE guacamole_sessions ADD COLUMN IF NOT EXISTS transcript_path TEXT;` + `ADD COLUMN IF NOT EXISTS transcript_generated_at TIMESTAMPTZ;`. Down: drop the two columns. Register v60 in `loader.go` (after v59). Mirror the two ALTERs into `init-db.sql` near the guacamole_sessions block. No RLS/belt change.
- [ ] **Step 2 (data-loss fix):** In `internal/access/guacamole.go handleGuacamoleConnect` (~line 487-510): change the `recordGuacSession` call to pass the **full file path** — `recFile := filepath.Join(recPath, recName)` (add `path/filepath` import) and pass `recFile` instead of `recPath`. (Keep `params["recording-path"]=recPath` and `params["recording-name"]=recName` for guacd unchanged.)
- [ ] **Step 3 (guard):** In `internal/access/remote_support_retention.go` where guac recordings are purged (`os.RemoveAll(recordingPath)`), add a guard: refuse to remove a path equal to (or a parent of) the configured recordings root — only remove a path strictly inside it. If `recordingPath == s.config.GuacamoleRecordingPath` (or the root), skip + Warn. (The Task-1 fix makes new rows store files, but this guards legacy dir-valued rows.)
- [ ] **Step 4:** `go build ./... && go test ./internal/migrations/ -run TestInitDBParity -v && gofmt -l`.
- [ ] **Step 5:** Commit `feat(access): v60 transcript columns + fix recording purge to per-file (data-loss)`.

---

## Task 2: Session-end detection sweep

**Files:** `internal/access/remote_support_retention.go`.

- [ ] **Step 1:** Add `detectEndedGuacSessions(ctx)` invoked from the same ticker that runs `sweepExpiredGuacRecordings` (in `StartRecordingRetentionEnforcer`). Logic:
```go
func (h *RemoteSupportHandler) detectEndedGuacSessions(ctx context.Context) {
	if h.guacamoleClient == nil { return }
	active, err := h.guacamoleClient.ListActiveSessions(ctx)
	if err != nil { h.logger.Warn("detectEndedGuacSessions: list active failed", zap.Error(err)); return }
	live := map[string]bool{} // key: connectionIdentifier + "|" + username
	for _, a := range active { live[a.ConnectionIdentifier+"|"+a.Username] = true }
	rows, err := h.db.Pool.Query(ctx,
		//orgscope:ignore background cross-org sweep reconciling active guac sessions
		`SELECT gs.id, gc.guacamole_connection_id, COALESCE(u.username,'')
		 FROM guacamole_sessions gs
		 JOIN guacamole_connections gc ON gc.id = gs.connection_id
		 LEFT JOIN users u ON u.id = gs.user_id
		 WHERE gs.status='active' AND gs.started_at < NOW() - INTERVAL '2 minutes'`)
	if err != nil { h.logger.Warn(...); return }
	defer rows.Close()
	type ended struct{ id string }
	var toEnd []string
	for rows.Next() {
		var id, guacConnID, username string
		if rows.Scan(&id, &guacConnID, &username) != nil { continue }
		if !live[guacConnID+"|"+username] { toEnd = append(toEnd, id) }
	}
	for _, id := range toEnd {
		if _, err := h.db.Pool.Exec(ctx,
			//orgscope:ignore background sweep; row already selected by id
			`UPDATE guacamole_sessions SET status='ended', ended_at=NOW() WHERE id=$1 AND status='active'`, id); err == nil {
			h.audit(ctx, "guacamole.session_ended_detected", id, "session", "")
		}
	}
}
```
(Confirm the audit helper name in this file — grep `h.audit`/`RecordEvent`; adapt. Confirm `guacamole_connections.guacamole_connection_id` = the Guacamole identifier that `ListActiveSessions` returns as `ConnectionIdentifier`.)
- [ ] **Step 2:** `go build ./... && go vet ./internal/access/... && go run ./tools/orgscope -fail ./internal/access`.
- [ ] **Step 3:** Commit `feat(access): detect naturally-ended guacamole sessions`.

---

## Task 3: Transcript sweep (guaclog) + download endpoint + Dockerfile

**Files:** `internal/access/remote_support_retention.go` (sweep), `internal/access/guacamole_sessions.go` (download handler), `internal/access/service.go` (route), the access-service Dockerfile.

- [ ] **Step 1:** Add `generateGuacTranscripts(ctx)` to the retention ticker:
```go
func (h *RemoteSupportHandler) generateGuacTranscripts(ctx context.Context) {
	guaclog, lookErr := exec.LookPath("guaclog")
	if lookErr != nil { return } // guaclog not installed → feature inert, no error
	rows, err := h.db.Pool.Query(ctx,
		//orgscope:ignore background cross-org transcript sweep
		`SELECT id, recording_path FROM guacamole_sessions
		 WHERE status IN ('ended','terminated') AND recording_path IS NOT NULL AND recording_path<>''
		   AND recording_purged_at IS NULL AND transcript_path IS NULL LIMIT 50`)
	if err != nil { h.logger.Warn(...); return }
	defer rows.Close()
	type job struct{ id, path string }
	var jobs []job
	for rows.Next() { var j job; if rows.Scan(&j.id,&j.path)==nil { jobs=append(jobs,j) } }
	for _, j := range jobs {
		if _, statErr := os.Stat(j.path); statErr != nil { continue } // recording not on disk yet
		tpath := j.path + ".txt"
		cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		out, runErr := exec.CommandContext(cctx, guaclog, j.path).CombinedOutput()
		cancel()
		if runErr != nil { h.logger.Warn("guaclog failed", zap.String("session",j.id), zap.Error(runErr)); continue }
		// guaclog writes <path>.txt itself; if it writes to stdout instead, persist `out`.
		if _, statErr := os.Stat(tpath); statErr != nil { _ = os.WriteFile(tpath, out, 0o600) }
		_, _ = h.db.Pool.Exec(ctx,
			//orgscope:ignore background sweep; row by id
			`UPDATE guacamole_sessions SET transcript_path=$1, transcript_generated_at=NOW() WHERE id=$2`, tpath, j.id)
		h.audit(ctx, "guacamole.transcript_generated", j.id, "session", "")
	}
}
```
Invoke it from `StartRecordingRetentionEnforcer` (same ticker). Also extend the retention purge to remove `transcript_path` alongside the recording file (and require the RemoveAll-root guard from T1).
- [ ] **Step 2:** Download handler in `guacamole_sessions.go`: `handleGetGuacTranscript` (GET `/guacamole/sessions/:id/transcript`, admin): SELECT `transcript_path` for the session (org-scoped via `guacamole_connections`→`proxy_routes.org_id` JOIN like `handleSetGuacCredential`); 404 if none; stream the file (`c.File(path)` or read+`c.Data`). Register the route in `service.go` behind `requireAdminRole()`.
- [ ] **Step 3:** Dockerfile: in the access-service image, install `guaclog` (from guacamole-server). Best-effort — if the base image can't provide it, add a comment that the host must supply `guaclog` on PATH; the code is `LookPath`-gated so this never breaks the build/runtime. (Grep for the access-service Dockerfile; if it's a scratch/distroless Go image, document the host-PATH requirement instead of forcing a heavy image change — note which you did.)
- [ ] **Step 4:** `go build ./... && go vet && gofmt -l && orgscope`.
- [ ] **Step 5:** Commit `feat(access): guaclog transcript sweep + admin download endpoint`.

---

## Task 4: Live monitor (Guacamole connection sharing)

**Files:** `internal/access/guacamole.go` (client), `internal/access/guacamole_sessions.go` (handler), `internal/access/service.go` (route).

- [ ] **Step 1:** `GuacamoleClient.ShareActiveConnection(ctx, activeConnID string) (string, error)` — mint a read-only sharing link for an active connection via Guacamole's sharing API. Read Guacamole's REST docs pattern: typically requires a sharing-profile bound to the connection + requesting a share via the tunnel. Given version variance, implement the documented 1.x approach; on a non-2xx/unsupported response return a clear error `ErrSharingUnsupported`. Reuse `apiRequest`.
- [ ] **Step 2:** `handleShareGuacSession` (POST `/guacamole/sessions/:id/share`, admin): call `ShareActiveConnection(:id)`; on `ErrSharingUnsupported` → 501 with a message pointing to the active-session list; else return `{share_url}`; audit `guacamole.session_shared`. Register route behind `requireAdminRole()`.
- [ ] **Step 3:** build/vet/gofmt/orgscope.
- [ ] **Step 4:** Commit `feat(access): live-monitor via Guacamole read-only connection sharing`.

---

## Task 5: Attestation of privileged entitlements

**Files:** `internal/admin/attestation.go`.

- [ ] **Step 1:** Read `attestation.go`: the `validTypes` map (~line 125), `generateAttestationItems` switch (~line 321-429), and the revoke-remediation switch in `handleDecideAttestationItem` (~line 519-539). Match the exact idioms (org via `orgctx.From`, the item INSERT columns, the reviewer default).
- [ ] **Step 2:** Add `"vault_access"` and `"rotation_policy"` to `validTypes`.
- [ ] **Step 3:** In `generateAttestationItems`, add two cases:
  - `vault_access`: `SELECT vag.id, s.name, vag.principal_id, array_to_string(vag.actions,',') FROM vault_access_grants vag JOIN vault_secrets s ON s.id=vag.secret_id WHERE vag.org_id=$1 AND (vag.expires_at IS NULL OR vag.expires_at>NOW())` → INSERT one item per grant (`resource_type='vault_access'`, `resource_id=<grant id>`, `resource_name=<secret>:<actions>`, `user_id=<principal_id>`).
  - `rotation_policy`: `SELECT p.id, s.name, p.connector_type FROM credential_rotation_policies p JOIN vault_secrets s ON s.id=p.secret_id WHERE p.org_id=$1 AND p.enabled=true` → item per policy (`resource_type='rotation_policy'`, `resource_id=<policy id>`, name=`<secret>:<connector>`).
  Follow the existing per-case INSERT + reviewer-default pattern exactly.
- [ ] **Step 4:** In the revoke switch, add:
  - `vault_access`: `DELETE FROM vault_access_grants WHERE id=$1 AND org_id=$2` (grant id, org).
  - `rotation_policy`: `UPDATE credential_rotation_policies SET enabled=false, updated_at=NOW() WHERE id=$1 AND org_id=$2`.
  Keep fail-closed (item stays pending on error) + audit the revoke (match the file's audit idiom).
- [ ] **Step 5:** `go build ./... && go vet ./internal/admin/... && gofmt -l && go run ./tools/orgscope -fail ./internal/admin` (the enumerations are org-scoped in-handler; annotate only if flagged).
- [ ] **Step 6:** Commit `feat(admin): attestation of vault-access + rotation-policy entitlements`.

---

## Task 6: Unit tests

**Files:** `internal/access/guacamole_test.go` (extend).

- [ ] **Step 1:** Pure-logic unit tests: the recording full-file-path join; the RemoveAll-root guard (a helper `isUnderRoot(path, root) bool` if you extract one — safer to extract + test it); transcript path derivation (`path + ".txt"`); the session-end `live` set membership key building. Where a function is DB/exec-bound, extract the pure decision (e.g., `shouldPurge(path, root)`) and test that.
- [ ] **Step 2:** `go test ./internal/access/... && vet && gofmt`.
- [ ] **Step 3:** Commit `test(access): session-assurance pure-logic unit tests`.

---

## Task 7: Integration test

**Files:** `test/integration/session_assurance_test.go` (`//go:build integration`).

- [ ] **Step 1:** Reuse suite helpers (`integrationDB`, `seedOrg`, `bypassExec`; the guac seed helpers from `guacamole_injection_test.go` — `seedProxyRoute`, `seedGuacConnection`; vault-service ctor). Cover:
  - v60 columns (`transcript_path`, `transcript_generated_at`) exist on `guacamole_sessions`.
  - session-end detection SQL: seed a `guacamole_sessions` row `status='active', started_at=NOW()-10m`; run the detection UPDATE with an empty "live" set → row becomes `ended`; a `started_at=NOW()` row is left active (grace).
  - attestation `vault_access`: seed org + a vault secret + a `vault_access_grants` row; replicate the enumerate SELECT → yields the grant; run the revoke DELETE → grant gone.
  - RLS isolation on the new queries where applicable.
- [ ] **Step 2:** `go test -c -tags=integration ./test/integration/ -o /dev/null` (compiles); run if DB present.
- [ ] **Step 3:** Commit `test(access): session-assurance integration test`.

---

## Final verification
```bash
go build ./... && go vet ./... && gofmt -l internal/access internal/admin internal/migrations
go run ./tools/orgscope -fail ./internal
golangci-lint run && govulncheck ./...
go test ./internal/access/... ./internal/admin/... && go test ./internal/migrations/ -run TestInitDBParity
go test -c -tags=integration ./test/integration/ -o /dev/null
```

## Self-review notes
- **Data-loss fixed:** recording_path now a per-file path; purge guarded against removing the recordings root.
- **guaclog gated on LookPath** → absent tooling is a clean no-op, never a failure; transcript content never logged.
- **Live-monitor degrades gracefully** (501 + fallback) if the Guacamole sharing API is absent.
- **Attestation revoke** is fail-closed + audited; enumerations + remediation org-scoped.
- **Migration v60** plain `ADD COLUMN` (no `DO $$`), mirrored to init-db, parity green.
