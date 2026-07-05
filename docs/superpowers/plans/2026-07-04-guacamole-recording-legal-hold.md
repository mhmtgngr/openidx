# Guacamole recording legal-hold — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (or
> executing-plans). Steps use checkbox (`- [ ]`) syntax.

**Goal:** Extend recording legal-hold to Guacamole sessions so the retention purger never deletes a
held recording. Single PR in `internal/access` + `internal/migrations`.

**Spec:** `docs/superpowers/specs/2026-07-04-guacamole-recording-legal-hold-design.md`
**Module:** `github.com/openidx/openidx`. **Branch:** `feat/guac-recording-legal-hold` (spec committed).

Key facts: `sweepExpiredGuacRecordings` (remote_support_retention.go:308) purges guac recordings but
can't honor holds. Mirror the working remote-support legal-hold (`remote_support_legal_hold.go`), but
handlers go on the access **`*Service`** (like `guacamole_sessions.go`), using `s.db`, `s.logger`,
`s.auditLog(c, type, map)` (temp_access.go:451), and package funcs `getUserID(c)` (kiosk_api.go:500)
+ `isUniqueViolation(err)` (remote_support_legal_hold.go:179). Guac admin routes register in
`service.go:504-511` with `svc.requireAdminRole()`. Migration ceiling **v67**; init-db.sql retired
(no mirror/parity test).

---

## Task 1 — Migration v68: `guacamole_recording_legal_holds`

**Files:** create `internal/migrations/sql_v68.go`; edit `internal/migrations/loader.go`

- [ ] **Step 1:** `internal/migrations/sql_v68.go`:
```go
package migrations

// Migration v68 — Guacamole recording legal-hold. Parallels recording_legal_holds
// (v42, remote_support) but FKs to guacamole_sessions so a held Guacamole recording
// is never purged by sweepExpiredGuacRecordings. A separate table (not a polymorphic
// column) keeps the per-type FK + ON DELETE CASCADE. UNIQUE partial index enforces at
// most one active hold per session (so the place-hold 409 actually fires — the v42
// remote_support index is non-unique, a latent gap this improves on). Not RLS-belted
// (tenancy flows through the guacamole_sessions FK + org-scoped handler checks), mirroring
// recording_legal_holds. openidx_app exists by v68 (v53), so a plain GRANT is safe.
var guacRecordingLegalHoldsUp = `-- Migration 068: Guacamole recording legal-hold.
CREATE TABLE IF NOT EXISTS guacamole_recording_legal_holds (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID NOT NULL,
    reason          TEXT NOT NULL,
    placed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    placed_by       UUID,
    released_at     TIMESTAMPTZ,
    released_by     UUID,
    released_reason TEXT,
    CONSTRAINT guac_rec_legal_holds_session_fk
        FOREIGN KEY (session_id) REFERENCES guacamole_sessions(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_guac_rec_legal_holds_active
    ON guacamole_recording_legal_holds(session_id) WHERE released_at IS NULL;
GRANT SELECT, INSERT, UPDATE, DELETE ON guacamole_recording_legal_holds TO openidx_app;
`

var guacRecordingLegalHoldsDown = `-- Migration 068 down.
DROP TABLE IF EXISTS guacamole_recording_legal_holds;
`
```

- [ ] **Step 2:** In `loader.go`, append after the v67 entry (before the closing `}` of the slice):
```go
		{
			Version:     68,
			Name:        "guacamole_recording_legal_hold",
			Description: "Guacamole recording legal-hold: guacamole_recording_legal_holds (FK -> guacamole_sessions ON DELETE CASCADE, UNIQUE active-hold partial index) so sweepExpiredGuacRecordings never purges a held recording. Parallels recording_legal_holds (v42, remote_support). Not RLS-belted; plain GRANT to openidx_app (exists by v53). Idempotent.",
			UpSQL:       guacRecordingLegalHoldsUp,
			DownSQL:     guacRecordingLegalHoldsDown,
		},
```

- [ ] **Step 3: Verify migration** (dangerouslyDisableSandbox for oidx-pg):
```bash
cd /home/cmit/openidx
P=guac_lh_$(date +%s)
docker exec oidx-pg psql -U openidx -d postgres -c "CREATE DATABASE $P;"
DATABASE_URL="postgres://openidx:devpassword@localhost:55432/$P?sslmode=disable" go run ./cmd/migrate up 2>&1 | tail -2
docker exec oidx-pg psql -U openidx -d $P -tAc "SELECT 'v='||max(version) FROM schema_migrations; \d guacamole_recording_legal_holds" 2>&1 | grep -iE 'v=|legal_hold|session_id|fk' | head
# idempotency: re-run
DATABASE_URL="postgres://openidx:devpassword@localhost:55432/$P?sslmode=disable" go run ./cmd/migrate up 2>&1 | tail -1
docker exec oidx-pg psql -U openidx -d postgres -c "DROP DATABASE $P WITH (FORCE);"
```
Expected: version 68, table + FK + unique index present, re-run clean. `go build ./...`.

- [ ] **Step 4: Commit** `feat(migrations): v68 guacamole_recording_legal_holds`.

## Task 2 — Gate the purger on active holds

**Files:** `internal/access/remote_support_retention.go`

- [ ] **Step 1:** In `sweepExpiredGuacRecordings`, add to the candidate-selection `WHERE` (after
  `status IN ('ended','terminated')`):
```sql
           AND NOT EXISTS (
                SELECT 1 FROM guacamole_recording_legal_holds h
                 WHERE h.session_id = guacamole_sessions.id AND h.released_at IS NULL
           )
```
- [ ] **Step 2:** Replace the stale comment block (lines ~319-320, "Guacamole recording legal-hold is
  therefore out of scope") with a note that active holds are now skipped via
  `guacamole_recording_legal_holds`.
- [ ] **Step 3:** `go build ./...`; `go vet ./internal/access/`. Commit
  `feat(access): sweepExpiredGuacRecordings skips sessions under an active legal hold`.

## Task 3 — Legal-hold endpoints (place/release/list) on the access Service

**Files:** create `internal/access/guacamole_legal_hold.go`; edit `internal/access/service.go`

- [ ] **Step 1:** Create `guacamole_legal_hold.go` with three `*Service` handlers, mirroring
  `remote_support_legal_hold.go` but adapted to `s.db`/`s.logger`/`s.auditLog` + an **org-scoped
  session visibility pre-check** (the holds table isn't RLS-belted, so verify the session is visible
  under the caller's org before touching holds — prevents cross-org place/release/list):

```go
// sessionVisible reports whether the guacamole_sessions row is visible under the
// caller's org context (RLS on guacamole_sessions enforces the org scope).
func (s *Service) guacSessionVisible(ctx context.Context, sessionID string) (bool, error) {
	var ok bool
	err := s.db.Pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM guacamole_sessions WHERE id=$1::uuid)`, sessionID).Scan(&ok)
	return ok, err
}

// POST /api/v1/access/guacamole/sessions/:id/legal-hold
func (s *Service) handlePlaceGuacLegalHold(c *gin.Context) {
	sessionID := c.Param("id")
	var req struct{ Reason string `json:"reason" binding:"required"` }
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return
	}
	if s.db == nil || s.db.Pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"}); return
	}
	ctx := c.Request.Context()
	if vis, err := s.guacSessionVisible(ctx, sessionID); err != nil {
		s.logger.Error("place guac legal hold: session lookup", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"}); return
	} else if !vis {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"}); return
	}
	placedBy := getUserID(c)
	var placedByArg interface{}
	if placedBy != "" { placedByArg = placedBy }
	var id string
	err := s.db.Pool.QueryRow(ctx, `
        INSERT INTO guacamole_recording_legal_holds (session_id, reason, placed_by)
        VALUES ($1::uuid, $2, NULLIF($3,'')::uuid) RETURNING id::text
    `, sessionID, req.Reason, placedByArg).Scan(&id)
	if err != nil {
		if isUniqueViolation(err) {
			c.JSON(http.StatusConflict, gin.H{"error": "an active legal hold already exists for this session"}); return
		}
		s.logger.Error("place guac legal hold: insert", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to place hold"}); return
	}
	s.auditLog(c, "guacamole.legal_hold_placed", map[string]interface{}{"session_id": sessionID, "reason": req.Reason})
	c.JSON(http.StatusCreated, gin.H{"id": id, "session_id": sessionID, "reason": req.Reason})
}

// DELETE /api/v1/access/guacamole/sessions/:id/legal-hold
func (s *Service) handleReleaseGuacLegalHold(c *gin.Context) {
	sessionID := c.Param("id")
	var req struct{ Reason string `json:"reason"` }
	_ = c.ShouldBindJSON(&req)
	if s.db == nil || s.db.Pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"}); return
	}
	ctx := c.Request.Context()
	if vis, err := s.guacSessionVisible(ctx, sessionID); err != nil || !vis {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"}); return
	}
	releasedBy := getUserID(c)
	var releasedByArg interface{}
	if releasedBy != "" { releasedByArg = releasedBy }
	tag, err := s.db.Pool.Exec(ctx, `
        UPDATE guacamole_recording_legal_holds
           SET released_at=NOW(), released_by=NULLIF($2,'')::uuid, released_reason=NULLIF($3,'')
         WHERE session_id=$1::uuid AND released_at IS NULL
    `, sessionID, releasedByArg, req.Reason)
	if err != nil {
		s.logger.Error("release guac legal hold: update", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to release hold"}); return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "no active legal hold for this session"}); return
	}
	s.auditLog(c, "guacamole.legal_hold_released", map[string]interface{}{"session_id": sessionID, "reason": req.Reason})
	c.JSON(http.StatusOK, gin.H{"status": "released", "session_id": sessionID})
}

// GET /api/v1/access/guacamole/sessions/:id/legal-holds
func (s *Service) handleListGuacLegalHolds(c *gin.Context) {
	sessionID := c.Param("id")
	if s.db == nil || s.db.Pool == nil { c.JSON(http.StatusOK, gin.H{"legal_holds": []any{}}); return }
	ctx := c.Request.Context()
	if vis, err := s.guacSessionVisible(ctx, sessionID); err != nil || !vis {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"}); return
	}
	rows, err := s.db.Pool.Query(ctx, `
        SELECT id::text, reason, placed_at, COALESCE(placed_by::text,''),
               released_at, COALESCE(released_by::text,''), COALESCE(released_reason,'')
          FROM guacamole_recording_legal_holds
         WHERE session_id=$1::uuid ORDER BY placed_at DESC
    `, sessionID)
	if err != nil { s.logger.Error("list guac legal holds", zap.Error(err)); c.JSON(http.StatusInternalServerError, gin.H{"error":"failed"}); return }
	defer rows.Close()
	out := []gin.H{}
	for rows.Next() {
		var id, reason, placedBy, releasedBy, releasedReason string
		var placedAt time.Time
		var releasedAt *time.Time
		if err := rows.Scan(&id, &reason, &placedAt, &placedBy, &releasedAt, &releasedBy, &releasedReason); err != nil { continue }
		out = append(out, gin.H{"id": id, "reason": reason, "placed_at": placedAt, "placed_by": placedBy, "released_at": releasedAt, "released_by": releasedBy, "released_reason": releasedReason})
	}
	c.JSON(http.StatusOK, gin.H{"legal_holds": out})
}
```
  (Confirm imports: `context`, `net/http`, `time`, `gin`, `zap`. Confirm `s.auditLog`'s exact
  signature — temp_access.go:451 — and adapt the call. Confirm `getUserID`/`isUniqueViolation` names.)

- [ ] **Step 2:** Register in `service.go` next to the other guac session admin routes (~line 505):
```go
		api.POST("/guacamole/sessions/:id/legal-hold", svc.requireAdminRole(), svc.handlePlaceGuacLegalHold)
		api.DELETE("/guacamole/sessions/:id/legal-hold", svc.requireAdminRole(), svc.handleReleaseGuacLegalHold)
		api.GET("/guacamole/sessions/:id/legal-holds", svc.requireAdminRole(), svc.handleListGuacLegalHolds)
```

- [ ] **Step 3:** `go build ./...`, `go vet ./internal/access/`, `gofmt -l`. Commit
  `feat(access): guacamole recording legal-hold place/release/list endpoints`.

## Task 4 — Tests (integration: the purge gate is authoritative)

**Files:** `test/integration/guac_legal_hold_test.go` (reuse cross_org_test helpers: `integrationDSN`,
`seedOrg`, `bypassExec`/`bypassQueryRow`)

- [ ] **Step 1:** Write `TestGuacLegalHoldBlocksPurge` (`//go:build integration`): against the test DB
  (migrated), seed an org + a `guacamole_sessions` row (bypass-RLS insert) with a non-empty
  `recording_path` (a temp file that exists on disk), `status='ended'`, `ended_at` far in the past.
  Construct the retention `Service`/handler (find how `sweepExpiredGuacRecordings` is invoked/testable
  — it may be a method on a handler with `StartRecordingRetentionEnforcer`; call the sweep directly
  under a bypass-RLS ctx). Case A: insert an active hold → run sweep → assert `recording_purged_at`
  still NULL AND the temp file still exists. Case B: release the hold (stamp released_at) → run sweep
  → assert `recording_purged_at` set AND file removed. Clean up rows + temp files (`bypassExec`).
- [ ] **Step 2:** Run: `DATABASE_URL="postgres://openidx:devpassword@localhost:55432/openidx?sslmode=disable" go test -tags=integration ./test/integration/ -run TestGuacLegalHold -v` (dangerouslyDisableSandbox). PASS.
- [ ] **Step 3:** Commit `test(access): guacamole legal-hold blocks recording purge`.

## Task 5 — open PR, review, CI, merge (with go-ahead)
- [ ] Push; `gh pr create` (migration v68 + purge gate + endpoints; note the UNIQUE-index improvement
  over v42, the org-scoped visibility check, and that this is a **schema change** so box deploy needs
  v67→v68). Adversarial review (purge gate + org-scoping get the hard look). CI green. **Stop for
  per-PR merge go-ahead.**

---

## Self-review notes
- Spec coverage: migration v68 (T1), purge gate (T2), endpoints (T3), integration proof (T4).
- Security items: the purge-gate `NOT EXISTS active hold` (a held recording must never be purged —
  the whole point), and the org-scoped `guacSessionVisible` pre-check on all 3 handlers (holds table
  isn't RLS-belted). Improvement over remote_support: UNIQUE partial index so the 409 actually fires.
- Schema change (additive) → box deploy is a real v67→v68 migration.
- Verify-at-impl: exact `s.auditLog` signature; how `sweepExpiredGuacRecordings` is invoked for the test.
