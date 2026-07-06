package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// TestGuacSessionHistoryLegalHoldFlags proves handleListGuacSessionHistory reports
// recording_available and on_legal_hold correctly: a recorded session under an active
// hold shows both true; releasing the hold flips on_legal_hold back to false. Uses a
// migrated testcontainer DB (container superuser bypasses RLS, so the org GUC isn't
// needed — the handler's explicit WHERE org_id filter still applies).
func TestGuacSessionHistoryLegalHoldFlags(t *testing.T) {
	db, cleanup := setupTestDB(t) // skips if testcontainers unavailable
	defer cleanup()

	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const defaultOrg = "00000000-0000-0000-0000-000000000010" // seeded by migrations

	var sessionID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO guacamole_sessions (org_id, connection_id, recording_path, status, started_at, ended_at)
		VALUES ($1::uuid, gen_random_uuid(), '/rec/sess', 'ended', NOW() - INTERVAL '1 hour', NOW())
		RETURNING id::text`, defaultOrg).Scan(&sessionID); err != nil {
		t.Fatalf("seed guac session: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO guacamole_recording_legal_holds (session_id, reason) VALUES ($1::uuid, 'litigation')`,
		sessionID); err != nil {
		t.Fatalf("place hold: %v", err)
	}

	s := &Service{db: db, logger: zap.NewNop()}

	row := fetchHistoryRow(t, s, defaultOrg, sessionID)
	if !row.RecordingAvailable {
		t.Errorf("recording_available = false, want true (session has a recording_path)")
	}
	if !row.OnLegalHold {
		t.Errorf("on_legal_hold = false, want true (active hold exists)")
	}

	if _, err := db.Pool.Exec(ctx,
		`UPDATE guacamole_recording_legal_holds SET released_at = NOW() WHERE session_id = $1::uuid`,
		sessionID); err != nil {
		t.Fatalf("release hold: %v", err)
	}
	row = fetchHistoryRow(t, s, defaultOrg, sessionID)
	if row.OnLegalHold {
		t.Errorf("on_legal_hold = true after release, want false")
	}
}

// fetchHistoryRow drives the real handler over a gin test context whose request
// carries the org, then returns the single history row for sessionID.
func fetchHistoryRow(t *testing.T, s *Service, orgID, sessionID string) GuacSessionRow {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/access/guacamole/session-history", nil)
	req = req.WithContext(orgctx.With(req.Context(), orgctx.Org{ID: orgID}))
	c.Request = req

	s.handleListGuacSessionHistory(c)
	if w.Code != http.StatusOK {
		t.Fatalf("history handler status = %d, body = %s", w.Code, w.Body.String())
	}

	var body struct {
		Sessions []GuacSessionRow `json:"sessions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode history response: %v", err)
	}
	for _, r := range body.Sessions {
		if r.ID == sessionID {
			return r
		}
	}
	t.Fatalf("session %s not found in history (%d rows)", sessionID, len(body.Sessions))
	return GuacSessionRow{}
}
