package access

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

// TestRecordingRetentionPolicy_DBBacked proves the per-org retention surface
// works end-to-end against the real v78 table: before that migration the
// GET/PUT routes 500'd ("relation does not exist" is not ErrNoRows) and
// resolveEffectiveRetention silently fell through to the global default, so
// per-org retention was configurable in name only. Uses a migrated
// testcontainer DB (setupTestDB); the container's superuser bypasses RLS so
// seeding needs no org GUC.
func TestRecordingRetentionPolicy_DBBacked(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t) // skips if testcontainers unavailable
	defer cleanup()

	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const (
		defaultOrg = "00000000-0000-0000-0000-000000000010" // seeded by migrations
		otherOrg   = "00000000-0000-0000-0000-0000000000b1"
		adminUID   = "aaaaaaaa-0000-0000-0000-0000000000ad"
	)
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO organizations (id, name) VALUES ($1::uuid, $2)`,
		otherOrg, "retention-other-org"); err != nil {
		t.Fatalf("seed second org: %v", err)
	}

	h := &RemoteSupportHandler{logger: zap.NewNop(), db: db, defaultRetentionDays: 30}

	// call runs a retention handler with org/user in the auth context and
	// returns the decoded JSON body.
	call := func(t *testing.T, handler gin.HandlerFunc, orgID, userID string, body string) (int, map[string]any) {
		t.Helper()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		method := http.MethodGet
		var reqBody *bytes.Buffer = bytes.NewBuffer(nil)
		if body != "" {
			method = http.MethodPut
			reqBody = bytes.NewBufferString(body)
		}
		c.Request = httptest.NewRequest(method, "/recording-retention-policy", reqBody)
		c.Set("org_id", orgID)
		if userID != "" {
			c.Set("user_id", userID)
		}
		handler(c)
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode response %q: %v", w.Body.String(), err)
		}
		return w.Code, out
	}

	// No row yet: GET must return the configured default via the documented
	// ErrNoRows fallback — before v78 this path 500'd instead.
	code, out := call(t, h.HandleGetRetentionPolicy, defaultOrg, "", "")
	if code != http.StatusOK || out["source"] != "default" || out["retention_days"] != float64(30) {
		t.Fatalf("GET without row: code=%d body=%v, want 200/default/30", code, out)
	}

	// PUT inserts (upsert path 1) and records the actor as updated_by.
	code, out = call(t, h.HandleSetRetentionPolicy, defaultOrg, adminUID, `{"retention_days": 7}`)
	if code != http.StatusOK || out["retention_days"] != float64(7) {
		t.Fatalf("PUT insert: code=%d body=%v, want 200/7", code, out)
	}

	// PUT again updates in place (upsert path 2, ON CONFLICT (org_id)).
	code, out = call(t, h.HandleSetRetentionPolicy, defaultOrg, adminUID, `{"retention_days": 14}`)
	if code != http.StatusOK || out["retention_days"] != float64(14) {
		t.Fatalf("PUT update: code=%d body=%v, want 200/14", code, out)
	}
	var rows int
	var updatedBy string
	if err := db.Pool.QueryRow(ctx, `
		SELECT COUNT(*), MAX(updated_by::text)
		  FROM recording_retention_policies
		 WHERE org_id = $1::uuid`, defaultOrg).Scan(&rows, &updatedBy); err != nil {
		t.Fatalf("inspect policy row: %v", err)
	}
	if rows != 1 || updatedBy != adminUID {
		t.Fatalf("policy row after upserts: count=%d updated_by=%q, want 1/%s", rows, updatedBy, adminUID)
	}

	// GET now reflects the stored policy, not the default.
	code, out = call(t, h.HandleGetRetentionPolicy, defaultOrg, "", "")
	if code != http.StatusOK || out["source"] != "policy" || out["retention_days"] != float64(14) {
		t.Fatalf("GET with row: code=%d body=%v, want 200/policy/14", code, out)
	}

	// The enforcer's resolution chain must pick up the org policy (layer 2)
	// over the configured default — this is the read the sweeper runs.
	if got := h.resolveEffectiveRetention(ctx, nil, defaultOrg); got != 14 {
		t.Errorf("resolveEffectiveRetention(defaultOrg) = %d, want 14 (org policy)", got)
	}
	// Cross-org: the other org has no policy row and must stay on the default.
	if got := h.resolveEffectiveRetention(ctx, nil, otherOrg); got != 30 {
		t.Errorf("resolveEffectiveRetention(otherOrg) = %d, want 30 (default)", got)
	}

	// retention_days = 0 is the documented "infinite retention" contract: the
	// handler accepts it and the resolver propagates it so the sweeper skips.
	code, out = call(t, h.HandleSetRetentionPolicy, otherOrg, "", `{"retention_days": 0}`)
	if code != http.StatusOK {
		t.Fatalf("PUT zero: code=%d body=%v, want 200", code, out)
	}
	if got := h.resolveEffectiveRetention(ctx, nil, otherOrg); got != 0 {
		t.Errorf("resolveEffectiveRetention(otherOrg after 0) = %d, want 0 (infinite)", got)
	}

	// Negative values are rejected before touching the table.
	code, out = call(t, h.HandleSetRetentionPolicy, otherOrg, "", `{"retention_days": -1}`)
	if code != http.StatusBadRequest {
		t.Fatalf("PUT negative: code=%d body=%v, want 400", code, out)
	}
}
