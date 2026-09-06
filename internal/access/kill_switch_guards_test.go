package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// The kill switch is the most destructive single action an administrator has:
// it severs a user's live access across IAM, PAM and Ziti, and with
// disable_user it disables the account and deletes the overlay identity. Three
// checks stand in front of all of that, and none of them was named by a test.
//
// The pillar work itself is deliberately out of scope here — it reaches a Ziti
// controller and a Guacamole broker. What these tests pin is what has to be
// true BEFORE any of it runs.

const (
	ksOrgA     = "00000000-0000-0000-0000-0000000000a0"
	ksOrgB     = "00000000-0000-0000-0000-0000000000b0"
	ksVictim   = "00000000-0000-0000-0000-0000000000a1"
	ksAdmin    = "00000000-0000-0000-0000-0000000000a2"
	ksOtherOrg = "00000000-0000-0000-0000-0000000000b1"
)

const killSwitchSchema = `
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    org_id UUID NOT NULL
);
`

func newKillSwitchService(t *testing.T) (*Service, context.Context) {
	t.Helper()

	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: ksOrgA})
	if _, err := db.Pool.Exec(ctx, killSwitchSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	seed := []struct{ id, name, org string }{
		{ksVictim, "victim", ksOrgA},
		{ksAdmin, "root", ksOrgA},
		{ksOtherOrg, "tenant-b-user", ksOrgB},
	}
	for _, u := range seed {
		if _, err := db.Pool.Exec(ctx,
			`INSERT INTO users (id, username, org_id) VALUES ($1, $2, $3)`, u.id, u.name, u.org); err != nil {
			t.Fatalf("seed %s: %v", u.name, err)
		}
	}

	return &Service{db: db, config: &config.Config{}, logger: zap.NewNop()}, ctx
}

func killSwitch(t *testing.T, s *Service, ctx context.Context, targetID, actorID, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/access/users/"+targetID+"/kill-switch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req.WithContext(ctx)
	c.Params = gin.Params{{Key: "id", Value: targetID}}
	if actorID != "" {
		c.Set("user_id", actorID)
	}
	s.handleUserKillSwitch(c)
	return w
}

func TestKillSwitchRequiresAnOrganizationContext(t *testing.T) {
	s, _ := newKillSwitchService(t)

	// No orgctx: the request cannot say which tenant it is acting for, and the
	// user lookup below would then be unscoped.
	w := killSwitch(t, s, context.Background(), ksVictim, ksAdmin, `{"reason":"test"}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

func TestKillSwitchWillNotReachIntoAnotherTenant(t *testing.T) {
	s, ctx := newKillSwitchService(t)

	// A real user, in another organization. The answer must be the same as for
	// a user that does not exist — anything else confirms the account's
	// existence to an administrator with no business knowing.
	w := killSwitch(t, s, ctx, ksOtherOrg, ksAdmin, `{"reason":"test"}`)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant status = %d, want 404", w.Code)
	}
	missing := killSwitch(t, s, ctx, uuid.New().String(), ksAdmin, `{"reason":"test"}`)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("unknown-user status = %d, want 404", missing.Code)
	}
	if w.Body.String() != missing.Body.String() {
		t.Fatalf("a user in another org answered %s but an unknown user answered %s",
			w.Body.String(), missing.Body.String())
	}

	// And nothing happened to the row.
	var enabled bool
	if err := s.db.Pool.QueryRow(ctx, `SELECT enabled FROM users WHERE id = $1`, ksOtherOrg).Scan(&enabled); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !enabled {
		t.Fatal("a cross-tenant kill switch disabled the account anyway")
	}
}

func TestKillSwitchRefusesToSeverTheCallersOwnAccess(t *testing.T) {
	s, ctx := newKillSwitchService(t)

	// Locking yourself out of the console mid-incident is not a recoverable
	// mistake, and the action is idempotent enough to look harmless.
	w := killSwitch(t, s, ctx, ksAdmin, ksAdmin, `{"reason":"oops","disable_user":true}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body: %v", err)
	}
	if got, _ := body["error"].(string); !strings.Contains(got, "your own account") {
		t.Fatalf("error = %q, want it to name the reason", got)
	}

	var enabled bool
	if err := s.db.Pool.QueryRow(ctx, `SELECT enabled FROM users WHERE id = $1`, ksAdmin).Scan(&enabled); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !enabled {
		t.Fatal("the caller's own account was disabled")
	}
}
