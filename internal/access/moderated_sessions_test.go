package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// TestModeratedSessionStateMachine proves the PAM C3 four-eyes gate end to end
// against a migrated DB: a require_moderator connection blocks the requester
// until a moderator joins, a moderator cannot be the requester (four-eyes),
// join is atomic (single claim), and end terminates the session. It drives the
// real HTTP handlers over gin test contexts carrying org + user identity.
func TestModeratedSessionStateMachine(t *testing.T) {
	db, cleanup := setupTestDB(t) // skips if testcontainers unavailable
	defer cleanup()

	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const org = "00000000-0000-0000-0000-000000000010"
	const requester = "00000000-0000-0000-0000-0000000000a1"
	const moderator = "00000000-0000-0000-0000-0000000000b2"

	// Seed a route + a require_moderator connection.
	var routeID, connID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO proxy_routes (org_id, name, from_url, to_url)
		VALUES ($1::uuid, 'modtest', 'https://modtest.example.com', 'ssh://h:22')
		RETURNING id::text`, org).Scan(&routeID); err != nil {
		t.Fatalf("seed route: %v", err)
	}
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO guacamole_connections
		    (route_id, org_id, guacamole_connection_id, protocol, hostname, port,
		     require_approval, record_session, require_moderator)
		VALUES ($1::uuid, $2::uuid, 'gc-1', 'ssh', 'h', 22, false, false, true)
		RETURNING id::text`, routeID, org).Scan(&connID); err != nil {
		t.Fatalf("seed connection: %v", err)
	}

	s := &Service{db: db, logger: zap.NewNop()}

	// 1. Before any moderator, the gate reports inactive.
	if ok, err := s.checkModerationActive(ctx, org, connID, requester); err != nil || ok {
		t.Fatalf("checkModerationActive before request = (%v,%v), want (false,nil)", ok, err)
	}

	// 2. Requester opens a moderation request.
	modID := requestModeration(t, s, org, requester, routeID)

	// 3. Still pending → gate inactive.
	if ok, _ := s.checkModerationActive(ctx, org, connID, requester); ok {
		t.Fatal("gate active while still pending, want inactive")
	}

	// 4. Requester cannot self-moderate (four-eyes).
	if code := joinModeration(t, s, org, requester, modID); code != http.StatusConflict {
		t.Fatalf("self-join status = %d, want 409 (four-eyes)", code)
	}

	// 5. A real moderator joins → active.
	if code := joinModeration(t, s, org, moderator, modID); code != http.StatusOK {
		t.Fatalf("moderator join status = %d, want 200", code)
	}

	// 6. Gate now active → connect would proceed.
	if ok, err := s.checkModerationActive(ctx, org, connID, requester); err != nil || !ok {
		t.Fatalf("checkModerationActive after join = (%v,%v), want (true,nil)", ok, err)
	}

	// 7. A second join is a no-op conflict (already claimed).
	if code := joinModeration(t, s, org, moderator, modID); code != http.StatusConflict {
		t.Fatalf("double-join status = %d, want 409", code)
	}

	// 8. End the moderation → gate inactive again.
	if code := endModeration(t, s, org, moderator, modID); code != http.StatusOK {
		t.Fatalf("end status = %d, want 200", code)
	}
	if ok, _ := s.checkModerationActive(ctx, org, connID, requester); ok {
		t.Fatal("gate active after end, want inactive")
	}
}

func requestModeration(t *testing.T, s *Service, org, userID, routeID string) string {
	t.Helper()
	w := driveModeration(t, s, org, userID, http.MethodPost, "/pam/moderation/request",
		`{"route_id":"`+routeID+`","reason":"test"}`, func(c *gin.Context) { s.handleRequestModeration(c) })
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("request moderation status = %d, body = %s", w.Code, w.Body.String())
	}
	var body struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body.ID == "" {
		t.Fatal("no moderation id returned")
	}
	return body.ID
}

func joinModeration(t *testing.T, s *Service, org, userID, modID string) int {
	t.Helper()
	w := driveModeration(t, s, org, userID, http.MethodPost, "/pam/moderation/"+modID+"/join", "",
		func(c *gin.Context) { c.Params = gin.Params{{Key: "id", Value: modID}}; s.handleJoinModeration(c) })
	return w.Code
}

func endModeration(t *testing.T, s *Service, org, userID, modID string) int {
	t.Helper()
	w := driveModeration(t, s, org, userID, http.MethodPost, "/pam/moderation/"+modID+"/end", "",
		func(c *gin.Context) { c.Params = gin.Params{{Key: "id", Value: modID}}; s.handleEndModeration(c) })
	return w.Code
}

// driveModeration runs a handler over a gin test context carrying org + user_id.
func driveModeration(t *testing.T, s *Service, org, userID, method, path, body string, fn func(*gin.Context)) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req = req.WithContext(orgctx.With(req.Context(), orgctx.Org{ID: org}))
	c.Request = req
	c.Set("user_id", userID)
	fn(c)
	return w
}

// TestEndModerationRequiresAParty covers the check this handler's own doc
// comment claims and the code did not make.
//
// handleEndModeration is documented "(requester or moderator)". Its route
// carries no role guard, and the UPDATE checked neither: any authenticated
// caller could end any moderation session in the organization by naming its id
// — and ending it terminates the underlying privileged session, which is the
// moderator's kill switch. The direction of the error is deny rather than
// grant, so it cost availability rather than granting access; it is still a
// control the code asserted and did not make.
//
// An administrator keeps the ability to end a stuck session, which is why the
// role check sits beside the party check rather than replacing it.
func TestEndModerationRequiresAParty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const (
		org       = "00000000-0000-0000-0000-000000000010"
		requester = "00000000-0000-0000-0000-0000000000a3"
		moderator = "00000000-0000-0000-0000-0000000000b4"
		stranger  = "00000000-0000-0000-0000-0000000000c5"
	)
	var routeID, connID, modID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO proxy_routes (org_id, name, from_url, to_url)
		VALUES ($1::uuid, 'modend', 'https://modend.example.com', 'ssh://h:22')
		RETURNING id::text`, org).Scan(&routeID); err != nil {
		t.Fatalf("seed route: %v", err)
	}
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO guacamole_connections
		    (route_id, org_id, guacamole_connection_id, protocol, hostname, port,
		     require_approval, record_session, require_moderator)
		VALUES ($1::uuid, $2::uuid, 'gc-end', 'ssh', 'h', 22, false, false, true)
		RETURNING id::text`, routeID, org).Scan(&connID); err != nil {
		t.Fatalf("seed connection: %v", err)
	}
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO guacamole_moderation_sessions
		    (org_id, connection_id, requester_id, moderator_id, status, joined_at)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 'active', NOW())
		RETURNING id::text`, org, connID, requester, moderator).Scan(&modID); err != nil {
		t.Fatalf("seed moderation session: %v", err)
	}

	s := &Service{db: db, logger: zap.NewNop()}

	end := func(actor string, roles []string) int {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodPost, "/pam/moderation/"+modID+"/end", nil)
		req = req.WithContext(orgctx.With(req.Context(), orgctx.Org{ID: org}))
		c.Request = req
		c.Params = gin.Params{{Key: "id", Value: modID}}
		c.Set("user_id", actor)
		if roles != nil {
			c.Set("roles", roles)
		}
		s.handleEndModeration(c)
		return w.Code
	}
	stillActive := func() bool {
		var st string
		db.Pool.QueryRow(ctx, `SELECT status FROM guacamole_moderation_sessions WHERE id=$1`, modID).Scan(&st)
		return st == "active"
	}

	t.Run("a stranger cannot end it", func(t *testing.T) {
		if code := end(stranger, []string{"user"}); code != http.StatusConflict {
			t.Errorf("a user who is neither requester nor moderator ended the session (%d). "+
				"Ending it terminates the underlying privileged session — the moderator's "+
				"kill switch, available to everyone", code)
		}
		if !stillActive() {
			t.Error("the moderation session was ended by a stranger")
		}
	})

	t.Run("the requester can end it", func(t *testing.T) {
		if code := end(requester, []string{"user"}); code != http.StatusOK {
			t.Errorf("the requester could not end their own moderation session (%d)", code)
		}
		if stillActive() {
			t.Error("the requester's end did not take effect")
		}
	})
}
