package identity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// Offboarding is one operation, so a partial one is not reported as whole.
//
// Five statements make up a leaver: disable the account, revoke the API keys,
// remove the group memberships, remove the role assignments, terminate the
// sessions. Only the first had its error checked; the other four ran as bare
// Exec calls with the error discarded, and the handler then answered "User
// offboarded successfully". So a leaver could be disabled while keeping every
// API key, every group, every role and every live session -- and the operator
// who pressed the button was told the offboarding was complete, which is the
// reason nobody would go back and look.
func TestOffboardingIsAllOrNothing(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE users (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), username VARCHAR(64),
			enabled BOOLEAN DEFAULT true, org_id UUID, updated_at TIMESTAMPTZ);
		CREATE TABLE api_keys (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID, status VARCHAR(16), org_id UUID);
		CREATE TABLE group_memberships (user_id UUID, group_id UUID, org_id UUID);
		CREATE TABLE user_roles (user_id UUID, role_id UUID, org_id UUID);
		CREATE TABLE sessions (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID, org_id UUID);
	`); err != nil {
		t.Fatalf("schema: %v", err)
	}

	const org = "00000000-0000-0000-0000-0000000000e1"
	var userID string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO users (username, org_id) VALUES ('leaver', $1) RETURNING id::text`, org).Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	seed := func(q string) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, q, userID, org); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
	}
	seed(`INSERT INTO api_keys (user_id, status, org_id) VALUES ($1, 'active', $2)`)
	seed(`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1, gen_random_uuid(), $2)`)
	seed(`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1, gen_random_uuid(), $2)`)
	seed(`INSERT INTO sessions (user_id, org_id) VALUES ($1, $2)`)

	gin.SetMode(gin.TestMode)
	svc := &Service{db: db, logger: zap.NewNop()}
	offboard := func() int {
		t.Helper()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Params = gin.Params{{Key: "id", Value: userID}}
		c.Request = httptest.NewRequest(http.MethodPost, "/users/"+userID+"/offboard", nil).
			WithContext(orgctx.With(context.Background(), orgctx.Org{ID: org}))
		svc.handleOffboardUser(c)
		return w.Code
	}
	count := func(q string) int {
		t.Helper()
		var n int
		if err := db.Pool.QueryRow(ctx, q, userID).Scan(&n); err != nil {
			t.Fatalf("count (%s): %v", q, err)
		}
		return n
	}
	stillHeld := func() (int, int, int, int, bool) {
		t.Helper()
		var enabled bool
		if err := db.Pool.QueryRow(ctx, `SELECT enabled FROM users WHERE id=$1`, userID).Scan(&enabled); err != nil {
			t.Fatalf("read the account: %v", err)
		}
		return count(`SELECT COUNT(*) FROM api_keys WHERE user_id=$1 AND status='active'`),
			count(`SELECT COUNT(*) FROM group_memberships WHERE user_id=$1`),
			count(`SELECT COUNT(*) FROM user_roles WHERE user_id=$1`),
			count(`SELECT COUNT(*) FROM sessions WHERE user_id=$1`),
			enabled
	}

	t.Run("a step that cannot run changes nothing", func(t *testing.T) {
		// user_roles out of reach: the account disable, the key revocation and
		// the group removal all succeed before it. That is exactly the state
		// the discarded errors produced and reported as success.
		if _, err := db.Pool.Exec(ctx, `ALTER TABLE user_roles RENAME TO user_roles_hidden`); err != nil {
			t.Fatalf("hide user_roles: %v", err)
		}
		code := offboard()
		if _, err := db.Pool.Exec(ctx, `ALTER TABLE user_roles_hidden RENAME TO user_roles`); err != nil {
			t.Fatalf("restore user_roles: %v", err)
		}

		if code != http.StatusInternalServerError {
			t.Errorf("a partial offboarding answered %d, want 500", code)
		}
		keys, groups, roles, sessions, enabled := stillHeld()
		if !enabled || keys != 1 || groups != 1 || roles != 1 || sessions != 1 {
			t.Errorf("a failed offboarding left the account half-processed: enabled=%v keys=%d "+
				"groups=%d roles=%d sessions=%d; all five steps are one operation",
				enabled, keys, groups, roles, sessions)
		}
	})

	t.Run("a complete offboarding removes everything", func(t *testing.T) {
		if code := offboard(); code != http.StatusOK {
			t.Fatalf("offboard answered %d, want 200", code)
		}
		keys, groups, roles, sessions, enabled := stillHeld()
		if enabled || keys != 0 || groups != 0 || roles != 0 || sessions != 0 {
			t.Errorf("a leaver kept something: enabled=%v keys=%d groups=%d roles=%d sessions=%d",
				enabled, keys, groups, roles, sessions)
		}
	})
}
