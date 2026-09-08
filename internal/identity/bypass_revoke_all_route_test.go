package identity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// The route this test drives, spelled once. service.go must register exactly
// this path against exactly this handler, and the assertion below says so: the
// defect was a disagreement between a route and its handler, so a test that
// invented its own path could not have caught it.
const revokeAllBypassRoute = "/users/:id/bypass-codes"

// TestRevokeAllBypassCodesRevokes drives DELETE /users/:id/bypass-codes.
//
// The handler read c.Param("user_id"). The route declares :id. gin returns ""
// for a name the matched route does not declare, so the revoke ran against the
// empty user and PostgreSQL refused the statement outright:
//
//	ERROR: invalid input syntax for type uuid: ""
//
// mfa_bypass_codes.user_id is UUID, so this was never a quiet zero -- it was a
// 400 on every call, worded as though the administrator had sent something
// wrong. Revoking every break-glass code a user holds is what you do the minute
// a bypass code leaks, and this endpoint has never once done it.
func TestRevokeAllBypassCodesRevokes(t *testing.T) {
	db, cleanup := setupMigratedDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	seedCtx := orgctx.WithBypassRLS(context.Background())
	const (
		org    = "00000000-0000-0000-0000-000000000010"
		target = "66666666-0000-0000-0000-0000000000a1"
		admin  = "66666666-0000-0000-0000-0000000000a2"
		codeA  = "66666666-0000-0000-0000-0000000000b1"
		codeB  = "66666666-0000-0000-0000-0000000000b2"
		other  = "66666666-0000-0000-0000-0000000000b3"
		bystdr = "66666666-0000-0000-0000-0000000000a3"
	)
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Pool.Exec(seedCtx, q, args...); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
	}
	exec(`INSERT INTO users (id, username, email, org_id) VALUES
	        ($1, 'bypass-target', 'bypass-target@test.local', $4),
	        ($2, 'bypass-admin',  'bypass-admin@test.local',  $4),
	        ($3, 'bypass-other',  'bypass-other@test.local',  $4)`,
		target, admin, bystdr, org)

	code := func(id, user, status string) {
		exec(`INSERT INTO mfa_bypass_codes (id, org_id, user_id, code_hash, reason, generated_by, valid_until, status)
		      VALUES ($1, $2, $3, 'hash', 'seeded by the test', $4, NOW() + INTERVAL '1 day', $5)`,
			id, org, user, admin, status)
	}
	code(codeA, target, "active")
	code(codeB, target, "active")
	// A third code belonging to somebody else: "revoke all" must mean all of
	// ONE user's, and an empty predicate would have taken this one too.
	code(other, bystdr, "active")

	svc := &Service{db: db, logger: zap.NewNop()}
	router := gin.New()
	router.DELETE(revokeAllBypassRoute, func(c *gin.Context) {
		c.Set("user_id", admin)
		c.Set("roles", []string{"admin"})
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
		svc.handleRevokeAllBypassCodes(c)
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/users/"+target+"/bypass-codes", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("revoke all returned %d (%s), want 200", w.Code, strings.TrimSpace(w.Body.String()))
	}
	var body struct {
		RevokedCount int `json:"revoked_count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response %q: %v", w.Body.String(), err)
	}
	if body.RevokedCount != 2 {
		t.Errorf("revoked_count = %d, want 2", body.RevokedCount)
	}

	var active int
	if err := db.Pool.QueryRow(seedCtx,
		`SELECT COUNT(*) FROM mfa_bypass_codes WHERE user_id = $1 AND status = 'active'`, target).Scan(&active); err != nil {
		t.Fatalf("read back the target's codes: %v", err)
	}
	if active != 0 {
		t.Errorf("the target still holds %d active bypass code(s) after revoke-all", active)
	}

	// The bystander keeps theirs. A revoke-all that reached every user would be
	// a worse defect than one that reached none.
	if err := db.Pool.QueryRow(seedCtx,
		`SELECT COUNT(*) FROM mfa_bypass_codes WHERE user_id = $1 AND status = 'active'`, bystdr).Scan(&active); err != nil {
		t.Fatalf("read back the bystander's codes: %v", err)
	}
	if active != 1 {
		t.Errorf("the bystander has %d active code(s), want 1: revoke-all took somebody else's", active)
	}

	// And the action is recorded. An MFA bypass being destroyed is exactly the
	// kind of event an auditor comes looking for.
	var audits int
	if err := db.Pool.QueryRow(seedCtx,
		`SELECT COUNT(*) FROM mfa_bypass_audit WHERE user_id = $1 AND action = 'revoked_all'`, target).Scan(&audits); err != nil {
		t.Fatalf("read back the audit trail: %v", err)
	}
	if audits != 1 {
		t.Errorf("revoked_all audit entries = %d, want 1", audits)
	}
}

// The handler is only correct relative to the path it is mounted on, so the
// pairing is pinned here as well as by tools/routereach.
func TestRevokeAllBypassCodesIsMountedOnTheRouteItReads(t *testing.T) {
	src, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatalf("read service.go: %v", err)
	}
	want := `DELETE("` + revokeAllBypassRoute + `", svc.handleRevokeAllBypassCodes)`
	if !strings.Contains(string(src), want) {
		t.Errorf("service.go no longer registers %s; the handler reads c.Param(\"id\") "+
			"and gin returns \"\" for a name the matched route does not declare", want)
	}
}
