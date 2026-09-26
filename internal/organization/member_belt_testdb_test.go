package organization

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// ADDING A MEMBER, MEASURED AS THE APPLICATION ROLE.
//
// users carries the FORCE RLS belt; organizations and organization_members do
// not. The member routes look a user up by id outside the belt and apply their
// own rule to the organization it names. A superuser, which RLS does not apply
// to, cannot tell whether that is needed, so this runs only as
// TEST_POSTGRES_DSN, a role RLS applies to, with users under the policy shape
// SECURITY-TENANCY.md documents for every belted table. The requests carry the
// organization the tenant resolver would have attached:
//
//   - A's owner, scoped to A, adds A's user and gets 404 for B's;
//   - an owner of A whose token belongs to C -- scoped to C, where the belt
//     hides A's users -- still adds A's user and not B's;
//   - the platform admin, scoped to the default organization, adds B's user
//     to A, which the belt alone would have answered as no user at all.
func TestAddingAMemberUnderTheBelt(t *testing.T) {
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set; skipping the member lookup under the belt")
	}
	gin.SetMode(gin.TestMode)
	ctx := context.Background()

	schema := "orgmembers_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	bootstrap, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	var super bool
	require.NoError(t, bootstrap.QueryRow(ctx, `SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&super))
	require.False(t, super, "TEST_POSTGRES_DSN is a role RLS does not apply to; this test would pass by bypassing")
	_, err = bootstrap.Exec(ctx, `CREATE SCHEMA `+schema)
	bootstrap.Close()
	require.NoError(t, err, "the test DSN must be allowed to create a schema")
	t.Cleanup(func() {
		if drop, derr := pgxpool.New(context.Background(), dsn); derr == nil {
			_, _ = drop.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
			drop.Close()
		}
	})
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	db, err := database.NewPostgres(dsn + sep + "search_path=" + schema)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	raw := db.Pool.Raw()
	for _, stmt := range []string{
		`CREATE TABLE organizations (id UUID PRIMARY KEY, name TEXT NOT NULL, slug TEXT NOT NULL)`,
		`CREATE TABLE organization_members (id UUID PRIMARY KEY, organization_id UUID NOT NULL, user_id UUID NOT NULL,
			role VARCHAR(50) NOT NULL DEFAULT 'member', joined_at TIMESTAMPTZ DEFAULT NOW(), invited_by UUID,
			UNIQUE (organization_id, user_id))`,
		`CREATE TABLE users (id UUID PRIMARY KEY, org_id UUID NOT NULL)`,
		`CREATE POLICY pol_users_org_scope ON users
			USING (current_setting('app.bypass_rls', true) = 'on'
			       OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
			WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
			       OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)`,
		`ALTER TABLE users ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE users FORCE ROW LEVEL SECURITY`,
	} {
		_, err := raw.Exec(ctx, stmt)
		require.NoError(t, err, stmt)
	}

	orgA, orgB, orgC, defaultOrg := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	bypass := orgctx.WithBypassRLS(ctx)
	for _, org := range []string{orgA, orgB, orgC, defaultOrg} {
		_, err := db.Pool.Exec(bypass, `INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $2)`, org, "org-"+org)
		require.NoError(t, err)
	}
	user := func(org string) string {
		id := uuid.NewString()
		_, err := db.Pool.Exec(bypass, `INSERT INTO users (id, org_id) VALUES ($1, $2)`, id, org)
		require.NoError(t, err)
		return id
	}
	ownerA, ownerFromC := user(orgA), user(orgC)
	usersA := []string{user(orgA), user(orgA), user(orgA)}
	userB := user(orgB)
	platform := user(defaultOrg)
	for _, owner := range []string{ownerA, ownerFromC} {
		_, err := db.Pool.Exec(bypass, `INSERT INTO organization_members (id, organization_id, user_id, role) VALUES ($1, $2, $3, 'owner')`,
			uuid.NewString(), orgA, owner)
		require.NoError(t, err)
	}
	var visible int
	require.NoError(t, db.Pool.QueryRow(orgctx.With(ctx, orgctx.Org{ID: orgC}), `SELECT COUNT(*) FROM users WHERE org_id = $1`, orgA).Scan(&visible))
	require.Zero(t, visible, "the belt is not hiding A's users from a request scoped to C; the test would prove nothing")

	svc := &Service{db: db, logger: zap.NewNop()}
	engineFor := func(userID, scopedTo string, platformAdmin bool) *gin.Engine {
		r := gin.New()
		v1 := r.Group("/api/v1")
		v1.Use(func(c *gin.Context) {
			c.Set("user_id", userID)
			reqCtx := orgctx.With(c.Request.Context(), orgctx.Org{ID: scopedTo})
			if platformAdmin {
				reqCtx = orgctx.WithPlatformAdmin(reqCtx)
			}
			c.Request = c.Request.WithContext(reqCtx)
			c.Next()
		})
		RegisterRoutes(v1, svc)
		return r
	}
	add := func(r *gin.Engine, userID string) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+orgA+"/members",
			strings.NewReader(`{"user_id":"`+userID+`","role":"member"}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}
	member := func(userID string) bool {
		var n int
		require.NoError(t, db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM organization_members WHERE organization_id = $1 AND user_id = $2`,
			orgA, userID).Scan(&n))
		return n == 1
	}

	for _, tc := range []struct {
		name   string
		engine *gin.Engine
		user   string
		want   int
	}{
		{"A's owner, scoped to A, adding A's user", engineFor(ownerA, orgA, false), usersA[0], http.StatusCreated},
		{"A's owner, scoped to A, adding B's user", engineFor(ownerA, orgA, false), userB, http.StatusNotFound},
		{"an owner of A scoped to C adding A's user", engineFor(ownerFromC, orgC, false), usersA[1], http.StatusCreated},
		{"an owner of A scoped to C adding B's user", engineFor(ownerFromC, orgC, false), userB, http.StatusNotFound},
		{"the platform admin, scoped to the default organization, adding B's user", engineFor(platform, defaultOrg, true), userB, http.StatusCreated},
	} {
		if got := add(tc.engine, tc.user); got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, got, tc.want)
		}
		if got := member(tc.user); got != (tc.want == http.StatusCreated) {
			t.Errorf("%s: the user is a member of A = %v", tc.name, got)
		}
	}
}
