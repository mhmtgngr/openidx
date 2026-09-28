package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/auth"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/organization"
)

// EDITING AN APPLICATION CHANGES ONLY ITS OWN ORGANIZATION'S OAUTH CLIENT.
//
// PUT /api/v1/applications/:id copies the new name, redirect URIs, PKCE and
// logout settings and api_access onto the OAuth client behind the application,
// and found that client by the client_id the application row names, alone. An
// administrator creates that row and chooses its client_id, so an application
// of A could name a client of B, and editing it rewrote B's client -- its
// redirect URIs included. The row-level-security belt refuses that write for
// the role the services run as; this test connects as a superuser, as the belt
// cannot, and drives RegisterRoutes behind the tenant resolver as
// cmd/admin-api serves it:
//
//   - A's administrator edits an application of A that names B's client: the
//     edit of the application itself is saved, and B's client reads back
//     unchanged;
//   - A's administrator edits an application of A backed by A's own client,
//     and the client takes the new redirect URIs.
func TestEditingAnApplicationChangesOnlyItsOwnOrganizationsClient(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupPAMTestDB(t)
	t.Cleanup(cleanup)
	ctx := orgctx.WithBypassRLS(context.Background())
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scalar := func(query string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(ctx, query, args...).Scan(&v); err != nil {
			t.Fatalf("read %q: %v", query, err)
		}
		return v
	}
	orgA := scalar(`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`, "app-sync-a-"+suffix)
	orgB := scalar(`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`, "app-sync-b-"+suffix)
	adminA := scalar(`INSERT INTO users (org_id, username, email, enabled) VALUES ($1::uuid, $2::text, $2::text || '@example.test', true)
		RETURNING id::text`, orgA, "app-sync-admin-"+suffix)
	client := func(org, name string) string {
		id := name + "-" + suffix
		scalar(`INSERT INTO oauth_clients (client_id, client_secret, name, type, redirect_uris, org_id)
			VALUES ($1, 's', $1, 'confidential', '["https://`+name+`.example.test/cb"]'::jsonb, $2::uuid) RETURNING client_id`, id, org)
		return id
	}
	clientB := client(orgB, "b-client")
	clientA := client(orgA, "a-client")
	redirects := func(clientID string) string {
		return scalar(`SELECT redirect_uris::text FROM oauth_clients WHERE client_id = $1`, clientID)
	}

	svc := NewService(db, &database.RedisClient{}, &config.Config{}, zap.NewNop())
	lookup := organization.NewOrgLookup(organization.NewService(db, &database.RedisClient{}, &config.Config{}, zap.NewNop()))
	r := gin.New()
	v1 := r.Group("/api/v1")
	v1.Use(func(c *gin.Context) {
		c.Set("user_id", adminA)
		c.Set("roles", []string{"admin"})
		c.Set("org_id", orgA)
		c.Next()
	})
	v1.Use(middleware.TenantResolver(lookup, middleware.TenantResolverConfig{
		DefaultOrgFallback:     true,
		DefaultOrgID:           middleware.DefaultOrgID,
		PlatformAdminPredicate: auth.SuperAdminPredicate,
	}))
	RegisterRoutes(v1, svc)
	send := func(method, path, body string) (int, string) {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Org-Slug", "app-sync-a-"+suffix)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}
	application := func(clientID string) string {
		code, body := send(http.MethodPost, "/api/v1/applications",
			`{"client_id":"`+clientID+`","name":"app `+clientID+`","type":"web","protocol":"openid-connect"}`)
		var app struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal([]byte(body), &app); err != nil || code != http.StatusCreated || app.ID == "" {
			t.Fatalf("create an application for %s: %d %s", clientID, code, body)
		}
		return app.ID
	}

	before := redirects(clientB)
	squat := application(clientB)
	if code, body := send(http.MethodPut, "/api/v1/applications/"+squat,
		`{"name":"renamed","redirect_uris":["https://attacker.example.test/cb"]}`); code != http.StatusOK {
		t.Fatalf("edit the application naming B's client: %d %s", code, body)
	}
	if got := scalar(`SELECT name FROM applications WHERE id = $1::uuid`, squat); got != "renamed" {
		t.Errorf("the application itself was not saved: %s", got)
	}
	if after := redirects(clientB); after != before {
		t.Errorf("an edit in A rewrote B's client:\n  before %s\n  after  %s", before, after)
	}

	own := application(clientA)
	if code, body := send(http.MethodPut, "/api/v1/applications/"+own,
		`{"redirect_uris":["https://a-moved.example.test/cb"]}`); code != http.StatusOK {
		t.Fatalf("edit A's own application: %d %s", code, body)
	}
	if got := redirects(clientA); !strings.Contains(got, "a-moved.example.test") {
		t.Errorf("A's own client did not take the edit: %s", got)
	}
}
