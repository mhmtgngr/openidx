package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// THE TENANT TERM IS ON THE LINK ROW, NOT ON A LEFT JOIN.
//
// Before v200 the identity-link list joined identity_providers with
// `LEFT JOIN ... AND ip.org_id = $2` and filtered nothing: a LEFT JOIN keeps
// every row of the left table and merely nulls the right side, so the tenant
// term was a decoration and the list returned a user's links regardless of
// which tenant was asking. Both DELETEs addressed a link by bare id.
//
// This runs as the test database's superuser, deliberately: RLS does not
// apply to it, so what is measured is the SQL the handler sends, which is the
// thing the belt test (internal/oauth, as openidx_app) cannot see.
func TestIdentityLinks_TenantIsolation(t *testing.T) {
	db, cleanup := setupPAMTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const orgA = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	var orgB string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('links-b','links-b') RETURNING id::text`).Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	seed := func(org, name string) (user, prov, link string) {
		t.Helper()
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO users (org_id, username, email, enabled)
			VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
			org, name+"-"+suffix, name+"-"+suffix+"@example.test").Scan(&user); err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO identity_providers (org_id, name, provider_type, issuer_url, client_id, client_secret)
			VALUES ($1::uuid, $2, 'oidc', $3, 'cid', 'sec') RETURNING id::text`,
			org, "idp-"+name, "https://"+name+"-"+suffix+".example.test").Scan(&prov); err != nil {
			t.Fatalf("seed provider %s: %v", name, err)
		}
		// The same external subject in both tenants -- the case v200 decides.
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO user_identity_links (org_id, user_id, provider_id, external_id)
			VALUES ($1::uuid, $2::uuid, $3::uuid, 'shared-subject') RETURNING id::text`,
			org, user, prov).Scan(&link); err != nil {
			t.Fatalf("seed link %s: %v", name, err)
		}
		return user, prov, link
	}
	userA, _, linkA := seed(orgA, "links-a")
	userB, _, linkB := seed(orgB, "links-b")

	s := &Service{db: db, logger: zap.NewNop()}
	call := func(handler gin.HandlerFunc, org, method, path string, params gin.Params) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(method, path, nil).
			WithContext(orgctx.With(context.Background(), orgctx.Org{ID: org}))
		c.Params = params
		c.Set("roles", []string{"admin"})
		c.Set("user_id", "admin-"+org)
		handler(c)
		return w
	}
	links := func(w *httptest.ResponseRecorder) []map[string]any {
		t.Helper()
		var body struct {
			Data []map[string]any `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v (%s)", err, w.Body.String())
		}
		return body.Data
	}

	t.Run("a tenant listing another tenant's user sees no links", func(t *testing.T) {
		w := call(s.handleListUserIdentityLinks, orgA, http.MethodGet, "/users/"+userB+"/identity-links",
			gin.Params{{Key: "id", Value: userB}})
		if w.Code != http.StatusOK {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
		if got := links(w); len(got) != 0 {
			t.Fatalf("tenant A was shown tenant B's links: %v", got)
		}
	})

	t.Run("a tenant listing its own user sees its link (control)", func(t *testing.T) {
		w := call(s.handleListUserIdentityLinks, orgA, http.MethodGet, "/users/"+userA+"/identity-links",
			gin.Params{{Key: "id", Value: userA}})
		if got := links(w); len(got) != 1 || got[0]["id"] != linkA {
			t.Fatalf("want exactly link %s, got %v", linkA, got)
		}
	})

	stillThere := func(link string) bool {
		var n int
		if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM user_identity_links WHERE id = $1`, link).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n == 1
	}

	t.Run("a tenant cannot delete another tenant's link, with or without the user in the path", func(t *testing.T) {
		w := call(s.handleDeleteIdentityLink, orgA, http.MethodDelete, "/users/"+userB+"/identity-links/"+linkB,
			gin.Params{{Key: "id", Value: userB}, {Key: "linkId", Value: linkB}})
		if w.Code != http.StatusNotFound {
			t.Fatalf("with user id: status %d, want 404: %s", w.Code, w.Body.String())
		}
		w = call(s.handleDeleteIdentityLink, orgA, http.MethodDelete, "/identity-links/"+linkB,
			gin.Params{{Key: "linkId", Value: linkB}})
		if w.Code != http.StatusNotFound {
			t.Fatalf("bare id: status %d, want 404: %s", w.Code, w.Body.String())
		}
		if !stillThere(linkB) {
			t.Fatal("tenant B's link was deleted by tenant A")
		}
	})

	t.Run("the owning tenant can delete it (control)", func(t *testing.T) {
		w := call(s.handleDeleteIdentityLink, orgB, http.MethodDelete, "/users/"+userB+"/identity-links/"+linkB,
			gin.Params{{Key: "id", Value: userB}, {Key: "linkId", Value: linkB}})
		if w.Code != http.StatusOK && w.Code != http.StatusNoContent {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
		if stillThere(linkB) {
			t.Fatal("the owning tenant's delete did nothing")
		}
	})
}
