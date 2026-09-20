package identity

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

// The profile's "linked accounts" list and unlink carry the tenant on the link
// row (v200). Before, the list filtered the tenant on a LEFT JOIN -- a
// decoration, not a predicate -- and unlink addressed the row by id and user
// alone. Run as the test database's superuser so RLS does not apply and the
// SQL the handler sends is what is measured.
func TestMyIdentityLinks_TenantIsolation(t *testing.T) {
	db, cleanup := setupTestDB(t)
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
		`INSERT INTO organizations (name, slug) VALUES ('mylinks-b','mylinks-b') RETURNING id::text`).Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	seed := func(org, name string) (user, link string) {
		t.Helper()
		var prov string
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
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO user_identity_links (org_id, user_id, provider_id, external_id)
			VALUES ($1::uuid, $2::uuid, $3::uuid, 'shared-subject') RETURNING id::text`,
			org, user, prov).Scan(&link); err != nil {
			t.Fatalf("seed link %s: %v", name, err)
		}
		return user, link
	}
	userA, linkA := seed(orgA, "mylinks-a")
	userB, linkB := seed(orgB, "mylinks-b")

	s := &Service{db: db, logger: zap.NewNop()}
	call := func(handler gin.HandlerFunc, org, user, method, path string, params gin.Params) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(method, path, nil).
			WithContext(orgctx.With(context.Background(), orgctx.Org{ID: org}))
		c.Params = params
		c.Set("user_id", user)
		handler(c)
		return w
	}
	count := func(w *httptest.ResponseRecorder) int {
		t.Helper()
		var body struct {
			Data []json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v (%s)", err, w.Body.String())
		}
		return len(body.Data)
	}

	// A request whose tenant (the host) and whose subject (the token) disagree
	// must be answered by the tenant: B's user asking under A's host sees
	// nothing of B's.
	t.Run("a subject from another tenant sees no links under this tenant", func(t *testing.T) {
		w := call(s.handleGetMyIdentityLinks, orgA, userB, http.MethodGet, "/users/me/identity-links", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
		if n := count(w); n != 0 {
			t.Fatalf("tenant A answered with tenant B's %d link(s)", n)
		}
	})

	t.Run("a user in their own tenant sees their link (control)", func(t *testing.T) {
		w := call(s.handleGetMyIdentityLinks, orgA, userA, http.MethodGet, "/users/me/identity-links", nil)
		if n := count(w); n != 1 {
			t.Fatalf("want 1 link (%s), got %d", linkA, n)
		}
	})

	stillThere := func(link string) bool {
		var n int
		if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM user_identity_links WHERE id = $1`, link).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n == 1
	}

	t.Run("unlink under the wrong tenant is a 404 and deletes nothing", func(t *testing.T) {
		w := call(s.handleUnlinkMyIdentity, orgA, userB, http.MethodDelete, "/users/me/identity-links/"+linkB,
			gin.Params{{Key: "linkId", Value: linkB}})
		if w.Code != http.StatusNotFound {
			t.Fatalf("status %d, want 404: %s", w.Code, w.Body.String())
		}
		if !stillThere(linkB) {
			t.Fatal("tenant B's link was deleted through tenant A")
		}
	})

	t.Run("unlink in the owning tenant works (control)", func(t *testing.T) {
		w := call(s.handleUnlinkMyIdentity, orgB, userB, http.MethodDelete, "/users/me/identity-links/"+linkB,
			gin.Params{{Key: "linkId", Value: linkB}})
		if w.Code != http.StatusOK && w.Code != http.StatusNoContent {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
		if stillThere(linkB) {
			t.Fatal("the owning tenant's unlink did nothing")
		}
	})
}
