package access

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

// Tenant isolation for the temporary vendor access surface, migration v148.
//
// A temp access link grants an OUTSIDE PARTY SSH/RDP/VNC into an internal host.
// v71 closed the cross-tenant IDOR on the links table — before it, any
// authenticated user could enumerate, read and revoke every other tenant's
// vendor access — and it deliberately stopped short of the FORCE RLS belt,
// recording its reason in the migration: the public token-redemption path has
// no org context, so the belt would fail closed and break redemption.
//
// That reason expired. v145 belted magic_links, which is the same shape — a
// single-use secret redeemed by someone with no session — and redeems it under
// orgctx.WithBypassRLS, pinned by TestPreResolutionLookupsUnderRLS. v148 does
// the same here, so these tests must prove BOTH halves: the belt is on, and
// redemption still works with no organization on the context.
//
// The second table is the one v71's "the belt would add no protection there"
// missed. temp_access_usage — who redeemed a link, from which IP, with what
// user agent — has never had a tenant column, and its read was `WHERE link_id =
// $1` alone, safe only because a separate EXISTS statement ran first. Safety
// living in the order two statements are written in is the shape v143 and v147
// both found recorded as though it were a property.
//
// TestTempAccess_TenantIsolation in temp_access_isolation_test.go already
// covers v71's half — list/get/revoke never cross tenants — against a
// hand-rolled schema. This file is the v148 half and needs the REAL migrations,
// because what it exercises is the redemption path, the usage record and the
// expiry sweep, none of which that schema has.
//
// The pool connects as the container superuser, which bypasses RLS, so what
// these prove is the explicit predicate in each query and that redemption still
// works without an organization; the belt itself is proved under the
// NOSUPERUSER role by test/integration/cross_org_test.go.
func TestTempAccess_BeltAndUsageRecord(t *testing.T) {
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

	const orgA = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	orgB := ""
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('temp-access-b', 'temp-access-b') RETURNING id::text`).
		Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	seedUser := func(org, name string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO users (username, email, enabled, org_id)
			VALUES ($1::varchar, $1::varchar || '@ta.test', true, $2::uuid)
			RETURNING id::text`, name, org).Scan(&id); err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
		return id
	}
	// created_by is NOT NULL on the real schema (v54).
	creatorA := seedUser(orgA, "ta-a-"+suffix)
	creatorB := seedUser(orgB, "ta-b-"+suffix)

	seedLink := func(org, creator, name, token string) string {
		t.Helper()
		var id string
		// Every column the redemption handler scans into a non-pointer field
		// must be non-NULL, or the row Scan fails and the handler answers 404 —
		// the same trap temp_access_isolation_test.go documents. A non-empty
		// guacamole_connection_id also sends the success path down the redirect
		// branch rather than c.HTML, which panics with no templates loaded.
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO temp_access_links (
				token, name, description, protocol, target_host, target_port, username,
				created_by, created_by_email, expires_at, max_uses, current_uses,
				allowed_ips, notify_email, guacamole_connection_id, access_url,
				last_used_ip, status, created_at, updated_at, org_id)
			VALUES ($1, $2, '', 'ssh', 'internal-db.corp', 22, 'vendor',
				$4, 'vendor@example.test', NOW() + INTERVAL '1 day', 0, 0,
				'{}', '', $5, $6,
				'', 'active', NOW(), NOW(), $3)
			RETURNING id::text`, token, name, org, creator,
			"guac-"+token, "https://x/temp-access/"+token).Scan(&id); err != nil {
			t.Fatalf("seed link %s: %v", name, err)
		}
		return id
	}

	tokenA := "tok-a-" + suffix
	tokenB := "tok-b-" + suffix
	linkA := seedLink(orgA, creatorA, "org A vendor link", tokenA)
	linkB := seedLink(orgB, creatorB, "org B vendor link", tokenB)

	svc := &Service{db: db, logger: zap.NewNop()}

	call := func(org string, h gin.HandlerFunc, method, path string, params map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(method, path, nil).
			WithContext(orgctx.With(context.Background(), orgctx.Org{ID: org}))
		c.Set("roles", []string{"admin"})
		c.Set("user_id", "00000000-0000-0000-0000-000000000001")
		for k, v := range params {
			c.Params = append(c.Params, gin.Param{Key: k, Value: v})
		}
		h(c)
		return w
	}

	t.Run("redemption works with no organization on the context", func(t *testing.T) {
		// The half v71 was protecting, and the half a naive belt breaks. This
		// runs the real handler on a bare context — no orgctx.With at all —
		// which is exactly how a vendor's browser arrives.
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/temp-access/"+tokenA, nil)
		c.Params = append(c.Params, gin.Param{Key: "token", Value: tokenA})
		svc.handleUseTempAccess(c)

		if w.Code != http.StatusFound {
			t.Fatalf("redemption returned %d with no org on the context, want a 302 to Guacamole. "+
				"Under FORCE RLS the token lookup must run bypassed; without that every vendor link "+
				"stops redeeming, which is precisely why v71 declined the belt (body: %s)",
				w.Code, w.Body.String())
		}

		// The use is recorded, in the ISSUING tenant — not the redeemer's
		// (there isn't one) and not the oldest org.
		var n int
		if err := db.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM temp_access_usage WHERE link_id = $1 AND org_id = $2`, linkA, orgA).Scan(&n); err != nil {
			t.Fatalf("read usage: %v", err)
		}
		if n != 1 {
			t.Fatalf("the vendor connected and %d usage rows landed in org A; the record of an "+
				"outside party reaching an internal host must not go missing", n)
		}
		var uses int
		if err := db.Pool.QueryRow(ctx,
			`SELECT current_uses FROM temp_access_links WHERE id = $1`, linkA).Scan(&uses); err != nil {
			t.Fatalf("read link: %v", err)
		}
		if uses != 1 {
			t.Fatalf("current_uses = %d after one redemption, want 1 (the max-uses limit is "+
				"enforced from this counter)", uses)
		}
	})

	t.Run("usage history is scoped by the query, not by statement order", func(t *testing.T) {
		// Org B asking for org A's link id must get a 404 from the link check.
		w := call(orgB, svc.handleGetTempAccessUsage, "GET", "/temp-access/"+linkA+"/usage",
			map[string]string{"id": linkA})
		if w.Code != http.StatusNotFound {
			t.Fatalf("org B read org A's usage history: %d %s", w.Code, w.Body.String())
		}

		// And org A gets its own. The org predicate added in v148 must not have
		// broken the legitimate read while closing the cross-tenant one.
		w = call(orgA, svc.handleGetTempAccessUsage, "GET", "/temp-access/"+linkA+"/usage",
			map[string]string{"id": linkA})
		if w.Code != http.StatusOK {
			t.Fatalf("org A's own usage history: %d %s", w.Code, w.Body.String())
		}
		var got struct {
			Usage []TempAccessUsage `json:"usage"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("bad json: %s", w.Body.String())
		}
		if len(got.Usage) != 1 {
			t.Fatalf("org A sees %d usage rows for its own link, want the 1 recorded above; the "+
				"v148 org predicate must scope the read, not empty it", len(got.Usage))
		}

		// And the predicate must be LOAD-BEARING, not decorative. A usage row
		// whose org_id is org B's, hanging off org A's link, is what a bug or a
		// bad backfill produces — and it is the only case where the new
		// predicate does work the pre-existing EXISTS check does not. Under the
		// old `WHERE link_id = $1` this row comes back to org A.
		var stray string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO temp_access_usage (link_id, ip_address, user_agent, connected_at, org_id)
			VALUES ($1, '198.51.100.9', 'stray-ua', NOW(), $2) RETURNING id::text`,
			linkA, orgB).Scan(&stray); err != nil {
			t.Fatalf("seed mis-tenanted usage row: %v", err)
		}
		defer func() { _, _ = db.Pool.Exec(ctx, `DELETE FROM temp_access_usage WHERE id = $1`, stray) }()

		w = call(orgA, svc.handleGetTempAccessUsage, "GET", "/temp-access/"+linkA+"/usage",
			map[string]string{"id": linkA})
		if w.Code != http.StatusOK {
			t.Fatalf("org A's usage history after the stray row: %d %s", w.Code, w.Body.String())
		}
		got.Usage = nil
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("bad json: %s", w.Body.String())
		}
		for _, u := range got.Usage {
			if u.ID == stray {
				t.Fatal("org A read a usage row belonging to org B. The link check that runs first " +
					"cannot catch this: it only proves the LINK is org A's. The tenant has to be in " +
					"the usage query itself")
			}
		}
		if len(got.Usage) != 1 {
			t.Fatalf("org A sees %d usage rows, want 1 (its own; the org B row filtered)", len(got.Usage))
		}
	})

	t.Run("the expiry sweep still reaches every tenant under the belt", func(t *testing.T) {
		// The third pattern: a write that is install-wide on purpose. Under
		// FORCE RLS it silently matches zero rows unless it declares the bypass,
		// and the failure mode is a vendor keeping SSH into an internal host
		// past the link's expiry.
		if _, err := db.Pool.Exec(ctx,
			`UPDATE temp_access_links SET expires_at = NOW() - INTERVAL '1 hour' WHERE id IN ($1, $2)`,
			linkA, linkB); err != nil {
			t.Fatalf("age the links: %v", err)
		}

		// Exactly the statement internal/governance/jit_expiry.go runs, on a
		// context with no organization, as the background worker has.
		if _, err := db.Pool.Exec(orgctx.WithBypassRLS(context.Background()),
			`UPDATE temp_access_links SET status = 'expired' WHERE status = 'active' AND expires_at < NOW()`); err != nil {
			t.Fatalf("expiry sweep: %v", err)
		}

		for _, tc := range []struct{ id, org string }{{linkA, "A"}, {linkB, "B"}} {
			var status string
			if err := db.Pool.QueryRow(ctx,
				`SELECT status FROM temp_access_links WHERE id = $1`, tc.id).Scan(&status); err != nil {
				t.Fatalf("read link %s: %v", tc.org, err)
			}
			if status != "expired" {
				t.Fatalf("org %s's expired link is still %q. The sweep is install-wide on purpose — "+
					"a link the sweep misses is a vendor still holding SSH into an internal host", tc.org, status)
			}
		}
	})
}
