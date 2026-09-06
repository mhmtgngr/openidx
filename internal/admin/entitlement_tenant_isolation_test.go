package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// Tenant isolation for the entitlement catalog's governance annotations,
// migration v163.
//
// An entitlement_metadata row is the annotation on a role, a group or an
// application: its risk level, its owner, its tags, whether it requires review.
// v54 created it with no tenant column AND an install-wide
// UNIQUE (entitlement_type, entitlement_id).
//
// The catalog read was scoped -- the roles, groups and applications it unions
// all carry `WHERE org_id = $1` -- and then reached the annotation through a
// LEFT JOIN with no tenant term. UpdateEntitlementMetadata resolved no
// organization at all: it took the type and the id from the URL and upserted on
// the install-wide key, so a PUT naming another organization's role id wrote a
// row that appeared on THEIR catalog.
func TestEntitlementMetadata_TenantIsolation(t *testing.T) {
	db, cleanup := setupPAMTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const orgA = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	var orgB string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('ent-b','ent-b') RETURNING id::text`).Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	s := &Service{db: db, logger: zaptest.NewLogger(t)}

	seedRole := func(org, name string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO roles (name, description, org_id)
			VALUES ($1, 'isolation probe', $2::uuid) RETURNING id::text`,
			name+"-"+suffix, org).Scan(&id); err != nil {
			t.Fatalf("seed role %s: %v", name, err)
		}
		return id
	}
	seedUser := func(org, name string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO users (org_id, username, email, enabled)
			VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
			org, name+"-"+suffix, name+"-"+suffix+"@example.test").Scan(&id); err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
		return id
	}

	// org A's privileged role. This is the row org B must not be able to touch.
	roleA := seedRole(orgA, "ent-a-priv")
	userB := seedUser(orgB, "ent-b-user")

	call := func(handler gin.HandlerFunc, org, method, path, body string, params gin.Params) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		r.Header.Set("Content-Type", "application/json")
		c.Request = r.WithContext(orgctx.With(context.Background(), orgctx.Org{ID: org}))
		c.Params = params
		c.Set("roles", []string{"admin"})
		handler(c)
		return w
	}

	annotationOf := func(org, entID string) (risk string, reviewRequired bool, found bool) {
		t.Helper()
		entries, _, err := s.GetEntitlementCatalog(
			orgctx.With(context.Background(), orgctx.Org{ID: org}), 0, 100, "role", "", "")
		if err != nil {
			t.Fatalf("catalog as %s: %v", org, err)
		}
		for _, e := range entries {
			if e.ID == entID {
				return e.RiskLevel, e.ReviewRequired, true
			}
		}
		return "", false, false
	}

	t.Run("another tenant's entitlement cannot be annotated", func(t *testing.T) {
		p := gin.Params{{Key: "type", Value: "role"}, {Key: "id", Value: roleA}}
		w := call(s.handleUpdateEntitlementMetadata, orgB, "PUT", "/entitlements/role/"+roleA+"/metadata",
			`{"risk_level":"low","review_required":false,"description":"reclassified by org B"}`, p)
		if w.Code != 404 {
			t.Errorf("org B annotated org A's role: status %d, body %s. The handler took "+
				"the type and the id from the URL and upserted on an install-wide "+
				"UNIQUE (entitlement_type, entitlement_id), so the row landed on "+
				"org A's catalog", w.Code, w.Body.String())
		}

		// org A's own view of its own role is untouched: no annotation exists,
		// so the catalog's COALESCE shows the default.
		risk, review, found := annotationOf(orgA, roleA)
		if !found {
			t.Fatal("org A lost its own role from the catalog")
		}
		if risk != "low" || review {
			t.Errorf("org A's role is annotated risk=%q review_required=%v; org B wrote onto it",
				risk, review)
		}
	})

	t.Run("the owner can still be set, and only from this organization", func(t *testing.T) {
		userA := seedUser(orgA, "ent-a-owner")
		p := gin.Params{{Key: "type", Value: "role"}, {Key: "id", Value: roleA}}

		// The owner's own tenant: allowed, and the annotation takes effect.
		if w := call(s.handleUpdateEntitlementMetadata, orgA, "PUT", "/entitlements/role/"+roleA+"/metadata",
			fmt.Sprintf(`{"risk_level":"critical","review_required":true,"owner_id":%q}`, userA), p); w.Code != 200 {
			t.Fatalf("org A could not annotate its own role: status %d, body %s", w.Code, w.Body.String())
		}
		risk, review, found := annotationOf(orgA, roleA)
		if !found || risk != "critical" || !review {
			t.Errorf("org A's own annotation did not take: risk=%q review=%v found=%v", risk, review, found)
		}

		// A foreign account as the owner: owner_id carries no foreign key, so
		// nothing in the schema stops this. A row that points out of its own
		// tenant is refused rather than written and filtered later.
		if w := call(s.handleUpdateEntitlementMetadata, orgA, "PUT", "/entitlements/role/"+roleA+"/metadata",
			fmt.Sprintf(`{"risk_level":"critical","owner_id":%q}`, userB), p); w.Code != 404 {
			t.Errorf("org A named org B's account as the owner of its role: status %d, body %s",
				w.Code, w.Body.String())
		}
	})

	// The join predicate, proved directly: write the row the old handler would
	// have written -- org B's annotation naming org A's role id -- and check it
	// does not reach org A's catalog.
	t.Run("an annotation from another tenant does not reach this catalog", func(t *testing.T) {
		if _, err := db.Pool.Exec(ctx, `
			INSERT INTO entitlement_metadata (org_id, entitlement_type, entitlement_id, risk_level, review_required)
			VALUES ($1::uuid, 'role', $2::uuid, 'low', false)`, orgB, roleA); err != nil {
			t.Fatalf("seed foreign annotation: %v", err)
		}
		risk, review, found := annotationOf(orgA, roleA)
		if !found {
			t.Fatal("org A lost its own role from the catalog")
		}
		if risk != "critical" || !review {
			t.Errorf("org A's role now reads risk=%q review_required=%v — org B's annotation "+
				"of the same entitlement id reached org A's catalog through a LEFT "+
				"JOIN with no tenant term", risk, review)
		}
	})

	// A count of things, printed below zero.
	t.Run("the risk breakdown is this organization's and cannot go negative", func(t *testing.T) {
		// org B annotates more entitlements than org A owns in total.
		for i := 0; i < 12; i++ {
			r := seedRole(orgB, fmt.Sprintf("ent-b-role-%d", i))
			if _, err := db.Pool.Exec(ctx, `
				INSERT INTO entitlement_metadata (org_id, entitlement_type, entitlement_id, risk_level)
				VALUES ($1::uuid, 'role', $2::uuid, 'high')`, orgB, r); err != nil {
				t.Fatalf("seed org B annotation: %v", err)
			}
		}

		stats, err := s.GetEntitlementStats(orgctx.With(context.Background(), orgctx.Org{ID: orgA}))
		if err != nil {
			t.Fatalf("stats: %v", err)
		}
		for level, n := range stats.ByRiskLevel {
			if n < 0 {
				t.Errorf("org A's %q entitlement count is %d. The breakdown read "+
					"`SELECT risk_level, COUNT(*) FROM entitlement_metadata GROUP BY "+
					"risk_level` with no predicate while the total above it was "+
					"org-scoped, and the two were subtracted", level, n)
			}
		}
		if got := stats.ByRiskLevel["high"]; got != 0 {
			t.Errorf("org A reports %d high-risk entitlements; org B holds all twelve", got)
		}
		if got := stats.ByRiskLevel["critical"]; got != 1 {
			t.Errorf("org A reports %d critical entitlements, want its own 1", got)
		}
	})

	// The direction of a failure.
	t.Run("no organization is a refusal", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("PUT", "/entitlements/role/"+roleA+"/metadata",
			bytes.NewBufferString(`{"risk_level":"low"}`)) // bare context
		c.Request.Header.Set("Content-Type", "application/json")
		c.Params = gin.Params{{Key: "type", Value: "role"}, {Key: "id", Value: roleA}}
		c.Set("roles", []string{"admin"})
		s.handleUpdateEntitlementMetadata(c)
		if w.Code != 403 {
			t.Errorf("annotate with no organization returned %d, expected 403: %s", w.Code, w.Body.String())
		}
	})

	// v54's feature_adoption had no writer and one reader naming two columns it
	// never had; webhook_delivery_stats had neither. v163 drops both.
	t.Run("v54's two orphan tables are gone", func(t *testing.T) {
		for _, table := range []string{"feature_adoption", "webhook_delivery_stats"} {
			var reg *string
			if err := db.Pool.QueryRow(ctx, `SELECT to_regclass($1)::text`, table).Scan(&reg); err != nil {
				t.Fatalf("to_regclass(%s): %v", table, err)
			}
			if reg != nil {
				t.Errorf("%s still exists; it has no reader and no writer in the tree", table)
			}
		}
	})

	// Feature Adoption used to read the dropped table first and swallow the
	// error. The live computation is now the whole handler, and it must answer.
	t.Run("feature adoption still answers, from live data", func(t *testing.T) {
		w := call(s.handleFeatureAdoption, orgA, "GET", "/analytics/feature-adoption", "", nil)
		if w.Code != 200 {
			t.Fatalf("feature adoption: status %d, body %s", w.Code, w.Body.String())
		}
		var out struct {
			Adoption struct {
				Features []struct {
					Name string `json:"name"`
				} `json:"features"`
			} `json:"adoption"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("bad json: %v", err)
		}
		if len(out.Adoption.Features) != 6 {
			t.Errorf("feature adoption returned %d features, want the six live sources",
				len(out.Adoption.Features))
		}
	})
}
