package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestPublishedApps_TenantIsolation guards the published_apps / discovered_paths
// cross-tenant IDOR: before v73 the tables had no org_id and the app-publish
// handlers keyed on bare id (list had no org filter at all), so any caller could
// enumerate, read, and delete every org's apps and paths. With org_id + the
// per-handler org predicate, a caller only ever sees/acts on rows in its own
// org. DB-backed because the handlers run real org-scoped queries.
func TestPublishedApps_TenantIsolation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE published_apps (
			id UUID PRIMARY KEY, name VARCHAR(255) NOT NULL, description TEXT,
			target_url VARCHAR(500) NOT NULL, spec_url VARCHAR(500),
			status VARCHAR(50) DEFAULT 'pending',
			discovery_started_at TIMESTAMPTZ, discovery_completed_at TIMESTAMPTZ, discovery_error TEXT,
			discovery_strategies JSONB DEFAULT '[]', total_paths_discovered INTEGER DEFAULT 0,
			total_paths_published INTEGER DEFAULT 0, created_by UUID,
			created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now(),
			org_id UUID NOT NULL);
		CREATE TABLE discovered_paths (
			id UUID PRIMARY KEY, app_id UUID NOT NULL, path VARCHAR(500) NOT NULL,
			http_methods JSONB DEFAULT '["GET"]', classification VARCHAR(50) NOT NULL,
			classification_source VARCHAR(50) DEFAULT 'auto', discovery_strategy VARCHAR(50),
			suggested_policy TEXT, require_auth BOOLEAN DEFAULT true, allowed_roles JSONB DEFAULT '[]',
			require_device_trust BOOLEAN DEFAULT false, published BOOLEAN DEFAULT false, route_id UUID,
			metadata JSONB DEFAULT '{}', created_at TIMESTAMPTZ DEFAULT now(),
			updated_at TIMESTAMPTZ DEFAULT now(), org_id UUID NOT NULL);
	`); err != nil {
		t.Fatalf("schema: %v", err)
	}

	const (
		orgA  = "00000000-0000-0000-0000-00000000000a"
		orgB  = "00000000-0000-0000-0000-00000000000b"
		appA  = "aaaaaaaa-0000-0000-0000-000000000001"
		appB  = "aaaaaaaa-0000-0000-0000-000000000002"
		pathA = "dddddddd-0000-0000-0000-000000000001"
		pathB = "dddddddd-0000-0000-0000-000000000002"
	)
	// name/target_url/status are scanned into non-pointer strings — seed them.
	app := func(id, org string) {
		if _, err := db.Pool.Exec(ctx, `INSERT INTO published_apps (id, name, target_url, status, org_id)
			VALUES ($1, 'app-'||$1, 'https://up.internal', 'discovered', $2)`, id, org); err != nil {
			t.Fatalf("seed app: %v", err)
		}
	}
	// id/app_id/path/classification/classification_source are scanned into
	// non-pointer strings — all non-NULL.
	path := func(id, app, org string) {
		if _, err := db.Pool.Exec(ctx, `INSERT INTO discovered_paths (id, app_id, path, classification, classification_source, org_id)
			VALUES ($1, $2, '/x', 'protected', 'auto', $3)`, id, app, org); err != nil {
			t.Fatalf("seed path: %v", err)
		}
	}
	app(appA, orgA)
	app(appB, orgB)
	path(pathA, appA, orgA)
	path(pathB, appB, orgB)

	s := &Service{db: db, logger: zap.NewNop()}

	// newCtx builds a gin context acting as orgA with the given :appId param.
	newCtx := func(appID string) (*gin.Context, *httptest.ResponseRecorder) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodGet, "/apps", nil)
		req = req.WithContext(orgctx.With(req.Context(), orgctx.Org{ID: orgA}))
		c.Request = req
		if appID != "" {
			c.Params = gin.Params{{Key: "appId", Value: appID}}
		}
		return c, w
	}

	t.Run("list returns only own org's apps", func(t *testing.T) {
		c, w := newCtx("")
		s.handleListApps(c)
		if w.Code != http.StatusOK {
			t.Fatalf("list: expected 200, got %d (%s)", w.Code, w.Body.String())
		}
		if got := w.Header().Get("x-total-count"); got != "1" {
			t.Fatalf("x-total-count: expected 1 (only orgA's app), got %q", got)
		}
		var resp struct {
			Apps []struct {
				ID string `json:"id"`
			} `json:"apps"`
			Total int `json:"total"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.Total != 1 || len(resp.Apps) != 1 || resp.Apps[0].ID != appA {
			t.Fatalf("expected only orgA's app %s, got total=%d %+v", appA, resp.Total, resp.Apps)
		}
	})

	t.Run("get cross-org app is not found", func(t *testing.T) {
		c, w := newCtx(appB)
		s.handleGetApp(c)
		if w.Code != http.StatusNotFound {
			t.Fatalf("orgA reading orgB's app: expected 404, got %d (%s)", w.Code, w.Body.String())
		}
	})

	t.Run("get own app succeeds", func(t *testing.T) {
		c, w := newCtx(appA)
		s.handleGetApp(c)
		if w.Code != http.StatusOK {
			t.Fatalf("orgA reading its own app: expected 200, got %d (%s)", w.Code, w.Body.String())
		}
	})

	t.Run("list discovered paths of cross-org app is empty", func(t *testing.T) {
		c, w := newCtx(appB)
		s.handleListDiscoveredPaths(c)
		if w.Code != http.StatusOK {
			t.Fatalf("paths: expected 200, got %d (%s)", w.Code, w.Body.String())
		}
		var resp struct {
			Total int `json:"total"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.Total != 0 {
			t.Fatalf("orgA must not see orgB's app paths, got total=%d", resp.Total)
		}
	})

	t.Run("delete cross-org app is a no-op", func(t *testing.T) {
		c, w := newCtx(appB)
		s.handleDeleteApp(c)
		if w.Code != http.StatusNotFound {
			t.Fatalf("orgA deleting orgB's app: expected 404, got %d", w.Code)
		}
		var n int
		if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM published_apps WHERE id=$1`, appB).Scan(&n); err != nil {
			t.Fatalf("read back: %v", err)
		}
		if n != 1 {
			t.Fatalf("orgB's app must survive a cross-org delete attempt, rows=%d", n)
		}
	})
}
