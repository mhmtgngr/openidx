package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestTempAccess_TenantIsolation guards the temp_access_links cross-tenant IDOR:
// the management handlers listed/read/revoked PAM vendor access links by id with
// no org filter, so any authenticated user could enumerate, read and revoke
// every other org's links. With org_id (migration v71) + the handlers' org
// predicate, a caller must only ever see/act on links in their own org.
// DB-backed because the handlers run real org-scoped queries.
func TestTempAccess_TenantIsolation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE temp_access_links (
			id UUID PRIMARY KEY,
			token VARCHAR(255) UNIQUE,
			name VARCHAR(255),
			description TEXT,
			protocol VARCHAR(20),
			target_host VARCHAR(255),
			target_port INTEGER,
			username VARCHAR(255),
			created_by UUID,
			created_by_email VARCHAR(255),
			expires_at TIMESTAMPTZ,
			max_uses INTEGER DEFAULT 0,
			current_uses INTEGER DEFAULT 0,
			allowed_ips TEXT[],
			require_mfa BOOLEAN DEFAULT false,
			notify_on_use BOOLEAN DEFAULT false,
			notify_email VARCHAR(255),
			route_id UUID,
			guacamole_connection_id VARCHAR(255),
			access_url TEXT,
			status VARCHAR(20) DEFAULT 'active',
			last_used_at TIMESTAMPTZ,
			last_used_ip VARCHAR(45),
			created_at TIMESTAMPTZ DEFAULT now(),
			updated_at TIMESTAMPTZ DEFAULT now(),
			org_id UUID NOT NULL);
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	const (
		orgA  = "00000000-0000-0000-0000-00000000000a"
		orgB  = "00000000-0000-0000-0000-00000000000b"
		linkA = "aaaaaaaa-0000-0000-0000-000000000001"
		linkB = "bbbbbbbb-0000-0000-0000-000000000001"
	)
	// Provide non-NULL values for every column the handlers Scan into a
	// non-pointer field (description, username, created_by, created_by_email,
	// allowed_ips, notify_email, route_id, guacamole_connection_id, access_url,
	// last_used_ip). Production's create handler writes these (empty strings for
	// the optionals); a NULL would fail the row Scan and the handler would
	// return 404 rather than the row. last_used_at stays NULL (scanned into a
	// *time.Time).
	seed := func(id, org string) {
		if _, err := db.Pool.Exec(ctx, `
			INSERT INTO temp_access_links
				(id, token, name, description, protocol, target_host, target_port, username,
				 created_by, created_by_email, expires_at, allowed_ips, notify_email, route_id,
				 guacamole_connection_id, access_url, last_used_ip, status, org_id)
			VALUES ($1, $2, 'vendor', '', 'ssh', 'db.internal', 22, '',
				'00000000-0000-0000-0000-000000000001', 'creator@example.com', $3, '{}', '',
				'00000000-0000-0000-0000-000000000002', '', 'https://x/temp-access', '', 'active', $4)`,
			id, "tok-"+id, time.Now().Add(time.Hour), org); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	seed(linkA, orgA)
	seed(linkB, orgB)

	s := &Service{db: db, logger: zap.NewNop()}

	// newCtx builds a gin context acting as orgA with a URL :id param.
	newCtx := func(idParam string) (*gin.Context, *httptest.ResponseRecorder) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodGet, "/temp-access", nil)
		req = req.WithContext(orgctx.With(req.Context(), orgctx.Org{ID: orgA}))
		c.Request = req
		if idParam != "" {
			c.Params = gin.Params{{Key: "id", Value: idParam}}
		}
		return c, w
	}

	t.Run("get cross-org link is not found", func(t *testing.T) {
		c, w := newCtx(linkB)
		s.handleGetTempAccess(c)
		if w.Code != http.StatusNotFound {
			t.Fatalf("orgA reading orgB's link: expected 404, got %d (%s)", w.Code, w.Body.String())
		}
	})

	t.Run("get own link succeeds", func(t *testing.T) {
		c, w := newCtx(linkA)
		s.handleGetTempAccess(c)
		if w.Code != http.StatusOK {
			t.Fatalf("orgA reading its own link: expected 200, got %d (%s)", w.Code, w.Body.String())
		}
	})

	t.Run("list returns only own org's links", func(t *testing.T) {
		c, w := newCtx("")
		s.handleListTempAccess(c)
		if w.Code != http.StatusOK {
			t.Fatalf("list: expected 200, got %d", w.Code)
		}
		var resp struct {
			Links []struct {
				ID string `json:"id"`
			} `json:"links"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.Links) != 1 || resp.Links[0].ID != linkA {
			t.Fatalf("expected only orgA's link %s, got %+v", linkA, resp.Links)
		}
	})

	t.Run("revoke cross-org link is a no-op", func(t *testing.T) {
		c, w := newCtx(linkB)
		s.handleRevokeTempAccess(c)
		if w.Code != http.StatusNotFound {
			t.Fatalf("orgA revoking orgB's link: expected 404, got %d", w.Code)
		}
		var status string
		if err := db.Pool.QueryRow(ctx, `SELECT status FROM temp_access_links WHERE id = $1`, linkB).Scan(&status); err != nil {
			t.Fatalf("read back: %v", err)
		}
		if status != "active" {
			t.Fatalf("orgB's link must remain active after a cross-org revoke attempt, got %q", status)
		}
	})
}
