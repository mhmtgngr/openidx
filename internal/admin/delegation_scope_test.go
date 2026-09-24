package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// The delegation-scope decision (#956, option (b)), against Postgres.
//
// A group, role or application scope was recorded and shown on the console,
// and never enforced: RequirePermission compares resource and action only, so
// the delegated permissions applied across the whole organization. New
// delegations can therefore only be scoped to the organization, and an edit
// cannot move a delegation into a narrower scope. A delegation that already
// has one keeps it and stays editable, so nobody's access changes.
//
// Both halves are here: what is still allowed, and what is refused with
// nothing written.
func TestAdminDelegations_OnlyTheOrganizationScopeCanBeGranted(t *testing.T) {
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
		`INSERT INTO organizations (name, slug) VALUES ('dlg-scope-b','dlg-scope-b') RETURNING id::text`).Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	seedUser := func(name string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO users (org_id, username, email, enabled)
			VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
			orgA, name+"-"+suffix, name+"-"+suffix+"@example.test").Scan(&id); err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
		return id
	}
	seedGroup := func(name string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx,
			`INSERT INTO groups (org_id, name) VALUES ($1::uuid, $2) RETURNING id::text`,
			orgA, name+"-"+suffix).Scan(&id); err != nil {
			t.Fatalf("seed group %s: %v", name, err)
		}
		return id
	}
	delegate := seedUser("dlg-scope-delegate")
	admin := seedUser("dlg-scope-admin")
	engineering := seedGroup("dlg-scope-engineering")
	finance := seedGroup("dlg-scope-finance")

	ctxA := orgctx.With(ctx, orgctx.Org{ID: orgA})
	ctxB := orgctx.With(ctx, orgctx.Org{ID: orgB})
	s := &Service{db: db, logger: zap.NewNop()}

	scopeOf := func(id string) (string, string) {
		t.Helper()
		var typ, sid string
		if err := db.Pool.QueryRow(ctx,
			`SELECT scope_type, scope_id::text FROM admin_delegations WHERE id = $1::uuid`, id).Scan(&typ, &sid); err != nil {
			t.Fatalf("read back scope of %s: %v", id, err)
		}
		return typ, sid
	}
	countFor := func(scopeType string) int {
		t.Helper()
		var n int
		if err := db.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM admin_delegations WHERE delegate_id = $1::uuid AND scope_type = $2`,
			delegate, scopeType).Scan(&n); err != nil {
			t.Fatalf("count %s delegations: %v", scopeType, err)
		}
		return n
	}

	// THE ALLOWED HALF OF CREATE.
	orgScoped := &AdminDelegation{
		DelegateID:  delegate,
		DelegatedBy: admin,
		ScopeType:   "organization",
		Permissions: []string{"users:read"},
		Enabled:     true,
	}
	t.Run("an organization-scoped delegation is created, and may leave its id out", func(t *testing.T) {
		if err := s.CreateDelegation(ctxA, orgScoped); err != nil {
			t.Fatalf("the one scope that is enforced was refused: %v", err)
		}
		if typ, sid := scopeOf(orgScoped.ID); typ != "organization" || sid != orgA {
			t.Fatalf("stored scope %s/%s, want organization/%s", typ, sid, orgA)
		}
	})

	// THE REFUSED HALF OF CREATE.
	for _, tc := range []struct{ scopeType, scopeID string }{
		{"group", engineering},
		{"role", uuid.NewString()},
		{"application", uuid.NewString()},
	} {
		t.Run("a new "+tc.scopeType+"-scoped delegation is refused and nothing is written", func(t *testing.T) {
			err := s.CreateDelegation(ctxA, &AdminDelegation{
				DelegateID:  delegate,
				DelegatedBy: admin,
				ScopeType:   tc.scopeType,
				ScopeID:     tc.scopeID,
				Permissions: []string{"users:write"},
				Enabled:     true,
			})
			if !errors.Is(err, errDelegationScope) {
				t.Fatalf("got %v, want a scope refusal: this scope would read as a narrowing on the "+
					"console and grant users:write across the whole organization", err)
			}
			if n := countFor(tc.scopeType); n != 0 {
				t.Fatalf("%d %s-scoped delegations were written", n, tc.scopeType)
			}
		})
	}

	// A delegation created before the change, which carries a group scope.
	var legacy string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO admin_delegations (org_id, delegate_id, delegated_by, scope_type, scope_id, permissions, enabled)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'group', $4::uuid, '["users:read"]'::jsonb, true)
		RETURNING id::text`, orgA, delegate, admin, engineering).Scan(&legacy); err != nil {
		t.Fatalf("seed an existing group-scoped delegation: %v", err)
	}

	// THE ALLOWED HALF OF EDIT: nobody's existing delegation is taken away.
	t.Run("an existing group-scoped delegation stays editable", func(t *testing.T) {
		if err := s.UpdateDelegation(ctxA, legacy, map[string]interface{}{
			"permissions": []interface{}{"users:read", "groups:read"},
			"enabled":     false,
		}); err != nil {
			t.Fatalf("editing the permissions of an existing delegation was refused: %v", err)
		}
		if typ, sid := scopeOf(legacy); typ != "group" || sid != engineering {
			t.Fatalf("editing the permissions changed the scope to %s/%s", typ, sid)
		}
	})
	t.Run("sending its scope back unchanged is not a change", func(t *testing.T) {
		// The console before this change sent the whole row on every edit.
		if err := s.UpdateDelegation(ctxA, legacy, map[string]interface{}{
			"scope_type":  "group",
			"scope_id":    engineering,
			"permissions": []interface{}{"users:read"},
		}); err != nil {
			t.Fatalf("an edit that echoes the existing scope was refused: %v", err)
		}
		if err := s.UpdateDelegation(ctxA, legacy, map[string]interface{}{
			"scope_type": "group",
			"scope_id":   engineering,
		}); err != nil {
			t.Fatalf("an edit that only echoes the existing scope was refused: %v", err)
		}
	})

	// THE REFUSED HALF OF EDIT.
	t.Run("an existing group scope cannot be pointed at another group", func(t *testing.T) {
		err := s.UpdateDelegation(ctxA, legacy, map[string]interface{}{"scope_id": finance})
		if !errors.Is(err, errDelegationScope) {
			t.Fatalf("got %v, want a scope refusal", err)
		}
		if typ, sid := scopeOf(legacy); typ != "group" || sid != engineering {
			t.Fatalf("the refused edit still wrote %s/%s", typ, sid)
		}
	})
	t.Run("an organization-scoped delegation cannot be narrowed", func(t *testing.T) {
		err := s.UpdateDelegation(ctxA, orgScoped.ID, map[string]interface{}{
			"scope_type": "group",
			"scope_id":   engineering,
		})
		if !errors.Is(err, errDelegationScope) {
			t.Fatalf("got %v, want a scope refusal", err)
		}
		if typ, sid := scopeOf(orgScoped.ID); typ != "organization" || sid != orgA {
			t.Fatalf("the refused edit still wrote %s/%s", typ, sid)
		}
	})
	t.Run("an edit cannot name another tenant's organization", func(t *testing.T) {
		// This used to be written as it arrived, and the list resolves an
		// organization scope's name without a tenant term.
		err := s.UpdateDelegation(ctxA, orgScoped.ID, map[string]interface{}{"scope_id": orgB})
		if !errors.Is(err, errDelegationScope) {
			t.Fatalf("got %v, want a scope refusal", err)
		}
		if _, sid := scopeOf(orgScoped.ID); sid != orgA {
			t.Fatalf("the delegation now names organization %s", sid)
		}
	})
	t.Run("an unknown scope type is refused", func(t *testing.T) {
		err := s.UpdateDelegation(ctxA, orgScoped.ID, map[string]interface{}{"scope_type": "planet"})
		if !errors.Is(err, errDelegationScope) {
			t.Fatalf("got %v, want a scope refusal", err)
		}
	})
	t.Run("another tenant cannot edit the scope, not even by echoing it", func(t *testing.T) {
		for _, updates := range []map[string]interface{}{
			{"scope_type": "organization"},
			{"scope_type": "group", "scope_id": engineering},
		} {
			err := s.UpdateDelegation(ctxB, legacy, updates)
			if err == nil || !strings.Contains(err.Error(), "not found") {
				t.Fatalf("org B editing org A's delegation with %v got %v, want not found", updates, err)
			}
		}
		if typ, sid := scopeOf(legacy); typ != "group" || sid != engineering {
			t.Fatalf("org B's edit wrote %s/%s", typ, sid)
		}
	})

	// Widening to the organization is allowed: it is what the delegation
	// always granted, and afterwards the console no longer marks it.
	t.Run("an existing group scope can be widened to the organization", func(t *testing.T) {
		if err := s.UpdateDelegation(ctxA, legacy, map[string]interface{}{"scope_type": "organization"}); err != nil {
			t.Fatalf("widening to the enforced scope was refused: %v", err)
		}
		if typ, sid := scopeOf(legacy); typ != "organization" || sid != orgA {
			t.Fatalf("stored scope %s/%s, want organization/%s", typ, sid, orgA)
		}
	})

	// The same rules through the HTTP handlers, which must answer a refusal
	// with a 400 and a reason rather than a 500.
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(ctxA)
		c.Set("user_id", admin)
		c.Next()
	})
	r.POST("/delegations", s.handleCreateDelegation)
	r.PUT("/delegations/:id", s.handleUpdateDelegation)
	send := func(method, path, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}

	t.Run("the create handler fills in the organization and answers 201", func(t *testing.T) {
		w := send("POST", "/delegations",
			`{"delegate_id":"`+delegate+`","scope_type":"organization","permissions":["groups:read"]}`)
		if w.Code != http.StatusCreated {
			t.Fatalf("got %d, want 201 (body=%s)", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), `"scope_id":"`+orgA+`"`) {
			t.Fatalf("the created delegation does not name this organization: %s", w.Body.String())
		}
	})
	t.Run("the update handler answers a narrowing with 400", func(t *testing.T) {
		w := send("PUT", "/delegations/"+orgScoped.ID, `{"scope_type":"role","scope_id":"`+uuid.NewString()+`"}`)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("got %d, want 400 (body=%s)", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "not enforced") {
			t.Fatalf("the refusal does not say why: %s", w.Body.String())
		}
	})
}
