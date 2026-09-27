package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// super_admin held in the default organization is what makes a platform admin.
// Each organization's administrators create and name that organization's
// roles, so the identity API refuses the name in every other organization --
// on creation and on a rename, compared without case or surrounding space --
// and answers with a code the console explains. Any other name is the
// organization's to choose, and the default organization keeps super_admin.
func TestTheRoleNameSuperAdminIsReservedToTheDefaultOrganization(t *testing.T) {
	db, cleanup := setupMigratedDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	gin.SetMode(gin.TestMode)

	seed := orgctx.WithBypassRLS(context.Background())
	var tenant string
	if err := db.Pool.QueryRow(seed, `
		INSERT INTO organizations (name, slug, status) VALUES ('Reserved role tenant', 'reserved-role-tenant', 'active')
		RETURNING id::text`).Scan(&tenant); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	svc := &Service{db: db, logger: zap.NewNop()}

	send := func(orgID, method, path, body, roleID string, handler gin.HandlerFunc) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(method, path, strings.NewReader(body)).
			WithContext(orgctx.With(context.Background(), orgctx.Org{ID: orgID}))
		c.Request.Header.Set("Content-Type", "application/json")
		if roleID != "" {
			c.Params = gin.Params{{Key: "id", Value: roleID}}
		}
		handler(c)
		return w
	}
	create := func(orgID, name string) *httptest.ResponseRecorder {
		t.Helper()
		return send(orgID, http.MethodPost, "/api/v1/identity/roles", fmt.Sprintf(`{"name":%q}`, name), "", svc.handleCreateRole)
	}
	refused := func(w *httptest.ResponseRecorder) bool {
		var body map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		return w.Code == http.StatusBadRequest && body["error"] == "reserved_role_name"
	}
	held := func(orgID string) int {
		t.Helper()
		var n int
		if err := db.Pool.QueryRow(seed,
			`SELECT COUNT(*) FROM roles WHERE org_id = $1::uuid AND lower(trim(name)) = 'super_admin'`, orgID).Scan(&n); err != nil {
			t.Fatalf("count roles: %v", err)
		}
		return n
	}

	for _, name := range []string{"super_admin", " Super_Admin ", "SUPER_ADMIN"} {
		if w := create(tenant, name); !refused(w) {
			t.Errorf("creating %q in another organization: %d %s, want 400 reserved_role_name", name, w.Code, w.Body.String())
		}
	}
	if n := held(tenant); n != 0 {
		t.Fatalf("the organization holds %d roles named super_admin after the refusals", n)
	}

	w := create(tenant, "operations")
	if w.Code != http.StatusCreated {
		t.Fatalf("creating an ordinary role: %d %s", w.Code, w.Body.String())
	}
	var role Role
	if err := json.Unmarshal(w.Body.Bytes(), &role); err != nil || role.ID == "" {
		t.Fatalf("created role: %v %s", err, w.Body.String())
	}
	if w := send(tenant, http.MethodPut, "/api/v1/identity/roles/"+role.ID, `{"name":"super_admin"}`, role.ID, svc.handleUpdateRole); !refused(w) {
		t.Errorf("renaming a role to super_admin in another organization: %d %s, want 400 reserved_role_name", w.Code, w.Body.String())
	}
	var name string
	if err := db.Pool.QueryRow(seed, `SELECT name FROM roles WHERE id = $1::uuid`, role.ID).Scan(&name); err != nil || name != "operations" {
		t.Fatalf("the refused rename changed the role: %q %v", name, err)
	}

	if w := create(tenant, "super_admins"); w.Code != http.StatusCreated {
		t.Errorf("a name that is not the reserved one: %d %s, want 201", w.Code, w.Body.String())
	}
	if w := create(middleware.DefaultOrgID, "super_admin"); w.Code != http.StatusCreated {
		t.Errorf("super_admin in the default organization: %d %s, want 201", w.Code, w.Body.String())
	}
	if n := held(middleware.DefaultOrgID); n != 1 {
		t.Errorf("the default organization holds %d roles named super_admin, want 1", n)
	}
}
