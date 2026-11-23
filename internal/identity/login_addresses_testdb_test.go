package identity

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

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
)

func TestNormalizeLoginAddress(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"Ad.Soyad@Sirket.com.tr", "ad.soyad@sirket.com.tr", true},
		{"  ad@x.example \t", "ad@x.example", true},
		{"a+tag@x.example", "a+tag@x.example", true},
		{"", "", false},
		{"nodomain", "", false},
		{"@x.example", "", false},
		{"a@", "", false},
		{"a@@x.example", "", false},
		{"a@b@x.example", "", false},
		{"a b@x.example", "", false},
		{"a@x.example.", "", false},
		{"a@.x.example", "", false},
		{"a,b@x.example", "", false},
		{"<a@x.example>", "", false},
		{"a@x.example\n", "a@x.example", true}, // trailing newline is whitespace, trimmed
		{"a\n@x.example", "", false},
		{strings.Repeat("a", 250) + "@x.example", "", false},
	} {
		got, err := normalizeLoginAddress(tc.in)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("normalizeLoginAddress(%q) = %q, %v; want %q ok=%v", tc.in, got, err, tc.want, tc.ok)
		}
	}
}

// The sign-in addresses routes, on the migrated schema and through the REAL
// admin gate (requireAdminUnlessSelfService with the route template, exactly
// as RegisterRoutes mounts them): an administrator manages them, nobody else
// reaches them, not even for their own account.
func TestAdministratorManagesSignInAddresses(t *testing.T) {
	db, cleanup := setupMigratedDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	gin.SetMode(gin.TestMode)

	const org = "00000000-0000-0000-0000-000000000010"
	const otherOrg = "00000000-0000-0000-0000-0000000000b2"
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: org})
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scalar := func(c context.Context, q string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(c, q, args...).Scan(&v); err != nil {
			t.Fatalf("read (%s): %v", q, err)
		}
		return v
	}
	if _, err := db.Pool.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1, 'Other', $2) ON CONFLICT DO NOTHING`,
		otherOrg, "other-"+suffix); err != nil {
		t.Skipf("cannot create a second organization here: %v", err)
	}
	otherCtx := orgctx.With(context.Background(), orgctx.Org{ID: otherOrg})
	user := func(c context.Context, o, name string) string {
		return scalar(c, `INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@corp.example') RETURNING id::text`,
			o, name+"-"+suffix)
	}
	admin := user(ctx, org, "adm")
	hana := user(ctx, org, "hana")
	ivan := user(ctx, org, "ivan")
	foreign := user(otherCtx, otherOrg, "foreign")
	if _, err := db.Pool.Exec(ctx, `UPDATE users SET mail = $2 WHERE id = $1`, ivan, "ivan.mail-"+suffix+"@company.example"); err != nil {
		t.Fatal(err)
	}

	svc := NewService(db, nil, &config.Config{}, zap.NewNop())
	engine := func(userID string, roles ...string) *gin.Engine {
		r := gin.New()
		g := r.Group("/api/v1/identity")
		g.Use(func(c *gin.Context) {
			c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
			c.Set("user_id", userID)
			c.Set("roles", roles)
			c.Next()
		})
		g.Use(svc.requireAdminUnlessSelfService())
		g.GET("/users/:id/login-addresses", svc.handleListLoginAddresses)
		g.POST("/users/:id/login-addresses", svc.handleAddLoginAddress)
		g.DELETE("/users/:id/login-addresses/:addrId", svc.handleRemoveLoginAddress)
		return r
	}
	call := func(r *gin.Engine, method, path, body string) (int, map[string]interface{}) {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/api/v1/identity"+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		out := map[string]interface{}{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	asAdmin := engine(admin, "admin")
	add := func(userID, address string) (int, map[string]interface{}) {
		return call(asAdmin, http.MethodPost, "/users/"+userID+"/login-addresses", `{"address":"`+address+`"}`)
	}

	t.Run("nobody but an administrator reaches the routes, not even for their own account", func(t *testing.T) {
		member := engine(hana, "user")
		for _, tc := range []struct{ method, path, body string }{
			{http.MethodGet, "/users/" + hana + "/login-addresses", ""},
			{http.MethodPost, "/users/" + hana + "/login-addresses", `{"address":"mine@company.example"}`},
			{http.MethodPost, "/users/me/login-addresses", `{"address":"mine@company.example"}`},
			{http.MethodDelete, "/users/" + hana + "/login-addresses/" + admin, ""},
		} {
			// The route template for "/users/me/..." is not registered, so
			// it is a 404 here and nothing at all in production; the
			// others must be 403 from the admin gate.
			code, _ := call(member, tc.method, tc.path, tc.body)
			if tc.path == "/users/me/login-addresses" {
				if code != http.StatusNotFound && code != http.StatusForbidden {
					t.Errorf("%s %s = %d", tc.method, tc.path, code)
				}
				continue
			}
			if code != http.StatusForbidden {
				t.Errorf("%s %s by a plain user = %d, want 403", tc.method, tc.path, code)
			}
		}
		if isIdentitySelfService("/api/v1/identity/users/:id/login-addresses") ||
			isIdentitySelfService("/api/v1/identity/users/:id/login-addresses/:addrId") {
			t.Error("the sign-in address routes are listed as self-service")
		}
		var n int
		if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM user_login_addresses WHERE user_id = $1`, hana).Scan(&n); err != nil || n != 0 {
			t.Errorf("a refused call left %d rows (%v)", n, err)
		}
	})

	var hanaAddr string
	t.Run("add normalizes, lists, and is idempotent", func(t *testing.T) {
		code, body := add(hana, "  Hana.Real-"+suffix+"@Company.Example ")
		if code != http.StatusCreated {
			t.Fatalf("add = %d %v", code, body)
		}
		hanaAddr, _ = body["address"].(string)
		if hanaAddr != "hana.real-"+suffix+"@company.example" {
			t.Fatalf("stored %q", hanaAddr)
		}
		if code, _ := add(hana, strings.ToUpper(hanaAddr)); code != http.StatusOK {
			t.Errorf("adding it again = %d, want 200", code)
		}
		code, body = call(asAdmin, http.MethodGet, "/users/"+hana+"/login-addresses", "")
		list, _ := body["addresses"].([]interface{})
		if code != http.StatusOK || len(list) != 1 || body["email"] != "hana-"+suffix+"@corp.example" {
			t.Errorf("list = %d %v", code, body)
		}
	})

	t.Run("an address that signs in as somebody else is refused, naming nobody", func(t *testing.T) {
		ivanLogin := "ivan.login-" + suffix + "@company.example"
		if _, err := db.Pool.Exec(ctx, `UPDATE users SET username = $2 WHERE id = $1`, ivan, ivanLogin); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct{ name, target, address string }{
			{"another account's email", hana, "ivan-" + suffix + "@corp.example"},
			{"another account's mail", hana, "ivan.mail-" + suffix + "@company.example"},
			{"another account's username", hana, ivanLogin},
			{"another account's own address", ivan, hanaAddr},
		} {
			code, body := add(tc.target, tc.address)
			if code != http.StatusConflict || body["error"] != "address_in_use" {
				t.Errorf("%s: %d %v, want 409 address_in_use", tc.name, code, body)
			}
			for _, v := range body {
				if s, _ := v.(string); strings.Contains(s, hana) || strings.Contains(s, ivan) {
					t.Errorf("%s: the refusal names an account: %v", tc.name, body)
				}
			}
		}
	})

	t.Run("the account's own email is allowed", func(t *testing.T) {
		if code, body := add(hana, "hana-"+suffix+"@corp.example"); code != http.StatusCreated {
			t.Errorf("own email = %d %v", code, body)
		}
	})

	t.Run("bad input is a 400", func(t *testing.T) {
		for _, in := range []string{"nodomain", "a b@x.example", ""} {
			if code, body := add(hana, in); code != http.StatusBadRequest || body["error"] != "invalid_address" {
				t.Errorf("%q = %d %v", in, code, body)
			}
		}
	})

	t.Run("an account holds at most five", func(t *testing.T) {
		for i := 0; i < 8; i++ {
			code, body := add(hana, fmt.Sprintf("many%d-%s@company.example", i, suffix))
			var n int
			_ = db.Pool.QueryRow(ctx, `SELECT count(*) FROM user_login_addresses WHERE user_id = $1`, hana).Scan(&n)
			if n > maxLoginAddressesPerUser {
				t.Fatalf("%d addresses after call %d", n, i)
			}
			if n == maxLoginAddressesPerUser && code != http.StatusCreated && (code != http.StatusConflict || body["error"] != "too_many") {
				t.Fatalf("call %d at the limit = %d %v", i, code, body)
			}
		}
		if code, body := add(hana, "one-more-"+suffix+"@company.example"); code != http.StatusConflict || body["error"] != "too_many" {
			t.Errorf("over the limit = %d %v, want 409 too_many", code, body)
		}
	})

	t.Run("another organization's account is not found", func(t *testing.T) {
		if code, _ := add(foreign, "f"+suffix+"@company.example"); code != http.StatusNotFound {
			t.Errorf("add to a foreign account = %d, want 404", code)
		}
		if code, _ := call(asAdmin, http.MethodGet, "/users/"+foreign+"/login-addresses", ""); code != http.StatusNotFound {
			t.Errorf("list a foreign account = %d, want 404", code)
		}
	})

	t.Run("remove is scoped to the account, and the address stops signing in", func(t *testing.T) {
		var id string
		if err := db.Pool.QueryRow(ctx, `SELECT id::text FROM user_login_addresses WHERE address = $1`, hanaAddr).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if code, _ := call(asAdmin, http.MethodDelete, "/users/"+ivan+"/login-addresses/"+id, ""); code != http.StatusNotFound {
			t.Errorf("removing hana's address through ivan = %d, want 404", code)
		}
		who, err := svc.FindUserByLoginIdentifier(ctx, hanaAddr)
		if err != nil || who.ID != hana {
			t.Fatalf("before removal: %v %v", who, err)
		}
		if code, _ := call(asAdmin, http.MethodDelete, "/users/"+hana+"/login-addresses/"+id, ""); code != http.StatusNoContent {
			t.Fatalf("remove = %d, want 204", code)
		}
		if _, err := svc.FindUserByLoginIdentifier(ctx, hanaAddr); err == nil {
			t.Error("a removed address still finds the account")
		}
	})

	t.Run("the add and the removal are audited with who did them", func(t *testing.T) {
		deadline := time.Now().Add(5 * time.Second)
		for {
			var n int
			_ = db.Pool.QueryRow(ctx, `
				SELECT count(*) FROM audit_events
				WHERE action IN ('user.login_address_added','user.login_address_removed')
				  AND actor_id = $1 AND target_id = $2`, admin, hana).Scan(&n)
			if n >= 2 {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("only %d audit events for the administrator's changes", n)
			}
			time.Sleep(100 * time.Millisecond)
		}
	})
}
