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

	adminhandlers "github.com/openidx/openidx/internal/admin/handlers"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// THE CONSOLE SETTINGS NAME NO DOMAIN THE PROJECT DOES NOT OWN.
//
// The settings handler defaulted the support address and the WebAuthn relying
// party ID and origin to a domain the project has never owned, so every
// organization that opened the settings page was shown them, and saving or
// resetting the page wrote them into admin_console_settings. The defaults are
// empty now, and an empty support address, which the binding used to reject
// as missing, saves.
//
// Driven through RegisterAllRoutes, the route table cmd/admin-api mounts for
// the console, behind the admin gate main.go passes it, as an administrator of
// an organization that has never saved its settings:
//   - the settings, their JSON export and a reset carry none of the old
//     values, and neither does anything stored;
//   - the page's own round trip (read, then save what was read) is accepted,
//     and so is an address the administrator types;
//   - a support address that is not an address is still refused, and nothing
//     is stored.
func TestConsoleSettingsNameNoDomainTheProjectDoesNotOwn(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupPAMTestDB(t)
	if db == nil {
		return
	}
	t.Cleanup(cleanup)
	ctx := orgctx.WithBypassRLS(context.Background())
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	var org, admin string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`, "fresh-"+suffix).Scan(&org); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO users (org_id, username, email, enabled) VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
		org, "admin-"+suffix, "admin-"+suffix+"@example.test").Scan(&admin); err != nil {
		t.Fatalf("seed administrator: %v", err)
	}

	r := gin.New()
	v1 := r.Group("/api/v1")
	v1.Use(func(c *gin.Context) {
		c.Set("user_id", admin)
		c.Set("roles", []string{"admin"})
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
		c.Next()
	})
	adminhandlers.RegisterAllRoutes(v1, db.Pool, zap.NewNop(), RequireAdmin())

	do := func(method, path, body string) (int, string) {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}
	const oldDomain = "openidx.io" // domain-ok: the value these assertions look for
	namesOldDomain := func(s string) bool { return strings.Contains(strings.ToLower(s), oldDomain) }
	stored := func() string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(ctx,
			`SELECT COALESCE(string_agg(value::text, ' '), '') FROM admin_console_settings WHERE org_id = $1::uuid`, org).Scan(&v); err != nil {
			t.Fatalf("read stored settings: %v", err)
		}
		return v
	}
	type view struct {
		General struct {
			SupportEmail string `json:"support_email"`
		} `json:"general"`
		Security struct {
			MFA struct {
				WebAuthn struct {
					RelyingPartyID     string `json:"relying_party_id"`
					RelyingPartyOrigin string `json:"relying_party_origin"`
				} `json:"webauthn"`
			} `json:"mfa"`
		} `json:"security"`
	}
	decode := func(body string) view {
		t.Helper()
		var v view
		if err := json.Unmarshal([]byte(body), &v); err != nil {
			t.Fatalf("decode settings: %v (%s)", err, body)
		}
		return v
	}

	code, page := do(http.MethodGet, "/api/v1/settings", "")
	if code != http.StatusOK {
		t.Fatalf("GET /settings: %d %s", code, page)
	}
	if namesOldDomain(page) {
		t.Errorf("the settings of an organization that never saved them name the old domain: %s", page)
	}
	v := decode(page)
	if v.General.SupportEmail != "" || v.Security.MFA.WebAuthn.RelyingPartyID != "" || v.Security.MFA.WebAuthn.RelyingPartyOrigin != "" {
		t.Errorf("default support address %q, relying party %q / %q: want all empty",
			v.General.SupportEmail, v.Security.MFA.WebAuthn.RelyingPartyID, v.Security.MFA.WebAuthn.RelyingPartyOrigin)
	}
	if code, body := do(http.MethodGet, "/api/v1/settings/json", ""); code != http.StatusOK || namesOldDomain(body) {
		t.Errorf("GET /settings/json: %d, names the old domain: %v", code, namesOldDomain(body))
	}

	t.Run("an address that is not one is refused, and nothing is stored", func(t *testing.T) {
		bad := strings.Replace(page, `"support_email":""`, `"support_email":"not-an-address"`, 1)
		if bad == page {
			t.Fatalf("the fixture did not change the support address: %s", page)
		}
		if code, body := do(http.MethodPut, "/api/v1/settings", bad); code != http.StatusBadRequest {
			t.Errorf("PUT /settings with a malformed support address: %d %s, want 400", code, body)
		}
		if s := stored(); s != "" {
			t.Errorf("a refused save stored %s", s)
		}
	})

	t.Run("the page's own round trip saves, with no address", func(t *testing.T) {
		if code, body := do(http.MethodPut, "/api/v1/settings", page); code != http.StatusOK {
			t.Fatalf("PUT /settings with what GET returned: %d %s", code, body)
		}
		if s := stored(); s == "" || namesOldDomain(s) {
			t.Errorf("after the round trip the stored settings are %q", s)
		}
		_, again := do(http.MethodGet, "/api/v1/settings", "")
		if got := decode(again).General.SupportEmail; got != "" {
			t.Errorf("the saved support address reads back as %q", got)
		}
	})

	t.Run("an address the administrator types is kept", func(t *testing.T) {
		typed := strings.Replace(page, `"support_email":""`, `"support_email":"help@corp.example"`, 1)
		if code, body := do(http.MethodPut, "/api/v1/settings", typed); code != http.StatusOK {
			t.Fatalf("PUT /settings with a typed address: %d %s", code, body)
		}
		_, again := do(http.MethodGet, "/api/v1/settings", "")
		if got := decode(again).General.SupportEmail; got != "help@corp.example" {
			t.Errorf("the typed support address reads back as %q", got)
		}
	})

	t.Run("a reset writes none of the old values", func(t *testing.T) {
		code, body := do(http.MethodPost, "/api/v1/settings/reset", "")
		if code != http.StatusOK {
			t.Fatalf("POST /settings/reset: %d %s", code, body)
		}
		if namesOldDomain(body) {
			t.Errorf("the reset answered with the old domain: %s", body)
		}
		if s := stored(); namesOldDomain(s) {
			t.Errorf("the reset stored the old domain: %s", s)
		}
	})
}
