package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// A new MFA policy may carry nothing that the login path does not enforce
// (#990). The conditions this API used to accept are refused with the ones it
// already refused: none of them is both accepted and evaluated.
func TestNewMFAPolicyRefusesWhatNothingEnforces(t *testing.T) {
	cases := []struct {
		name        string
		conditions  string
		methods     string
		graceHours  int
		wantRefused bool
	}{
		{"a plain policy", ``, ``, 0, false},
		{"empty conditions and methods", `{}`, `[]`, 0, false},
		{"null conditions and methods", `null`, `null`, 0, false},
		{"required methods", ``, `["webauthn"]`, 0, true},
		{"a grace period", ``, ``, 24, true},
		// Accepted before #990 and read by nothing.
		{"factor_enrolled", `{"factor_enrolled":true}`, ``, 0, true},
		{"min_risk_score", `{"min_risk_score":70}`, ``, 0, true},
		{"client_ids", `{"client_ids":["admin-console"]}`, ``, 0, true},
		// Read by the evaluator and refused before #990 too: the console cannot
		// show them, and a condition it cannot show narrows who is challenged.
		{"groups", `{"groups":["Admins"]}`, ``, 0, true},
		{"ip_ranges", `{"ip_ranges":["10.0.0.0/8"]}`, ``, 0, true},
		{"conditions that are not an object", `[1,2,3]`, ``, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkNewMFAPolicy(json.RawMessage(tc.conditions), json.RawMessage(tc.methods), tc.graceHours)
			if (err != nil) != tc.wantRefused {
				t.Fatalf("checkNewMFAPolicy(%q, %q, %d) = %v, want refused %v",
					tc.conditions, tc.methods, tc.graceHours, err, tc.wantRefused)
			}
			if err != nil && !errors.Is(err, errMFAPolicyNotEnforced) {
				t.Errorf("refusal %v is not errMFAPolicyNotEnforced, so the handler would not answer 400", err)
			}
		})
	}
}

// An update may clear these settings or send back what is stored, so a policy
// written before #990 can still be renamed and toggled. It may not set a new one.
func TestMFAPolicyUpdateMayClearOrEchoButNotSet(t *testing.T) {
	stored := storedMFAPolicySettings{
		conditions:      json.RawMessage(`{"client_ids": ["a"]}`),
		requiredMethods: json.RawMessage(`["webauthn"]`),
		graceHours:      24,
	}
	raw := func(s string) *json.RawMessage { r := json.RawMessage(s); return &r }
	hours := func(n int) *int { return &n }
	cases := []struct {
		name        string
		conditions  *json.RawMessage
		methods     *json.RawMessage
		graceHours  *int
		wantRefused bool
	}{
		{"none of the three sent", nil, nil, nil, false},
		{"the stored values sent back", raw(`{"client_ids":["a"]}`), raw(`["webauthn"]`), hours(24), false},
		{"all three cleared", raw(`{}`), raw(`[]`), hours(0), false},
		{"a new method", nil, raw(`["totp"]`), nil, true},
		{"a method added", nil, raw(`["webauthn","totp"]`), nil, true},
		{"a new grace period", nil, nil, hours(48), true},
		{"a new condition", raw(`{"client_ids":["b"]}`), nil, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkMFAPolicyUpdate(stored, tc.conditions, tc.methods, tc.graceHours)
			if (err != nil) != tc.wantRefused {
				t.Fatalf("checkMFAPolicyUpdate = %v, want refused %v", err, tc.wantRefused)
			}
		})
	}
}

// The same rules through the handlers, against Postgres: what is refused
// writes nothing, and a policy that already stores these settings keeps them
// until an admin clears them.
func TestMFAPolicyHandlersRefuseWhatNothingEnforces(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupPAMTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	const org = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	s := &Service{db: db, logger: zap.NewNop()}
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
		c.Set("roles", []string{"admin"})
		c.Next()
	})
	router.POST("/mfa/policies", s.handleCreateMFAPolicy)
	router.PUT("/mfa/policies/:id", s.handleUpdateMFAPolicy)

	call := func(method, path, body string) (int, string) {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}
	count := func(name string) int {
		t.Helper()
		var n int
		if err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM mfa_policies WHERE name = $1`, name).Scan(&n); err != nil {
			t.Fatalf("count policies: %v", err)
		}
		return n
	}
	settings := func(id string) (methods string, grace int, enabled bool) {
		t.Helper()
		if err := db.Pool.QueryRow(ctx,
			`SELECT required_methods::text, grace_period_hours, enabled FROM mfa_policies WHERE id = $1::uuid`,
			id).Scan(&methods, &grace, &enabled); err != nil {
			t.Fatalf("read policy %s: %v", id, err)
		}
		return methods, grace, enabled
	}

	t.Run("a plain policy is created", func(t *testing.T) {
		name := "everyone-" + suffix
		code, body := call(http.MethodPost, "/mfa/policies", `{"name":"`+name+`","enabled":true,"priority":10}`)
		if code != http.StatusCreated || count(name) != 1 {
			t.Fatalf("want 201 and one row, got %d %s", code, body)
		}
	})
	for _, tc := range []struct{ name, extra string }{
		{"required methods", `"required_methods":["webauthn"]`},
		{"a grace period", `"grace_period_hours":24`},
		{"a condition", `"conditions":{"client_ids":["admin-console"]}`},
	} {
		t.Run("a policy with "+tc.name+" is refused and not written", func(t *testing.T) {
			name := "refused-" + strings.ReplaceAll(tc.name, " ", "-") + "-" + suffix
			code, body := call(http.MethodPost, "/mfa/policies", `{"name":"`+name+`","enabled":true,`+tc.extra+`}`)
			if code != http.StatusBadRequest || !strings.Contains(body, "not enforced") {
				t.Fatalf("want 400 saying it is not enforced, got %d %s", code, body)
			}
			if n := count(name); n != 0 {
				t.Fatalf("a refused policy was written (%d rows)", n)
			}
		})
	}

	// A policy written before #990, as the console used to write it.
	var legacy string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO mfa_policies (name, description, enabled, priority, conditions, required_methods, grace_period_hours, org_id)
		VALUES ($1, '', true, 100, '{}', '["webauthn"]', 24, $2::uuid) RETURNING id::text`,
		"legacy-"+suffix, org).Scan(&legacy); err != nil {
		t.Fatalf("seed legacy policy: %v", err)
	}
	path := "/mfa/policies/" + legacy

	t.Run("an old policy can still be toggled", func(t *testing.T) {
		if code, body := call(http.MethodPut, path, `{"enabled":false}`); code != http.StatusOK {
			t.Fatalf("toggle: %d %s", code, body)
		}
		if _, _, enabled := settings(legacy); enabled {
			t.Fatal("the toggle did not take effect")
		}
	})
	t.Run("an old policy can be saved with its stored values sent back", func(t *testing.T) {
		code, body := call(http.MethodPut, path,
			`{"name":"legacy-renamed-`+suffix+`","conditions":{},"required_methods":["webauthn"],"grace_period_hours":24}`)
		if code != http.StatusOK {
			t.Fatalf("echo: %d %s", code, body)
		}
	})
	t.Run("an old policy cannot be given a different method or grace period", func(t *testing.T) {
		if code, body := call(http.MethodPut, path, `{"required_methods":["totp"]}`); code != http.StatusBadRequest {
			t.Fatalf("new method: want 400, got %d %s", code, body)
		}
		if code, body := call(http.MethodPut, path, `{"grace_period_hours":48}`); code != http.StatusBadRequest {
			t.Fatalf("new grace period: want 400, got %d %s", code, body)
		}
		if methods, grace, _ := settings(legacy); methods != `["webauthn"]` || grace != 24 {
			t.Fatalf("a refused update changed the policy: methods %s, grace %d", methods, grace)
		}
	})
	t.Run("an old policy's settings can be cleared", func(t *testing.T) {
		if code, body := call(http.MethodPut, path, `{"required_methods":[],"grace_period_hours":0}`); code != http.StatusOK {
			t.Fatalf("clear: %d %s", code, body)
		}
		if methods, grace, _ := settings(legacy); methods != `[]` || grace != 0 {
			t.Fatalf("clearing left methods %s, grace %d", methods, grace)
		}
	})
	t.Run("an unknown policy is 404, not a refusal", func(t *testing.T) {
		code, body := call(http.MethodPut, "/mfa/policies/00000000-0000-0000-0000-00000000ffff", `{"required_methods":["totp"]}`)
		if code != http.StatusNotFound {
			t.Fatalf("want 404, got %d %s", code, body)
		}
	})
}
