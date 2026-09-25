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

// A new MFA policy may require methods, with a grace period to add one, and
// the login enforces both (evaluateMFA). What it cannot enforce as written is
// refused: a method it does not know, a grace period on a policy with no
// method to add, and conditions, which nothing enforces yet (#990).
func TestNewMFAPolicyRules(t *testing.T) {
	cases := []struct {
		name       string
		conditions string
		methods    string
		graceHours int
		want       error // nil: accepted
	}{
		{"a plain policy", ``, ``, 0, nil},
		{"empty conditions and methods", `{}`, `[]`, 0, nil},
		{"null conditions and methods", `null`, `null`, 0, nil},
		{"one required method", ``, `["webauthn"]`, 0, nil},
		{"methods and a grace period", ``, `["totp","webauthn"]`, 72, nil},
		{"the longest grace period", ``, `["totp"]`, maxMFAGraceHours, nil},
		{"every method", ``, `["totp","webauthn","push","sms","email"]`, 0, nil},

		{"a grace period with no method to add", ``, ``, 24, errMFAPolicyInvalid},
		{"a grace period over 30 days", ``, `["totp"]`, maxMFAGraceHours + 1, errMFAPolicyInvalid},
		{"a negative grace period", ``, `["totp"]`, -1, errMFAPolicyInvalid},
		{"an unknown method", ``, `["password"]`, 0, errMFAPolicyInvalid},
		{"a method in the wrong case", ``, `["TOTP"]`, 0, errMFAPolicyInvalid},
		// Recovery codes are how a user gets back in, not a method to require.
		{"backup codes", ``, `["backup"]`, 0, errMFAPolicyInvalid},
		{"bypass codes", ``, `["bypass"]`, 0, errMFAPolicyInvalid},
		{"a method listed twice", ``, `["totp","totp"]`, 0, errMFAPolicyInvalid},
		{"methods that are not a list", ``, `"totp"`, 0, errMFAPolicyInvalid},

		// Accepted before #990 and read by nothing.
		{"factor_enrolled", `{"factor_enrolled":true}`, ``, 0, errMFAPolicyNotEnforced},
		{"min_risk_score", `{"min_risk_score":70}`, ``, 0, errMFAPolicyNotEnforced},
		{"client_ids", `{"client_ids":["admin-console"]}`, ``, 0, errMFAPolicyNotEnforced},
		// Read by the evaluator and refused before #990 too: the console cannot
		// show them, and a condition it cannot show narrows who is challenged.
		{"groups", `{"groups":["Admins"]}`, ``, 0, errMFAPolicyNotEnforced},
		{"ip_ranges", `{"ip_ranges":["10.0.0.0/8"]}`, ``, 0, errMFAPolicyNotEnforced},
		{"conditions that are not an object", `[1,2,3]`, ``, 0, errMFAPolicyNotEnforced},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkNewMFAPolicy(json.RawMessage(tc.conditions), json.RawMessage(tc.methods), tc.graceHours)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("checkNewMFAPolicy(%q, %q, %d) refused: %v", tc.conditions, tc.methods, tc.graceHours, err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("checkNewMFAPolicy(%q, %q, %d) = %v, want %v",
					tc.conditions, tc.methods, tc.graceHours, err, tc.want)
			}
		})
	}
}

// An update is checked against the policy it changes: the result must be a
// policy the login can enforce. It reports whether the method set changed,
// which is what restarts the users' grace periods; an order change, a grace
// change or an echo does not.
func TestMFAPolicyUpdateRules(t *testing.T) {
	stored := storedMFAPolicySettings{
		// Conditions written before #991; v203 leaves them in place.
		conditions:      json.RawMessage(`{"client_ids": ["a"]}`),
		requiredMethods: json.RawMessage(`["webauthn", "totp"]`),
		graceHours:      24,
	}
	raw := func(s string) *json.RawMessage { r := json.RawMessage(s); return &r }
	hours := func(n int) *int { return &n }
	cases := []struct {
		name        string
		conditions  *json.RawMessage
		methods     *json.RawMessage
		graceHours  *int
		want        error
		wantChanged bool
	}{
		{"none of the three sent", nil, nil, nil, nil, false},
		{"the stored values sent back", raw(`{"client_ids":["a"]}`), raw(`["webauthn","totp"]`), hours(24), nil, false},
		{"the methods in another order", nil, raw(`["totp","webauthn"]`), nil, nil, false},
		{"a longer grace period", nil, nil, hours(96), nil, false},
		{"a method removed", nil, raw(`["webauthn"]`), nil, nil, true},
		{"a method added", nil, raw(`["webauthn","totp","push"]`), nil, nil, true},
		{"a method replaced", nil, raw(`["webauthn","email"]`), nil, nil, true},
		{"everything cleared", raw(`{}`), raw(`[]`), hours(0), nil, true},

		{"methods cleared but the grace period kept", nil, raw(`[]`), nil, errMFAPolicyInvalid, false},
		{"an unknown method", nil, raw(`["webauthn","password"]`), nil, errMFAPolicyInvalid, false},
		{"a grace period over 30 days", nil, nil, hours(maxMFAGraceHours + 1), errMFAPolicyInvalid, false},
		{"a new condition", raw(`{"client_ids":["b"]}`), nil, nil, errMFAPolicyNotEnforced, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed, err := checkMFAPolicyUpdate(stored, tc.conditions, tc.methods, tc.graceHours)
			if tc.want == nil && err != nil {
				t.Fatalf("checkMFAPolicyUpdate refused: %v", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("checkMFAPolicyUpdate = %v, want %v", err, tc.want)
			}
			if changed != tc.wantChanged {
				t.Fatalf("methods changed = %v, want %v", changed, tc.wantChanged)
			}
		})
	}

	t.Run("a policy with no methods accepts a grace period set with them", func(t *testing.T) {
		plain := storedMFAPolicySettings{requiredMethods: json.RawMessage(`[]`)}
		changed, err := checkMFAPolicyUpdate(plain, nil, raw(`["totp"]`), hours(48))
		if err != nil || !changed {
			t.Fatalf("got changed=%v err=%v, want a change and no error", changed, err)
		}
		if _, err := checkMFAPolicyUpdate(plain, nil, nil, hours(48)); !errors.Is(err, errMFAPolicyInvalid) {
			t.Fatalf("a grace period alone on a policy with no methods: got %v, want %v", err, errMFAPolicyInvalid)
		}
	})
}

// The same rules through the handlers, against Postgres: a refused request
// writes nothing, and changing a policy's method set, and only that, starts
// every user's grace period under it again (mfa_policy_grace, v203).
func TestMFAPolicyHandlersEnforceTheRules(t *testing.T) {
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
	for _, tc := range []struct{ name, extra, reason string }{
		{"an unknown method", `"required_methods":["password"]`, "not a method a policy can require"},
		{"a grace period and no method", `"grace_period_hours":24`, "applies only to a policy that requires methods"},
		{"a grace period over 30 days", `"required_methods":["totp"],"grace_period_hours":721`, "between 0 and 720"},
		{"a condition", `"conditions":{"client_ids":["admin-console"]}`, "not enforced"},
	} {
		t.Run("a policy with "+tc.name+" is refused and not written", func(t *testing.T) {
			name := "refused-" + strings.ReplaceAll(tc.name, " ", "-") + "-" + suffix
			code, body := call(http.MethodPost, "/mfa/policies", `{"name":"`+name+`","enabled":true,`+tc.extra+`}`)
			if code != http.StatusBadRequest || !strings.Contains(body, tc.reason) {
				t.Fatalf("want 400 saying %q, got %d %s", tc.reason, code, body)
			}
			if n := count(name); n != 0 {
				t.Fatalf("a refused policy was written (%d rows)", n)
			}
		})
	}

	// A policy that requires TOTP or WebAuthn, with three days to add one.
	var created MFAPolicy
	code, body := call(http.MethodPost, "/mfa/policies",
		`{"name":"strong-`+suffix+`","enabled":true,"priority":5,"required_methods":["totp","webauthn"],"grace_period_hours":72}`)
	if code != http.StatusCreated {
		t.Fatalf("create a policy with methods and a grace period: %d %s", code, body)
	}
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatalf("decode created policy: %v", err)
	}
	if methods, grace, _ := settings(created.ID); methods != `["totp", "webauthn"]` || grace != 72 {
		t.Fatalf("stored methods %s, grace %d; want [\"totp\", \"webauthn\"] and 72", methods, grace)
	}
	path := "/mfa/policies/" + created.ID

	// A user whose grace period under it is running.
	var user string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO users (username, email, enabled, org_id)
		VALUES ($1, $2, true, $3::uuid) RETURNING id::text`,
		"grace-"+suffix, "grace-"+suffix+"@test.local", org).Scan(&user); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	startGrace := func() {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, `
			INSERT INTO mfa_policy_grace (org_id, policy_id, user_id) VALUES ($1::uuid, $2::uuid, $3::uuid)
			ON CONFLICT DO NOTHING`, org, created.ID, user); err != nil {
			t.Fatalf("seed grace row: %v", err)
		}
	}
	graceRows := func() int {
		t.Helper()
		var n int
		if err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM mfa_policy_grace WHERE policy_id = $1::uuid`,
			created.ID).Scan(&n); err != nil {
			t.Fatalf("count grace rows: %v", err)
		}
		return n
	}
	startGrace()

	for _, tc := range []struct{ name, body string }{
		{"a toggle", `{"enabled":false}`},
		{"a rename", `{"name":"strong-renamed-` + suffix + `"}`},
		{"a longer grace period", `{"grace_period_hours":96}`},
		{"the same methods in another order", `{"required_methods":["webauthn","totp"]}`},
		{"the stored values sent back", `{"conditions":{},"required_methods":["totp","webauthn"],"grace_period_hours":96}`},
	} {
		t.Run(tc.name+" keeps the running grace periods", func(t *testing.T) {
			if code, body := call(http.MethodPut, path, tc.body); code != http.StatusOK {
				t.Fatalf("update: %d %s", code, body)
			}
			if n := graceRows(); n != 1 {
				t.Fatalf("%d grace rows after %s, want the running one kept", n, tc.name)
			}
		})
	}
	if _, grace, enabled := settings(created.ID); grace != 96 || enabled {
		t.Fatalf("the updates did not take effect: grace %d, enabled %v", grace, enabled)
	}

	t.Run("a refused update changes nothing", func(t *testing.T) {
		for _, body := range []string{
			`{"required_methods":["totp","password"]}`,
			`{"required_methods":[]}`, // the 96-hour grace period would be left with no method
			`{"grace_period_hours":721}`,
			`{"conditions":{"groups":["Admins"]}}`,
		} {
			if code, resp := call(http.MethodPut, path, body); code != http.StatusBadRequest {
				t.Fatalf("%s: want 400, got %d %s", body, code, resp)
			}
		}
		if methods, grace, _ := settings(created.ID); methods != `["totp", "webauthn"]` || grace != 96 {
			t.Fatalf("a refused update changed the policy: methods %s, grace %d", methods, grace)
		}
		if n := graceRows(); n != 1 {
			t.Fatalf("a refused update touched the grace periods: %d rows", n)
		}
	})

	t.Run("a new method set starts every grace period again", func(t *testing.T) {
		if code, body := call(http.MethodPut, path, `{"required_methods":["webauthn"]}`); code != http.StatusOK {
			t.Fatalf("update: %d %s", code, body)
		}
		if n := graceRows(); n != 0 {
			t.Fatalf("%d grace rows left after the method set changed, want 0", n)
		}
		if methods, _, _ := settings(created.ID); methods != `["webauthn"]` {
			t.Fatalf("stored methods %s, want [\"webauthn\"]", methods)
		}
	})

	t.Run("clearing the methods takes the grace period with it", func(t *testing.T) {
		startGrace()
		if code, body := call(http.MethodPut, path, `{"required_methods":[],"grace_period_hours":0}`); code != http.StatusOK {
			t.Fatalf("clear: %d %s", code, body)
		}
		if methods, grace, _ := settings(created.ID); methods != `[]` || grace != 0 {
			t.Fatalf("clearing left methods %s, grace %d", methods, grace)
		}
		if n := graceRows(); n != 0 {
			t.Fatalf("%d grace rows left after the methods were cleared, want 0", n)
		}
	})

	t.Run("an unknown policy is 404, not a refusal", func(t *testing.T) {
		code, body := call(http.MethodPut, "/mfa/policies/00000000-0000-0000-0000-00000000ffff", `{"required_methods":["totp"]}`)
		if code != http.StatusNotFound {
			t.Fatalf("want 404, got %d %s", code, body)
		}
	})
}
