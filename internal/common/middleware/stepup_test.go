package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// The admin-API half of the freshness gate. It is mounted on the whole
// /api/v1 group, so what it does NOT gate matters as much as what it does: a
// console that prompted for a second factor on every page load would be turned
// off within the hour, and an unattended integration that started 403-ing at
// 03:00 would be worse.
//
// These run with a nil database on purpose. Every case here must be decided
// before any query is made — off, safe method, non-admin, machine caller — so
// a nil pool is the proof that no query happens. The DB-backed decisions
// (fresh, stale, never verified) are pinned in internal/access, which has a
// real Postgres in its suite.

func stepupRouter(gate string, roles []string, rec StepUpRecorder) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", "11111111-1111-1111-1111-111111111111")
		c.Set("org_id", "22222222-2222-2222-2222-222222222222")
		if roles != nil {
			c.Set("roles", roles)
		}
		c.Next()
	})
	r.Use(RequireFreshMFA(nil, StepUpConfig{
		Gate: gate, MaxAge: 15 * time.Minute, Source: "admin-api",
	}, rec, zap.NewNop()))
	h := func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) }
	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete} {
		r.Handle(m, "/api/v1/users", h)
	}
	return r
}

func TestAdminWriteGate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		gate   string
		method string
		roles  []string
		want   int
	}{
		{"off changes nothing", "off", http.MethodPost, []string{"admin"}, http.StatusOK},
		{"a read is never gated", "enforce", http.MethodGet, []string{"admin"}, http.StatusOK},
		{"a preflight is never gated", "enforce", http.MethodOptions, []string{"admin"}, http.StatusOK},
		// A non-admin's own writes — updating their profile, marking a
		// notification read — are not admin writes and are not gated. The
		// design's rule is about admin authority, not about everyone.
		{"a non-admin write is not an admin write", "enforce", http.MethodPost, []string{"user"}, http.StatusOK},
		{"a caller with no roles at all", "enforce", http.MethodPost, nil, http.StatusOK},

		// With no session id on the token, freshness cannot be established.
		// Observe records it; enforce refuses. Both are pinned because the
		// difference IS the staged rollout.
		{"observe permits an admin write it cannot vouch for", "observe", http.MethodPost, []string{"admin"}, http.StatusOK},
		{"enforce refuses an admin write it cannot vouch for", "enforce", http.MethodPost, []string{"admin"}, http.StatusForbidden},
		{"enforce refuses an admin delete", "enforce", http.MethodDelete, []string{"super_admin"}, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := stepupRouter(tc.gate, tc.roles, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(tc.method, "/api/v1/users", nil))
			if tc.method == http.MethodOptions {
				// gin answers an unregistered OPTIONS with 404; what matters
				// is that the gate did not turn it into a 403.
				if w.Code == http.StatusForbidden {
					t.Fatalf("a preflight was gated")
				}
				return
			}
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

// TestBothBranchesRecord is the property the rollout rests on: an operator
// runs observe to count who would be interrupted, then flips to enforce. If
// enforce recorded less than observe, the flip would destroy the evidence that
// justified it.
func TestBothBranchesRecord(t *testing.T) {
	for _, gate := range []string{"observe", "enforce"} {
		t.Run(gate, func(t *testing.T) {
			var got []string
			rec := func(_ context.Context, _, eventType, _, _, _ string, details map[string]interface{}) error {
				got = append(got, eventType)
				if _, ok := details["max_age_seconds"]; !ok {
					t.Error("no max_age_seconds in the record; an operator reading observe mode is " +
						"choosing a NUMBER and cannot do it from a denial count alone")
				}
				if _, ok := details["factor_age_seconds"]; !ok {
					t.Error("no factor_age_seconds in the record")
				}
				return nil
			}
			r := stepupRouter(gate, []string{"admin"}, rec)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/users", nil))

			if len(got) != 1 {
				t.Fatalf("recorded %d events, want exactly 1 (status %d)", len(got), w.Code)
			}
			want := "access.stepup.would_require"
			if gate == "enforce" {
				want = "access.stepup.required"
			}
			if got[0] != want {
				t.Errorf("event_type = %q, want %q", got[0], want)
			}
		})
	}
}

// TestMachineCallersAreNotGated: an API key or service account holding an
// admin role is an unattended integration. There is nobody to prompt, so a
// gate here does not produce a step-up, it produces an outage.
func TestMachineCallersAreNotGated(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*gin.Context)
	}{
		{"api key", func(c *gin.Context) { c.Set("auth_method", "api_key") }},
		{"service account", func(c *gin.Context) { c.Set("service_account_id", "sa1") }},
		{"client credentials, no subject", func(c *gin.Context) { c.Set("user_id", "") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			r := gin.New()
			r.Use(func(c *gin.Context) {
				c.Set("user_id", "11111111-1111-1111-1111-111111111111")
				c.Set("org_id", "22222222-2222-2222-2222-222222222222")
				c.Set("roles", []string{"admin"})
				tc.set(c)
				c.Next()
			})
			r.Use(RequireFreshMFA(nil, StepUpConfig{Gate: "enforce", MaxAge: time.Minute}, nil, zap.NewNop()))
			r.POST("/api/v1/users", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/users", nil))
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
			}
		})
	}
}
