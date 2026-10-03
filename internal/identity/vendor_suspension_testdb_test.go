package identity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestASuspendedVendorHoldsItsAccountsUntilItComesBack: suspending a vendor
// organization used to change the vendor's row and nothing else, so its
// people kept signing in, kept their sessions and kept their access. On the
// migrated schema:
//
//   - suspending the vendor suspends each of its live accounts (active,
//     pending_mfa), severs it (session revoked, severing recorded) and tells
//     the SSF receivers session-revoked, since the account may come back. An
//     account already disabled and another vendor's account are left alone;
//   - while the vendor is suspended, an account cannot be reactivated, the
//     list offers no reactivation window, and the sweep neither disables a
//     suspension older than the sponsor grace period nor lets an account the
//     route missed stay live;
//   - reactivating the vendor reactivates no account, and restarts the grace
//     window of its suspended ones, so the sweep does not disable them the
//     minute the vendor is back and a sponsor can take each one back.
func TestASuspendedVendorHoldsItsAccountsUntilItComesBack(t *testing.T) {
	db, cleanup := setupMigratedDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	gin.SetMode(gin.TestMode)
	f := newExternalFixture(t, db)
	svc := NewService(db, nil, &config.Config{}, zap.NewNop())
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: f.org}))
		c.Set("user_id", f.admin)
		c.Set("roles", []string{"admin"})
		c.Next()
	})
	r.PUT("/vendor-orgs/:id", svc.handleUpdateVendorOrg)
	r.GET("/external-users", svc.handleListExternalUsers)
	r.POST("/external-users/:id/reactivate", svc.handleReactivateExternalUser)
	call := func(method, path, body string) (int, map[string]interface{}) {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		out := map[string]interface{}{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	setVendor := func(status string) {
		t.Helper()
		body := `{"name":"Acme Field Service ` + f.suffix + `","status":"` + status + `","contract_end":"2099-12-31"}`
		if code, out := call(http.MethodPut, "/vendor-orgs/"+f.vendor, body); code != http.StatusOK || out["status"] != status {
			t.Fatalf("PUT the vendor %s: %d %v", status, code, out)
		}
	}
	sweep := func() { svc.sweepExternalAccounts(orgctx.WithBypassRLS(context.Background())) }
	listed := func(id string) map[string]interface{} {
		t.Helper()
		code, out := call(http.MethodGet, "/external-users?vendor_org_id="+f.vendor, "")
		if code != http.StatusOK {
			t.Fatalf("list external users: %d %v", code, out)
		}
		users, _ := out["external_users"].([]interface{})
		for _, u := range users {
			if m, _ := u.(map[string]interface{}); m["id"] == id {
				return m
			}
		}
		t.Fatalf("external user %s is not listed: %v", id, out)
		return nil
	}

	live := f.external("vs-live", f.vendor, f.sponsor, 30)
	pending := f.external("vs-pending", f.vendor, f.sponsor, 30)
	f.exec(`UPDATE users SET account_status = 'pending_mfa', enabled = false WHERE id = $1`, pending)
	disabled := f.external("vs-disabled", f.vendor, f.sponsor, 30)
	f.exec(`UPDATE users SET account_status = 'disabled', enabled = false, access_severed_at = NOW() WHERE id = $1`, disabled)
	// A sponsor's departure suspended this one six days ago: one day of its
	// grace is left when the vendor is suspended.
	departed := f.external("vs-departed", f.vendor, f.sponsor, 30)
	f.exec(`UPDATE users SET account_status = 'suspended', enabled = false, access_severed_at = NOW(),
	               status_changed_at = NOW() - interval '6 days' WHERE id = $1`, departed)
	other := f.newVendor("Other Supplier", "2099-12-31")
	bystander := f.external("vs-bystander", other, f.sponsor, 30)

	setVendor("suspended")

	for _, id := range []string{live, pending} {
		s := f.state(id)
		if s.status != "suspended" || s.enabled || s.severed == nil || s.liveSess != 0 {
			t.Errorf("account %s after its vendor's suspension: %+v; want suspended, unable to sign in, severed, no live session", id, s)
		}
		if got := f.signals(id); !slices.Equal(got, []string{"session-revoked"}) {
			t.Errorf("SSF signals for %s: %v, want [session-revoked]: the account may come back with its vendor", id, got)
		}
		if n := f.auditCount(id, "external.suspended", 1); n != 1 {
			t.Errorf("external.suspended events for %s = %d, want 1", id, n)
		}
	}
	if s := f.state(disabled); s.status != "disabled" {
		t.Errorf("a disabled account became %q when its vendor was suspended", s.status)
	}
	if got := f.signals(disabled); len(got) != 0 {
		t.Errorf("a disabled account was signalled again: %v", got)
	}
	if s := f.state(bystander); s.status != "active" || !s.enabled || s.liveSess != 1 {
		t.Errorf("another vendor's account: %+v; want untouched", s)
	}

	// Suspending a suspended vendor again moves nothing and signals nothing.
	setVendor("suspended")
	if got := f.signals(live); len(got) != 1 {
		t.Errorf("a second suspension signalled again: %v", got)
	}

	// While the vendor is suspended: no reactivation, no window offered.
	code, out := call(http.MethodPost, "/external-users/"+live+"/reactivate",
		`{"reason":"back to work","sponsor_user_id":"`+f.sponsor2+`"}`)
	if code != http.StatusConflict && code != http.StatusForbidden && code != http.StatusBadRequest {
		t.Errorf("reactivating an account of a suspended vendor: %d %v, want a refusal", code, out)
	}
	if s := f.state(live); s.status != "suspended" {
		t.Fatalf("a refused reactivation changed the account: %+v", s)
	}
	if u := listed(departed); u["reactivate_until"] != nil {
		t.Errorf("the list offers a reactivation window while the vendor is suspended: %v", u["reactivate_until"])
	}

	// The sweep, two days on: the departed account's grace has run out on
	// the clock, but the window does not run while the vendor is suspended.
	// An account the route did not reach (written live behind its back) is
	// suspended by the sweep.
	f.exec(`UPDATE users SET status_changed_at = NOW() - interval '8 days' WHERE id = $1`, departed)
	missed := f.external("vs-missed", f.vendor, f.sponsor, 30)
	sweep()
	if s := f.state(departed); s.status != "suspended" {
		t.Errorf("the sweep moved a suspended vendor's account past its grace to %q; the window is held while the vendor is suspended", s.status)
	}
	if s := f.state(missed); s.status != "suspended" || s.enabled || s.severed == nil || s.liveSess != 0 {
		t.Errorf("a live account of a suspended vendor after the sweep: %+v; want suspended and severed", s)
	}
	if got := f.signals(missed); !slices.Equal(got, []string{"session-revoked"}) {
		t.Errorf("SSF signals for the account the sweep suspended: %v, want [session-revoked]", got)
	}

	// The vendor comes back: nothing is reactivated, and every suspended
	// account has a fresh window. Restarting the window is not a new
	// departure: an account already severed is not severed again.
	signalsBefore := map[string][]string{}
	for _, id := range []string{live, pending, departed, missed} {
		signalsBefore[id] = f.signals(id)
	}
	setVendor("active")
	for _, id := range []string{live, pending, departed, missed} {
		s := f.state(id)
		if s.status != "suspended" || s.enabled {
			t.Errorf("account %s after its vendor came back: %+v; want still suspended until a sponsor takes it back", id, s)
		}
		if f.scalar(`SELECT (status_changed_at > NOW() - interval '1 minute')::text FROM users WHERE id = $1`, id) != "true" {
			t.Errorf("account %s: the grace window was not restarted (status changed at %v)", id, s.changedAt)
		}
	}
	sweep()
	if s := f.state(departed); s.status != "suspended" {
		t.Errorf("the sweep disabled an account the minute its vendor came back (%q); its window restarts", s.status)
	}
	for id, before := range signalsBefore {
		if got := f.signals(id); !slices.Equal(got, before) {
			t.Errorf("account %s was severed again when its vendor came back: signals %v, were %v", id, got, before)
		}
	}
	if u := listed(departed); u["reactivate_until"] == nil {
		t.Errorf("the list offers no reactivation window once the vendor is back")
	}
	code, out = call(http.MethodPost, "/external-users/"+live+"/reactivate",
		`{"reason":"back to work","sponsor_user_id":"`+f.sponsor2+`"}`)
	if code != http.StatusOK {
		t.Fatalf("reactivating an account of the reactivated vendor: %d %v", code, out)
	}
	if s := f.state(live); s.status != "active" || !s.enabled {
		t.Errorf("after reactivation: %+v; want active", s)
	}
}
