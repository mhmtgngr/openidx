package identity

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

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/externalid"
)

// externalFixture is an org with an administrator, two sponsors and a vendor,
// on the migrated schema, for the external-account management and sweep
// tests.
type externalFixture struct {
	t        *testing.T
	db       *database.PostgresDB
	ctx      context.Context
	org      string
	suffix   string
	admin    string
	sponsor  string
	sponsor2 string
	vendor   string
}

func newExternalFixture(t *testing.T, db *database.PostgresDB) *externalFixture {
	f := &externalFixture{
		t:      t,
		db:     db,
		org:    "00000000-0000-0000-0000-000000000010",
		suffix: fmt.Sprintf("%d", time.Now().UnixNano()),
	}
	f.ctx = orgctx.With(context.Background(), orgctx.Org{ID: f.org})
	f.admin = f.internal("xa-admin")
	f.sponsor = f.internal("xa-sponsor")
	f.sponsor2 = f.internal("xa-sponsor-2")
	f.vendor = f.newVendor("Acme Field Service", "2099-12-31")
	return f
}

func (f *externalFixture) exec(q string, args ...interface{}) {
	f.t.Helper()
	if _, err := f.db.Pool.Exec(f.ctx, q, args...); err != nil {
		f.t.Fatalf("seed (%s): %v", q, err)
	}
}

func (f *externalFixture) scalar(q string, args ...interface{}) string {
	f.t.Helper()
	var v string
	if err := f.db.Pool.QueryRow(f.ctx, q, args...).Scan(&v); err != nil {
		f.t.Fatalf("read (%s): %v", q, err)
	}
	return v
}

func (f *externalFixture) internal(name string) string {
	return f.scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
		f.org, name+"-"+f.suffix)
}

func (f *externalFixture) newVendor(name, contractEnd string) string {
	return f.scalar(`INSERT INTO vendor_organizations (org_id, name, contract_end) VALUES ($1, $2, $3::date) RETURNING id::text`,
		f.org, name+" "+f.suffix, contractEnd)
}

// external creates a live external account of vendor, sponsored by sponsor,
// ending in the given number of days, with a live session to sever.
func (f *externalFixture) external(name, vendor, sponsor string, days int) string {
	id := f.scalar(`
		INSERT INTO users (org_id, username, email, user_type, vendor_org_id, sponsor_user_id, account_expires_at, status_changed_at)
		VALUES ($1, $2::text, $2::text || '@supplier.example.test', 'external', $3, $4, NOW() + make_interval(days => $5), NOW())
		RETURNING id::text`, f.org, name+"-"+f.suffix, vendor, sponsor, days)
	f.exec(`INSERT INTO sessions (user_id, client_id, expires_at, org_id, revoked)
		VALUES ($1::uuid, 'admin-console', NOW() + interval '1 day', $2::uuid, false)`, id, f.org)
	return id
}

type externalState struct {
	status    string
	enabled   bool
	sponsor   string
	expires   time.Time
	severed   *time.Time
	liveSess  int
	changedAt *time.Time
}

func (f *externalFixture) state(id string) externalState {
	f.t.Helper()
	var s externalState
	var sponsor *string
	if err := f.db.Pool.QueryRow(f.ctx, `
		SELECT account_status, COALESCE(enabled, false), sponsor_user_id::text, account_expires_at, access_severed_at, status_changed_at,
		       (SELECT count(*) FROM sessions WHERE user_id = u.id AND org_id = u.org_id AND NOT COALESCE(revoked, false))
		  FROM users u WHERE id = $1`, id).
		Scan(&s.status, &s.enabled, &sponsor, &s.expires, &s.severed, &s.changedAt, &s.liveSess); err != nil {
		f.t.Fatalf("read external account %s: %v", id, err)
	}
	if sponsor != nil {
		s.sponsor = *sponsor
	}
	return s
}

// auditCount waits briefly for the asynchronous audit writes, then counts
// the events of action about target.
func (f *externalFixture) auditCount(target, action string, want int) int {
	f.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		n := 0
		if err := f.db.Pool.QueryRow(f.ctx,
			`SELECT count(*) FROM audit_events WHERE target_id = $1 AND action = $2 AND org_id = $3`, target, action, f.org).Scan(&n); err != nil {
			f.t.Fatalf("count audit events: %v", err)
		}
		if n >= want || time.Now().After(deadline) {
			return n
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// TestExternalAccountsAreManagedWithinTheirLifecycle drives the routes an
// administrator uses on an external account after it exists, on the migrated
// schema: suspend, disable, extend, reactivate, change of sponsor and the
// list. Each move is checked against the state it may start from, and each
// refusal against the request it must refuse:
//
//   - every route needs a reason, refuses an external caller (I12) and
//     answers 404 for an internal user's id;
//   - suspending and disabling sever the account (the session is revoked and
//     the severing recorded); neither repeats on an account already there;
//   - extending stays within a year and the vendor's contract, and only while
//     the vendor is active;
//   - reactivating needs a suspended account, a valid new sponsor, an active
//     vendor and the grace period (decision D5), and clears the severing so a
//     later departure severs again.
func TestExternalAccountsAreManagedWithinTheirLifecycle(t *testing.T) {
	db, cleanup := setupMigratedDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	gin.SetMode(gin.TestMode)
	f := newExternalFixture(t, db)

	svc := NewService(db, nil, &config.Config{}, zap.NewNop())
	actor := f.admin
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: f.org}))
		c.Set("user_id", actor)
		c.Set("roles", []string{"admin"})
		c.Next()
	})
	r.GET("/external-users", svc.handleListExternalUsers)
	r.POST("/external-users/:id/suspend", svc.handleSuspendExternalUser)
	r.POST("/external-users/:id/disable", svc.handleDisableExternalUser)
	r.POST("/external-users/:id/extend", svc.handleExtendExternalUser)
	r.POST("/external-users/:id/reactivate", svc.handleReactivateExternalUser)
	r.POST("/external-users/:id/sponsor", svc.handleChangeExternalSponsor)
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
	expect := func(t *testing.T, what string, code int, body map[string]interface{}, wantStatus int, wantCode string) {
		t.Helper()
		if code != wantStatus || (wantCode != "" && body["code"] != wantCode) {
			t.Errorf("%s: %d %v, want %d %s", what, code, body, wantStatus, wantCode)
		}
	}

	vendorUser := f.external("xa-vendor", f.vendor, f.sponsor, 30)

	t.Run("every route needs a reason, an internal caller and an external account", func(t *testing.T) {
		for _, path := range []string{"suspend", "disable", "extend", "reactivate", "sponsor"} {
			code, body := call(http.MethodPost, "/external-users/"+vendorUser+"/"+path, `{}`)
			expect(t, path+" without a reason", code, body, http.StatusBadRequest, "")
		}
		code, body := call(http.MethodPost, "/external-users/"+f.sponsor2+"/suspend", `{"reason":"test"}`)
		expect(t, "suspending an internal user through the external route", code, body, http.StatusNotFound, "")

		other := f.external("xa-other", f.vendor, f.sponsor, 30)
		actor = vendorUser
		code, body = call(http.MethodPost, "/external-users/"+other+"/extend", `{"reason":"more time","extend_days":30}`)
		actor = f.admin
		expect(t, "an external user extending an account", code, body, http.StatusForbidden, "external_not_permitted")
		if s := f.state(vendorUser); s.status != "active" || !s.enabled {
			t.Fatalf("a refused request changed the account: %+v", s)
		}
	})

	t.Run("suspend severs once, and a suspended account is not suspended again", func(t *testing.T) {
		code, body := call(http.MethodPost, "/external-users/"+vendorUser+"/suspend", `{"reason":"investigation"}`)
		expect(t, "suspend", code, body, http.StatusOK, "")
		s := f.state(vendorUser)
		if s.status != "suspended" || s.enabled || s.severed == nil || s.liveSess != 0 {
			t.Fatalf("after suspend: %+v; want suspended, disabled, severed, no live session", s)
		}
		code, body = call(http.MethodPost, "/external-users/"+vendorUser+"/suspend", `{"reason":"again"}`)
		expect(t, "suspending a suspended account", code, body, http.StatusConflict, "external_status_conflict")
		code, body = call(http.MethodPost, "/external-users/"+vendorUser+"/sponsor", `{"reason":"handover","sponsor_user_id":"`+f.sponsor2+`"}`)
		expect(t, "changing the sponsor of a suspended account", code, body, http.StatusConflict, "external_status_conflict")
		if n := f.auditCount(vendorUser, "external.suspended", 1); n != 1 {
			t.Errorf("external.suspended events = %d, want 1", n)
		}
	})

	t.Run("reactivation needs a valid sponsor, an active vendor and the grace period", func(t *testing.T) {
		code, body := call(http.MethodPost, "/external-users/"+vendorUser+"/reactivate",
			`{"reason":"cleared","sponsor_user_id":"`+f.external("xa-not-a-sponsor", f.vendor, f.sponsor, 30)+`"}`)
		expect(t, "an external user as the new sponsor", code, body, http.StatusForbidden, "external_sponsor_invalid")

		f.exec(`UPDATE vendor_organizations SET status = 'suspended' WHERE id = $1`, f.vendor)
		code, body = call(http.MethodPost, "/external-users/"+vendorUser+"/reactivate", `{"reason":"cleared","sponsor_user_id":"`+f.sponsor2+`"}`)
		expect(t, "reactivating while the vendor is suspended", code, body, http.StatusForbidden, "vendor_not_active")
		f.exec(`UPDATE vendor_organizations SET status = 'active' WHERE id = $1`, f.vendor)

		code, body = call(http.MethodPost, "/external-users/"+vendorUser+"/reactivate", `{"reason":"cleared","sponsor_user_id":"`+f.sponsor2+`"}`)
		expect(t, "reactivate", code, body, http.StatusOK, "")
		s := f.state(vendorUser)
		if s.status != "active" || !s.enabled || s.sponsor != f.sponsor2 || s.severed != nil {
			t.Fatalf("after reactivation: %+v; want active, enabled, the new sponsor, the severing cleared", s)
		}
		code, body = call(http.MethodPost, "/external-users/"+vendorUser+"/reactivate", `{"reason":"twice","sponsor_user_id":"`+f.sponsor+`"}`)
		expect(t, "reactivating an active account", code, body, http.StatusConflict, "external_status_conflict")

		late := f.external("xa-late", f.vendor, f.sponsor, 30)
		f.exec(`UPDATE users SET account_status = 'suspended', enabled = false, status_changed_at = NOW() - interval '8 days' WHERE id = $1`, late)
		code, body = call(http.MethodPost, "/external-users/"+late+"/reactivate", `{"reason":"too late","sponsor_user_id":"`+f.sponsor2+`"}`)
		expect(t, "reactivating after the grace period", code, body, http.StatusConflict, "external_status_conflict")
		if s := f.state(late); s.status != "suspended" || s.enabled {
			t.Errorf("a refused reactivation changed the account: %+v", s)
		}
	})

	t.Run("the sponsor of a live account changes to a valid sponsor only", func(t *testing.T) {
		code, body := call(http.MethodPost, "/external-users/"+vendorUser+"/sponsor", `{"reason":"handover","sponsor_user_id":"`+vendorUser+`"}`)
		expect(t, "the account as its own sponsor", code, body, http.StatusForbidden, "external_sponsor_invalid")
		code, body = call(http.MethodPost, "/external-users/"+vendorUser+"/sponsor", `{"reason":"handover","sponsor_user_id":"`+f.sponsor+`"}`)
		expect(t, "change the sponsor", code, body, http.StatusOK, "")
		if s := f.state(vendorUser); s.sponsor != f.sponsor {
			t.Errorf("sponsor = %s, want %s", s.sponsor, f.sponsor)
		}
	})

	t.Run("extension stays within a year, the contract and an active vendor", func(t *testing.T) {
		before := f.state(vendorUser).expires
		code, body := call(http.MethodPost, "/external-users/"+vendorUser+"/extend", `{"reason":"project extended","extend_days":30}`)
		expect(t, "extend by 30 days", code, body, http.StatusOK, "")
		if got := f.state(vendorUser).expires; got.Sub(before) < 29*24*time.Hour || got.Sub(before) > 31*24*time.Hour {
			t.Errorf("the account moved from %v to %v, want 30 days later", before, got)
		}
		code, body = call(http.MethodPost, "/external-users/"+vendorUser+"/extend", `{"reason":"too long","extend_days":400}`)
		expect(t, "extending past a year", code, body, http.StatusForbidden, "external_expiry_invalid")
		code, body = call(http.MethodPost, "/external-users/"+vendorUser+"/extend", `{"reason":"no date"}`)
		expect(t, "extending with no date", code, body, http.StatusBadRequest, "")

		shortVendor := f.newVendor("Short Contract", time.Now().AddDate(0, 0, 10).Format("2006-01-02"))
		short := f.external("xa-short", shortVendor, f.sponsor, 5)
		code, body = call(http.MethodPost, "/external-users/"+short+"/extend", `{"reason":"past the contract","extend_days":20}`)
		expect(t, "extending past the vendor's contract", code, body, http.StatusForbidden, "external_expiry_invalid")
		f.exec(`UPDATE vendor_organizations SET status = 'suspended' WHERE id = $1`, shortVendor)
		code, body = call(http.MethodPost, "/external-users/"+short+"/extend", `{"reason":"vendor suspended","extend_days":2}`)
		expect(t, "extending while the vendor is suspended", code, body, http.StatusForbidden, "vendor_not_active")
	})

	t.Run("disable is final", func(t *testing.T) {
		code, body := call(http.MethodPost, "/external-users/"+vendorUser+"/disable", `{"reason":"left the vendor"}`)
		expect(t, "disable", code, body, http.StatusOK, "")
		if s := f.state(vendorUser); s.status != "disabled" || s.enabled || s.severed == nil {
			t.Fatalf("after disable: %+v", s)
		}
		for _, path := range []string{"disable", "suspend"} {
			code, body = call(http.MethodPost, "/external-users/"+vendorUser+"/"+path, `{"reason":"again"}`)
			expect(t, path+" a disabled account", code, body, http.StatusConflict, "external_status_conflict")
		}
		code, body = call(http.MethodPost, "/external-users/"+vendorUser+"/reactivate", `{"reason":"back","sponsor_user_id":"`+f.sponsor+`"}`)
		expect(t, "reactivating a disabled account", code, body, http.StatusConflict, "external_status_conflict")
		code, body = call(http.MethodPost, "/external-users/"+vendorUser+"/extend", `{"reason":"back","extend_days":10}`)
		expect(t, "extending a disabled account", code, body, http.StatusConflict, "external_status_conflict")
	})

	t.Run("the list shows each account with its vendor, sponsor and state", func(t *testing.T) {
		live := f.external("xa-listed", f.vendor, f.sponsor, 7)
		f.exec(`INSERT INTO mfa_totp (user_id, secret, enabled, org_id) VALUES ($1, 'unused', true, $2)`, live, f.org)
		code, body := call(http.MethodGet, "/external-users?vendor_org_id="+f.vendor, "")
		if code != http.StatusOK {
			t.Fatalf("list: %d %v", code, body)
		}
		byID := map[string]map[string]interface{}{}
		list, _ := body["external_users"].([]interface{})
		for _, e := range list {
			m, _ := e.(map[string]interface{})
			byID[fmt.Sprint(m["id"])] = m
		}
		got := byID[live]
		if got == nil || got["vendor_name"] != "Acme Field Service "+f.suffix || got["sponsor_name"] != "xa-sponsor-"+f.suffix ||
			got["has_strong_factor"] != true || got["expiring_soon"] != true || got["status"] != "active" {
			t.Errorf("the listed account: %v", got)
		}
		if byID[vendorUser] == nil || byID[vendorUser]["status"] != "disabled" || byID[vendorUser]["has_strong_factor"] != false {
			t.Errorf("the disabled account: %v", byID[vendorUser])
		}
		if _, ok := byID[f.sponsor]; ok {
			t.Error("the list shows an internal user")
		}
		code, body = call(http.MethodGet, "/external-users?status=disabled&vendor_org_id="+f.vendor, "")
		list, _ = body["external_users"].([]interface{})
		if code != http.StatusOK || len(list) != 1 {
			t.Errorf("the disabled filter: %d, %d accounts, want 1", code, len(list))
		}
	})
}

// TestExternalAccountSweepEndsWhatTheClockAndDeparturesEnd runs the sweep on
// the migrated schema against one account per transition, next to the
// accounts it must leave alone, and runs it twice:
//
//   - I8: an account past its end is expired, a suspended one included;
//   - I9: an account whose sponsor was disabled by a writer that does not know
//     about sponsorship is suspended; one of a vendor closed behind the close
//     route's back is disabled;
//   - D5: an account suspended past the grace period is disabled;
//   - an account still waiting for its second factor after its invitation
//     lapsed is expired;
//   - each is severed once (the session revoked, access_severed_at set, one
//     external.access_severed event), and the second run moves and severs
//     nothing.
//
// The controls: a live account with a valid sponsor and time left, a pending
// account whose invitation still answers, a suspension inside the grace
// period, and a disabled internal user.
func TestExternalAccountSweepEndsWhatTheClockAndDeparturesEnd(t *testing.T) {
	db, cleanup := setupMigratedDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	f := newExternalFixture(t, db)
	svc := NewService(db, nil, &config.Config{}, zap.NewNop())

	ended := f.external("xs-ended", f.vendor, f.sponsor, 30)
	f.exec(`UPDATE users SET account_expires_at = NOW() - interval '1 minute' WHERE id = $1`, ended)
	endedWhileSuspended := f.external("xs-ended-suspended", f.vendor, f.sponsor, 30)
	f.exec(`UPDATE users SET account_status = 'suspended', enabled = false, access_severed_at = NOW(),
	               account_expires_at = NOW() - interval '1 minute' WHERE id = $1`, endedWhileSuspended)

	leaver := f.internal("xs-leaver")
	orphaned := f.external("xs-orphaned", f.vendor, leaver, 30)
	f.exec(`UPDATE users SET enabled = false WHERE id = $1`, leaver)

	closedVendor := f.newVendor("Closed Behind The Route", "2099-12-31")
	ofClosed := f.external("xs-of-closed", closedVendor, f.sponsor, 30)
	f.exec(`UPDATE vendor_organizations SET status = 'closed', closed_at = NOW() WHERE id = $1`, closedVendor)

	lapsedGrace := f.external("xs-lapsed-grace", f.vendor, f.sponsor, 30)
	f.exec(`UPDATE users SET account_status = 'suspended', enabled = false, access_severed_at = NOW() - interval '8 days',
	               status_changed_at = NOW() - interval '8 days' WHERE id = $1`, lapsedGrace)
	inGrace := f.external("xs-in-grace", f.vendor, f.sponsor, 30)
	f.exec(`UPDATE users SET account_status = 'suspended', enabled = false, access_severed_at = NOW(),
	               status_changed_at = NOW() - interval '6 days' WHERE id = $1`, inGrace)

	pending := func(name, invitationExpiry string) string {
		id := f.external(name, f.vendor, f.sponsor, 30)
		f.exec(`UPDATE users SET account_status = 'pending_mfa', enabled = false WHERE id = $1`, id)
		f.exec(`INSERT INTO user_invitations (email, invited_by, token, expires_at, org_id, status, accepted_at,
		                                      user_type, vendor_org_id, sponsor_user_id, account_expires_at)
		        SELECT email, $2, $3, NOW() + $4::interval, org_id, 'accepted', NOW(),
		               'external', vendor_org_id, sponsor_user_id, account_expires_at
		          FROM users WHERE id = $1`, id, f.admin, "tok-"+name+"-"+f.suffix, invitationExpiry)
		return id
	}
	lapsedInvite := pending("xs-lapsed-invite", "-1 hour")
	openInvite := pending("xs-open-invite", "2 days")

	live := f.external("xs-live", f.vendor, f.sponsor, 30)
	disabledInternal := f.internal("xs-disabled-internal")
	f.exec(`UPDATE users SET enabled = false WHERE id = $1`, disabledInternal)

	// Between the account's end and the sweep the account still reads active,
	// and the enforcement points already refuse it (I8). Both accounts have
	// a strong factor, so the end is the only difference.
	for _, id := range []string{ended, live} {
		f.exec(`INSERT INTO mfa_totp (user_id, secret, enabled, org_id) VALUES ($1, 'unused', true, $2)`, id, f.org)
	}
	if err := externalid.CheckEffective(f.ctx, db.Pool, f.org, ended); !errors.Is(err, externalid.ErrNotActivated) {
		t.Errorf("an active account past its end, before the sweep: CheckEffective = %v, want ErrNotActivated", err)
	}
	if err := externalid.CheckEffective(f.ctx, db.Pool, f.org, live); err != nil {
		t.Errorf("a live account with time left: CheckEffective = %v, want nil", err)
	}

	sweepCtx := orgctx.WithBypassRLS(context.Background())
	svc.sweepExternalAccounts(sweepCtx)

	want := []struct {
		name, id, status, action string
	}{
		{"an account past its end", ended, "expired", "external.expired"},
		{"a suspended account past its end", endedWhileSuspended, "expired", "external.expired"},
		{"an account whose sponsor was disabled", orphaned, "suspended", "external.suspended"},
		{"an account of a closed vendor", ofClosed, "disabled", "external.disabled"},
		{"a suspension past the grace period", lapsedGrace, "disabled", "external.disabled"},
		{"a pending account whose invitation lapsed", lapsedInvite, "expired", "external.expired"},
	}
	first := map[string]time.Time{}
	for _, w := range want {
		s := f.state(w.id)
		if s.status != w.status || s.enabled || s.severed == nil || s.liveSess != 0 {
			t.Errorf("%s: %+v; want %s, disabled, severed, no live session", w.name, s, w.status)
			continue
		}
		if s.changedAt == nil || s.severed.Before(*s.changedAt) {
			t.Errorf("%s: severed at %v, before its status changed at %v", w.name, s.severed, s.changedAt)
		}
		first[w.id] = *s.severed
		if n := f.auditCount(w.id, w.action, 1); n != 1 {
			t.Errorf("%s: %d %s events, want 1", w.name, n, w.action)
		}
		if n := f.auditCount(w.id, "external.access_severed", 1); n != 1 {
			t.Errorf("%s: %d external.access_severed events, want 1", w.name, n)
		}
	}

	untouched := []struct {
		name, id, status string
		enabled          bool
		liveSess         int
	}{
		{"a live account", live, "active", true, 1},
		{"a pending account whose invitation still answers", openInvite, "pending_mfa", false, 1},
		{"a suspension inside the grace period", inGrace, "suspended", false, 1},
	}
	for _, u := range untouched {
		s := f.state(u.id)
		if s.status != u.status || s.enabled != u.enabled || s.liveSess != u.liveSess {
			t.Errorf("%s was touched: %+v", u.name, s)
		}
	}
	var internalStatus string
	var internalSevered *time.Time
	if err := db.Pool.QueryRow(f.ctx, `SELECT account_status, access_severed_at FROM users WHERE id = $1`, disabledInternal).
		Scan(&internalStatus, &internalSevered); err != nil {
		t.Fatal(err)
	}
	if internalStatus != "active" || internalSevered != nil {
		t.Errorf("the sweep touched a disabled internal user: %s, severed %v", internalStatus, internalSevered)
	}

	t.Run("a second run moves and severs nothing", func(t *testing.T) {
		svc.sweepExternalAccounts(sweepCtx)
		for _, w := range want {
			s := f.state(w.id)
			if s.status != w.status || s.severed == nil || !s.severed.Equal(first[w.id]) {
				t.Errorf("%s: %+v after the second run; want %s, severed at %v", w.name, s, w.status, first[w.id])
			}
		}
		time.Sleep(200 * time.Millisecond) // a second, wrong event would be written asynchronously
		for _, w := range want {
			if n := f.auditCount(w.id, "external.access_severed", 1); n != 1 {
				t.Errorf("%s: %d external.access_severed events after the second run, want 1", w.name, n)
			}
			if n := f.auditCount(w.id, w.action, 1); n != 1 {
				t.Errorf("%s: %d %s events after the second run, want 1", w.name, n, w.action)
			}
		}
	})
}
