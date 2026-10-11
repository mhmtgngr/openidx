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

	"github.com/openidx/openidx/internal/accessdecision"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/externalid"
)

// Invariant I13 and the engagement lifecycle on the migrated schema. A vendor
// created now requires engagements, so before one exists its external user is
// refused an application (accessdecision) and a PAM launch or request
// (externalid.CheckEngagement) although nothing else stands in the way. An
// engagement that starts now writes, before its response, an assignment to
// its application and a connect grant on its PAM entry for its member and for
// nobody else, ending with it; the decision then allows the member and still
// refuses the vendor's other user. A request window past the engagement is
// refused. Shortening the engagement shortens what it wrote. An assignment a
// request gave for longer is shared, kept at its own window and never cut.
// Closing cuts what the engagement wrote, and the decision refuses again. A
// scheduled engagement writes nothing until the sweep finds it started, and
// the sweep closes it once its window is over. The report lists the member.
func TestAnEngagementGrantsItsTargetsForItsWindowAndNothingElse(t *testing.T) {
	db, cleanup := setupMigratedDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	gin.SetMode(gin.TestMode)
	const org = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: org})
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scalar := func(q string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(ctx, q, args...).Scan(&v); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
		return v
	}
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
	}
	admin := scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
		org, "eng-admin-"+suffix)
	sponsor := scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
		org, "eng-sponsor-"+suffix)
	app := scalar(`INSERT INTO applications (org_id, name, client_id, type) VALUES ($1, $2, $2, 'web') RETURNING id::text`, org, "eng-app-"+suffix)
	shared := scalar(`INSERT INTO applications (org_id, name, client_id, type) VALUES ($1, $2, $2, 'web') RETURNING id::text`, org, "eng-shared-"+suffix)
	entry := scalar(`INSERT INTO pam_entries (org_id, name, entry_type, hostname, port)
		VALUES ($1, $2, 'ssh', 'target.example.test', 22) RETURNING id::text`, org, "eng-db-"+suffix)

	svc := NewService(db, nil, &config.Config{}, zap.NewNop())
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
		c.Set("user_id", admin)
		c.Set("roles", []string{"admin"})
		c.Next()
	})
	r.POST("/vendor-orgs", svc.handleCreateVendorOrg)
	r.GET("/vendor-orgs/:id", svc.handleGetVendorOrg)
	r.PUT("/vendor-orgs/:id", svc.handleUpdateVendorOrg)
	r.GET("/vendor-orgs/:id/engagements", svc.handleListVendorEngagements)
	r.POST("/vendor-orgs/:id/engagements", svc.handleCreateEngagement)
	r.GET("/engagements", svc.handleListEngagements)
	r.GET("/engagements/:id", svc.handleGetEngagement)
	r.PUT("/engagements/:id", svc.handleUpdateEngagement)
	r.POST("/engagements/:id/close", svc.handleCloseEngagement)
	r.GET("/engagements/:id/report", svc.handleEngagementReport)
	call := func(method, path string, body interface{}) (int, map[string]interface{}) {
		t.Helper()
		var raw string
		if body != nil {
			b, _ := json.Marshal(body)
			raw = string(b)
		}
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		out := map[string]interface{}{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}

	code, body := call(http.MethodPost, "/vendor-orgs", map[string]interface{}{"name": "Acme " + suffix, "default_sponsor_user_id": sponsor})
	vendor, _ := body["id"].(string)
	if code != http.StatusCreated || vendor == "" {
		t.Fatalf("create vendor = %d %v", code, body)
	}
	if body["require_engagement"] != true {
		t.Fatalf("a vendor created now should require engagements, got %v", body["require_engagement"])
	}
	external := func(name string) string {
		return scalar(`
			INSERT INTO users (org_id, username, email, user_type, vendor_org_id, sponsor_user_id, account_expires_at, account_status)
			VALUES ($1, $2::text, $2::text || '@supplier.example.test', 'external', $3, $4, NOW() + interval '30 days', 'active')
			RETURNING id::text`, org, name+"-"+suffix, vendor, sponsor)
	}
	member := external("eng-member")
	other := external("eng-other")

	decide := func(user string) accessdecision.Decision {
		t.Helper()
		d, err := accessdecision.Evaluate(ctx, db, true, accessdecision.Subject{UserID: user, OrgID: org}, app)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		return d
	}
	hasReason := func(d accessdecision.Decision, reason string) bool {
		for _, r := range d.Reasons {
			if r == reason {
				return true
			}
		}
		return false
	}

	// Before any engagement: refused for want of one, even with an assignment.
	exec(`INSERT INTO user_application_assignments (user_id, application_id, org_id) VALUES ($1, $2, $3)`, other, app, org)
	if d := decide(other); d.Allowed || !hasReason(d, accessdecision.ReasonNoEngagement) {
		t.Fatalf("an assigned external user outside any engagement: allowed=%v reasons=%v", d.Allowed, d.Reasons)
	}
	if err := externalid.CheckEngagement(ctx, db.Pool, org, member, "pam_entry", entry, nil); !errors.Is(err, externalid.ErrNoEngagement) {
		t.Fatalf("launch outside any engagement: %v", err)
	}
	if err := externalid.CheckEngagement(ctx, db.Pool, org, member, "network_service", entry, nil); !errors.Is(err, externalid.ErrEngagementTargetType) {
		t.Fatalf("a legacy network service for an engagement vendor: %v", err)
	}
	if err := externalid.CheckEngagement(ctx, db.Pool, org, admin, "pam_entry", entry, nil); err != nil {
		t.Fatalf("an internal user is not bound by I13: %v", err)
	}

	// Refusals at the create.
	ends := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	targets := []map[string]string{{"target_type": "application", "target_id": app}, {"target_type": "pam_entry", "target_id": entry}}
	for name, bad := range map[string]map[string]interface{}{
		"no title":         {"ends_at": ends, "targets": targets},
		"ends in the past": {"title": "x", "ends_at": time.Now().Add(-time.Hour), "targets": targets},
		"no targets":       {"title": "x", "ends_at": ends},
		"unknown target":   {"title": "x", "ends_at": ends, "targets": []map[string]string{{"target_type": "application", "target_id": sponsor}}},
		"internal member":  {"title": "x", "ends_at": ends, "targets": targets, "member_user_ids": []string{admin}},
		"too long":         {"title": "x", "ends_at": time.Now().Add(400 * 24 * time.Hour), "targets": targets},
	} {
		if code, body := call(http.MethodPost, "/vendor-orgs/"+vendor+"/engagements", bad); code != http.StatusBadRequest {
			t.Errorf("%s: %d %v, want 400", name, code, body)
		}
	}

	// An engagement that starts now writes its grants before it answers.
	code, body = call(http.MethodPost, "/vendor-orgs/"+vendor+"/engagements", map[string]interface{}{
		"title": "Firmware upgrade", "ticket_ref": "CHG-1", "ends_at": ends, "member_user_ids": []string{member}, "targets": targets,
	})
	eng, _ := body["id"].(string)
	if code != http.StatusCreated || eng == "" || body["state"] != "running" || body["sponsor_user_id"] != sponsor {
		t.Fatalf("create engagement = %d %v", code, body)
	}
	appEnd := func(user, application string) *time.Time {
		t.Helper()
		var at *time.Time
		if err := db.Pool.QueryRow(ctx, `SELECT expires_at FROM user_application_assignments WHERE user_id = $1 AND application_id = $2`,
			user, application).Scan(&at); err != nil {
			t.Fatalf("read assignment: %v", err)
		}
		return at
	}
	pamEnd := func(user string) *time.Time {
		t.Helper()
		var at *time.Time
		if err := db.Pool.QueryRow(ctx, `SELECT expires_at FROM pam_entry_grants WHERE engagement_id = $1 AND principal_id = $2`,
			eng, user).Scan(&at); err != nil {
			t.Fatalf("read PAM grant: %v", err)
		}
		return at
	}
	if at := appEnd(member, app); at == nil || !at.Equal(ends) {
		t.Fatalf("the member's assignment should end with the engagement (%v), got %v", ends, at)
	}
	if at := pamEnd(member); at == nil || !at.Equal(ends) {
		t.Fatalf("the member's PAM grant should end with the engagement (%v), got %v", ends, at)
	}
	if n := scalar(`SELECT count(*)::text FROM pam_entry_grants WHERE engagement_id = $1 AND principal_id = $2`, eng, other); n != "0" {
		t.Fatalf("a vendor user not on the engagement got %s PAM grants", n)
	}
	if d := decide(member); !d.Allowed {
		t.Fatalf("the member inside the engagement: reasons=%v", d.Reasons)
	}
	if d := decide(other); d.Allowed || !hasReason(d, accessdecision.ReasonNoEngagement) {
		t.Fatalf("a vendor user not on the engagement: allowed=%v reasons=%v", d.Allowed, d.Reasons)
	}
	if err := externalid.CheckEngagement(ctx, db.Pool, org, member, "pam_entry", entry, nil); err != nil {
		t.Fatalf("launch inside the engagement: %v", err)
	}
	past := ends.Add(time.Hour)
	if err := externalid.CheckEngagement(ctx, db.Pool, org, member, "application", app, &past); !errors.Is(err, externalid.ErrWindowPastEngagement) {
		t.Fatalf("a request window past the engagement: %v", err)
	}

	// A request gave the member the shared application for ten days; the
	// engagement adds it and keeps the longer window, without owning it.
	requestEnd := time.Now().Add(10 * 24 * time.Hour).UTC().Truncate(time.Second)
	exec(`INSERT INTO user_application_assignments (user_id, application_id, org_id, expires_at) VALUES ($1, $2, $3, $4)`,
		member, shared, org, requestEnd)

	// Shorter, with the shared application: what it wrote follows.
	shorter := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	code, body = call(http.MethodPut, "/engagements/"+eng, map[string]interface{}{
		"ends_at": shorter,
		"targets": append(targets, map[string]string{"target_type": "application", "target_id": shared}),
	})
	if code != http.StatusOK || len(body["targets"].([]interface{})) != 3 {
		t.Fatalf("update engagement = %d %v", code, body)
	}
	if at := appEnd(member, app); at == nil || !at.Equal(shorter) {
		t.Fatalf("the assignment should follow the shorter engagement (%v), got %v", shorter, at)
	}
	if at := pamEnd(member); at == nil || !at.Equal(shorter) {
		t.Fatalf("the PAM grant should follow the shorter engagement (%v), got %v", shorter, at)
	}
	if at := appEnd(member, shared); at == nil || !at.Equal(requestEnd) {
		t.Fatalf("the request's longer window should stand (%v), got %v", requestEnd, at)
	}

	// The report names the member and the grants still held.
	code, body = call(http.MethodGet, "/engagements/"+eng+"/report", nil)
	if code != http.StatusOK || len(body["members"].([]interface{})) != 1 {
		t.Fatalf("report = %d %v", code, body)
	}
	if held := body["grants_held"].(map[string]interface{}); held["pam_entry"] != float64(1) || held["application"] != float64(1) {
		t.Fatalf("report grants_held = %v", held)
	}

	// Closing cuts what it wrote, and only that.
	code, body = call(http.MethodPost, "/engagements/"+eng+"/close", map[string]string{"note": "done"})
	if code != http.StatusOK || body["state"] != "closed" || body["close_reason"] != "closed" {
		t.Fatalf("close = %d %v", code, body)
	}
	now := time.Now()
	if at := appEnd(member, app); at == nil || at.After(now) {
		t.Fatalf("the engagement's assignment should be cut at the close, ends %v", at)
	}
	if at := pamEnd(member); at == nil || at.After(now) {
		t.Fatalf("the engagement's PAM grant should be cut at the close, ends %v", at)
	}
	if at := appEnd(member, shared); at == nil || !at.Equal(requestEnd) {
		t.Fatalf("the request's assignment should survive the close (%v), got %v", requestEnd, at)
	}
	if d := decide(member); d.Allowed {
		t.Fatal("the member after the close should be refused")
	}
	if code, _ := call(http.MethodPost, "/engagements/"+eng+"/close", nil); code != http.StatusConflict {
		t.Fatalf("a second close = %d, want 409", code)
	}
	if code, _ := call(http.MethodPut, "/engagements/"+eng, map[string]interface{}{"title": "again"}); code != http.StatusConflict {
		t.Fatalf("changing a closed engagement = %d, want 409", code)
	}

	// Scheduled: nothing until the sweep finds it started; closed by the
	// sweep once over. Everyone of the vendor is on it (no members named).
	starts := time.Now().Add(time.Hour)
	code, body = call(http.MethodPost, "/vendor-orgs/"+vendor+"/engagements", map[string]interface{}{
		"title": "Next week", "starts_at": starts, "ends_at": starts.Add(time.Hour),
		"targets": []map[string]string{{"target_type": "pam_entry", "target_id": entry}},
	})
	later, _ := body["id"].(string)
	if code != http.StatusCreated || body["state"] != "scheduled" {
		t.Fatalf("schedule = %d %v", code, body)
	}
	if n := scalar(`SELECT count(*)::text FROM pam_entry_grants WHERE engagement_id = $1`, later); n != "0" {
		t.Fatalf("a scheduled engagement wrote %s grants", n)
	}
	exec(`UPDATE vendor_engagements SET starts_at = NOW() - interval '1 minute' WHERE id = $1`, later)
	svc.sweepEngagements(orgctx.WithBypassRLS(context.Background()))
	if n := scalar(`SELECT count(*)::text FROM pam_entry_grants WHERE engagement_id = $1 AND expires_at > NOW()`, later); n != "2" {
		t.Fatalf("a started engagement naming nobody should grant both vendor users, got %s", n)
	}
	exec(`UPDATE vendor_engagements SET starts_at = NOW() - interval '2 minutes', ends_at = NOW() - interval '1 second' WHERE id = $1`, later)
	svc.sweepEngagements(orgctx.WithBypassRLS(context.Background()))
	if got := scalar(`SELECT status || '/' || COALESCE(close_reason, '') FROM vendor_engagements WHERE id = $1`, later); got != "closed/ended" {
		t.Fatalf("the sweep should close an engagement past its window, got %s", got)
	}

	if code, body := call(http.MethodGet, "/vendor-orgs/"+vendor+"/engagements", nil); code != http.StatusOK || len(body["engagements"].([]interface{})) != 2 {
		t.Fatalf("list = %d %v", code, body)
	}
	if code, body := call(http.MethodGet, "/engagements?state=running", nil); code != http.StatusOK {
		t.Fatalf("list running = %d %v", code, body)
	}

	// A suspended vendor takes no new engagement.
	if code, body := call(http.MethodPut, "/vendor-orgs/"+vendor, map[string]interface{}{"name": "Acme " + suffix, "status": "suspended", "default_sponsor_user_id": sponsor}); code != http.StatusOK {
		t.Fatalf("suspend vendor = %d %v", code, body)
	}
	if code, body := call(http.MethodPost, "/vendor-orgs/"+vendor+"/engagements", map[string]interface{}{"title": "x", "ends_at": ends, "targets": targets}); code != http.StatusConflict {
		t.Fatalf("engagement for a suspended vendor = %d %v, want 409", code, body)
	}
}
