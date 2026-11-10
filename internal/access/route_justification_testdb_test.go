package access

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/migrations"
)

// Purpose justification through the real built-in proxy and the justify
// endpoints on the application's own host. A route that requires it:
//
//   - a browser navigation by an assigned person is sent to the form and the
//     upstream is not reached; an API call gets 403 justification_required;
//   - a reason too short re-asks; a form token bound to another session or
//     used twice is refused;
//   - a good reason is audited with the person and the text, and then the
//     same session reaches the upstream, while another session of the same
//     person is still asked;
//   - someone the decision refuses never sees the form;
//   - with the route not requiring it, nothing changes.
func TestRouteJustificationAsksBeforeTheApplicationOpens(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "upstream-ok")
	}))
	t.Cleanup(upstream.Close)

	const org = "00000000-0000-0000-0000-000000000010"
	suffix := fmt.Sprint(time.Now().UnixNano())
	host := "payroll-j-" + suffix + ".example.test"
	q := func(dst *string, sql string, args ...interface{}) {
		t.Helper()
		if err := db.Pool.QueryRow(ctx, sql, args...).Scan(dst); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	var routeID, appID, userID, outsiderID string
	q(&routeID, `INSERT INTO proxy_routes (org_id, name, from_url, to_url, require_justification, justification_ttl_minutes)
		VALUES ($1::uuid, $2, $3, $4, true, 30) RETURNING id::text`, org, "payroll-"+suffix, "https://"+host, upstream.URL)
	q(&appID, `INSERT INTO applications (org_id, client_id, name, type, route_id) VALUES ($1::uuid, $2, 'Payroll', 'web', $3::uuid) RETURNING id::text`,
		org, "payroll-"+suffix, routeID)
	q(&userID, `INSERT INTO users (org_id, username, email, enabled) VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
		org, "hr-"+suffix, "hr-"+suffix+"@example.test")
	q(&outsiderID, `INSERT INTO users (org_id, username, email, enabled) VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
		org, "x-"+suffix, "x-"+suffix+"@example.test")
	if _, err := db.Pool.Exec(ctx, `INSERT INTO user_application_assignments (user_id, application_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`,
		userID, appID, org); err != nil {
		t.Fatal(err)
	}

	mini := miniredis.RunT(t)
	rc := goredis.NewClient(&goredis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rc.Close() })
	session := func(name, user string) string {
		t.Helper()
		token := "cookie-" + name + "-" + suffix
		blob, _ := json.Marshal(map[string]interface{}{
			"id": "sess-" + name + "-" + suffix, "user_id": user, "email": name + "@example.test", "roles": []string{}, "host": host,
			"expires": time.Now().Add(time.Hour).Unix(), "last_active": time.Now().Unix(),
		})
		if err := rc.Set(ctx, "proxy_session:"+hashToken(token), blob, time.Hour).Err(); err != nil {
			t.Fatal(err)
		}
		return token
	}
	mine, mineAgain, theirs := session("a", userID), session("b", userID), session("x", outsiderID)

	svc := &Service{db: db, redis: &database.RedisClient{Client: rc}, logger: zap.NewNop(),
		config: &config.Config{AccessAssignmentEnforce: true}, auditService: NewUnifiedAuditService(db, zap.NewNop())}
	r := gin.New()
	r.GET("/access/.auth/justify", svc.handleJustifyForm)
	r.POST("/access/.auth/justify", svc.handleJustifySubmit)
	r.NoRoute(svc.handleProxy)

	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	type answer struct {
		Code   int
		header http.Header
		body   string
	}
	do := func(method, path, cookie, accept string, form url.Values) *answer {
		t.Helper()
		var body io.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		req, err := http.NewRequest(method, srv.URL+path, body)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		req.AddCookie(&http.Cookie{Name: proxySessionCookie, Value: cookie})
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return &answer{Code: resp.StatusCode, header: resp.Header, body: string(b)}
	}
	const page = "text/html,application/xhtml+xml"
	tokenRE := regexp.MustCompile(`name="token" value="([0-9a-f]{32})"`)
	formToken := func(cookie string) string {
		t.Helper()
		w := do(http.MethodGet, "/access/.auth/justify?redirect_url=%2Fsalaries", cookie, page, nil)
		m := tokenRE.FindStringSubmatch(w.body)
		if w.Code != http.StatusOK || m == nil {
			t.Fatalf("form: %d %s", w.Code, w.body)
		}
		if csp := w.header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "form-action 'self'") {
			t.Errorf("form served under %q", csp)
		}
		return m[1]
	}

	// A navigation is sent to the form, an API call is refused; neither is forwarded.
	if w := do(http.MethodGet, "/salaries", mine, page, nil); w.Code != http.StatusFound ||
		!strings.HasPrefix(w.header.Get("Location"), "/access/.auth/justify?redirect_url=%2Fsalaries") {
		t.Fatalf("navigation: %d %q", w.Code, w.header.Get("Location"))
	}
	if w := do(http.MethodGet, "/api/salaries", mine, "application/json", nil); w.Code != http.StatusForbidden ||
		!strings.Contains(w.body, "justification_required") {
		t.Fatalf("API call: %d %s", w.Code, w.body)
	}
	if hits.Load() != 0 {
		t.Fatal("the upstream was reached before a reason")
	}
	// Someone the decision refuses gets the refusal, not the form.
	if w := do(http.MethodGet, "/salaries", theirs, page, nil); w.Code != http.StatusForbidden || strings.Contains(w.body, "justification") {
		t.Errorf("unassigned person: %d %s, want the decision's 403", w.Code, w.body)
	}

	// A short reason re-asks; the token it spent is gone.
	tok := formToken(mine)
	if w := do(http.MethodPost, "/access/.auth/justify", mine, page, url.Values{"token": {tok}, "reason": {"short"}, "redirect_url": {"/salaries"}}); w.Code != http.StatusBadRequest {
		t.Errorf("short reason: %d", w.Code)
	}
	if w := do(http.MethodPost, "/access/.auth/justify", mine, page, url.Values{"token": {tok}, "reason": {"monthly payroll close"}}); w.Code != http.StatusForbidden {
		t.Errorf("a spent token answered %d", w.Code)
	}
	// Another session's form cannot be submitted from this one.
	foreign := formToken(mineAgain)
	if w := do(http.MethodPost, "/access/.auth/justify", mine, page, url.Values{"token": {foreign}, "reason": {"monthly payroll close"}}); w.Code != http.StatusForbidden {
		t.Errorf("another session's token answered %d", w.Code)
	}

	// A good reason: audited, then the session goes through.
	tok = formToken(mine)
	w := do(http.MethodPost, "/access/.auth/justify", mine, page, url.Values{"token": {tok}, "reason": {"monthly payroll close for October"}, "redirect_url": {"/salaries"}})
	if w.Code != http.StatusSeeOther || w.header.Get("Location") != "/salaries" {
		t.Fatalf("submit: %d %q %s", w.Code, w.header.Get("Location"), w.body)
	}
	var reason string
	if err := db.Pool.QueryRow(ctx, `SELECT COALESCE(details->>'reason','') FROM unified_audit_events
		WHERE event_type = $1 AND user_id = $2::uuid ORDER BY created_at DESC LIMIT 1`, auditAccessJustified, userID).Scan(&reason); err != nil ||
		reason != "monthly payroll close for October" {
		t.Errorf("audit: %q %v", reason, err)
	}
	if w := do(http.MethodGet, "/salaries", mine, page, nil); w.Code != http.StatusOK || w.body != "upstream-ok" {
		t.Errorf("after the reason: %d %s", w.Code, w.body)
	}
	if w := do(http.MethodGet, "/api/salaries", mine, "application/json", nil); w.Code != http.StatusOK {
		t.Errorf("API call after the reason: %d", w.Code)
	}
	// The answer is this session's: the same person's other session is asked.
	if w := do(http.MethodGet, "/salaries", mineAgain, page, nil); w.Code != http.StatusFound {
		t.Errorf("the other session: %d, want the form", w.Code)
	}
	// The answer holds for the route's TTL.
	if ttl := mini.TTL(justifiedKey("sess-a-"+suffix, routeID)); ttl < 29*time.Minute || ttl > 30*time.Minute {
		t.Errorf("answer held for %v, want the route's 30 minutes", ttl)
	}

	// The APISIX forward-auth hook takes the same decision: before a reason
	// the other session's navigation is sent to the form and its API call
	// refused; this session, with its reason, is allowed.
	decide := func(cookie, accept string) *httptest.ResponseRecorder {
		t.Helper()
		fr := gin.New()
		fr.GET("/decide", svc.handleAuthDecide)
		req := httptest.NewRequest(http.MethodGet, "/decide", nil)
		req.Header.Set("X-Forwarded-Host", host)
		req.Header.Set("X-Forwarded-Uri", "/salaries")
		req.Header.Set("X-Forwarded-Method", http.MethodGet)
		req.Header.Set("Accept", accept)
		req.AddCookie(&http.Cookie{Name: proxySessionCookie, Value: cookie})
		w := httptest.NewRecorder()
		fr.ServeHTTP(w, req)
		return w
	}
	if w := decide(mineAgain, page); w.Code != http.StatusFound || !strings.HasPrefix(w.Header().Get("Location"), justifyPath) {
		t.Errorf("forward-auth navigation without a reason: %d %q", w.Code, w.Header().Get("Location"))
	}
	if w := decide(mineAgain, "application/json"); w.Code != http.StatusForbidden {
		t.Errorf("forward-auth API call without a reason: %d", w.Code)
	}
	if w := decide(mine, page); w.Code != http.StatusOK {
		t.Errorf("forward-auth with a reason: %d %s", w.Code, w.Body.String())
	}

	// Off: nothing asks.
	if _, err := db.Pool.Exec(ctx, `UPDATE proxy_routes SET require_justification = false WHERE id = $1::uuid`, routeID); err != nil {
		t.Fatal(err)
	}
	if w := do(http.MethodGet, "/salaries", mineAgain, page, nil); w.Code != http.StatusOK {
		t.Errorf("route not requiring it: %d", w.Code)
	}
	if w := do(http.MethodGet, "/access/.auth/justify", mineAgain, page, nil); w.Code != http.StatusNotFound {
		t.Errorf("the form on a route that does not ask: %d", w.Code)
	}
}
