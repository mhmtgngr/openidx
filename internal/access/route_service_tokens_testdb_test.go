package access

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// Service tokens through the real built-in proxy and the forward-auth hook.
// A route admits one service account. Its API key reaches the upstream,
// which is told a machine (service-account:<id>, role service_account) and
// never sees the key; the same key is refused on a route that has not
// admitted the account, once revoked, once expired, when the account is
// disabled, from another organization's route, on a route that needs a
// person (here: a reason), and a key with no service account is refused.
// A key the database does not know is 401. No refusal is forwarded.
func TestServiceTokensReachOnlyTheRoutesThatAdmitThem(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	var mu sync.Mutex
	var seen []http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Clone())
		mu.Unlock()
		_, _ = io.WriteString(w, "upstream-ok")
	}))
	t.Cleanup(upstream.Close)

	const org = "00000000-0000-0000-0000-000000000010"
	const otherOrg = "bbbbbbbb-0000-0000-0000-00000000000b"
	sfx := fmt.Sprint(time.Now().UnixNano())
	exec := func(sql string, args ...interface{}) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	q := func(sql string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(ctx, sql, args...).Scan(&v); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return v
	}
	exec(`INSERT INTO organizations (id, name, slug) VALUES ($1::uuid, 'Other', $2) ON CONFLICT DO NOTHING`, otherOrg, "other-"+sfx)
	route := func(name, orgID string, justify bool) (string, string) {
		host := name + "-" + sfx + ".example.test"
		id := q(`INSERT INTO proxy_routes (org_id, name, from_url, to_url, require_justification) VALUES ($1::uuid, $2, $3, $4, $5) RETURNING id::text`,
			orgID, name+"-"+sfx, "https://"+host, upstream.URL, justify)
		return id, host
	}
	billing, billingHost := route("billing", org, false)
	_, reportsHost := route("reports", org, false)
	reasons, reasonsHost := route("reasons", org, true)
	foreign, foreignHost := route("foreign", otherOrg, false)

	sa := q(`INSERT INTO service_accounts (name, org_id, status) VALUES ($1, $2::uuid, 'active') RETURNING id::text`, "etl-"+sfx, org)
	key := func(saID, userID *string, orgID, status string, expires *time.Time) string {
		t.Helper()
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		raw := "oidx_" + hex.EncodeToString(b)
		sum := sha256.Sum256([]byte(raw))
		exec(`INSERT INTO api_keys (name, key_prefix, key_hash, service_account_id, user_id, scopes, status, expires_at, org_id)
			VALUES ('k', $1, $2, $3::uuid, $4::uuid, '{}', $5, $6, $7::uuid)`, raw[:12], hex.EncodeToString(sum[:]), saID, userID, status, expires, orgID)
		return raw
	}
	good := key(&sa, nil, org, "active", nil)
	revoked := key(&sa, nil, org, "revoked", nil)
	past := time.Now().Add(-time.Hour)
	expired := key(&sa, nil, org, "active", &past)
	// A person's own API key: the proxy does not make it a machine.
	person := q(`INSERT INTO users (org_id, username, email, enabled) VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
		org, "dev-"+sfx, "dev-"+sfx+"@example.test")
	personal := key(nil, &person, org, "active", nil)
	for _, r := range []string{billing, reasons} {
		exec(`INSERT INTO proxy_route_service_accounts (route_id, service_account_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`, r, sa, org)
	}
	// Org B's route has no row for org A's account; the key is org A's.
	_ = foreign

	mini := miniredis.RunT(t)
	rc := goredis.NewClient(&goredis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rc.Close() })
	svc := &Service{db: db, redis: &database.RedisClient{Client: rc}, logger: zap.NewNop(),
		config: &config.Config{AccessAssignmentEnforce: true}, auditService: NewUnifiedAuditService(db, zap.NewNop())}
	r := gin.New()
	r.NoRoute(svc.handleProxy)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	call := func(host, bearer string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/export", nil)
		req.Host = host
		req.Header.Set("Authorization", "Bearer "+bearer)
		req.Header.Set("X-Forwarded-User", "admin") // a forged identity the proxy must replace
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, string(b)
	}

	if code, body := call(billingHost, good); code != http.StatusOK || body != "upstream-ok" {
		t.Fatalf("admitted key: %d %s", code, body)
	}
	mu.Lock()
	h := seen[len(seen)-1]
	mu.Unlock()
	if h.Get("X-Forwarded-User") != "service-account:"+sa || h.Get("X-Forwarded-Roles") != "service_account" {
		t.Errorf("upstream told %q / %q", h.Get("X-Forwarded-User"), h.Get("X-Forwarded-Roles"))
	}
	if strings.Contains(h.Get("Authorization"), good) {
		t.Error("the upstream received the service token")
	}

	before := len(seen)
	for name, tc := range map[string]struct {
		host, key string
		want      int
	}{
		"route not admitting it": {reportsHost, good, http.StatusForbidden},
		"revoked":                {billingHost, revoked, http.StatusUnauthorized},
		"expired":                {billingHost, expired, http.StatusUnauthorized},
		"no service account":     {billingHost, personal, http.StatusUnauthorized},
		"another org's route":    {foreignHost, good, http.StatusUnauthorized},
		"route needs a person":   {reasonsHost, good, http.StatusForbidden},
		"unknown key":            {billingHost, "oidx_" + strings.Repeat("ab", 32), http.StatusUnauthorized},
	} {
		if code, body := call(tc.host, tc.key); code != tc.want {
			t.Errorf("%s: %d %s, want %d", name, code, body, tc.want)
		}
	}
	exec(`UPDATE service_accounts SET status = 'disabled' WHERE id = $1::uuid`, sa)
	if code, _ := call(billingHost, good); code != http.StatusUnauthorized {
		t.Errorf("disabled account: %d", code)
	}
	mu.Lock()
	if len(seen) != before {
		t.Errorf("%d refused requests reached the upstream", len(seen)-before)
	}
	mu.Unlock()
	exec(`UPDATE service_accounts SET status = 'active' WHERE id = $1::uuid`, sa)

	// The forward-auth hook: the same verdicts, and the machine's identity
	// in the answer the edge forwards.
	decide := func(host, bearer string) *httptest.ResponseRecorder {
		fr := gin.New()
		fr.GET("/decide", svc.handleAuthDecide)
		req := httptest.NewRequest(http.MethodGet, "/decide", nil)
		req.Header.Set("X-Forwarded-Host", host)
		req.Header.Set("X-Forwarded-Uri", "/export")
		req.Header.Set("Authorization", "Bearer "+bearer)
		w := httptest.NewRecorder()
		fr.ServeHTTP(w, req)
		return w
	}
	if w := decide(billingHost, good); w.Code != http.StatusOK || w.Header().Get("X-Forwarded-User") != "service-account:"+sa ||
		w.Header().Get("Authorization") != "" {
		t.Errorf("forward-auth admitted key: %d user=%q auth=%q", w.Code, w.Header().Get("X-Forwarded-User"), w.Header().Get("Authorization"))
	}
	if w := decide(reportsHost, good); w.Code != http.StatusForbidden {
		t.Errorf("forward-auth on a route not admitting it: %d", w.Code)
	}
	if w := decide(billingHost, revoked); w.Code != http.StatusUnauthorized {
		t.Errorf("forward-auth revoked: %d", w.Code)
	}

	// The admin API, as the console calls it under org A.
	admin := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		ar := gin.New()
		ar.Use(func(c *gin.Context) {
			c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
			c.Next()
		})
		ar.GET("/routes/:id/service-accounts", svc.handleListRouteServiceAccounts)
		ar.POST("/routes/:id/service-accounts", svc.handleAddRouteServiceAccount)
		ar.DELETE("/routes/:id/service-accounts/:sa", svc.handleRemoveRouteServiceAccount)
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		req := httptest.NewRequest(method, path, rd)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		ar.ServeHTTP(w, req)
		return w
	}
	reports := q(`SELECT id::text FROM proxy_routes WHERE name = $1`, "reports-"+sfx)
	if w := admin(http.MethodPost, "/routes/"+reasons+"/service-accounts", `{"service_account_id":"`+sa+`"}`); w.Code != http.StatusConflict {
		t.Errorf("admitting on a route that asks why: %d", w.Code)
	}
	otherSA := q(`INSERT INTO service_accounts (name, org_id, status) VALUES ($1, $2::uuid, 'active') RETURNING id::text`, "b-etl-"+sfx, otherOrg)
	if w := admin(http.MethodPost, "/routes/"+reports+"/service-accounts", `{"service_account_id":"`+otherSA+`"}`); w.Code != http.StatusNotFound {
		t.Errorf("admitting another org's account: %d", w.Code)
	}
	if w := admin(http.MethodPost, "/routes/"+reports+"/service-accounts", `{"service_account_id":"`+sa+`"}`); w.Code != http.StatusCreated {
		t.Fatalf("admit: %d %s", w.Code, w.Body.String())
	}
	if code, _ := call(reportsHost, good); code != http.StatusOK {
		t.Errorf("after admitting: %d", code)
	}
	if w := admin(http.MethodGet, "/routes/"+reports+"/service-accounts", ""); !strings.Contains(w.Body.String(), sa) {
		t.Errorf("list: %s", w.Body.String())
	}
	if w := admin(http.MethodDelete, "/routes/"+reports+"/service-accounts/"+sa, ""); w.Code != http.StatusNoContent {
		t.Errorf("remove: %d", w.Code)
	}
	if code, _ := call(reportsHost, good); code != http.StatusForbidden {
		t.Errorf("after removing: %d", code)
	}
}

// routeNeedsAPerson: what keeps a machine out of a route.
func TestAdmittingAServiceAccountNeedsAMachineReachableRoute(t *testing.T) {
	if got := routeNeedsAPerson(&ProxyRoute{RequireJustification: true}, ""); got == "" {
		t.Error("a route asking why admits machines")
	}
	if got := routeNeedsAPerson(&ProxyRoute{}, "app-1"); got == "" {
		t.Error("an application route admits machines")
	}
	if got := routeNeedsAPerson(&ProxyRoute{RequireDeviceTrust: true}, ""); got == "" {
		t.Error("a device-trust route admits machines")
	}
	if got := routeNeedsAPerson(&ProxyRoute{MaxRiskScore: 100}, ""); got != "" {
		t.Errorf("a plain route needs %q", got)
	}
}
