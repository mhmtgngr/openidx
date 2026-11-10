package access

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

type explainAnswer struct {
	Decision struct {
		Allowed   bool     `json:"allowed"`
		WouldDeny bool     `json:"would_deny"`
		Reasons   []string `json:"reasons"`
		Grant     string   `json:"grant"`
		Conds     []struct {
			Name   string `json:"name"`
			Judged bool   `json:"judged"`
		} `json:"conditions"`
	} `json:"decision"`
	WhatIf    bool     `json:"what_if"`
	NotJudged []string `json:"not_judged"`
}

// The policy tester answers what the enforcement point does. An application
// behind a route requires a trusted device and allows only TR; an assigned
// person reaches it through the real built-in proxy from an unknown device
// (refused, device_trust_required), and the tester stating "untrusted device"
// says the same; stating a trusted device from DE says country_not_allowed,
// from TR allowed. Without a stated situation the conditions are unjudged, as
// they were. Malformed situations are a 400, and someone not assigned is
// not_assigned whatever the situation.
func TestTheWhatIfExplainMatchesTheProxy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	t.Cleanup(upstream.Close)

	const org = "00000000-0000-0000-0000-000000000010"
	suffix := fmt.Sprint(time.Now().UnixNano())
	host := "vault-" + suffix + ".example.test"
	var routeID, appID, userID, outsiderID string
	q := func(dst *string, sql string, args ...interface{}) {
		t.Helper()
		if err := db.Pool.QueryRow(ctx, sql, args...).Scan(dst); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	q(&routeID, `INSERT INTO proxy_routes (org_id, name, from_url, to_url) VALUES ($1::uuid, $2, $3, $4) RETURNING id::text`,
		org, "vault-"+suffix, "https://"+host, upstream.URL)
	q(&appID, `INSERT INTO applications (org_id, client_id, name, type, route_id) VALUES ($1::uuid, $2, 'Vault', 'web', $3::uuid) RETURNING id::text`,
		org, "vault-"+suffix, routeID)
	q(&userID, `INSERT INTO users (org_id, username, email, enabled) VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
		org, "ops-"+suffix, "ops-"+suffix+"@example.test")
	q(&outsiderID, `INSERT INTO users (org_id, username, email, enabled) VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
		org, "out-"+suffix, "out-"+suffix+"@example.test")
	if _, err := db.Pool.Exec(ctx, `INSERT INTO user_application_assignments (user_id, application_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`,
		userID, appID, org); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `INSERT INTO resource_conditions (application_id, org_id, require_device_trust, allowed_countries)
		VALUES ($1::uuid, $2::uuid, true, '{TR}')`, appID, org); err != nil {
		t.Fatal(err)
	}

	mini := miniredis.RunT(t)
	rc := goredis.NewClient(&goredis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rc.Close() })
	newSvc := func() *Service {
		return &Service{db: db, redis: &database.RedisClient{Client: rc}, logger: zap.NewNop(),
			config: &config.Config{AccessAssignmentEnforce: true}, auditService: NewUnifiedAuditService(db, zap.NewNop())}
	}

	// The enforcement point: the real proxy, a cookie session, an unknown device.
	token := "cookie-" + suffix
	blob, _ := json.Marshal(map[string]interface{}{
		"id": "sess-" + suffix, "user_id": userID, "email": "ops@example.test", "roles": []string{}, "host": host,
		"expires": time.Now().Add(time.Hour).Unix(), "last_active": time.Now().Unix(),
	})
	if err := rc.Set(ctx, "proxy_session:"+hashToken(token), blob, time.Hour).Err(); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.NoRoute(newSvc().handleProxy)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = host
	req.AddCookie(&http.Cookie{Name: "_openidx_proxy_session", Value: token})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "device_trust_required") {
		t.Fatalf("the proxy answered %d %s, want 403 device_trust_required", w.Code, w.Body.String())
	}

	explain := func(user string, params url.Values) (int, explainAnswer) {
		t.Helper()
		r := gin.New()
		r.GET("/x", func(c *gin.Context) {
			c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
			newSvc().handleExplainReach(c)
		})
		params.Set("user", user)
		params.Set("app", appID)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x?"+params.Encode(), nil))
		var a explainAnswer
		_ = json.Unmarshal(w.Body.Bytes(), &a)
		return w.Code, a
	}
	reasons := func(a explainAnswer) string { return strings.Join(a.Decision.Reasons, ",") }

	// The proxy's situation: an untrusted device, country unknown, risk 15.
	if code, a := explain(userID, url.Values{"device_trusted": {"false"}, "risk": {"15"}}); code != 200 || a.Decision.Allowed ||
		reasons(a) != "device_trust_required" || !a.WhatIf {
		t.Errorf("stated untrusted device: %d %+v, want denied device_trust_required like the proxy", code, a)
	}
	if _, a := explain(userID, url.Values{"device_trusted": {"true"}, "risk": {"10"}, "country": {"de"}}); a.Decision.Allowed ||
		reasons(a) != "country_not_allowed" {
		t.Errorf("trusted device from DE: %+v, want country_not_allowed", a)
	}
	if _, a := explain(userID, url.Values{"device_trusted": {"true"}, "risk": {"10"}, "country": {"TR"}}); !a.Decision.Allowed {
		t.Errorf("trusted device from TR: %+v, want allowed", a)
	}
	// No situation: the conditions are listed, unjudged, and nothing is denied for them.
	if _, a := explain(userID, url.Values{}); a.WhatIf || !a.Decision.Allowed || len(a.Decision.Conds) == 0 {
		t.Errorf("no situation: %+v, want allowed with unjudged conditions", a)
	} else {
		for _, c := range a.Decision.Conds {
			if c.Judged {
				t.Errorf("condition %s judged without a situation", c.Name)
			}
		}
	}
	if _, a := explain(outsiderID, url.Values{"device_trusted": {"true"}, "risk": {"0"}, "country": {"TR"}}); a.Decision.Allowed ||
		!strings.Contains(reasons(a), "not_assigned") {
		t.Errorf("unassigned person: %+v, want not_assigned", a)
	}
	if _, a := explain(userID, url.Values{"device_trusted": {"true"}, "risk": {"0"}}); len(a.NotJudged) == 0 {
		t.Error("the answer does not say what it leaves out")
	}
	for name, p := range map[string]url.Values{
		"country alone":   {"country": {"TR"}},
		"risk 101":        {"device_trusted": {"true"}, "risk": {"101"}},
		"bad bool":        {"device_trusted": {"yes please"}, "risk": {"1"}},
		"long country":    {"device_trusted": {"true"}, "risk": {"1"}, "country": {"TUR"}},
		"digits country":  {"device_trusted": {"true"}, "risk": {"1"}, "country": {"12"}},
		"mixed country":   {"device_trusted": {"true"}, "risk": {"1"}, "country": {"T1"}},
		"fresh_mfa alone": {"fresh_mfa": {"true"}},
	} {
		if code, _ := explain(userID, p); code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, code)
		}
	}
}
