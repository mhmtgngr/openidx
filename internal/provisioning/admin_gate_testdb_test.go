package provisioning

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/cell"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
	"github.com/openidx/openidx/internal/organization"
)

// THE PROVISIONING API IS AN ADMINISTRATOR'S.
//
// /api/v1/provisioning holds the organization's provisioning rules and its
// outbound SCIM targets: where the worker sends every user and group, with
// the target's credentials, and /sync, which sends the whole directory at
// once. Every route asked only for a signed-in user unless ENABLE_OPA_AUTHZ
// was on, so any user could add a target at a server of their own and have
// the directory delivered there. The console gives the Provisioning Rules
// page to admins; the targets have no page.
//
// Driven through RegisterRoutes as cmd/provisioning-service mounts it -- the
// tenant resolver on the engine, the service's own bearer-token middleware,
// the cell guard, OPA off (the default) -- over a migrated database, with a
// signed token for each role:
//
//   - a user, an auditor, an operator, a compliance_reader and a machine
//     credential that holds no role get 403 from all thirteen routes, and
//     nothing changes: no rule or target is added, renamed or deleted, the
//     target's connection test never reaches it, and no sync is queued;
//   - an admin and a super_admin create, read, list, update and delete rules
//     and targets, test a target's connection, queue its sync and read its
//     status;
//   - no token is still 401, and the inbound SCIM server keeps its own
//     bearer-token authentication: the SCIM client's credential, which holds
//     no role, still reaches it.
func TestTheProvisioningAPINeedsTheAdminRole(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	t.Cleanup(cleanup)
	ctx := orgctx.WithBypassRLS(context.Background())
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	var org orgctx.Org
	org.Slug = fmt.Sprintf("provisioning-gate-%d", time.Now().UnixNano())
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`, org.Slug).Scan(&org.ID); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO users (org_id, username, email, enabled) VALUES ($1::uuid, $2, $3, true)`,
		org.ID, "member-"+org.Slug, "member-"+org.Slug+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": []map[string]string{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "provisioning-gate",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	t.Cleanup(jwks.Close)
	cfg := &config.Config{OAuthIssuer: "https://issuer.example.test", OAuthJWKSURL: jwks.URL}
	token := func(sub string, roles ...string) string {
		t.Helper()
		claims := jwt.MapClaims{
			"iss": cfg.OAuthIssuer, "sub": sub, "exp": time.Now().Add(time.Hour).Unix(),
			middleware.OrgIDClaim: org.ID, middleware.APIAccessClaim: true,
		}
		if roles != nil {
			rs := make([]interface{}, len(roles))
			for i, r := range roles {
				rs[i] = r
			}
			claims["roles"] = rs
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["typ"] = middleware.AccessTokenType
		signed, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}

	// The service provider the targets point at. Its connection test is the
	// one request a target route makes on the spot.
	var probes atomic.Int64
	sp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/ServiceProviderConfig") {
			probes.Add(1)
		}
		w.Header().Set("Content-Type", "application/scim+json")
		_, _ = io.WriteString(w, `{"patch":{"supported":true},"filter":{"supported":true}}`)
	}))
	t.Cleanup(sp.Close)

	// The chain cmd/provisioning-service mounts, with OPA off.
	svc := NewService(db, nil, cfg, zap.NewNop())
	svc.outbound = testOutbound(t) // the service provider is a local server
	r := gin.New()
	r.Use(middleware.TenantResolver(organization.NewOrgLookup(organization.NewService(db, nil, cfg, zap.NewNop())),
		middleware.TenantResolverConfig{DefaultOrgFallback: true, DefaultOrgID: middleware.DefaultOrgID, Logger: zap.NewNop()}))
	RegisterRoutes(r, svc, cell.Guard("", zap.NewNop()))

	call := func(method, path, bearer string, body interface{}) (int, []byte) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			rd = strings.NewReader(string(raw))
		}
		req := httptest.NewRequest(method, path, rd)
		req.Header.Set("X-Org-Slug", org.Slug)
		if rd != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code, w.Body.Bytes()
	}
	count := func(query string) int {
		t.Helper()
		var n int
		if err := db.Pool.QueryRow(ctx, query, org.ID).Scan(&n); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		return n
	}
	rules := func() int { return count(`SELECT count(*) FROM provisioning_rules WHERE org_id = $1::uuid`) }
	targets := func() int { return count(`SELECT count(*) FROM scim_target_apps WHERE org_id = $1::uuid`) }
	queued := func() int { return count(`SELECT count(*) FROM scim_provisioning_queue WHERE org_id = $1::uuid`) }
	var ruleName, targetName, targetURL string
	readBack := func(ruleID, targetID string) {
		t.Helper()
		if err := db.Pool.QueryRow(ctx, `SELECT name FROM provisioning_rules WHERE id = $1::uuid`, ruleID).Scan(&ruleName); err != nil {
			t.Fatalf("read rule %s: %v", ruleID, err)
		}
		if err := db.Pool.QueryRow(ctx, `SELECT name, base_url FROM scim_target_apps WHERE id = $1::uuid`, targetID).Scan(&targetName, &targetURL); err != nil {
			t.Fatalf("read target %s: %v", targetID, err)
		}
	}

	newRule := map[string]interface{}{"name": "grant engineering", "trigger": "user_created", "enabled": true}
	newTarget := map[string]interface{}{
		"name": "downstream", "base_url": sp.URL, "auth_type": "bearer", "bearer_token": "downstream-token",
		"provision_users": true, "enabled": true,
	}

	// The organization's own rule and target, as an administrator set them up.
	octx := orgctx.With(ctx, org)
	rule, err := svc.CreateRule(octx, &ProvisioningRule{Name: "existing rule", Trigger: TriggerUserCreated, Enabled: true})
	if err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	target, err := svc.CreateTargetApp(octx, org.ID, &TargetAppInput{
		Name: "existing target", BaseURL: sp.URL, AuthType: "bearer", BearerToken: "downstream-token",
		ProvisionUsers: true, Enabled: true,
	})
	if err != nil {
		t.Fatalf("seed target: %v", err)
	}

	if code, _ := call(http.MethodGet, "/api/v1/provisioning/rules", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("no token: %d, want 401 -- the authentication in front of the gate is gone", code)
	}

	routes := func(ruleID, targetID string) []struct {
		method, path string
		body         interface{}
	} {
		return []struct {
			method, path string
			body         interface{}
		}{
			{http.MethodGet, "/api/v1/provisioning/rules", nil},
			{http.MethodPost, "/api/v1/provisioning/rules", newRule},
			{http.MethodGet, "/api/v1/provisioning/rules/" + ruleID, nil},
			{http.MethodPut, "/api/v1/provisioning/rules/" + ruleID, map[string]interface{}{"name": "renamed", "trigger": "user_created"}},
			{http.MethodDelete, "/api/v1/provisioning/rules/" + ruleID, nil},
			{http.MethodGet, "/api/v1/provisioning/targets", nil},
			{http.MethodPost, "/api/v1/provisioning/targets", newTarget},
			{http.MethodGet, "/api/v1/provisioning/targets/" + targetID, nil},
			{http.MethodPut, "/api/v1/provisioning/targets/" + targetID, map[string]interface{}{"name": "renamed", "base_url": "https://collector.example.test/scim/v2", "enabled": true}},
			{http.MethodDelete, "/api/v1/provisioning/targets/" + targetID, nil},
			{http.MethodPost, "/api/v1/provisioning/targets/" + targetID + "/test", nil},
			{http.MethodPost, "/api/v1/provisioning/targets/" + targetID + "/sync", nil},
			{http.MethodGet, "/api/v1/provisioning/targets/" + targetID + "/status", nil},
		}
	}

	for _, refused := range []struct{ name, token string }{
		{"a user", token("44444444-0000-0000-0000-000000000001", "user")},
		{"an auditor", token("44444444-0000-0000-0000-000000000002", "auditor")},
		{"an operator", token("44444444-0000-0000-0000-000000000003", "operator")},
		{"a compliance_reader", token("44444444-0000-0000-0000-000000000004", "compliance_reader")},
		{"a machine credential with no role", token("44444444-0000-0000-0000-000000000005")},
	} {
		for _, rt := range routes(rule.ID, target.ID) {
			if code, body := call(rt.method, rt.path, refused.token, rt.body); code != http.StatusForbidden {
				t.Errorf("%s: %s %s answered %d %s, want 403", refused.name, rt.method, rt.path, code, body)
			}
		}
	}
	readBack(rule.ID, target.ID)
	if rules() != 1 || targets() != 1 || ruleName != "existing rule" || targetName != "existing target" || targetURL != sp.URL {
		t.Fatalf("after the refused callers: %d rules, %d targets, rule %q, target %q at %q; want the organization's own, unchanged",
			rules(), targets(), ruleName, targetName, targetURL)
	}
	if probes.Load() != 0 || queued() != 0 {
		t.Fatalf("a refused caller reached the service provider (%d probes) or queued a sync (%d items)", probes.Load(), queued())
	}

	// The inbound SCIM server is untouched: the SCIM client's credential,
	// which holds no role, still reaches it.
	if code, body := call(http.MethodGet, "/scim/v2/ServiceProviderConfig", token("scim-client"), nil); code != http.StatusOK {
		t.Errorf("the SCIM server refused the SCIM client: %d %s", code, body)
	}

	for n, admitted := range []struct{ name, token string }{
		{"an admin", token("55555555-0000-0000-0000-000000000001", "admin")},
		{"a super_admin", token("55555555-0000-0000-0000-000000000002", "super_admin")},
	} {
		code, body := call(http.MethodPost, "/api/v1/provisioning/rules", admitted.token, newRule)
		var created struct {
			ID string `json:"id"`
		}
		if code != http.StatusCreated || json.Unmarshal(body, &created) != nil || created.ID == "" {
			t.Fatalf("%s: create rule answered %d %s", admitted.name, code, body)
		}
		ruleID := created.ID
		code, body = call(http.MethodPost, "/api/v1/provisioning/targets", admitted.token, newTarget)
		created.ID = ""
		if code != http.StatusCreated || json.Unmarshal(body, &created) != nil || created.ID == "" {
			t.Fatalf("%s: create target answered %d %s", admitted.name, code, body)
		}
		targetID := created.ID
		queuedBefore := queued()
		if rules() != 2 || targets() != 2 {
			t.Fatalf("%s: %d rules and %d targets after creating one of each", admitted.name, rules(), targets())
		}

		for _, rt := range routes(ruleID, targetID) {
			if rt.method == http.MethodPost && (strings.HasSuffix(rt.path, "/rules") || strings.HasSuffix(rt.path, "/targets")) {
				continue // created above
			}
			if rt.method == http.MethodDelete {
				continue // deleted below, once everything else has read the rows
			}
			if strings.HasSuffix(rt.path, "/"+targetID) && rt.method == http.MethodPut {
				rt.body = map[string]interface{}{"name": "renamed", "base_url": sp.URL, "provision_users": true, "enabled": true}
			}
			code, body := call(rt.method, rt.path, admitted.token, rt.body)
			if code < 200 || code > 299 {
				t.Errorf("%s: %s %s answered %d %s, want success", admitted.name, rt.method, rt.path, code, body)
			}
			if strings.HasSuffix(rt.path, "/test") && !strings.Contains(string(body), `"ok":true`) {
				t.Errorf("%s: the connection test answered %s", admitted.name, body)
			}
		}
		readBack(ruleID, targetID)
		if ruleName != "renamed" || targetName != "renamed" {
			t.Errorf("%s: the updates did not land: rule %q, target %q", admitted.name, ruleName, targetName)
		}
		if probes.Load() != int64(n+1) {
			t.Errorf("%s: %d connection tests reached the service provider, want %d", admitted.name, probes.Load(), n+1)
		}
		if queued() <= queuedBefore {
			t.Errorf("%s: the sync queued nothing for a directory with a member", admitted.name)
		}
		if code, body := call(http.MethodDelete, "/api/v1/provisioning/targets/"+targetID, admitted.token, nil); code != http.StatusOK {
			t.Errorf("%s: delete target answered %d %s", admitted.name, code, body)
		}
		if code, body := call(http.MethodDelete, "/api/v1/provisioning/rules/"+ruleID, admitted.token, nil); code != http.StatusNoContent {
			t.Errorf("%s: delete rule answered %d %s", admitted.name, code, body)
		}
		if rules() != 1 || targets() != 1 {
			t.Errorf("%s: %d rules and %d targets after deleting theirs, want the organization's one of each", admitted.name, rules(), targets())
		}
	}
}
