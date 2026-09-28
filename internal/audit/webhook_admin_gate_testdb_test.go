package audit

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
	"github.com/openidx/openidx/internal/organization"
)

// THE AUDIT SERVICE'S WEBHOOK SUBSCRIPTIONS ARE AN ADMINISTRATOR'S.
//
// /api/v1/audit/webhooks registers, lists, tests and deletes the URLs the
// organization's audit events are to be delivered to. It asked only for a
// signed-in user. Driven through the routes as cmd/audit-service mounts them
// -- the tenant resolver on the engine, the event streamer's routes with its
// JWKS set -- over a migrated database, with a token for each role:
//
//   - a user, an auditor, an operator, a compliance_reader and a machine
//     credential that holds no role are refused with 403 on every route: no
//     subscription is added, the organization's subscription is neither
//     listed to them nor deleted, and its test delivery is never sent;
//   - an admin and a super_admin register a subscription, see it listed,
//     have its test delivered, and delete it.
func TestTheAuditWebhookRoutesNeedTheAdminRole(t *testing.T) {
	db, cleanup := setupComplianceSchemaDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	gin.SetMode(gin.TestMode)

	ctx := orgctx.WithBypassRLS(context.Background())
	var org orgctx.Org
	org.Slug = fmt.Sprintf("audit-webhooks-%d", time.Now().UnixNano())
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`, org.Slug).Scan(&org.ID); err != nil {
		t.Fatalf("seed organization: %v", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "audit-webhook-admin-gate"
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(middleware.JWKS{Keys: []middleware.JWKSKey{{
			Kty: "RSA", Use: "sig", Alg: "RS256", Kid: kid,
			N: base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	defer jwksSrv.Close()
	token := func(sub string, roles ...string) string {
		t.Helper()
		claims := jwt.MapClaims{
			"sub": sub, "client_id": "admin-console", middleware.APIAccessClaim: true,
			middleware.OrgIDClaim: org.ID, "exp": time.Now().Add(time.Hour).Unix(),
		}
		if roles != nil {
			rs := make([]interface{}, len(roles))
			for i, r := range roles {
				rs[i] = r
			}
			claims["roles"] = rs
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = kid
		tok.Header["typ"] = middleware.AccessTokenType
		s, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	// Where a test delivery lands. The streamer's outbound guard allows
	// loopback here, as an operator's allowlist would, so the receiver can be
	// a local server.
	var delivered atomic.Int64
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		delivered.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer receiver.Close()

	// The chain cmd/audit-service mounts.
	cfg := &config.Config{}
	svc := NewService(db, nil, cfg, zap.NewNop())
	r := gin.New()
	r.Use(middleware.TenantResolver(organization.NewOrgLookup(organization.NewService(db, nil, cfg, zap.NewNop())),
		middleware.TenantResolverConfig{DefaultOrgFallback: true, DefaultOrgID: middleware.DefaultOrgID, Logger: zap.NewNop()}))
	RegisterRoutes(r, svc, middleware.Auth(jwksSrv.URL), cell.Guard("", zap.NewNop()))
	streamer := NewEventStreamerWithConfig(zap.NewNop(), svc, nil)
	streamer.guard = testWebhookGuard(t)
	streamer.SetJWKSURL(jwksSrv.URL)
	streamer.RegisterRoutes(r.Group("/api/v1/audit"))

	call := func(method, path, bearer, body string) (int, string) {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Org-Slug", org.Slug)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		raw, _ := io.ReadAll(w.Body)
		return w.Code, string(raw)
	}
	subscriptions := func() []string {
		t.Helper()
		rows, err := db.Pool.Query(ctx, `SELECT id FROM audit_webhook_subscriptions WHERE org_id = $1::uuid ORDER BY id`, org.ID)
		if err != nil {
			t.Fatalf("read subscriptions: %v", err)
		}
		defer rows.Close()
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, id)
		}
		return ids
	}
	register := `{"url":"` + receiver.URL + `/hook","secret":"webhook-signing-secret","enabled":true}`

	// The organization's subscription, as an administrator registered it.
	existing := "aaaaaaaa-0000-0000-0000-000000000001"
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO audit_webhook_subscriptions (id, url, secret, enabled, created_at, org_id)
		VALUES ($1, $2, 'webhook-signing-secret', true, NOW(), $3::uuid)`, existing, receiver.URL+"/hook", org.ID); err != nil {
		t.Fatalf("seed subscription: %v", err)
	}

	if code, _ := call(http.MethodGet, "/api/v1/audit/webhooks", "", ""); code != http.StatusUnauthorized {
		t.Fatalf("no token: %d, want 401 -- the authentication in front of the gate is gone", code)
	}

	for _, refused := range []struct{ name, token string }{
		{"a user", token("22222222-0000-0000-0000-000000000001", "user")},
		{"an auditor", token("22222222-0000-0000-0000-000000000002", "auditor")},
		{"an operator", token("22222222-0000-0000-0000-000000000003", "operator")},
		{"a compliance_reader", token("22222222-0000-0000-0000-000000000004", "compliance_reader")},
		{"a machine credential with no role", token("22222222-0000-0000-0000-000000000005")},
	} {
		for _, rt := range []struct{ method, path, body string }{
			{http.MethodPost, "/api/v1/audit/webhooks", register},
			{http.MethodGet, "/api/v1/audit/webhooks", ""},
			{http.MethodPost, "/api/v1/audit/webhooks/" + existing + "/test", ""},
			{http.MethodDelete, "/api/v1/audit/webhooks/" + existing, ""},
		} {
			if code, body := call(rt.method, rt.path, refused.token, rt.body); code != http.StatusForbidden {
				t.Errorf("%s: %s %s answered %d %s, want 403", refused.name, rt.method, rt.path, code, body)
			}
		}
	}
	if got := subscriptions(); len(got) != 1 || got[0] != existing {
		t.Fatalf("after the refused callers the organization's subscriptions are %v, want only %s", got, existing)
	}
	if n := delivered.Load(); n != 0 {
		t.Fatalf("a refused caller's test delivery was sent (%d)", n)
	}

	for i, admitted := range []struct{ name, token string }{
		{"an admin", token("33333333-0000-0000-0000-000000000001", "admin")},
		{"a super_admin", token("33333333-0000-0000-0000-000000000002", "super_admin")},
	} {
		code, body := call(http.MethodPost, "/api/v1/audit/webhooks", admitted.token, register)
		if code != http.StatusCreated {
			t.Fatalf("%s: register answered %d %s, want 201", admitted.name, code, body)
		}
		var created struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal([]byte(body), &created); err != nil || created.ID == "" {
			t.Fatalf("%s: register answered %s", admitted.name, body)
		}
		if got := subscriptions(); len(got) != 2 {
			t.Fatalf("%s: %d subscriptions after registering, want 2", admitted.name, len(got))
		}
		if code, body := call(http.MethodGet, "/api/v1/audit/webhooks", admitted.token, ""); code != http.StatusOK || !strings.Contains(body, created.ID) {
			t.Errorf("%s: list answered %d %s, want 200 naming %s", admitted.name, code, body, created.ID)
		}
		if code, body := call(http.MethodPost, "/api/v1/audit/webhooks/"+created.ID+"/test", admitted.token, ""); code != http.StatusOK {
			t.Errorf("%s: test answered %d %s, want 200", admitted.name, code, body)
		}
		if n := delivered.Load(); n != int64(i+1) {
			t.Errorf("%s: %d test deliveries so far, want %d", admitted.name, n, i+1)
		}
		if code, body := call(http.MethodDelete, "/api/v1/audit/webhooks/"+created.ID, admitted.token, ""); code != http.StatusNoContent {
			t.Errorf("%s: delete answered %d %s, want 204", admitted.name, code, body)
		}
		if got := subscriptions(); len(got) != 1 || got[0] != existing {
			t.Errorf("%s: after the delete the subscriptions are %v, want only %s", admitted.name, got, existing)
		}
	}
}
