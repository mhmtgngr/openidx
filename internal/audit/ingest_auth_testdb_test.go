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

// AUDIT EVENTS ARE WRITTEN ONLY BY SERVICES HOLDING THE INTERNAL TOKEN.
//
// POST /api/v1/audit/events files an event under the organization X-Org-Slug
// names, with the actor, address, action and outcome the body states, and the
// sealer chains it like any other. It took any caller, and every reference
// edge forwarded the whole /api/v1/audit prefix, so anyone could write a
// forged event into any organization's trail.
//
// Driven through RegisterRoutes behind the tenant resolver, as
// cmd/audit-service mounts them, with the read routes behind middleware.Auth
// over a real JWKS and a migrated database:
//
//   - no credential, a wrong internal token, and an administrator's access
//     token of the organization named are each refused with 401, and no row is
//     written;
//   - an audit service with no INTERNAL_SERVICE_TOKEN configured refuses the
//     empty token too;
//   - the internal token files the event under the organization named, and
//     the administrator reads it back through GET /api/v1/audit/events;
//   - on the edge listener (AUDIT_EDGE_ADDR) the internal token is refused
//     with 404 too, and the read still answers.
func TestAuditEventsAreWrittenOnlyByServicesHoldingTheInternalToken(t *testing.T) {
	db, cleanup := setupComplianceSchemaDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	gin.SetMode(gin.TestMode)

	const internalToken = "audit-ingest-test-internal-service-token"
	ctx := orgctx.WithBypassRLS(context.Background())
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	var org orgctx.Org
	org.Slug = "ingest-" + suffix
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`, org.Slug).Scan(&org.ID); err != nil {
		t.Fatalf("seed organization: %v", err)
	}

	// The administrator's access token: the console's, allowed to call the
	// APIs, minted in the organization the events are filed under.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "audit-ingest-internal-token"
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(middleware.JWKS{Keys: []middleware.JWKSKey{{
			Kty: "RSA", Use: "sig", Alg: "RS256", Kid: kid,
			N: base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	defer jwksSrv.Close()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "11111111-1111-1111-1111-111111111111", "client_id": "admin-console",
		"roles": []interface{}{"admin", "super_admin"}, middleware.APIAccessClaim: true,
		middleware.OrgIDClaim: org.ID, "exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = kid
	tok.Header["typ"] = middleware.AccessTokenType
	adminToken, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}

	// The chain cmd/audit-service mounts: the tenant resolver on the engine,
	// then RegisterRoutes with the authentication the read routes take.
	routes := func(configured string) http.Handler {
		cfg := &config.Config{InternalServiceToken: configured}
		svc := NewService(db, nil, cfg, zap.NewNop())
		r := gin.New()
		r.Use(middleware.TenantResolver(organization.NewOrgLookup(organization.NewService(db, nil, cfg, zap.NewNop())),
			middleware.TenantResolverConfig{DefaultOrgFallback: true, DefaultOrgID: middleware.DefaultOrgID, Logger: zap.NewNop()}))
		RegisterRoutes(r, svc, middleware.Auth(jwksSrv.URL), cell.Guard("", zap.NewNop()))
		return r
	}
	internal := httptest.NewServer(routes(internalToken))
	defer internal.Close()
	edge := httptest.NewUnstartedServer(routes(internalToken))
	edge.Config.ConnContext = MarkEdgeListener
	edge.Start()
	defer edge.Close()
	unconfigured := httptest.NewServer(routes(""))
	defer unconfigured.Close()

	// The actor every attempt names, so the read below can ask for its events.
	actor := "99999999-0000-0000-0000-" + fmt.Sprintf("%012d", time.Now().UnixNano()%1e12)
	post := func(base, action string, headers ...string) (int, string) {
		t.Helper()
		body := `{"event_type":"authorization","category":"access_proxy","action":"` + action + `",` +
			`"outcome":"success","actor_id":"` + actor + `","actor_ip":"198.51.100.7",` +
			`"target_type":"pam_entry","details":{"forged":true}}`
		req, _ := http.NewRequest(http.MethodPost, base+"/api/v1/audit/events", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Org-Slug", org.Slug)
		for i := 0; i+1 < len(headers); i += 2 {
			req.Header.Set(headers[i], headers[i+1])
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", base, err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(raw)
	}
	rows := func(action string) (n int, orgID string) {
		t.Helper()
		if err := db.Pool.QueryRow(ctx,
			`SELECT COUNT(*), COALESCE(MAX(org_id::text), '') FROM audit_events WHERE action = $1`, action).Scan(&n, &orgID); err != nil {
			t.Fatalf("count %s: %v", action, err)
		}
		return n, orgID
	}

	refused := []struct {
		name    string
		base    string
		want    int
		headers []string
	}{
		{"no credential", internal.URL, http.StatusUnauthorized, nil},
		{"a wrong internal token", internal.URL, http.StatusUnauthorized,
			[]string{middleware.InternalTokenHeader, internalToken + "-not"}},
		{"the organization administrator's access token", internal.URL, http.StatusUnauthorized,
			[]string{"Authorization", "Bearer " + adminToken}},
		{"the administrator's token with a wrong internal token", internal.URL, http.StatusUnauthorized,
			[]string{"Authorization", "Bearer " + adminToken, middleware.InternalTokenHeader, "guess"}},
		{"an empty token to a service with none configured", unconfigured.URL, http.StatusUnauthorized,
			[]string{middleware.InternalTokenHeader, ""}},
		{"the internal token on the edge listener", edge.URL, http.StatusNotFound,
			[]string{middleware.InternalTokenHeader, internalToken}},
	}
	for i, r := range refused {
		action := fmt.Sprintf("ingest.refused.%d.%s", i, suffix)
		if code, body := post(r.base, action, r.headers...); code != r.want {
			t.Errorf("%s: POST /api/v1/audit/events answered %d %s, want %d", r.name, code, body, r.want)
		}
		if n, _ := rows(action); n != 0 {
			t.Errorf("%s was refused, and %d event(s) reached the trail anyway", r.name, n)
		}
	}

	// The service's own call: the token, and the organization it acted in.
	accepted := "ingest.accepted." + suffix
	if code, body := post(internal.URL, accepted, middleware.InternalTokenHeader, internalToken); code != http.StatusCreated {
		t.Fatalf("the internal token: POST /api/v1/audit/events answered %d %s, want 201", code, body)
	}
	if n, orgID := rows(accepted); n != 1 || orgID != org.ID {
		t.Fatalf("the accepted event: %d row(s) in org %q, want 1 in %s", n, orgID, org.ID)
	}

	// The console's read of the trail is untouched, on both listeners.
	for _, base := range []string{internal.URL, edge.URL} {
		req, _ := http.NewRequest(http.MethodGet, base+"/api/v1/audit/events?actor_id="+actor, nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("X-Org-Slug", org.Slug)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", base, err)
		}
		var events []ServiceAuditEvent
		decErr := json.NewDecoder(resp.Body).Decode(&events)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || decErr != nil {
			t.Fatalf("GET /api/v1/audit/events on %s answered %d (%v), want 200", base, resp.StatusCode, decErr)
		}
		found := false
		for _, e := range events {
			found = found || e.Action == accepted
		}
		if !found {
			t.Errorf("GET /api/v1/audit/events on %s did not list the accepted event", base)
		}
	}
}
