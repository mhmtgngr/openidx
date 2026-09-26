package audit

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// The audit stream authenticates its WebSocket itself, from the
// access_token_<jwt> subprotocol, with middleware.VerifyBearerToken rather than
// behind middleware.Auth like the service's other routes. So it has to hold the
// token to the organization the request resolved to, as middleware.Auth does:
// organization A's token does not open organization B's stream, it opens its
// own, and a token naming no organization opens none. A real key signs the
// tokens, a real JWKS endpoint serves the public half and a real WebSocket
// client dials, so the stream opens exactly when the handler lets it.
func TestTheAuditStreamBindsATokenToItsOrganization(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// VerifyBearerToken's key cache is process-wide and keyed by kid, so no
	// other test in this package signs under it.
	const (
		kid  = "audit-stream-org-binding"
		orgA = "aaaaaaaa-0000-0000-0000-00000000000a"
		orgB = "bbbbbbbb-0000-0000-0000-00000000000b"
	)
	jwks := middleware.JWKS{Keys: []middleware.JWKSKey{{
		Kty: "RSA", Use: "sig", Alg: "RS256", Kid: kid,
		N: base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}}
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer jwksSrv.Close()

	es := NewEventStreamerWithConfig(zap.NewNop(), nil, DefaultStreamConfig())
	es.SetJWKSURL(jwksSrv.URL)

	// sign mints an administrator's access token in org, or naming no
	// organization when org is empty.
	sign := func(org string) string {
		t.Helper()
		claims := jwt.MapClaims{
			"sub": "11111111-1111-1111-1111-111111111111", "client_id": "admin-console",
			"roles": []interface{}{"admin"}, "exp": time.Now().Add(time.Hour).Unix(),
		}
		if org != "" {
			claims[middleware.OrgIDClaim] = org
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = kid
		tok.Header["typ"] = middleware.AccessTokenType
		signed, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	// open dials the stream of a request resolved to org, the tenant resolver's
	// job in cmd/audit-service, and returns the handshake's status.
	open := func(org, bearer string) int {
		t.Helper()
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
			c.Next()
		})
		r.GET("/api/v1/audit/stream", es.handleWebSocketStream)
		srv := httptest.NewServer(r)
		defer srv.Close()
		dialer := websocket.Dialer{Subprotocols: []string{"access_token_" + bearer}}
		conn, resp, err := dialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/api/v1/audit/stream", nil)
		if conn != nil {
			conn.Close()
		}
		if resp == nil {
			t.Fatalf("dial: %v", err)
		}
		return resp.StatusCode
	}

	if code := open(orgB, sign(orgA)); code != http.StatusForbidden {
		t.Errorf("org A's token opening org B's audit stream answered %d, want 403", code)
	}
	if code := open(orgA, sign(orgA)); code != http.StatusSwitchingProtocols {
		t.Errorf("org A's token opening its own audit stream answered %d, want 101", code)
	}
	if code := open(orgA, sign("")); code != http.StatusUnauthorized {
		t.Errorf("a token naming no organization opening the audit stream answered %d, want 401", code)
	}
}
