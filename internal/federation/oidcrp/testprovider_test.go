package oidcrp

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// fakeProvider is an OpenID provider with a discovery document and a JWKS,
// signing with one RSA key. It stands in for Entra ID, ADFS or Keycloak: the
// only thing the relying party may rely on is what the two documents say.
type fakeProvider struct {
	srv       *httptest.Server
	key       *rsa.PrivateKey
	kid       string
	issuer    string // what the discovery document claims; defaults to the server URL
	discovery atomic.Int32
	jwks      atomic.Int32
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProvider{key: key, kid: "k1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		p.discovery.Add(1)
		iss := p.issuer
		if iss == "" {
			iss = p.srv.URL
		}
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                iss,
			"authorization_endpoint":                p.srv.URL + "/authorize",
			"token_endpoint":                        p.srv.URL + "/token",
			"jwks_uri":                              p.srv.URL + "/keys",
			"userinfo_endpoint":                     p.srv.URL + "/userinfo",
			"response_types_supported":              []string{"code"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"code_challenge_methods_supported":      []string{"S256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		p.jwks.Add(1)
		pub := p.key.PublicKey
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": p.kid,
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

// token signs claims with the provider's key, filling iss/iat/exp when absent.
func (p *fakeProvider) token(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = p.srv.URL
	}
	now := time.Now()
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = now.Unix()
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = now.Add(5 * time.Minute).Unix()
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = p.kid
	s, err := tok.SignedString(p.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
