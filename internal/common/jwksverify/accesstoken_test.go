package jwksverify

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestIsAccessToken(t *testing.T) {
	cases := []struct {
		name   string
		header map[string]interface{}
		claims map[string]interface{}
		want   bool
	}{
		{"typed at+jwt", map[string]interface{}{"typ": "at+jwt"}, map[string]interface{}{}, true},
		{"typed with the media type", map[string]interface{}{"typ": "application/at+jwt"}, map[string]interface{}{}, true},
		{"type compared without case", map[string]interface{}{"typ": "AT+JWT"}, map[string]interface{}{}, true},
		{"minted before the type: client_id", map[string]interface{}{"typ": "JWT"}, map[string]interface{}{"client_id": "admin-console"}, true},
		{"minted before the type, no typ header at all", map[string]interface{}{}, map[string]interface{}{"client_id": "admin-console"}, true},
		{"an ID token", map[string]interface{}{"typ": "JWT"}, map[string]interface{}{"aud": "admin-console", "roles": []interface{}{"admin"}}, false},
		{"neither a type nor a client_id", map[string]interface{}{}, map[string]interface{}{"sub": "u"}, false},
		{"an empty client_id is none", map[string]interface{}{"typ": "JWT"}, map[string]interface{}{"client_id": ""}, false},
		{"a logout token, even naming a client", map[string]interface{}{"typ": "logout+jwt"}, map[string]interface{}{"client_id": "c"}, false},
		{"a security event token", map[string]interface{}{"typ": "secevent+jwt"}, map[string]interface{}{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsAccessToken(tc.header, tc.claims); got != tc.want {
				t.Fatalf("IsAccessToken(%v, %v) = %v, want %v", tc.header, tc.claims, got, tc.want)
			}
		})
	}
}

// TestVerifyBearerTokenAcceptsOnlyAccessTokens is the same rule through the
// verification path the access proxy, the MCP gateway, device enrolment and
// the audit stream call: a correctly signed ID token is refused.
func TestVerifyBearerTokenAcceptsOnlyAccessTokens(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	const kid = "access-token-kid"
	srv := newJWKSServer(t, kid, &key.PublicKey)
	defer srv.Close()

	sign := func(typ string, claims jwt.MapClaims) string {
		t.Helper()
		claims["exp"] = float64(time.Now().Add(time.Hour).Unix())
		claims[OrgIDClaim] = testOrgID
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = kid
		if typ == "" {
			delete(tok.Header, "typ")
		} else {
			tok.Header["typ"] = typ
		}
		s, err := tok.SignedString(key)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return s
	}

	accepted := map[string]string{
		"an access token":                 sign(AccessTokenType, jwt.MapClaims{"sub": "u", "client_id": "c"}),
		"an access token minted untyped":  sign("JWT", jwt.MapClaims{"sub": "u", "client_id": "c"}),
		"an access token with no typ key": sign("", jwt.MapClaims{"sub": "u", "client_id": "c"}),
	}
	for name, tok := range accepted {
		resetJWKSCache()
		if _, err := VerifyBearerToken(srv.URL, tok); err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
	}

	refused := map[string]string{
		"an admin's ID token": sign("JWT", jwt.MapClaims{
			"sub": "u", "aud": "admin-console", "roles": []interface{}{"admin"},
		}),
		"a token with neither a type nor a client": sign("", jwt.MapClaims{"sub": "u"}),
		"a logout token": sign("logout+jwt", jwt.MapClaims{"sub": "u", "aud": "c"}),
	}
	for name, tok := range refused {
		resetJWKSCache()
		if _, err := VerifyBearerToken(srv.URL, tok); !errors.Is(err, ErrNotAccessToken) {
			t.Errorf("%s: err = %v, want ErrNotAccessToken", name, err)
		}
	}
}

func TestTokenOrgID(t *testing.T) {
	if org, err := TokenOrgID(map[string]interface{}{OrgIDClaim: testOrgID}); err != nil || org != testOrgID {
		t.Fatalf("TokenOrgID = %q, %v; want %q", org, err, testOrgID)
	}
	for name, claims := range map[string]map[string]interface{}{
		"no claim":     {"sub": "u"},
		"empty claim":  {OrgIDClaim: ""},
		"not a string": {OrgIDClaim: 42},
	} {
		if _, err := TokenOrgID(claims); !errors.Is(err, ErrNoOrganization) {
			t.Errorf("%s: err = %v, want ErrNoOrganization", name, err)
		}
	}
}

// An access token minted before the claim existed names no organization. It is
// refused, not read as the default organization: whichever organization it came
// from, it would otherwise act in the default one.
func TestVerifyBearerTokenRefusesAnAccessTokenWithNoOrganization(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	const kid = "no-org-kid"
	srv := newJWKSServer(t, kid, &key.PublicKey)
	defer srv.Close()
	resetJWKSCache()

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "u", "client_id": "admin-console", "roles": []interface{}{"admin"},
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	tok.Header["kid"] = kid
	tok.Header["typ"] = AccessTokenType
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := VerifyBearerToken(srv.URL, signed); !errors.Is(err, ErrNoOrganization) {
		t.Fatalf("err = %v, want ErrNoOrganization", err)
	}
}
