package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newJWKSServer(t *testing.T, kid string, pub *rsa.PublicKey) *httptest.Server {
	t.Helper()
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	jwks := JWKS{Keys: []JWKSKey{{
		Kty: "RSA", Use: "sig", Kid: kid, Alg: "RS256",
		N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(eBytes),
	}}}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func resetJWKSCache() {
	globalJWKSCache.mu.Lock()
	globalJWKSCache.keys = make(map[string]*rsa.PublicKey)
	globalJWKSCache.expiresAt = time.Time{}
	globalJWKSCache.mu.Unlock()
}

func TestVerifyBearerToken(t *testing.T) {
	resetJWKSCache()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	const kid = "test-kid-1"
	srv := newJWKSServer(t, kid, &key.PublicKey)
	defer srv.Close()
	jwksURL := srv.URL

	t.Run("valid token verifies and returns claims", func(t *testing.T) {
		resetJWKSCache()
		tok := signRS256(t, key, kid, jwt.MapClaims{
			"sub": "user-123", "email": "u@example.test",
			"exp": float64(time.Now().Add(time.Hour).Unix()),
		})
		claims, err := VerifyBearerToken(jwksURL, tok)
		if err != nil {
			t.Fatalf("expected valid, got error: %v", err)
		}
		if claims["sub"] != "user-123" {
			t.Fatalf("sub = %v, want user-123", claims["sub"])
		}
	})

	t.Run("unsigned alg=none token is rejected", func(t *testing.T) {
		resetJWKSCache()
		hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT","kid":"` + kid + `"}`))
		pl := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"attacker","roles":["admin"],"exp":` +
			strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + `}`))
		forged := hdr + "." + pl + "."
		if _, err := VerifyBearerToken(jwksURL, forged); err == nil {
			t.Fatal("alg=none token must be rejected")
		}
	})

	t.Run("token signed by a different key is rejected", func(t *testing.T) {
		resetJWKSCache()
		other, _ := rsa.GenerateKey(rand.Reader, 2048)
		tok := signRS256(t, other, kid, jwt.MapClaims{
			"sub": "user-123", "exp": float64(time.Now().Add(time.Hour).Unix()),
		})
		if _, err := VerifyBearerToken(jwksURL, tok); err == nil {
			t.Fatal("wrong-key signature must be rejected")
		}
	})

	t.Run("expired token is rejected", func(t *testing.T) {
		resetJWKSCache()
		tok := signRS256(t, key, kid, jwt.MapClaims{
			"sub": "user-123", "exp": float64(time.Now().Add(-time.Hour).Unix()),
		})
		if _, err := VerifyBearerToken(jwksURL, tok); err == nil {
			t.Fatal("expired token must be rejected")
		}
	})

	t.Run("token missing exp is rejected", func(t *testing.T) {
		resetJWKSCache()
		tok := signRS256(t, key, kid, jwt.MapClaims{"sub": "user-123"})
		if _, err := VerifyBearerToken(jwksURL, tok); err == nil {
			t.Fatal("token without exp must be rejected")
		}
	})

	t.Run("token missing kid is rejected", func(t *testing.T) {
		resetJWKSCache()
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub": "user-123", "exp": float64(time.Now().Add(time.Hour).Unix()),
		})
		s, _ := tok.SignedString(key)
		if _, err := VerifyBearerToken(jwksURL, s); err == nil {
			t.Fatal("token without kid must be rejected")
		}
	})
}
