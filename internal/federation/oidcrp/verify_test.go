package oidcrp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func verifySetup(t *testing.T) (*fakeProvider, *Discoverer, *Metadata) {
	t.Helper()
	p := newFakeProvider(t)
	d := NewDiscoverer(nil)
	md, err := d.Discover(context.Background(), p.srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	return p, d, md
}

func TestVerifyIDTokenAcceptsAWellFormedToken(t *testing.T) {
	p, d, md := verifySetup(t)
	raw := p.token(t, jwt.MapClaims{
		"aud": "client-1", "sub": "abc", "nonce": "n1",
		"email": "ayse@example.org", "email_verified": true, "name": "Ayşe Yılmaz",
		"preferred_username": "ayse@example.org", "oid": "oid-1", "tid": "tid-1",
		"groups": []string{"g1", "g2"}, "amr": []string{"pwd", "mfa"}, "acr": "urn:x",
	})
	c, err := d.VerifyIDToken(context.Background(), md, raw, VerifyOptions{ClientID: "client-1", Nonce: "n1"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Sub != "abc" || c.Email != "ayse@example.org" || !c.EmailVerified || c.OID != "oid-1" || c.TID != "tid-1" ||
		len(c.Groups) != 2 || len(c.AMR) != 2 || c.ACR != "urn:x" || c.Name != "Ayşe Yılmaz" {
		t.Errorf("claims = %+v", c)
	}
	if c.Raw["preferred_username"] != "ayse@example.org" {
		t.Error("raw claims not kept")
	}
}

func TestVerifyIDTokenRefusesTheWrongAudience(t *testing.T) {
	p, d, md := verifySetup(t)
	raw := p.token(t, jwt.MapClaims{"aud": "someone-else", "sub": "abc", "nonce": "n1"})
	_, err := d.VerifyIDToken(context.Background(), md, raw, VerifyOptions{ClientID: "client-1", Nonce: "n1"})
	if !errors.Is(err, ErrAudience) {
		t.Fatalf("err = %v, want ErrAudience", err)
	}
}

func TestVerifyIDTokenAcceptsAnAudienceListNamingTheClient(t *testing.T) {
	p, d, md := verifySetup(t)
	raw := p.token(t, jwt.MapClaims{"aud": []string{"other", "client-1"}, "azp": "client-1", "sub": "abc", "nonce": "n1"})
	if _, err := d.VerifyIDToken(context.Background(), md, raw, VerifyOptions{ClientID: "client-1", Nonce: "n1"}); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyIDTokenRefusesTheWrongIssuer(t *testing.T) {
	p, d, md := verifySetup(t)
	raw := p.token(t, jwt.MapClaims{"iss": "https://evil.example", "aud": "client-1", "sub": "abc", "nonce": "n1"})
	_, err := d.VerifyIDToken(context.Background(), md, raw, VerifyOptions{ClientID: "client-1", Nonce: "n1"})
	if !errors.Is(err, ErrIssuer) {
		t.Fatalf("err = %v, want ErrIssuer", err)
	}
}

func TestVerifyIDTokenRefusesTheWrongNonce(t *testing.T) {
	p, d, md := verifySetup(t)
	raw := p.token(t, jwt.MapClaims{"aud": "client-1", "sub": "abc", "nonce": "replayed"})
	_, err := d.VerifyIDToken(context.Background(), md, raw, VerifyOptions{ClientID: "client-1", Nonce: "n1"})
	if !errors.Is(err, ErrNonce) {
		t.Fatalf("err = %v, want ErrNonce", err)
	}
}

func TestVerifyIDTokenRefusesAMissingNonceWhenOneWasSent(t *testing.T) {
	p, d, md := verifySetup(t)
	raw := p.token(t, jwt.MapClaims{"aud": "client-1", "sub": "abc"})
	_, err := d.VerifyIDToken(context.Background(), md, raw, VerifyOptions{ClientID: "client-1", Nonce: "n1"})
	if !errors.Is(err, ErrNonce) {
		t.Fatalf("err = %v, want ErrNonce", err)
	}
}

func TestVerifyIDTokenRefusesAnExpiredToken(t *testing.T) {
	p, d, md := verifySetup(t)
	raw := p.token(t, jwt.MapClaims{"aud": "client-1", "sub": "abc", "nonce": "n1",
		"iat": time.Now().Add(-time.Hour).Unix(), "exp": time.Now().Add(-30 * time.Minute).Unix()})
	_, err := d.VerifyIDToken(context.Background(), md, raw, VerifyOptions{ClientID: "client-1", Nonce: "n1"})
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
}

func TestVerifyIDTokenMayAcceptAnExpiredHint(t *testing.T) {
	// Entra's id_token_hint for an external MFA method is issued already
	// expired, on purpose; the caller says so explicitly.
	p, d, md := verifySetup(t)
	raw := p.token(t, jwt.MapClaims{"aud": "client-1", "sub": "abc",
		"iat": time.Now().Add(-time.Hour).Unix(), "exp": time.Now().Add(-30 * time.Minute).Unix()})
	if _, err := d.VerifyIDToken(context.Background(), md, raw, VerifyOptions{ClientID: "client-1", AllowExpired: true}); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyIDTokenRefusesAnUnsignedToken(t *testing.T) {
	_, d, md := verifySetup(t)
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"iss": md.Issuer, "aud": "client-1", "sub": "abc", "nonce": "n1",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()})
	raw, _ := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	_, err := d.VerifyIDToken(context.Background(), md, raw, VerifyOptions{ClientID: "client-1", Nonce: "n1"})
	if !errors.Is(err, ErrAlgorithm) {
		t.Fatalf("err = %v, want ErrAlgorithm", err)
	}
}

func TestVerifyIDTokenRefusesAKeyTheProviderDoesNotPublish(t *testing.T) {
	p, d, md := verifySetup(t)
	other := newFakeProvider(t) // a different key under the same kid
	raw := other.token(t, jwt.MapClaims{"iss": p.srv.URL, "aud": "client-1", "sub": "abc", "nonce": "n1"})
	_, err := d.VerifyIDToken(context.Background(), md, raw, VerifyOptions{ClientID: "client-1", Nonce: "n1"})
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("err = %v, want ErrSignature", err)
	}
}

func TestSigningKeysAreCachedPerJWKSURI(t *testing.T) {
	p, d, md := verifySetup(t)
	for i := 0; i < 3; i++ {
		raw := p.token(t, jwt.MapClaims{"aud": "client-1", "sub": "abc", "nonce": "n1"})
		if _, err := d.VerifyIDToken(context.Background(), md, raw, VerifyOptions{ClientID: "client-1", Nonce: "n1"}); err != nil {
			t.Fatal(err)
		}
	}
	if n := p.jwks.Load(); n != 1 {
		t.Errorf("jwks fetched %d times, want 1", n)
	}
}

func TestAnUnknownKidRefreshesTheKeySetOnce(t *testing.T) {
	p, d, md := verifySetup(t)
	raw := p.token(t, jwt.MapClaims{"aud": "client-1", "sub": "abc", "nonce": "n1"})
	if _, err := d.VerifyIDToken(context.Background(), md, raw, VerifyOptions{ClientID: "client-1", Nonce: "n1"}); err != nil {
		t.Fatal(err)
	}
	p.kid = "k2" // the provider rolled its key
	raw = p.token(t, jwt.MapClaims{"aud": "client-1", "sub": "abc", "nonce": "n1"})
	if _, err := d.VerifyIDToken(context.Background(), md, raw, VerifyOptions{ClientID: "client-1", Nonce: "n1"}); err != nil {
		t.Fatalf("after rollover: %v", err)
	}
	if n := p.jwks.Load(); n != 2 {
		t.Errorf("jwks fetched %d times, want 2", n)
	}
}
