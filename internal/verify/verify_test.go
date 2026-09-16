package verify

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

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/jwksverify"
)

// issuer is a JWKS endpoint that can be taken down, which is the condition
// every test below is really about: this tier's value is what it does when the
// thing it depends on is unreachable.
type issuer struct {
	srv  *httptest.Server
	down atomic.Bool
}

func newIssuer(t *testing.T, keys map[string]*rsa.PublicKey) *issuer {
	t.Helper()
	is := &issuer{}
	doc := jwksverify.JWKS{}
	for kid, pub := range keys {
		doc.Keys = append(doc.Keys, jwksverify.JWKSKey{
			Kty: "RSA", Use: "sig", Alg: "RS256", Kid: kid,
			N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		})
	}
	is.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if is.down.Load() {
			http.Error(w, "issuer down", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(is.srv.Close)
	return is
}

func newKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return k
}

func serve(t *testing.T, jwksURL string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	New(jwksURL, zap.NewNop()).RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	return rec
}

func decodeJWKS(t *testing.T, rec *httptest.ResponseRecorder) jwksverify.JWKS {
	t.Helper()
	var doc jwksverify.JWKS
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode: %v (body %s)", err, rec.Body.String())
	}
	return doc
}

func TestTheTierServesTheIssuersKeys(t *testing.T) {
	jwksverify.ResetCache()
	t.Cleanup(jwksverify.SetWindows(time.Hour, time.Hour))

	k1, k2 := newKey(t), newKey(t)
	is := newIssuer(t, map[string]*rsa.PublicKey{"kid-b": &k1.PublicKey, "kid-a": &k2.PublicKey})

	rec := serve(t, is.srv.URL)
	if rec.Code != http.StatusOK {
		t.Fatalf("jwks = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=300" {
		t.Fatalf("Cache-Control = %q, want the issuer's own max-age", got)
	}
	doc := decodeJWKS(t, rec)
	if len(doc.Keys) != 2 {
		t.Fatalf("served %d keys, want 2", len(doc.Keys))
	}
	// Stable order: a document that reshuffles between two requests answered
	// from the same key set defeats every cache in front of this tier.
	if doc.Keys[0].Kid != "kid-a" || doc.Keys[1].Kid != "kid-b" {
		t.Fatalf("keys not in stable kid order: %s, %s", doc.Keys[0].Kid, doc.Keys[1].Kid)
	}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Use != "sig" || k.Alg != "RS256" || k.N == "" || k.E == "" {
			t.Fatalf("key %s is not a usable RSA signing key: %+v", k.Kid, k)
		}
	}
}

// The reason this tier is worth separating: it keeps answering while the issuer
// -- and the database behind the issuer -- is unreachable.
func TestTheTierKeepsServingWhileTheIssuerIsDown(t *testing.T) {
	jwksverify.ResetCache()
	t.Cleanup(jwksverify.SetWindows(time.Hour, time.Hour))

	k := newKey(t)
	is := newIssuer(t, map[string]*rsa.PublicKey{"kid-1": &k.PublicKey})

	if rec := serve(t, is.srv.URL); rec.Code != http.StatusOK {
		t.Fatalf("prime: %d", rec.Code)
	}

	is.down.Store(true)
	jwksverify.ExpireCache()

	rec := serve(t, is.srv.URL)
	if rec.Code != http.StatusOK {
		t.Fatalf("during issuer outage: %d, want 200 — the tier stopped answering exactly when it matters (body %s)",
			rec.Code, rec.Body.String())
	}
	if doc := decodeJWKS(t, rec); len(doc.Keys) != 1 || doc.Keys[0].Kid != "kid-1" {
		t.Fatalf("stale document lost the key: %+v", doc)
	}
}

// With nothing cached and the issuer unreachable there is no honest 200 to
// give. An empty key set with a 200 tells a relying party, authoritatively,
// that this issuer signs nothing -- and the correct response to that answer is
// to reject every token it is holding, including the valid ones.
func TestAnUnreachableIssuerWithNoCacheIsAnErrorNotAnEmptyKeySet(t *testing.T) {
	jwksverify.ResetCache()
	t.Cleanup(jwksverify.SetWindows(time.Hour, time.Hour))

	k := newKey(t)
	is := newIssuer(t, map[string]*rsa.PublicKey{"kid-1": &k.PublicKey})
	is.down.Store(true)

	rec := serve(t, is.srv.URL)
	if rec.Code == http.StatusOK {
		doc := decodeJWKS(t, rec)
		t.Fatalf("answered 200 with %d keys while the issuer was unreachable and nothing was cached; "+
			"a verifier would take that as \"this issuer has no keys\"", len(doc.Keys))
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q on a failure; a cached 503 would outlive the outage", got)
	}
}

func TestOnlyReadMethodsAreServed(t *testing.T) {
	jwksverify.ResetCache()
	t.Cleanup(jwksverify.SetWindows(time.Hour, time.Hour))

	k := newKey(t)
	is := newIssuer(t, map[string]*rsa.PublicKey{"kid-1": &k.PublicKey})

	mux := http.NewServeMux()
	New(is.srv.URL, zap.NewNop()).RegisterRoutes(mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodOptions, "/.well-known/jwks.json", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("OPTIONS = %d, want 204 (CORS preflight, as the issuer answers it)", rec.Code)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d, want 405", rec.Code)
	}
}

// The tier must not publish a key it would refuse to verify with. The cache
// keeps only RSA keys marked use=sig that parse, so anything else the issuer
// advertises is dropped -- and dropping it from the SERVED document too is what
// keeps this endpoint and this tier's own verification consistent. Publishing
// it would tell a relying party to accept signatures the product will not.
func TestTheTierPublishesOnlyKeysItCouldVerifyWith(t *testing.T) {
	jwksverify.ResetCache()
	t.Cleanup(jwksverify.SetWindows(time.Hour, time.Hour))

	k := newKey(t)
	usable := jwksverify.JWKSKey{
		Kty: "RSA", Use: "sig", Alg: "RS256", Kid: "rsa-sig",
		N: base64.RawURLEncoding.EncodeToString(k.PublicKey.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.PublicKey.E)).Bytes()),
	}
	// An encryption key and an EC key: both legitimate JWKS entries, neither
	// usable for verifying an RS256 signature.
	encryption := usable
	encryption.Kid, encryption.Use = "rsa-enc", "enc"
	elliptic := jwksverify.JWKSKey{Kty: "EC", Use: "sig", Alg: "ES256", Kid: "ec-sig", N: "ignored", E: "ignored"}

	doc := jwksverify.JWKS{Keys: []jwksverify.JWKSKey{usable, encryption, elliptic}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(srv.Close)

	rec := serve(t, srv.URL)
	if rec.Code != http.StatusOK {
		t.Fatalf("jwks = %d, want 200", rec.Code)
	}
	served := decodeJWKS(t, rec)
	if len(served.Keys) != 1 || served.Keys[0].Kid != "rsa-sig" {
		var kids []string
		for _, key := range served.Keys {
			kids = append(kids, key.Kid)
		}
		t.Fatalf("served %v; want only rsa-sig — the tier published a key it cannot verify with", kids)
	}
}
