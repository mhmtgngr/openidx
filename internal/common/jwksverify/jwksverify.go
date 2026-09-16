// Package jwksverify is the token-verification half of OpenIDX's auth path,
// with nothing behind it but an HTTP fetch of the issuer's JWKS.
//
// It used to live inside internal/common/middleware, and that is why this
// package exists. Verification needs no database -- it needs a public key and
// a signature -- but the package holding it also holds PermissionResolver and
// RequireFreshMFA, which read tenant-scoped tables, so `github.com/jackc/pgx`
// sat in the import graph of every binary that merely validated a bearer. A
// service that verifies tokens and nothing else could not be built without
// linking a PostgreSQL driver it would never open a connection with, and the
// plane split in ADR-2 is exactly that service. The implementation was not
// copied here: middleware now calls this package, so there is still one JWKS
// cache, one serve-stale window and one algorithm pin in the tree.
//
// The availability contract is unchanged and is the reason this code is worth
// isolating: a token that has already been issued MUST keep verifying while the
// issuer -- and the database behind it -- is unreachable. See SigningKey.
package jwksverify

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWKSKey represents a single key from the JWKS endpoint
type JWKSKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWKSKey `json:"keys"`
}

// jwksKeyCache stores parsed RSA public keys.
//
// It keeps the last successfully fetched key set and the time of that fetch so
// that, when a refresh fails (the OAuth/JWKS endpoint or the shared database is
// down), we can SERVE STALE keys rather than reject otherwise-valid tokens. This
// is the Tier 0 availability belt: token verification survives a JWKS/DB outage
// for up to jwksMaxStale past the normal TTL. See jwks_metrics.go.
type jwksKeyCache struct {
	keys          map[string]*rsa.PublicKey
	expiresAt     time.Time // freshness horizon: keys are "fresh" until this time
	lastRefreshOK time.Time // when we last fetched a valid key set (for staleness math)
	mu            sync.RWMutex
}

// Global JWKS cache with 1 hour freshness TTL.
var globalJWKSCache = &jwksKeyCache{
	keys: make(map[string]*rsa.PublicKey),
}

// jwksTTL is how long a fetched key set is considered fresh before we try to
// refresh it. jwksMaxStale is how long past that we will keep serving the cached
// keys when refresh fails; beyond it we stop trusting the stale set and fail
// verification (a signing key could have been rotated + retired by then).
//
// Rationale: OAuth signing keys rotate on the order of days/weeks with a long
// verification grace (internal/oauth/signer.go), so serving keys a few hours
// stale is safe and keeps every already-issued token verifiable through a
// database outage. Both are overridable for tests / tuning.
var (
	jwksTTL      = envDuration("JWKS_TTL", time.Hour)
	jwksMaxStale = envDuration("JWKS_MAX_STALE", 12*time.Hour)
)

// envDuration reads a Go duration (e.g. "1h", "30m") from env, falling back to
// def on empty/unparseable input.
func envDuration(name string, def time.Duration) time.Duration {
	if v := os.Getenv(name); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}

// fetchJWKS fetches and parses JWKS from the given URL
func fetchJWKS(jwksURL string) (map[string]*rsa.PublicKey, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey)
	for _, key := range jwks.Keys {
		if key.Kty != "RSA" || key.Use != "sig" {
			continue
		}

		pubKey, err := parseRSAPublicKey(key.N, key.E)
		if err != nil {
			continue // Skip invalid keys
		}
		keys[key.Kid] = pubKey
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no valid RSA signing keys found in JWKS")
	}

	return keys, nil
}

// parseRSAPublicKey parses RSA public key from base64url encoded n and e
func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	// Decode n (modulus)
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode n: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)

	// Decode e (exponent)
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode e: %w", err)
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

// refreshJWKSLocked attempts to fetch a fresh key set and update the cache.
// It MUST be called with globalJWKSCache.mu held for writing.
//
// On success it swaps in the new keys, extends the freshness TTL, records the
// refresh time, and returns nil. On failure it does NOT clear the existing keys
// (serve-stale): the caller decides whether the still-cached keys are within the
// max-stale window and may be used. Metrics are emitted for both outcomes.
func refreshJWKSLocked(jwksURL string) error {
	keys, err := fetchJWKS(jwksURL)
	if err != nil {
		RefreshFailuresTotal.Inc()
		return err
	}
	globalJWKSCache.keys = keys
	now := time.Now()
	globalJWKSCache.expiresAt = now.Add(jwksTTL)
	globalJWKSCache.lastRefreshOK = now
	RefreshSuccessTotal.Inc()
	return nil
}

// staleUsableLocked reports whether the currently cached key set, though past
// its freshness TTL, is still within the max-stale window and may be served.
// MUST be called with the cache mutex held (read or write).
func staleUsableLocked() bool {
	if len(globalJWKSCache.keys) == 0 {
		return false
	}
	// lastRefreshOK zero means we never successfully fetched — nothing to trust.
	if globalJWKSCache.lastRefreshOK.IsZero() {
		return false
	}
	return time.Since(globalJWKSCache.expiresAt) <= jwksMaxStale
}

// noteServeStaleLocked records staleness metrics when a stale key is served.
func noteServeStaleLocked() {
	ServeStaleTotal.Inc()
	StaleSeconds.Set(time.Since(globalJWKSCache.lastRefreshOK).Seconds())
}

// SigningKey retrieves the RSA public key for token validation.
//
// Availability contract (Tier 0): a valid, already-issued token MUST keep
// verifying through a JWKS/database outage. Order of preference:
//  1. fresh cache hit;
//  2. successful refresh;
//  3. SERVE STALE — if refresh fails but a previously-fetched key set is still
//     within JWKS_MAX_STALE, use it rather than rejecting the token.
//
// Only when there is no usable (fresh or stale) key set do we surface the error.
func SigningKey(jwksURL, kid string) (*rsa.PublicKey, error) {
	// Fast path: fresh cache hit.
	globalJWKSCache.mu.RLock()
	if time.Now().Before(globalJWKSCache.expiresAt) {
		if key, ok := globalJWKSCache.keys[kid]; ok {
			globalJWKSCache.mu.RUnlock()
			return key, nil
		}
	}
	globalJWKSCache.mu.RUnlock()

	globalJWKSCache.mu.Lock()
	defer globalJWKSCache.mu.Unlock()

	// Double-check after acquiring the write lock.
	if time.Now().Before(globalJWKSCache.expiresAt) {
		if key, ok := globalJWKSCache.keys[kid]; ok {
			return key, nil
		}
	}

	if err := refreshJWKSLocked(jwksURL); err != nil {
		// Refresh failed. Serve stale if we still have a trustworthy cached set.
		if staleUsableLocked() {
			if key, ok := globalJWKSCache.keys[kid]; ok {
				noteServeStaleLocked()
				return key, nil
			}
			// Stale set is usable but doesn't contain this kid: the token was
			// signed by a key we've never seen. That is a real verification
			// failure, not an availability issue — surface it.
			return nil, fmt.Errorf("key with kid %s not found in JWKS (issuer unreachable; served from stale cache): %w", kid, err)
		}
		return nil, fmt.Errorf("JWKS refresh failed and no usable cached keys: %w", err)
	}

	if key, ok := globalJWKSCache.keys[kid]; ok {
		return key, nil
	}

	return nil, fmt.Errorf("key with kid %s not found in JWKS", kid)
}

// FirstSigningKey returns the first RSA signing key from JWKS (for tokens
// without kid). It follows the same fresh → refresh → serve-stale availability
// contract as getSigningKey.
func FirstSigningKey(jwksURL string) (*rsa.PublicKey, error) {
	globalJWKSCache.mu.RLock()
	if time.Now().Before(globalJWKSCache.expiresAt) && len(globalJWKSCache.keys) > 0 {
		for _, key := range globalJWKSCache.keys {
			globalJWKSCache.mu.RUnlock()
			return key, nil
		}
	}
	globalJWKSCache.mu.RUnlock()

	globalJWKSCache.mu.Lock()
	defer globalJWKSCache.mu.Unlock()

	if time.Now().Before(globalJWKSCache.expiresAt) && len(globalJWKSCache.keys) > 0 {
		for _, key := range globalJWKSCache.keys {
			return key, nil
		}
	}

	if err := refreshJWKSLocked(jwksURL); err != nil {
		if staleUsableLocked() {
			noteServeStaleLocked()
			for _, key := range globalJWKSCache.keys {
				return key, nil
			}
		}
		return nil, fmt.Errorf("JWKS refresh failed and no usable cached keys: %w", err)
	}

	for _, key := range globalJWKSCache.keys {
		return key, nil
	}

	return nil, fmt.Errorf("no signing keys found in JWKS")
}

// VerifyBearerToken validates a bearer JWT against the OAuth JWKS and returns
// its claims. It enforces the same guarantees as Auth(): an RS256 algorithm pin
// (rejecting "none"/HS256 and alg-confusion), a kid→JWKS signing-key lookup via
// the shared 1-hour key cache, and a required, unexpired exp. It is for services
// that authenticate a bearer OUTSIDE the Auth() middleware (e.g. the access
// reverse proxy resolving a forwarded bearer). Any verification failure returns
// an error; callers MUST treat a non-nil error as "unauthenticated" and build no
// session from it.
func VerifyBearerToken(jwksURL, tokenString string) (map[string]interface{}, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		alg, ok := token.Header["alg"].(string)
		if !ok || alg == "" {
			return nil, fmt.Errorf("token missing alg header")
		}
		if alg != "RS256" {
			return nil, fmt.Errorf("unexpected signing algorithm: %s (only RS256 is allowed)", alg)
		}
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("token method is not RSA despite alg header")
		}
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("token missing kid header")
		}
		return SigningKey(jwksURL, kid)
	})
	if err != nil {
		return nil, err
	}
	if token == nil || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("token missing exp")
	}
	if time.Now().Unix() > int64(exp) {
		return nil, fmt.Errorf("token expired")
	}
	return claims, nil
}

// FetchJWKS fetches a JWKS from the given URL and returns the appropriate signing key for the token.
// This is used for verifying ID tokens from external identity providers.
func FetchJWKS(jwksURL string, token *jwt.Token) (interface{}, error) {
	// CRITICAL: Explicitly verify algorithm to prevent "none" algorithm attacks
	alg, ok := token.Header["alg"].(string)
	if !ok || alg == "" {
		return nil, fmt.Errorf("token missing alg header")
	}
	// Only allow RS256 algorithm
	if alg != "RS256" {
		return nil, fmt.Errorf("unexpected signing algorithm: %s (only RS256 is allowed)", alg)
	}
	// Verify signing method is RSA
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("token method is not RSA despite alg header")
	}

	kid, _ := token.Header["kid"].(string)

	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from %s: %w", jwksURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint %s returned status %d", jwksURL, resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	for _, key := range jwks.Keys {
		if key.Kty != "RSA" || key.Use != "sig" {
			continue
		}
		if kid != "" && key.Kid != kid {
			continue
		}
		pubKey, err := parseRSAPublicKey(key.N, key.E)
		if err != nil {
			continue
		}
		return pubKey, nil
	}

	return nil, fmt.Errorf("no matching RSA signing key found in JWKS")
}

// ResetCache drops the cached key set entirely, so the next lookup fetches.
//
// Exported because the callers of this package own the drills that prove the
// availability contract above, and a drill has to start from a known state.
// It is also the operation an install performs to make a key rotation take
// effect immediately rather than at the next TTL.
func ResetCache() {
	globalJWKSCache.mu.Lock()
	globalJWKSCache.keys = make(map[string]*rsa.PublicKey)
	globalJWKSCache.expiresAt = time.Time{}
	globalJWKSCache.lastRefreshOK = time.Time{}
	globalJWKSCache.mu.Unlock()
}

// ExpireCache marks the cached set past its freshness window WITHOUT dropping
// it: the next lookup takes the refresh path, and if that refresh fails the
// serve-stale belt can still engage. That distinction is the whole point of
// the belt, so a drill needs to be able to produce exactly this state.
func ExpireCache() {
	globalJWKSCache.mu.Lock()
	globalJWKSCache.expiresAt = time.Now().Add(-time.Second)
	globalJWKSCache.mu.Unlock()
}

// SetWindows overrides the freshness and max-stale windows and returns a
// function that restores the previous pair. Production reads them once from
// JWKS_TTL and JWKS_MAX_STALE; this exists so a drill can compress hours of
// staleness into a test that finishes.
func SetWindows(ttl, maxStale time.Duration) (restore func()) {
	oldTTL, oldStale := jwksTTL, jwksMaxStale
	jwksTTL, jwksMaxStale = ttl, maxStale
	return func() { jwksTTL, jwksMaxStale = oldTTL, oldStale }
}

// CachedJWKS returns the key set as a JWKS document, for a service that
// re-serves /.well-known/jwks.json in front of the issuer.
//
// It renders from the SAME cache the verification path reads, not from the
// bytes the issuer sent. That is deliberate: a tier that published a key it
// would not itself accept would be telling verifiers something its own
// introspection endpoint contradicts. fetchJWKS keeps only RSA keys marked
// use=sig that parse, so the document below is a subset of the issuer's --
// equal to it for OpenIDX's own issuer, which emits nothing else (see
// internal/oauth/signer.go refreshSigner), and deliberately smaller than a
// third-party issuer that published something this code cannot verify with.
//
// Same availability contract as SigningKey: fresh, else refresh, else serve
// stale within the max-stale window. A verifier polling this endpoint through
// an issuer outage keeps getting the keys that still verify live tokens.
func CachedJWKS(jwksURL string) (JWKS, error) {
	globalJWKSCache.mu.RLock()
	if time.Now().Before(globalJWKSCache.expiresAt) && len(globalJWKSCache.keys) > 0 {
		doc := renderJWKSLocked()
		globalJWKSCache.mu.RUnlock()
		return doc, nil
	}
	globalJWKSCache.mu.RUnlock()

	globalJWKSCache.mu.Lock()
	defer globalJWKSCache.mu.Unlock()

	if time.Now().Before(globalJWKSCache.expiresAt) && len(globalJWKSCache.keys) > 0 {
		return renderJWKSLocked(), nil
	}

	if err := refreshJWKSLocked(jwksURL); err != nil {
		if staleUsableLocked() {
			noteServeStaleLocked()
			return renderJWKSLocked(), nil
		}
		return JWKS{}, fmt.Errorf("JWKS refresh failed and no usable cached keys: %w", err)
	}
	return renderJWKSLocked(), nil
}

// renderJWKSLocked turns the cached public keys back into a JWKS document.
// Ordered by kid so the served bytes do not change between two requests that
// answer from the same key set -- a document that reshuffles on every request
// defeats every cache in front of it.
//
// MUST be called with the cache mutex held (read or write).
func renderJWKSLocked() JWKS {
	kids := make([]string, 0, len(globalJWKSCache.keys))
	for kid := range globalJWKSCache.keys {
		kids = append(kids, kid)
	}
	sort.Strings(kids)

	doc := JWKS{Keys: make([]JWKSKey, 0, len(kids))}
	for _, kid := range kids {
		pub := globalJWKSCache.keys[kid]
		doc.Keys = append(doc.Keys, JWKSKey{
			Kid: kid,
			Kty: "RSA",
			Alg: "RS256",
			Use: "sig",
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		})
	}
	return doc
}
