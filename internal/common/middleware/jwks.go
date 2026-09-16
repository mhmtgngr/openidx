package middleware

import (
	"github.com/golang-jwt/jwt/v5"

	"github.com/openidx/openidx/internal/common/jwksverify"
)

// The JWKS cache and the bearer-verification path moved to
// internal/common/jwksverify so that a binary which only verifies tokens does
// not link a PostgreSQL driver: this package also holds PermissionResolver and
// RequireFreshMFA, which read tenant-scoped tables, and their pgx import
// reached every service that merely called Auth().
//
// These are aliases, not a second implementation. Every existing caller keeps
// working unchanged, and there is still exactly one key cache in the process.

// JWKSKey is a single key from a JWKS document.
type JWKSKey = jwksverify.JWKSKey

// JWKS is a JSON Web Key Set.
type JWKS = jwksverify.JWKS

// VerifyBearerToken validates a bearer JWT against the OAuth JWKS and returns
// its claims. See jwksverify.VerifyBearerToken for the guarantees it enforces.
func VerifyBearerToken(jwksURL, tokenString string) (map[string]interface{}, error) {
	return jwksverify.VerifyBearerToken(jwksURL, tokenString)
}

// FetchJWKS resolves the signing key for a token against a remote JWKS. Used
// for ID tokens from external identity providers.
func FetchJWKS(jwksURL string, token *jwt.Token) (interface{}, error) {
	return jwksverify.FetchJWKS(jwksURL, token)
}
