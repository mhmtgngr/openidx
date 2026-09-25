package oauth

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/openidx/openidx/internal/revocation"
)

type grantedAtKey struct{}

// withGrantedAt tells GenerateJWT when the grant it is minting from was issued,
// so the access token can carry revocation.GrantedAtClaim. Two grants set it:
// the authorization-code grant, with the code's created_at, and the refresh
// grant, with the moment it began, since it checks the refresh token, its
// session and the user again then. A token minted without it carries no claim
// and is compared with the per-user revocation cutoff at whole-second
// precision, as every token was before the claim existed.
func withGrantedAt(ctx context.Context, at time.Time) context.Context {
	if at.IsZero() {
		return ctx
	}
	return context.WithValue(ctx, grantedAtKey{}, at)
}

func grantedAtFrom(ctx context.Context) (time.Time, bool) {
	at, ok := ctx.Value(grantedAtKey{}).(time.Time)
	return at, ok && !at.IsZero()
}

// tokenIssuedAt reads what a verified access token says about when it dates
// from: its `iat` and, when present, revocation.GrantedAtClaim.
func tokenIssuedAt(claims jwt.MapClaims) revocation.IssuedAt {
	var t revocation.IssuedAt
	if iat, ok := claims["iat"].(float64); ok {
		t.Seconds = int64(iat)
	}
	if us, ok := claims[revocation.GrantedAtClaim].(float64); ok && us > 0 {
		t.GrantedMicros = int64(us)
	}
	return t
}
