// Package revocation holds the one definition of the "revoke everything this
// user holds" marker: its Redis key, its value, and how long it lives.
//
// THE SHAPE IT REPLACES. There were two.
//
// internal/oauth writes oauth:user_tokens_revoked_at:<uid> on /oauth/logout-all
// and reads it in IsAccessTokenRevoked, where a token whose `iat` is at or
// before the marker is refused. That is the enforcement point, and it works.
//
// internal/governance wrote auth:user_revoked:<uid> from killUserSessions,
// which the comment above it describes as "the user-wide token-revocation
// marker the auth middleware checks, so a live session cannot keep using access
// an access review just revoked". It is called from two places: when a reviewer
// revokes access in a certification campaign, and from the SoD remediation
// path. The key format came from internal/auth's TokenService -- and NO BINARY
// EVER REACHED TokenService, so nothing in the product has ever read that key.
//
// So an access review could revoke somebody's access and their live session and
// outstanding access tokens kept working until they expired on their own. The
// revocation was recorded, the audit said it happened, the access survived. The
// reviewer had no way to know: the marker was written successfully, to a key
// with no reader.
//
// Neither half was obviously wrong on its own. Each was a correct
// implementation of a contract the other did not share, and the shared piece --
// the key -- lived in unreachable code, where it looked authoritative.
//
// So it lives here now, in a package small enough that both sides import it and
// neither can drift. Changing the key means changing it once, and the test in
// internal/oauth that drives a governance-shaped write through
// IsAccessTokenRevoked fails if the two ever separate again.
package revocation

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// MarkerTTL bounds how long a marker lives. Seven days is comfortably longer
// than any access token this product mints (an hour by default), so a token
// that outlives its marker cannot exist; and it bounds memory at one short
// string per revoked user.
const MarkerTTL = 7 * 24 * time.Hour

// UserTokensRevokedAtKey is the Redis key recording the most recent "revoke
// everything for this user" timestamp. Any access token whose `iat` is at or
// before the value at this key is revoked.
func UserTokensRevokedAtKey(userID string) string {
	return "oauth:user_tokens_revoked_at:" + userID
}

// MarkerValue renders the marker for a moment in time. It is seconds since the
// epoch as a decimal string, which is what ParseMarker reads back and what the
// `iat` claim is measured in -- comparing them needs no conversion and no
// timezone.
func MarkerValue(at time.Time) string {
	return strconv.FormatInt(at.Unix(), 10)
}

// ParseMarker reads a stored marker. An unparseable value is an error rather
// than a zero: a zero would silently mean "nothing is revoked", which is the
// direction this control must never fail in by accident.
func ParseMarker(v string) (int64, error) {
	if v == "" {
		return 0, fmt.Errorf("empty revocation marker")
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("revocation marker %q is not a unix timestamp: %w", v, err)
	}
	return n, nil
}

// RevokeUserTokens writes the cutoff that stops every access token this user
// already holds.
//
// THE HALF THIS PACKAGE HAD NOT REACHED YET. When it was written, the divergence
// it fixed was between two spellings of the key. The other half of the same
// defect is a path that severs a user's access and never writes the marker at
// all -- and the sever paths were exactly that. deprovisionUser (identity and
// provisioning) and the access-service kill switch each collected the user's
// live session ids and published `revoked_session:<id>`, which the REFRESH grant
// honours. Nothing they wrote was read by /oauth/userinfo or /oauth/introspect,
// because those two consult this marker and the per-token blacklist and nothing
// else. So an administrator disabling a leaver, or firing the kill switch on a
// compromised account, cut the refresh -- and the access token already in that
// browser kept answering for the rest of its hour.
//
// Which put the controls in the wrong order: an access-review revocation, the
// slowest and least urgent of them, killed outstanding tokens; the kill switch,
// the one you reach for when an account is compromised, did not.
//
// Best-effort by contract, like the callers: the account is already disabled and
// the sessions already revoked when this runs, so a Redis hiccup must not fail
// the request that did the severing. It returns the error for the caller to log
// rather than swallowing it, because "the tokens were not actually cut" is
// something an operator needs in the record.
func RevokeUserTokens(ctx context.Context, client redis.UniversalClient, userID string) error {
	if client == nil {
		return fmt.Errorf("no redis client: cannot revoke tokens for user %s", userID)
	}
	return client.Set(ctx, UserTokensRevokedAtKey(userID), MarkerValue(time.Now()), MarkerTTL).Err()
}

// IsRevoked reports whether a token issued at issuedAt (seconds since the
// epoch) falls under a marker set at cutoff.
//
// The comparison is `<=`, not `<`, deliberately: a token minted in the same
// wall-clock second as the revocation must not survive it. Redis stores seconds,
// so a strict comparison would leave a one-second window in which a token
// issued at the moment somebody said "revoke everything" keeps working.
func IsRevoked(issuedAt, cutoff int64) bool {
	return issuedAt > 0 && cutoff > 0 && issuedAt <= cutoff
}
