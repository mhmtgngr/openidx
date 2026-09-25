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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// MarkerTTL bounds how long a marker lives. Seven days is comfortably longer
// than any access token this product mints (an hour by default), so a token
// that outlives its marker cannot exist; and it bounds memory at one short
// string per revoked user.
const MarkerTTL = 7 * 24 * time.Hour

// UserTokensRevokedAtKey is the Redis key recording the most recent "revoke
// everything for this user" timestamp. Any access token that dates from at or
// before the value at this key is revoked (Cutoff.Revokes).
func UserTokensRevokedAtKey(userID string) string {
	return "oauth:user_tokens_revoked_at:" + userID
}

// GrantedAtClaim is the private access-token claim that records, in
// microseconds since the epoch, when the authorization the token was minted
// from was granted -- for a token from the authorization-code grant, the moment
// the code was issued; for one from the refresh grant, the moment that grant
// began. It is never later than the token's own issue time.
//
// WHY IT EXISTS. The marker used to hold whole seconds and the comparison was
// `iat <= cutoff`, also in whole seconds, so that a token minted in the same
// second as a revocation could not survive it. The price was that a token
// minted in that second AFTER the revocation was refused too: somebody who
// signed out and straight back in inside one second got a token that
// /oauth/userinfo rejected, and the OpenID conformance suite, which starts its
// next test inside that second, met it on every logout. The issue time in the
// token (iat) is whole seconds by convention and cannot say which side of the
// cutoff it fell on; this claim can.
//
// A token without it -- every token an older release minted, and those from
// grants that do not stamp it -- is compared as before, at whole-second
// precision and conservatively (IssuedAt, Cutoff.Revokes).
const GrantedAtClaim = "granted_at_us"

// MarkerValue renders the marker for a moment in time: seconds since the epoch,
// a dot, and six digits of microseconds ("1727200000.123456"). ParseMarker
// reads it back, and also reads the whole-second form ("1727200000") that
// releases before this one wrote, so a marker already in Redis during an
// upgrade keeps working.
//
// An older oauth-service that reads the new form cannot parse it and fails
// closed: it refuses that user's tokens rather than serving them. That lasts
// until the service is upgraded, and only for users revoked meanwhile.
func MarkerValue(at time.Time) string {
	return fmt.Sprintf("%d.%06d", at.Unix(), at.Nanosecond()/int(time.Microsecond))
}

// Cutoff is a parsed marker: the last instant, in microseconds since the
// epoch, that it revokes. Tokens dating from that instant or earlier are
// revoked.
type Cutoff struct {
	lastRevokedMicros int64
}

// ParseMarker reads a stored marker. An unparseable value is an error rather
// than a zero: a zero would silently mean "nothing is revoked", which is the
// direction this control must never fail in by accident.
//
// A whole-second marker (written by a release before this one) says only that
// the revocation happened somewhere inside that second, so it revokes up to the
// END of the second -- exactly the reach the `<=` comparison on seconds had. A
// fractional marker revokes up to its own microsecond; digits past the sixth
// are dropped, which moves the cutoff earlier by less than a microsecond and
// is compared against token times truncated the same way (Revokes).
func ParseMarker(v string) (Cutoff, error) {
	if v == "" {
		return Cutoff{}, fmt.Errorf("empty revocation marker")
	}
	secPart, fracPart, fractional := strings.Cut(v, ".")
	sec, err := strconv.ParseInt(secPart, 10, 64)
	if err != nil {
		return Cutoff{}, fmt.Errorf("revocation marker %q is not a unix timestamp: %w", v, err)
	}
	if !fractional {
		return Cutoff{lastRevokedMicros: sec*1e6 + 999_999}, nil
	}
	if fracPart == "" || len(fracPart) > 9 || strings.Trim(fracPart, "0123456789") != "" {
		return Cutoff{}, fmt.Errorf("revocation marker %q has a malformed fraction", v)
	}
	micros, _ := strconv.ParseInt((fracPart + "000000")[:6], 10, 64)
	return Cutoff{lastRevokedMicros: sec*1e6 + micros}, nil
}

// IssuedAt is what an access token says about when it dates from.
type IssuedAt struct {
	// Seconds is the token's `iat` claim, seconds since the epoch.
	Seconds int64
	// GrantedMicros is the token's GrantedAtClaim, or 0 when it has none.
	GrantedMicros int64
}

// earliestMicros is the earliest instant the token may date from.
//
// Without GrantedAtClaim, the start of its `iat` second: the token was minted
// somewhere inside that second, and assuming the earliest point is what keeps
// a token that may have come before a revocation on the revoked side. With it,
// the claim -- unless the claim lies after the end of the `iat` second, which
// no minter here produces; a token that says so is read by its `iat` instead,
// never by the later of the two.
func (t IssuedAt) earliestMicros() int64 {
	start := t.Seconds * 1e6
	if t.GrantedMicros > 0 && t.GrantedMicros < start+1e6 {
		return t.GrantedMicros
	}
	return start
}

// Revokes reports whether a token that dates from t falls under this cutoff.
//
// The comparison is `<=`, not `<`: a token whose time equals the cutoff's, to
// the precision both carry, is revoked. With whole seconds on either side that
// is the old rule exactly -- a token minted in the same second as the
// revocation does not survive it, whichever came first. Only when BOTH sides
// carry microseconds does a token minted later in the same second survive, and
// then only because it provably came after.
func (c Cutoff) Revokes(t IssuedAt) bool {
	return t.Seconds > 0 && c.lastRevokedMicros > 0 && t.earliestMicros() <= c.lastRevokedMicros
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
	if noClient(client) {
		// The error does not name the user. Callers log it with the user's id
		// already attached, and an id copied into error text would reach the
		// log without the cleaning that field gets.
		return errors.New("no redis client: cannot revoke the user's tokens")
	}
	return client.Set(ctx, UserTokensRevokedAtKey(userID), MarkerValue(time.Now()), MarkerTTL).Err()
}

// noClient reports whether client is unusable -- nil, or a NIL POINTER WEARING
// AN INTERFACE.
//
// The second case is the one that matters here, and it is not hypothetical: it
// took down a test job. Every caller reaches this through
// `s.redis.RevocationDB()`, whose documented contract is that it is nil-safe
// and returns nil when there is no client. Its return type is the concrete
// *redis.Client, and assigning a nil *redis.Client to this redis.UniversalClient
// parameter produces an interface value that is NOT nil -- it carries the type
// and a nil pointer -- so `client == nil` is false and the very next line calls
// a method on a nil receiver and segfaults.
//
// A panic is the worst available outcome for a best-effort sever: this function
// exists so that a Redis that is missing or unreachable degrades into a logged
// error beside an account that is already disabled. Taking the process down
// instead turns "the tokens were not cut" into "the request that severed the
// account never finished", which is a strictly worse failure than the one this
// package was written to fix.
//
// Kind is checked before IsNil because IsNil itself panics on a kind that
// cannot be nil, and a client need not be a pointer -- a value type satisfying
// the interface is usable and must not be reported as absent.
func noClient(client redis.UniversalClient) bool {
	if client == nil {
		return true
	}
	v := reflect.ValueOf(client)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return v.IsNil()
	default:
		return false
	}
}

// Revoker returns the "cut this user's outstanding tokens" callback a service
// hands to a component that severs access but does not own a Redis client.
//
// WHY A CALLBACK RATHER THAN A CLIENT. internal/directory's sync engine
// disables accounts an HR feed or a directory says have gone, and it holds a
// database handle and a logger and nothing else. Giving it its own Redis client
// is how this product ended up with five hand-rolled copies of one sanitiser
// and, per this package's own doc, two spellings of this very marker -- one of
// which nothing read. One function, passed down, cannot drift from the other
// callers.
//
// It also forces the caller to pick the RIGHT Redis. The roles were split into
// three, and the enforcement point reads the revocation one: handing over a
// general client would write the marker where /oauth/userinfo never looks,
// which is exactly the defect this package was created to fix.
//
// Best-effort and loud, the contract every sever path in this product shares:
// the account is already disabled when this runs, so a Redis hiccup must not
// fail the sever, and "the tokens were not actually cut" belongs in the record.
// why names the path, so the line says which control left a live credential.
func Revoker(client redis.UniversalClient, logger *zap.Logger) func(ctx context.Context, userID, why string) {
	return func(ctx context.Context, userID, why string) {
		if noClient(client) || userID == "" {
			return
		}
		if err := RevokeUserTokens(ctx, client, userID); err != nil && logger != nil {
			logger.Error("account severed, but its outstanding access tokens were not revoked",
				zap.String("path", why), zap.String("user_id", userID), zap.Error(err))
		}
	}
}

// AccessTokenBlacklistKey is the Redis key for a single revoked access token,
// set by /oauth/revoke and by a single-session /oauth/logout. The token is
// hashed: the key space is readable by anyone with access to the Redis, and a
// bearer stored verbatim there would be a credential at rest.
//
// It lives here for the reason this package exists. The spelling used to be
// private to internal/oauth, which was correct for as long as the enforcement
// point and the revoking endpoint were the same process. They are not any more:
// ADR-2 splits a verification tier off that answers introspection without a
// database, and a tier computing this key for itself would be a second
// implementation of a revocation check -- the shape recorded at the top of this
// file, where a revocation is written to a key with no reader.
func AccessTokenBlacklistKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "oauth:revoked_access_token:" + hex.EncodeToString(sum[:])
}

// IsAccessTokenRevoked reports whether an access token has been revoked, by
// either of the two mechanisms this product has: the token's own blacklist
// entry, or the user's "revoke everything issued up to T" marker standing at or
// after the time the token dates from (Cutoff.Revokes).
//
// It takes the revocation Redis, not a general client. An error means the
// question could not be answered, and EVERY caller must fail closed on it --
// introspection answers active:false, the middleware refuses the bearer. A
// revocation check that cannot reach Redis and reports "not revoked" is the
// defect this package was written about: a control that returns success while
// the thing it is supposed to establish is unknown.
func IsAccessTokenRevoked(ctx context.Context, client redis.UniversalClient, token, userID string, issuedAt IssuedAt) (bool, error) {
	if noClient(client) {
		return false, fmt.Errorf("revocation redis not configured")
	}

	if n, err := client.Exists(ctx, AccessTokenBlacklistKey(token)).Result(); err != nil {
		return false, err
	} else if n > 0 {
		return true, nil
	}

	// The per-user marker only bears on a token that says who it is for and
	// when it was minted; without both there is nothing to compare.
	if userID == "" || issuedAt.Seconds <= 0 {
		return false, nil
	}
	v, err := client.Get(ctx, UserTokensRevokedAtKey(userID)).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	cutoff, perr := ParseMarker(v)
	if perr != nil {
		// An unreadable marker is not "no marker": somebody revoked, and the
		// record of it cannot be interpreted. Fail closed rather than serve a
		// token the install has already been told to stop honouring.
		return false, fmt.Errorf("unreadable revocation marker for user: %w", perr)
	}
	return cutoff.Revokes(issuedAt), nil
}
