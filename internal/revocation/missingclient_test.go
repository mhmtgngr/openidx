package revocation

import (
	"context"
	"strings"
	"testing"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// A SEVER PATH WITH NO REDIS MUST REPORT THAT, NOT CRASH.
//
// Every caller of RevokeUserTokens reaches it through
// `s.redis.RevocationDB()`, an accessor documented as nil-safe: it returns a
// nil *redis.Client when the service has no Redis at all. That nil then travels
// into a redis.UniversalClient parameter, and THAT is where a nil stops looking
// like one -- an interface holding a typed nil pointer is not equal to nil, so
// the `client == nil` guard let it through and the next line called Set on a
// nil receiver.
//
// The result was a segmentation fault inside a request that was severing an
// account. That is strictly worse than the failure this package exists to fix:
// "the tokens were not cut" becomes "the sever never finished", and the account
// is left in whatever half-disabled state the panic interrupted.
//
// It reached CI as a nil-pointer panic in the identity lifecycle tenant
// isolation suite, from the disable_user branch of executeLifecycleAction --
// found by a test that was written to ask about tenant isolation and had no
// opinion about Redis at all.
func TestRevokeUserTokensRefusesANilClientWearingAnInterface(t *testing.T) {
	// Exactly what database.RedisClient.RevocationDB() returns when the service
	// holds no Redis. Spelled with the concrete type on purpose: writing
	// `var c redis.UniversalClient` instead would produce a TRUE nil interface
	// and test the guard that already worked.
	var fromAccessor *redis.Client

	err := RevokeUserTokens(context.Background(), fromAccessor, "user-with-no-redis")
	if err == nil {
		t.Fatal("a revoke with no usable Redis client reported success; the marker " +
			"was never written and the caller has nothing to log")
	}
}

// The callback form has the same parameter and the same trap, and it swallows
// its error by contract, so a panic here would be the only thing the caller
// ever saw. It must do nothing, loudly, and return.
func TestRevokerSurvivesANilClientWearingAnInterface(t *testing.T) {
	var fromAccessor *redis.Client

	revoke := Revoker(fromAccessor, zap.NewNop())
	revoke(context.Background(), "user-with-no-redis", "test")
}

// And the guard must not report a USABLE client as absent: noClient is checked
// on every revoke, so a false positive would silently turn every sever path in
// the product into a no-op that logs an error nobody reads as fatal.
func TestNoClientDoesNotRejectARealClient(t *testing.T) {
	// Not connected to anything -- constructing a client does not dial -- which
	// is the point: the question is whether the guard lets it through, and the
	// Set that follows fails with a connection error rather than a panic.
	c := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	defer c.Close()

	if noClient(c) {
		t.Fatal("a live client was reported absent; every sever path would stop writing markers")
	}

	// And the refusal it does produce must be the DIAL failing, not the guard:
	// both reach a caller as a non-nil error and they mean opposite things --
	// one says Redis is down, the other says this build cannot revoke at all.
	err := RevokeUserTokens(context.Background(), c, "u")
	if err == nil {
		t.Fatal("a Set against a port nothing listens on reported success")
	}
	if strings.Contains(err.Error(), "no redis client") {
		t.Fatalf("the guard rejected a usable client: %v", err)
	}
}
