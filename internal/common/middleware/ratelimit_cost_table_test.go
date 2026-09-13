package middleware

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The table is data, and data rots silently. These tests are about the table
// itself rather than the middleware: a rule that can never win, two rules that
// disagree, or a cost that drifts out of step with the auth tier are all
// invisible at runtime -- the limiter keeps working and sheds the wrong thing.

func TestNoTwoRulesClaimTheSameRoute(t *testing.T) {
	seen := map[string]costRule{}
	for _, r := range routeCosts {
		k := r.method + " " + r.prefix
		prev, dup := seen[k]
		require.False(t, dup, "duplicate rule for %q: cost %d and %d", k, prev.cost, r.cost)
		seen[k] = r
	}
}

// A shadowed rule is a decision someone wrote down that never takes effect.
func TestEveryRuleCanWin(t *testing.T) {
	// Methods a wildcard rule could be probed with, minus any that a
	// method-specific rule at the same prefix has already claimed.
	candidates := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch}

	for _, r := range routeCosts {
		method := r.method
		if method == "" {
			claimed := map[string]bool{}
			for _, other := range routeCosts {
				if other.prefix == r.prefix && other.method != "" {
					claimed[other.method] = true
				}
			}
			for _, m := range candidates {
				if !claimed[m] {
					method = m
					break
				}
			}
			require.NotEmpty(t, method, "wildcard rule %q is claimed by a specific rule for every method", r.prefix)
		}
		assert.Equal(t, r.cost, RouteCost(method, r.prefix),
			"rule %q %q (cost %d) never wins", r.method, r.prefix, r.cost)
	}
}

// Prefixes match element-wise. The pairs below are the ones where string
// prefixing would actually change an answer, and /oauth/logout is the sharp
// one: string matching would make a session logout cost what a fan-out
// revocation of every session costs.
func TestPrefixesDoNotBleedIntoSiblingRoutes(t *testing.T) {
	assert.Equal(t, CostStandard, RouteCost(http.MethodPost, "/oauth/logout"))
	assert.Equal(t, CostCredential, RouteCost(http.MethodPost, "/oauth/logout-all"))

	assert.Equal(t, CostCredential, RouteCost(http.MethodPost, "/oauth/token"))
	assert.Equal(t, CostCheap, RouteCost(http.MethodPost, "/oauth/token-exchange"),
		"an unlisted sibling is unclassified, which means cheap -- never the neighbour's cost by spelling")

	// A route UNDER a listed prefix does inherit it, which is the point of a
	// prefix: /oauth/authorize/v2 is the same work as /oauth/authorize.
	assert.Equal(t, CostCredential, RouteCost(http.MethodGet, "/oauth/authorize/v2"))
	assert.Equal(t, CostBulk, RouteCost(http.MethodGet, "/api/v1/analytics/predictions/capacity"))
}

// The auth tier and the cost table both answer "is this route expensive", from
// two different lists. They must not disagree: a path strict enough to fail
// closed on a Redis outage is not a path that can be cost 1.
func TestEveryAuthTierPathIsAtLeastCredentialCost(t *testing.T) {
	for _, p := range authPaths {
		assert.GreaterOrEqual(t, RouteCost(http.MethodPost, p), CostCredential,
			"%q is strict enough for the auth tier but is not ranked expensive", p)
	}
}

// Status polls are exempt, and it matters that they are exempt for the same
// reason they are exempt from the per-IP counter: they are a login already in
// progress, waiting on a human to tap approve. Shedding one abandons work the
// platform has already paid for.
func TestStatusPollsAreNeverShed(t *testing.T) {
	for _, p := range pollPaths {
		probe := p + "abc123"
		require.True(t, isPollPath(probe), "%q should be recognised as a poll", probe)
		assert.LessOrEqual(t, RouteCost(http.MethodGet, probe), CostCheap,
			"%q must also rank cheap, so it stays exempt if the poll list ever changes", probe)
	}
}

// Unlisted is cheap, deliberately: a shedder that refuses what it has not
// classified refuses at random.
func TestUnclassifiedRoutesAreCheap(t *testing.T) {
	assert.Equal(t, CostCheap, RouteCost(http.MethodGet, "/api/v1/identity/users/00000000-0000-0000-0000-000000000000"))
	assert.Equal(t, CostCheap, RouteCost(http.MethodGet, "/"))
	assert.Equal(t, CostCheap, RouteCost(http.MethodGet, "/.well-known/jwks.json"))
}
