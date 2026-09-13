package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// A TENANT COST BUDGET: A SHEDDING ORDER, NOT AN ACCOUNTING SYSTEM.
//
// The limiter above this one counts REQUESTS, and a request is not a unit of
// anything. Measured on this codebase, against pwhash.Default (Argon2id,
// m=19456 KiB, t=2):
//
//	password verification   37.3 ms   19,926,087 B allocated
//	a JWKS response          6.0 µs          540 B allocated
//
// Six thousand times the CPU and thirty-seven thousand times the memory, on
// the same axis a per-IP counter treats as one tick each. The memory is the
// dangerous half: a hundred concurrent logins hold two gigabytes of Argon2
// scratch, which is how a pod OOMs while its request rate looks unremarkable.
//
// WHAT THIS IS NOT. Those numbers do not become the weights. A ratio-true
// table would make one login worth six thousand JWKS reads, the budget would
// be spent entirely by the credential class, and the mechanism would be a
// login limiter with extra arithmetic -- which is exactly what the auth tier
// already is. The weights here are ORDINAL: 1, 2, 5, 10 rank the classes and
// nothing more. The measurement decides the ORDER and says the gaps are real;
// it does not decide the integers.
//
// WHAT IT IS. A priority for shedding. When a tenant has spent its budget, the
// expensive classes are refused and the cheap ones keep flowing. That is a
// different guarantee from "the tenant is cut off", and it is the one worth
// having: a tenant flooding /oauth/token gets 429s on /oauth/token while its
// relying parties still fetch JWKS and still verify the tokens they already
// hold. Cutting the tenant off entirely would turn one team's load test into
// an authentication outage for every application they run.
//
// WHY THE CHEAP CLASS IS NEVER SHED, AND NEVER SPENDS. Cost-1 routes are the
// ones whose cost is dominated by the HTTP round trip itself -- discovery,
// JWKS, an out-of-band status poll. Refusing them saves the server nothing
// measurable and costs every downstream verifier its key material. They are
// also exempt from SPENDING, for two reasons: a Redis round trip on the JWKS
// path would cost more than serving it, and if a dashboard's polling could
// spend the budget then a tenant's own console could shed that tenant's
// logins. Bounding cheap traffic is the request counter's job, and it already
// does it.
//
// FAIL OPEN. This is a capacity control, not a security control. The auth tier
// fails closed because brute-force protection must not vanish with a cache;
// this fails open because refusing every expensive request fleet-wide during a
// Redis blip IS the outage it exists to prevent (see ratelimit_fallback.go for
// the same argument from the other side).
//
// KNOWN GAP. The admission gate in admission.go bounds concurrency uniformly:
// a slot is a slot, whether it holds 19.9 MB of Argon2 or 540 bytes of JSON.
// A MaxInflight sized against the cheap case will still OOM on the expensive
// one. Making a slot cost what the route costs is the obvious next step and is
// deliberately not taken here -- it changes the gate's fast path, and this
// mechanism needs to be measured in observe mode before anything is built on
// its numbers.

// CostMode selects what the budget does when it is exhausted.
type CostMode string

const (
	// CostModeOff does not account at all: no Redis call, no metrics, no
	// decision. The default, so wiring this in changes nothing.
	CostModeOff CostMode = "off"
	// CostModeObserve accounts and reports what it WOULD refuse, and refuses
	// nothing. This is how a budget gets sized: run it for a week, read
	// openidx_ratelimit_cost_rejected_total, and find out whether the number
	// you guessed would have cut off a real tenant.
	CostModeObserve CostMode = "observe"
	// CostModeEnforce refuses the expensive classes over budget.
	CostModeEnforce CostMode = "enforce"
)

// ParseCostMode reads RATELIMIT_COST_MODE. An unrecognised value is an error
// rather than a silent fallback to off: "costmode=enfroce" must not look like
// a working enforcement.
func ParseCostMode(v string) (CostMode, error) {
	switch m := CostMode(strings.ToLower(strings.TrimSpace(string(v)))); m {
	case "", CostModeOff:
		return CostModeOff, nil
	case CostModeObserve, CostModeEnforce:
		return m, nil
	default:
		return "", fmt.Errorf("unknown RATELIMIT_COST_MODE %q: want one of %q, %q, %q",
			v, CostModeOff, CostModeObserve, CostModeEnforce)
	}
}

// The cost classes. Ordinal, not proportional -- see the header.
const (
	// CostCheap is dominated by the round trip: discovery, JWKS, a status
	// poll. Never shed, never spends.
	CostCheap = 1
	// CostStandard is a DB lookup and maybe a signature check: introspection,
	// userinfo, revocation, consent.
	CostStandard = 2
	// CostCredential runs a KDF or a WebAuthn/PKI operation and writes: the
	// token endpoint, every login and second-factor step, magic links,
	// passkeys, client registration.
	CostCredential = 5
	// CostBulk scans or aggregates over a tenant's history, or fans out over
	// its whole directory: analytics, reports, exports, bulk operations,
	// attestation campaigns, SCIM bulk.
	CostBulk = 10
)

type costRule struct {
	// method "" matches any method. A method-specific rule beats a wildcard
	// rule at the same prefix.
	method string
	prefix string
	cost   int
}

// routeCosts ranks the routes that are not ordinary. Anything unlisted is
// CostCheap, which is the safe default for a shedder: an unclassified route is
// never refused. Observe mode is how the list grows -- it shows which unlisted
// routes carry real load.
//
// Prefixes match ELEMENT-WISE, not as strings: "/oauth/token" covers
// "/oauth/token" and "/oauth/token/anything" and never "/oauth/token-exchange".
// The identity plane rules learned this the hard way against Kubernetes Ingress
// (see internal/identity/profile.go); a new sibling route must not inherit a
// neighbour's cost by spelling.
var routeCosts = []costRule{
	// -- Cheap, listed so the decision is recorded rather than inherited from
	// the default. Shedding these breaks token verification for every relying
	// party in the tenant and saves the server nothing.
	{prefix: "/.well-known", cost: CostCheap},
	{prefix: "/protocol/openid-connect/certs", cost: CostCheap},

	// -- Credential: a KDF, a signature, or both, plus writes.
	{method: http.MethodPost, prefix: "/oauth/token", cost: CostCredential},
	{method: http.MethodPost, prefix: "/oauth/login", cost: CostCredential},
	{method: http.MethodPost, prefix: "/oauth/force-login", cost: CostCredential},
	{method: http.MethodPost, prefix: "/oauth/native/login-init", cost: CostCredential},
	{method: http.MethodPost, prefix: "/oauth/mfa-verify", cost: CostCredential},
	{method: http.MethodPost, prefix: "/oauth/mfa-send-otp", cost: CostCredential},
	{method: http.MethodPost, prefix: "/oauth/mfa-webauthn-begin", cost: CostCredential},
	{method: http.MethodPost, prefix: "/oauth/mfa-push-begin", cost: CostCredential},
	{method: http.MethodPost, prefix: "/oauth/passwordless/phone/init", cost: CostCredential},
	{method: http.MethodPost, prefix: "/oauth/stepup-challenge", cost: CostCredential},
	{method: http.MethodPost, prefix: "/oauth/stepup-verify", cost: CostCredential},
	{method: http.MethodPost, prefix: "/oauth/magic-link", cost: CostCredential},
	{method: http.MethodPost, prefix: "/oauth/magic-link-verify", cost: CostCredential},
	{method: http.MethodPost, prefix: "/oauth/passkey-begin", cost: CostCredential},
	{method: http.MethodPost, prefix: "/oauth/passkey-finish", cost: CostCredential},
	{method: http.MethodPost, prefix: "/oauth/qr-login/create", cost: CostCredential},
	{method: http.MethodPost, prefix: "/oauth/device_authorization", cost: CostCredential},
	{method: http.MethodPost, prefix: "/oauth/register", cost: CostCredential},
	{prefix: "/oauth/authorize", cost: CostCredential},
	{method: http.MethodPost, prefix: "/oauth/logout-all", cost: CostCredential},
	{method: http.MethodPost, prefix: "/api/v1/identity/users/login", cost: CostCredential},
	{method: http.MethodPost, prefix: "/api/v1/identity/users/forgot-password", cost: CostCredential},
	{method: http.MethodPost, prefix: "/api/v1/identity/users/reset-password", cost: CostCredential},

	// -- Standard: a lookup, maybe a signature check, no KDF.
	{prefix: "/oauth/introspect", cost: CostStandard},
	{prefix: "/oauth/userinfo", cost: CostStandard},
	{prefix: "/oauth/revoke", cost: CostStandard},
	{prefix: "/oauth/consent", cost: CostStandard},
	{prefix: "/oauth/session-info", cost: CostStandard},
	{method: http.MethodPost, prefix: "/oauth/logout", cost: CostStandard},

	// -- Bulk: aggregates over history, or a fan-out over the directory.
	{prefix: "/api/v1/analytics", cost: CostBulk},
	{prefix: "/api/v1/reports", cost: CostBulk},
	{prefix: "/api/v1/bulk-operations", cost: CostBulk},
	{prefix: "/api/v1/users/export", cost: CostBulk},
	{prefix: "/api/v1/users/search", cost: CostBulk},
	{prefix: "/api/v1/audit/reports", cost: CostBulk},
	{prefix: "/api/v1/audit/events/search", cost: CostBulk},
	{prefix: "/api/v1/audit/unified/sync", cost: CostBulk},
	{prefix: "/api/v1/governance/campaigns", cost: CostBulk},
	{prefix: "/api/v1/governance/attestation-campaigns", cost: CostBulk},
	{prefix: "/api/v1/provisioning/scim/v2/Bulk", cost: CostBulk},
}

// costPathMatches is element-wise prefix matching: the prefix must end on a
// path separator, not mid-segment.
func costPathMatches(prefix, path string) bool {
	p := strings.TrimSuffix(prefix, "/")
	return path == p || strings.HasPrefix(path, p+"/")
}

// RouteCost returns what this request costs the platform, in the ordinal units
// above. Longest matching prefix wins; at equal length a method-specific rule
// beats a wildcard one. Unlisted is CostCheap.
func RouteCost(method, path string) int {
	cost := CostCheap
	bestLen := -1
	bestSpecific := false
	for _, r := range routeCosts {
		if r.method != "" && r.method != method {
			continue
		}
		if !costPathMatches(r.prefix, path) {
			continue
		}
		n := len(strings.TrimSuffix(r.prefix, "/"))
		specific := r.method != ""
		if n > bestLen || (n == bestLen && specific && !bestSpecific) {
			cost, bestLen, bestSpecific = r.cost, n, specific
		}
	}
	return cost
}

// CostConfig configures the per-tenant budget.
type CostConfig struct {
	// Mode is off (default), observe or enforce.
	Mode CostMode
	// Budget is the cost units one tenant may spend per window. Zero disables
	// the limiter however Mode is set: a budget nobody has sized is a guess,
	// and a guessed budget is an outage.
	Budget int
	// Window is the accounting window. Defaults to a minute.
	Window time.Duration
	// AlwaysAdmit is the cost at or below which a request is neither charged
	// nor refused. Defaults to CostCheap. Raising it widens the class that
	// survives a flood; setting it at or above CostBulk disables shedding
	// entirely, which the constructor refuses to do silently.
	AlwaysAdmit int
	// RetryAfter is what a refused caller is told. Defaults to the remaining
	// window, which is when the budget actually resets -- a shorter promise
	// invites a retry that cannot succeed.
	RetryAfter time.Duration
}

// TenantCostLimit returns a per-tenant cost budget. Off, unbudgeted, or with
// no Redis it is a pass-through.
func TenantCostLimit(redisClient *redis.Client, cfg CostConfig, logger *zap.Logger) gin.HandlerFunc {
	passthrough := func(c *gin.Context) { c.Next() }

	if cfg.Mode == "" {
		cfg.Mode = CostModeOff
	}
	if cfg.Mode == CostModeOff {
		return passthrough
	}
	if cfg.Budget <= 0 {
		logger.Warn("Tenant cost budget is enabled but unsized; no cost accounting will happen",
			zap.String("mode", string(cfg.Mode)))
		return passthrough
	}
	if redisClient == nil {
		// Not fatal: the cost budget is a capacity control, and a deployment
		// without the rate-limit Redis has already accepted that its counters
		// do not exist. It must not be silent, though.
		logger.Warn("Tenant cost budget is enabled but has no Redis; nothing will be accounted",
			zap.String("mode", string(cfg.Mode)))
		return passthrough
	}
	if cfg.Window <= 0 {
		cfg.Window = time.Minute
	}
	if cfg.AlwaysAdmit <= 0 {
		cfg.AlwaysAdmit = CostCheap
	}
	if cfg.AlwaysAdmit >= CostBulk {
		logger.Warn("Tenant cost budget admits every class unconditionally; nothing can be shed",
			zap.Int("always_admit", cfg.AlwaysAdmit), zap.Int("bulk_cost", CostBulk))
	}

	l := &costLimiter{cfg: cfg, rdb: redisClient, logger: logger, skip: map[string]bool{}}
	for _, p := range skipPaths { // /health, /metrics, /ready
		l.skip[p] = true
	}
	return l.handle
}

type costLimiter struct {
	cfg    CostConfig
	rdb    *redis.Client
	logger *zap.Logger
	skip   map[string]bool
}

func (l *costLimiter) handle(c *gin.Context) {
	path := c.Request.URL.Path
	if l.skip[path] || isPollPath(path) {
		c.Next()
		return
	}

	cost := RouteCost(c.Request.Method, path)
	if cost <= l.cfg.AlwaysAdmit {
		// Not charged and not refused -- and, deliberately, not a Redis call.
		c.Next()
		return
	}

	// Tenants are separate budgets. Traffic with no resolved tenant shares one
	// "_" budget rather than being exempt: an exemption would make evasion a
	// matter of omitting a header.
	orgSeg := "_"
	if org, err := orgctx.From(c.Request.Context()); err == nil && org.ID != "" {
		orgSeg = org.ID
	}

	windowSecs := int64(l.cfg.Window.Seconds())
	epoch := time.Now().Unix() / windowSecs
	key := fmt.Sprintf("ratelimit:cost:%s:%d", orgSeg, epoch)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 200*time.Millisecond)
	defer cancel()

	after, err := l.rdb.IncrBy(ctx, key, int64(cost)).Result()
	if err != nil {
		rlCostFailOpenTotal.Inc()
		l.logger.Warn("Tenant cost budget Redis error, failing open",
			zap.Error(err), logsafe.String("key", key))
		c.Next()
		return
	}
	if after == int64(cost) {
		l.rdb.Expire(ctx, key, l.cfg.Window+time.Second)
	}

	// The decision is taken on the spend BEFORE this request, so the request
	// that crosses the line is served: the budget is a threshold, not a
	// ceiling, and an off-by-one here would refuse the first expensive request
	// of a tenant whose budget is exactly one request wide.
	//
	// Concurrent requests can both read a "before" under the budget and both
	// be admitted. That overshoot is bounded by the concurrency, and closing
	// it would need a Lua round trip on every expensive request to buy a
	// guarantee nobody needs: this is a shedder, not a quota.
	before := after - int64(cost)
	remaining := int64(l.cfg.Budget) - after
	if remaining < 0 {
		remaining = 0
	}
	c.Header("X-RateLimit-Cost", strconv.Itoa(cost))
	c.Header("X-RateLimit-Cost-Budget", strconv.Itoa(l.cfg.Budget))
	c.Header("X-RateLimit-Cost-Remaining", strconv.FormatInt(remaining, 10))

	if before < int64(l.cfg.Budget) {
		rlCostSpentTotal.Add(float64(cost))
		c.Next()
		return
	}

	// Over budget. Give the units back, so the counter measures work ADMITTED
	// rather than work attempted: a sustained flood would otherwise drive the
	// counter to a number that says nothing about what the platform actually
	// did, and would keep the tenant shed for the rest of the window even
	// after the flood stopped.
	l.rdb.DecrBy(ctx, key, int64(cost))

	costLabel := strconv.Itoa(cost)
	if l.cfg.Mode == CostModeObserve {
		rlCostRejectedTotal.WithLabelValues(string(CostModeObserve), costLabel).Inc()
		c.Header("X-RateLimit-Cost-Exceeded", "1")
		c.Next()
		return
	}

	rlCostRejectedTotal.WithLabelValues(string(CostModeEnforce), costLabel).Inc()
	c.Header("Retry-After", strconv.FormatInt(l.retryAfterSeconds(windowSecs), 10))
	c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
		"error":             "cost_budget_exceeded",
		"error_description": "This tenant has spent its request-cost budget for the current window. Cheaper endpoints are unaffected; retry after the interval in the Retry-After header.",
	})
}

// retryAfterSeconds is the time left in the window, which is when the budget
// actually resets. A fixed shorter value would send the caller back before
// anything could have changed.
func (l *costLimiter) retryAfterSeconds(windowSecs int64) int64 {
	if l.cfg.RetryAfter > 0 {
		return int64(l.cfg.RetryAfter.Seconds())
	}
	left := windowSecs - (time.Now().Unix() % windowSecs)
	if left < 1 {
		left = 1
	}
	return left
}
