package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// costKeyFor rebuilds the key the limiter writes, so the tests can read the
// counter back rather than infer it from status codes.
func costKeyFor(orgID string) string {
	return fmt.Sprintf("ratelimit:cost:%s:%d", orgID, time.Now().Unix()/60)
}

func costRouter(t *testing.T, rdb *redis.Client, cfg CostConfig) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(TenantCostLimit(rdb, cfg, zap.NewNop()))
	r.Any("/*any", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

func costRedis(t *testing.T) *redis.Client {
	t.Helper()
	mini, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mini.Close)
	c := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// asOrg issues one request carrying a resolved tenant, the way the tenant
// resolver middleware leaves it.
func asOrg(r *gin.Engine, method, path, orgID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req = req.WithContext(orgctx.With(req.Context(), orgctx.Org{ID: orgID, Slug: orgID}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// THE ACCEPTANCE CRITERION, stated in the plan as: a token flood exhausts the
// tenant's budget while that same tenant's cheap reads are unaffected, and a
// neighbouring tenant is never affected.
//
// All three halves are asserted in one walk, because they are one property:
// what the budget sheds is a CLASS of work belonging to ONE tenant.
func TestACostBudgetShedsTheFloodAndNothingElse(t *testing.T) {
	rdb := costRedis(t)
	// 50 units = ten /oauth/token requests at CostCredential.
	r := costRouter(t, rdb, CostConfig{Mode: CostModeEnforce, Budget: 50, Window: time.Minute})

	const noisy, quiet = "org-noisy", "org-quiet"

	admitted, refused := 0, 0
	for i := 0; i < 40; i++ {
		if asOrg(r, http.MethodPost, "/oauth/token", noisy).Code == http.StatusOK {
			admitted++
		} else {
			refused++
		}

		// Interleaved, every iteration: the flooding tenant's own cheap reads,
		// and the neighbour's expensive ones. Interleaving matters -- checking
		// them only after the flood would not show that they kept working
		// DURING it.
		assert.Equal(t, http.StatusOK, asOrg(r, http.MethodGet, "/.well-known/jwks.json", noisy).Code,
			"the flooding tenant's own JWKS must keep working: its relying parties still have tokens to verify")
		assert.Equal(t, http.StatusOK, asOrg(r, http.MethodGet, "/.well-known/openid-configuration", noisy).Code,
			"discovery is cost 1 and must never be shed")
		// The neighbour, meanwhile, behaves like an ordinary tenant: eight
		// logins over the window, well inside its own budget. That is the
		// tenant whose experience must not change.
		if i%5 == 0 {
			assert.Equal(t, http.StatusOK, asOrg(r, http.MethodPost, "/oauth/token", quiet).Code,
				"a neighbouring tenant must never pay for this flood")
		}
	}

	assert.Equal(t, 10, admitted, "50 units of budget is exactly ten CostCredential requests")
	assert.Equal(t, 30, refused)

	// 8 logins at 5 units each, none refused -- which only holds because the
	// neighbour's budget is its own key.
	assert.Equal(t, "40", rdb.Get(t.Context(), costKeyFor(quiet)).Val())
}

// The refund is what makes the counter mean "work admitted". Without it a
// flood drives the key far past the budget and the tenant stays shed for the
// rest of the window after the flood has stopped.
func TestRefusedWorkIsNotCharged(t *testing.T) {
	rdb := costRedis(t)
	r := costRouter(t, rdb, CostConfig{Mode: CostModeEnforce, Budget: 50, Window: time.Minute})

	for i := 0; i < 100; i++ {
		asOrg(r, http.MethodPost, "/oauth/token", "org-a")
	}
	assert.Equal(t, "50", rdb.Get(t.Context(), costKeyFor("org-a")).Val(),
		"100 requests against a 50-unit budget must leave 50 units spent, not 500")
}

// Observe mode is how a budget gets sized. It must account and report exactly
// what enforcement would refuse, and refuse nothing.
func TestObserveModeReportsWithoutRefusing(t *testing.T) {
	rdb := costRedis(t)
	r := costRouter(t, rdb, CostConfig{Mode: CostModeObserve, Budget: 10, Window: time.Minute})

	exceeded := 0
	for i := 0; i < 10; i++ {
		w := asOrg(r, http.MethodPost, "/oauth/token", "org-a")
		require.Equal(t, http.StatusOK, w.Code, "observe mode must never refuse")
		if w.Header().Get("X-RateLimit-Cost-Exceeded") == "1" {
			exceeded++
		}
	}
	assert.Equal(t, 8, exceeded, "two requests fit in 10 units; the other eight are what enforcement would have refused")
}

// Off is the default and must not even reach Redis: a mechanism that is off
// should cost nothing at all, including a round trip on the token path.
func TestOffModeTouchesNothing(t *testing.T) {
	mini, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mini.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	r := costRouter(t, rdb, CostConfig{Mode: CostModeOff, Budget: 1, Window: time.Minute})
	for i := 0; i < 20; i++ {
		require.Equal(t, http.StatusOK, asOrg(r, http.MethodPost, "/oauth/token", "org-a").Code)
	}
	assert.Empty(t, mini.Keys(), "off must not write a counter")
}

// Cheap routes are exempt from SPENDING, not merely from refusal. A dashboard
// polling a cost-1 endpoint must not be able to shed its own tenant's logins,
// and JWKS must not pay for a Redis round trip.
func TestCheapRoutesNeverSpendTheBudget(t *testing.T) {
	mini, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mini.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	r := costRouter(t, rdb, CostConfig{Mode: CostModeEnforce, Budget: 10, Window: time.Minute})
	for i := 0; i < 500; i++ {
		require.Equal(t, http.StatusOK, asOrg(r, http.MethodGet, "/.well-known/jwks.json", "org-a").Code)
	}
	assert.Empty(t, mini.Keys(), "500 cheap requests must leave no counter at all")

	// And the expensive class is still fully available afterwards.
	require.Equal(t, http.StatusOK, asOrg(r, http.MethodPost, "/oauth/token", "org-a").Code)
}

// Losing the rate-limit Redis must not refuse expensive work: this is a
// capacity control, and failing closed here would be the outage.
func TestCostBudgetFailsOpen(t *testing.T) {
	mini, err := miniredis.Run()
	require.NoError(t, err)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr(), MaxRetries: 0})
	t.Cleanup(func() { _ = rdb.Close() })

	r := costRouter(t, rdb, CostConfig{Mode: CostModeEnforce, Budget: 5, Window: time.Minute})
	require.Equal(t, http.StatusOK, asOrg(r, http.MethodPost, "/oauth/token", "org-a").Code)
	mini.Close()

	for i := 0; i < 5; i++ {
		assert.Equal(t, http.StatusOK, asOrg(r, http.MethodPost, "/oauth/token", "org-a").Code,
			"with no limiter backend the expensive path stays open")
	}
}

// A refused caller is told when the budget actually resets. A shorter promise
// sends it back before anything can have changed, which turns one refusal into
// a retry loop.
func TestRetryAfterPointsAtTheWindowReset(t *testing.T) {
	rdb := costRedis(t)
	r := costRouter(t, rdb, CostConfig{Mode: CostModeEnforce, Budget: 1, Window: time.Minute})

	w := asOrg(r, http.MethodPost, "/oauth/token", "org-a") // admitted, crosses the line
	require.Equal(t, http.StatusOK, w.Code)
	w = asOrg(r, http.MethodPost, "/oauth/token", "org-a")
	require.Equal(t, http.StatusTooManyRequests, w.Code)

	ra := w.Header().Get("Retry-After")
	require.NotEmpty(t, ra)
	secs, err := strconv.Atoi(ra)
	require.NoError(t, err)
	assert.Greater(t, secs, 0)
	assert.LessOrEqual(t, secs, 60, "never longer than the window it is waiting for")
}

func TestUnknownCostModeIsRejected(t *testing.T) {
	for _, ok := range []string{"", "off", "OFF", " observe ", "enforce"} {
		_, err := ParseCostMode(ok)
		assert.NoError(t, err, "%q", ok)
	}
	for _, bad := range []string{"enfroce", "on", "true", "strict"} {
		_, err := ParseCostMode(bad)
		assert.Error(t, err, "%q must not be read as a working mode", bad)
	}
}
