package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// RFC 8628 §5.2 requires both user_code entropy and rate limiting on the
// verification endpoint. These tests cover the second half: the first shipped
// in v125, the throttle did not, and entropy alone does nothing against a
// caller guessing in a loop for the ten minutes a code stays live.

const deviceTestIP = "203.0.113.7"

// failN records n failed guesses for one caller.
func failN(t *testing.T, s *Service, ctx context.Context, subject, ip string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		s.recordDeviceVerificationFailure(ctx, deviceTestOrg, subject, ip)
	}
}

// TestVerificationThrottleStopsACodeSweep is the property the whole change
// exists for: a caller cannot keep guessing user_codes indefinitely.
func TestVerificationThrottleStopsACodeSweep(t *testing.T) {
	s, ctx := deviceTestService(t)

	// One short of the cap the caller is still trusted — the limit must not
	// bite a user who mistyped the code on the screen in front of them.
	failN(t, s, ctx, deviceTestUser, deviceTestIP, deviceVerifyMaxPerSubject-1)
	throttled, _, err := s.deviceVerificationThrottled(ctx, deviceTestOrg, deviceTestUser, deviceTestIP)
	if err != nil {
		t.Fatalf("throttle check: %v", err)
	}
	if throttled {
		t.Fatalf("throttled after %d failures, before reaching the cap of %d",
			deviceVerifyMaxPerSubject-1, deviceVerifyMaxPerSubject)
	}

	failN(t, s, ctx, deviceTestUser, deviceTestIP, 1)
	throttled, retryAfter, err := s.deviceVerificationThrottled(ctx, deviceTestOrg, deviceTestUser, deviceTestIP)
	if err != nil {
		t.Fatalf("throttle check: %v", err)
	}
	if !throttled {
		t.Fatalf("a caller was allowed to keep guessing after %d failed user_codes", deviceVerifyMaxPerSubject)
	}
	if retryAfter <= 0 || retryAfter > int(deviceVerifyWindow.Seconds()) {
		t.Fatalf("retry-after = %ds, want between 1 and the %ds window",
			retryAfter, int(deviceVerifyWindow.Seconds()))
	}
}

// TestVerificationThrottleIsPerCaller — the limit must not be global. If one
// caller's failures throttled everyone, an attacker could take the device grant
// down for the whole tenant with ten bad guesses, which is the very denial the
// throttle is meant to prevent.
func TestVerificationThrottleIsPerCaller(t *testing.T) {
	s, ctx := deviceTestService(t)

	failN(t, s, ctx, deviceTestUser, deviceTestIP, deviceVerifyMaxPerSubject+5)

	throttled, _, err := s.deviceVerificationThrottled(ctx, deviceTestOrg, deviceTestUser, deviceTestIP)
	if err != nil {
		t.Fatal(err)
	}
	if !throttled {
		t.Fatalf("the offending caller was not throttled")
	}

	// A different user from a different address is unaffected.
	throttled, _, err = s.deviceVerificationThrottled(ctx, deviceTestOrg, deviceTestOther, "198.51.100.9")
	if err != nil {
		t.Fatal(err)
	}
	if throttled {
		t.Fatalf("one caller's failures throttled an unrelated user — the limit is global, not per caller")
	}
}

// TestVerificationThrottleCapsOneAddressAcrossAccounts — the per-subject limit
// alone is only as strong as the cost of another account. The IP dimension is
// what bounds an attacker who has several.
func TestVerificationThrottleCapsOneAddressAcrossAccounts(t *testing.T) {
	s, ctx := deviceTestService(t)

	// Spread failures over many subjects so no single one reaches its cap.
	perSubject := deviceVerifyMaxPerSubject - 1
	subjects := (deviceVerifyMaxPerIP / perSubject) + 1
	for i := 0; i < subjects; i++ {
		failN(t, s, ctx, "subject-"+strconv.Itoa(i), deviceTestIP, perSubject)
	}

	// A fresh subject on that address is still refused.
	throttled, _, err := s.deviceVerificationThrottled(ctx, deviceTestOrg, "subject-fresh", deviceTestIP)
	if err != nil {
		t.Fatal(err)
	}
	if !throttled {
		t.Fatalf("an address that burned %d guesses across %d accounts was not throttled",
			subjects*perSubject, subjects)
	}

	// ...while the same fresh subject elsewhere is not.
	throttled, _, err = s.deviceVerificationThrottled(ctx, deviceTestOrg, "subject-fresh", "198.51.100.9")
	if err != nil {
		t.Fatal(err)
	}
	if throttled {
		t.Fatalf("the IP limit followed the subject to a different address")
	}
}

// TestSuccessDoesNotResetTheCounter guards a bypass that the usual
// failed-login reset-on-success pattern would open here. Any caller can mint a
// device code of their own and look it up successfully, so if success cleared
// the counter, ten guesses plus one self-issued lookup would buy ten more,
// forever.
//
// Driven through the handler rather than through resolveUserCode, because the
// handler is where such a reset would plausibly be added — a service-level
// check would not see it.
func TestSuccessDoesNotResetTheCounter(t *testing.T) {
	s, ctx := deviceTestService(t)
	router := deviceThrottleRouter(s, deviceTestUser)

	// One short of the cap, so the successful lookup below is still allowed
	// through — past the cap the guard would refuse it and prove nothing.
	failN(t, s, ctx, deviceTestUser, deviceTestIP, deviceVerifyMaxPerSubject-1)

	// A genuine, successful lookup of a code the caller legitimately holds.
	seedDeviceCode(t, s, ctx, "ACDEFGHW", "pending", deviceCodeLifetime)
	req := httptest.NewRequest(http.MethodGet, "/oauth/device/lookup?user_code=ACDE-FGHW", nil)
	req.RemoteAddr = deviceTestIP + ":1234"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("lookup of a valid code answered %d, want 200: %s", w.Code, w.Body.String())
	}

	// The budget must be where it was, so one more failure reaches the cap.
	failN(t, s, ctx, deviceTestUser, deviceTestIP, 1)
	throttled, _, err := s.deviceVerificationThrottled(ctx, deviceTestOrg, deviceTestUser, deviceTestIP)
	if err != nil {
		t.Fatal(err)
	}
	if !throttled {
		t.Fatalf("a successful lookup cleared the failure budget; a guesser can refill it at will by looking up a code of their own")
	}
}

// TestVerificationThrottleForgetsOldFailures — the limit is a window, not a
// permanent ban. A user who exhausted it must be able to try again later.
func TestVerificationThrottleForgetsOldFailures(t *testing.T) {
	s, ctx := deviceTestService(t)

	failN(t, s, ctx, deviceTestUser, deviceTestIP, deviceVerifyMaxPerSubject)
	throttled, _, err := s.deviceVerificationThrottled(ctx, deviceTestOrg, deviceTestUser, deviceTestIP)
	if err != nil {
		t.Fatal(err)
	}
	if !throttled {
		t.Fatalf("precondition: caller should be throttled")
	}

	// Age every recorded failure past the window.
	if _, err := s.db.Pool.Exec(ctx, `
		UPDATE oauth_device_verification_attempts
		   SET attempted_at = NOW() - $2::interval - INTERVAL '1 minute'
		 WHERE org_id = $1`, deviceTestOrg, deviceVerifyWindow.String()); err != nil {
		t.Fatal(err)
	}

	throttled, _, err = s.deviceVerificationThrottled(ctx, deviceTestOrg, deviceTestUser, deviceTestIP)
	if err != nil {
		t.Fatal(err)
	}
	if throttled {
		t.Fatalf("failures older than the %s window still counted — the limit is a permanent ban",
			deviceVerifyWindow)
	}
}

// TestVerificationThrottleIsOrgScoped — attempts in one tenant must not spend
// another tenant's budget.
func TestVerificationThrottleIsOrgScoped(t *testing.T) {
	s, ctx := deviceTestService(t)

	failN(t, s, ctx, deviceTestUser, deviceTestIP, deviceVerifyMaxPerSubject+2)

	throttled, _, err := s.deviceVerificationThrottled(ctx, deviceTestOther, deviceTestUser, deviceTestIP)
	if err != nil {
		t.Fatal(err)
	}
	if throttled {
		t.Fatalf("failures recorded in one organization throttled the same caller in another")
	}
}

// --- handler wiring -------------------------------------------------------
//
// The tests above prove the counter is correct. These prove it is actually in
// front of both endpoints: a correct limit that no handler consults is not a
// limit, and the decision endpoint is the one that matters most — it answers
// the same "is this code live?" question as the lookup and, on a hit, decides
// the grant rather than merely describing it.

// deviceThrottleRouter mounts the two verification handlers with a fixed
// subject and org, bypassing the real auth middleware.
func deviceThrottleRouter(s *Service, subject string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	inject := func(c *gin.Context) {
		c.Set("user_id", subject)
		c.Request = c.Request.WithContext(
			orgctx.With(c.Request.Context(), orgctx.Org{ID: deviceTestOrg}))
		c.Next()
	}
	r.GET("/oauth/device/lookup", inject, s.handleDeviceVerificationLookup)
	r.POST("/oauth/device/decision", inject, s.handleDeviceVerificationDecision)
	return r
}

func TestVerificationEndpointsRefuseAThrottledCaller(t *testing.T) {
	s, ctx := deviceTestService(t)
	router := deviceThrottleRouter(s, deviceTestUser)

	for _, tc := range []struct {
		name string
		req  func() *http.Request
	}{
		{
			name: "lookup",
			req: func() *http.Request {
				return httptest.NewRequest(http.MethodGet,
					"/oauth/device/lookup?user_code=ACDEFGHZ", nil)
			},
		},
		{
			name: "decision",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/oauth/device/decision",
					strings.NewReader(`{"user_code":"ACDEFGHZ","approve":true}`))
				r.Header.Set("Content-Type", "application/json")
				return r
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Clear the ledger, then spend exactly the budget.
			if _, err := s.db.Pool.Exec(ctx,
				`DELETE FROM oauth_device_verification_attempts`); err != nil {
				t.Fatal(err)
			}
			failN(t, s, ctx, deviceTestUser, "", deviceVerifyMaxPerSubject)

			req := tc.req()
			// c.ClientIP() reads this; the subject dimension is what trips here.
			req.RemoteAddr = deviceTestIP + ":1234"
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != http.StatusTooManyRequests {
				t.Fatalf("%s answered %d for a caller past its guess budget, want %d — "+
					"the endpoint is not consulting the throttle",
					tc.name, w.Code, http.StatusTooManyRequests)
			}
			if ra := w.Header().Get("Retry-After"); ra == "" {
				t.Fatalf("%s returned 429 with no Retry-After; a client cannot tell when to come back", tc.name)
			}
		})
	}
}

// TestFailedLookupIsCounted — the guard is only as good as what feeds it. If a
// rejected code left no trace, the budget would never be spent and the limit
// would never fire.
func TestFailedLookupIsCounted(t *testing.T) {
	s, ctx := deviceTestService(t)
	router := deviceThrottleRouter(s, deviceTestUser)

	req := httptest.NewRequest(http.MethodGet, "/oauth/device/lookup?user_code=ACDEFGHY", nil)
	req.RemoteAddr = deviceTestIP + ":1234"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("lookup of an unknown code answered %d, want 404", w.Code)
	}

	var n int
	if err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM oauth_device_verification_attempts
		 WHERE org_id = $1 AND subject = $2`, deviceTestOrg, deviceTestUser).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("failed lookup recorded %d attempts, want 1 — guesses are not being counted", n)
	}
}

// TestFailedDecisionIsCounted — same for the decision endpoint, which can be
// driven directly without ever calling the lookup.
func TestFailedDecisionIsCounted(t *testing.T) {
	s, ctx := deviceTestService(t)
	router := deviceThrottleRouter(s, deviceTestUser)

	req := httptest.NewRequest(http.MethodPost, "/oauth/device/decision",
		strings.NewReader(`{"user_code":"ACDEFGXY","approve":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = deviceTestIP + ":1234"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("decision on an unknown code answered %d, want 404", w.Code)
	}

	var n int
	if err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM oauth_device_verification_attempts
		 WHERE org_id = $1 AND subject = $2`, deviceTestOrg, deviceTestUser).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("failed decision recorded %d attempts, want 1 — the decision endpoint can be swept for free", n)
	}
}

// TestThrottleFailsClosed — if the counter cannot be read, the request must be
// refused rather than let through uncounted. A control that switches itself off
// when the store is unhappy is not a control.
func TestThrottleFailsClosed(t *testing.T) {
	s, ctx := deviceTestService(t)
	router := deviceThrottleRouter(s, deviceTestUser)

	if _, err := s.db.Pool.Exec(ctx, `DROP TABLE oauth_device_verification_attempts`); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth/device/lookup?user_code=ACDEFGHJ", nil)
	req.RemoteAddr = deviceTestIP + ":1234"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("with the attempt ledger unavailable the lookup answered %d, want %d — "+
			"guesses would go uncounted", w.Code, http.StatusInternalServerError)
	}
}
