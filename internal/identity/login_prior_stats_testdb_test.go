package identity

import (
	"testing"

	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// B7.4: a successful password login resets failed_login_count, but the risk
// engine must score it against the failures that preceded it. AuthenticateUser
// returns the pre-reset values on the user, and the stored count is still 0.
func TestASuccessfulLoginCarriesThePreResetLoginStats(t *testing.T) {
	h := newSelfServiceHarness(t)
	user := h.seedUser("priorstats")
	username := h.scalar(`SELECT username FROM users WHERE id = $1::uuid`, user)
	h.exec(`UPDATE users SET failed_login_count = 3, last_login_at = NOW() - INTERVAL '2 hours' WHERE id = $1::uuid`, user)

	ctx := orgctx.With(h.seedCtx(), orgctx.Org{ID: middleware.DefaultOrgID})
	u, err := h.svc.AuthenticateUser(ctx, username, harnessPassword)
	if err != nil {
		t.Fatalf("sign-in: %v", err)
	}
	failed, last := u.RiskLoginStats()
	if failed != 3 {
		t.Errorf("prior failed = %d, want 3", failed)
	}
	if last == nil {
		t.Fatal("prior last_login_at missing")
	}
	if u.LastLoginAt == nil || !u.LastLoginAt.After(*last) {
		t.Errorf("stored last_login_at %v should be after the prior %v", u.LastLoginAt, last)
	}
	if n := h.count(`SELECT failed_login_count FROM users WHERE id = $1::uuid`, user); n != 0 {
		t.Errorf("stored failed_login_count = %d, want 0", n)
	}
}
