package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/identity"
)

// A magic link proves the mailbox and nothing more, and its redirect cannot ask
// for a second factor. So it signs in only a user whom the password login
// would let in without one, and it asks the password login's own decision
// (evaluateMFA). Anyone else goes back to the login page for the same pending
// request. Each case is shown from both sides.
func TestMagicLinkSignsInOnlyWhoNeedsNoSecondFactor(t *testing.T) {
	gin.SetMode(gin.TestMode)
	f := newMFAGraceFixture(t)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: f.org}))
		c.Next()
	})
	router.GET("/oauth/magic-link-verify", f.s.handleMagicLinkVerify)
	ctx := context.Background()

	type outcome struct {
		location     *url.URL
		loginSession string
		userID       string
	}
	follow := func(u *identity.User) outcome {
		t.Helper()
		ls := GenerateRandomToken(32) // the handler takes 32 to 128 characters
		params, _ := json.Marshal(map[string]string{
			"redirect_uri": "https://app.example.test/callback", "scope": "openid", "state": "st-1",
		})
		if err := f.s.redis.Client.Set(ctx, "login_session:"+ls, params, time.Minute).Err(); err != nil {
			t.Fatalf("seed login session: %v", err)
		}
		link, err := f.s.identityService.CreateMagicLink(f.orgCtx, u.UserName+"@example.test", "login", "", "203.0.113.7", "evidence-run")
		if err != nil {
			t.Fatalf("mint a magic link: %v", err)
		}
		w := httptest.NewRecorder()
		q := url.Values{"token": {link.Token}, "login_session": {ls}}
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/oauth/magic-link-verify?"+q.Encode(), nil))
		if w.Code != http.StatusFound {
			t.Fatalf("want a redirect, got %d %s", w.Code, w.Body.String())
		}
		loc, err := url.Parse(w.Header().Get("Location"))
		if err != nil {
			t.Fatalf("bad Location %q: %v", w.Header().Get("Location"), err)
		}
		return outcome{location: loc, loginSession: ls, userID: u.ID}
	}
	codes := func(userID string) int {
		t.Helper()
		var n int
		if err := f.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM oauth_authorization_codes WHERE user_id = $1::uuid`, userID).Scan(&n); err != nil {
			t.Fatalf("count codes: %v", err)
		}
		return n
	}
	signedIn := func(t *testing.T, o outcome) {
		t.Helper()
		if o.location.Host != "app.example.test" || o.location.Query().Get("code") == "" {
			t.Fatalf("want a code for the client, got %s", o.location)
		}
		if n := codes(o.userID); n != 1 {
			t.Fatalf("%d authorization codes minted, want 1", n)
		}
	}
	sentBack := func(t *testing.T, o outcome, reason string) {
		t.Helper()
		if o.location.Path != "/login" || o.location.Query().Get("error") != reason {
			t.Fatalf("want the login page with error=%s, got %s", reason, o.location)
		}
		if got := o.location.Query().Get("login_session"); got != o.loginSession {
			t.Fatalf("the login page must continue the same pending request: login_session %q, want %q", got, o.loginSession)
		}
		if n := codes(o.userID); n != 0 {
			t.Fatalf("%d authorization codes minted for a refused magic link, want 0", n)
		}
		if err := f.s.redis.Client.Get(ctx, "login_session:"+o.loginSession).Err(); err != nil {
			t.Fatalf("the pending request is gone (%v), so the password sign-in could not complete it", err)
		}
	}
	setPolicyEnabled := func(enabled bool) {
		f.exec(`UPDATE mfa_policies SET enabled = $1 WHERE id = $2::uuid`, enabled, f.policy)
	}

	t.Run("a user with no second factor signs in with the link", func(t *testing.T) {
		f.setPolicy(`[]`, 0)
		setPolicyEnabled(true)
		signedIn(t, follow(f.user("link-no-factor")))
	})

	t.Run("a user with TOTP is sent back to sign in with it", func(t *testing.T) {
		f.setPolicy(`[]`, 0)
		setPolicyEnabled(false)
		sentBack(t, follow(f.user("link-totp", "totp")), "mfa_required")
	})

	t.Run("an MFA policy decides for a user whose only factor is email OTP, both ways", func(t *testing.T) {
		f.setPolicy(`[]`, 0)
		setPolicyEnabled(false)
		// Without a policy the password login does not challenge this user
		// either, so neither does the link.
		signedIn(t, follow(f.user("link-email-no-policy", "email")))
		setPolicyEnabled(true)
		sentBack(t, follow(f.user("link-email-policy", "email")), "mfa_required")
	})

	t.Run("after a policy's grace period the link is refused too", func(t *testing.T) {
		f.setPolicy(`["totp"]`, 0)
		setPolicyEnabled(true)
		sentBack(t, follow(f.user("link-overdue")), "mfa_enrollment_required")
	})

	t.Run("the refused link is spent", func(t *testing.T) {
		f.setPolicy(`[]`, 0)
		setPolicyEnabled(false)
		u := f.user("link-spent", "totp")
		o := follow(u)
		sentBack(t, o, "mfa_required")
		var pending int
		if err := f.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM magic_links WHERE user_id = $1::uuid AND status = 'pending'`,
			u.ID).Scan(&pending); err != nil {
			t.Fatalf("count pending links: %v", err)
		}
		if pending != 0 {
			t.Fatalf("%d links still pending after a refusal: a refused link must not stay redeemable", pending)
		}
	})
}
