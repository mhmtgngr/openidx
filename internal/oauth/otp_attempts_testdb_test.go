package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/pwhash"
	"github.com/openidx/openidx/internal/identity"
)

// THE SIGN-IN TAKES NO MORE GUESSES AT AN SMS OR EMAIL CODE THAN THE LIMIT.
//
// The second step of a password sign-in (POST /oauth/login, then
// POST /oauth/mfa-verify with method "sms" or "email") reaches
// identity.VerifyOTP, whose attempt limit was a read, a comparison in Go and a
// separate increment: guesses sent together all passed it. This is where the
// guessing happens -- whoever has the password and not the phone -- so the
// limit is driven here, through RegisterRoutes as cmd/oauth-service wires it,
// over a migrated database with the real identity service. The challenge is
// written as POST /oauth/mfa-send-otp leaves it, with a code the test knows:
// delivering it is not what is under test.
func TestTheSignInTakesNoMoreOTPGuessesThanTheLimit(t *testing.T) {
	h := newTokenHarness(t)
	h.issuer.identityService = identity.NewService(h.db, h.issuer.redis, &config.Config{
		Environment: "production", OAuthIssuer: h.issuer.issuer, OAuthJWKSURL: h.jwksURL,
	}, zap.NewNop())
	api := h.oauthRouteTable(nil)
	ctx := context.Background()

	const password = "a-long-enough-test-password"
	hash, err := pwhash.Hash(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := h.seedUser(middleware.DefaultOrgID, "otp-limit")
	username := h.scalar(`SELECT username FROM users WHERE id = $1::uuid`, user)
	h.exec(`UPDATE users SET password_hash = $1 WHERE id = $2::uuid`, hash, user)
	h.exec(`INSERT INTO mfa_email_otp (user_id, email_address, enabled, org_id)
		VALUES ($1::uuid, $2, true, $3::uuid)`, user, username+"@example.test", middleware.DefaultOrgID)
	// And a TOTP credential, with which the sign-in asks for a second factor
	// whatever the risk engine says; the guesses go to the email code, which
	// the same challenge offers.
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "OpenIDX", AccountName: username})
	if err != nil {
		t.Fatalf("generate TOTP key: %v", err)
	}
	h.exec(`INSERT INTO mfa_totp (user_id, secret, enabled, enrolled_at, org_id)
		VALUES ($1::uuid, $2, true, NOW(), $3::uuid)`, user, key.Secret(), middleware.DefaultOrgID)

	post := func(path string, body interface{}) (int, map[string]interface{}) {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		api.ServeHTTP(w, req)
		var out map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}

	// signIn passes the password step and returns the MFA session.
	signIn := func() string {
		t.Helper()
		loginSession := GenerateRandomToken(16)
		params, _ := json.Marshal(map[string]string{
			"client_id": "admin-console", "redirect_uri": "http://localhost:3000/callback",
			"response_type": "code", "scope": "openid", "state": "st-1",
		})
		if err := h.issuer.redis.Client.Set(ctx, "login_session:"+loginSession, params, time.Minute).Err(); err != nil {
			t.Fatalf("seed login session: %v", err)
		}
		status, body := post("/oauth/login", map[string]string{
			"username": username, "password": password, "login_session": loginSession,
		})
		if status != http.StatusOK || body["mfa_required"] != true {
			t.Fatalf("password step: status %d (%v), want 200 with mfa_required", status, body)
		}
		mfaSession, _ := body["mfa_session"].(string)
		return mfaSession
	}

	// challenge writes a pending email challenge for code, returning its id.
	challenge := func(code string) string {
		t.Helper()
		sum := sha256.Sum256([]byte(code))
		return h.scalar(`INSERT INTO mfa_otp_challenges
			(user_id, org_id, method, recipient, code_hash, attempts, max_attempts, status,
			 ip_address, user_agent, created_at, expires_at)
			VALUES ($1::uuid, $2::uuid, 'email', $3, $4, 0, 3, 'pending',
			 '203.0.113.9', 'test', NOW(), NOW() + INTERVAL '5 minutes')
			RETURNING id::text`, user, middleware.DefaultOrgID, username+"@example.test", hex.EncodeToString(sum[:]))
	}

	verify := func(mfaSession, code string) int {
		status, _ := post("/oauth/mfa-verify", map[string]string{
			"mfa_session": mfaSession, "code": code, "method": "email",
		})
		return status
	}

	// Sixteen wrong guesses at once, on one sign-in.
	mfaSession := signIn()
	id := challenge("246810")
	const guesses = 16
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	statuses := map[int]int{}
	for i := 0; i < guesses; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			st := verify(mfaSession, "135791")
			mu.Lock()
			statuses[st]++
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()
	if statuses[http.StatusUnauthorized] != guesses {
		t.Fatalf("wrong guesses: answers %v, want %d x 401", statuses, guesses)
	}
	// Each guess compared with the code is one counted attempt, so the count is
	// the number of guesses the code was tested against.
	if n := h.scalar(`SELECT attempts::text FROM mfa_otp_challenges WHERE id = $1::uuid`, id); n != "3" {
		t.Fatalf("attempts = %s after %d guesses sent at once, want 3 (max_attempts)", n, guesses)
	}
	if st := verify(mfaSession, "246810"); st != http.StatusUnauthorized {
		t.Fatalf("the right code after the limit: status %d, want 401", st)
	}

	// The other side: the right code within the limit signs in.
	mfaSession = signIn()
	challenge("112233")
	if st := verify(mfaSession, "445566"); st != http.StatusUnauthorized {
		t.Fatalf("a wrong guess: status %d, want 401", st)
	}
	if st := verify(mfaSession, "112233"); st != http.StatusOK {
		t.Fatalf("the right code on the second attempt: status %d, want 200", st)
	}
}
