package identity

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/openidx/openidx/internal/common/middleware"
)

// AN OTP CHALLENGE TAKES NO MORE GUESSES THAN ITS LIMIT.
//
// verifyOTPCode read a challenge's attempt count, compared it with
// max_attempts in Go and incremented it in a separate statement whose error
// was discarded, so guesses sent together all read the same count and were
// all compared with the code: a six-digit SMS or email code took as many
// guesses as could be sent at once. The guess is now counted, and refused at
// the limit, in the one statement that counts it, before the code is looked
// at; and the challenge is spent by a status change only one request can make.
//
// Driven through identity-service's route table as cmd/identity-service wires
// it: the code is sent by POST /mfa/email/challenge and guessed at through
// POST /mfa/otp/verify, the verifier the sign-in's and step-up's OTP steps
// share.

// seedEmailOTP enrolls userID for email one-time codes, as enrollment leaves it.
func (h *selfServiceHarness) seedEmailOTP(userID string) {
	h.t.Helper()
	h.exec(`INSERT INTO mfa_email_otp (user_id, email_address, enabled, org_id)
		VALUES ($1::uuid, $2, true, $3::uuid)`, userID, "otp-"+h.suffix+"@example.test", middleware.DefaultOrgID)
}

// sendOTP asks for a code by email and returns the code the message carried.
func (h *selfServiceHarness) sendOTP(bearer string) string {
	h.t.Helper()
	before := h.mailer.lastCode()
	status, out := h.do(http.MethodPost, "/api/v1/identity/mfa/email/challenge", bearer, nil)
	if status != http.StatusOK {
		h.t.Fatalf("request a code: status %d (%v), want 200", status, out)
	}
	code := h.mailer.lastCode()
	if code == "" || code == before {
		h.t.Fatal("no code was emailed")
	}
	return code
}

// otherCode is a code of the same length that is not code.
func otherCode(code string) string {
	b := []byte(code)
	b[0] = '0' + (b[0]-'0'+1)%10
	return string(b)
}

// otpAnswer is one response from POST /mfa/otp/verify.
type otpAnswer struct {
	status int
	err    string
}

// burstOTP sends n verifications of code at once and returns the answers.
func (h *selfServiceHarness) burstOTP(bearer, code string, n int) []otpAnswer {
	body, _ := json.Marshal(map[string]string{"method": "email", "code": code})
	start := make(chan struct{})
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		answers []otpAnswer
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			req := httptest.NewRequest(http.MethodPost, "/api/v1/identity/mfa/otp/verify", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+bearer)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.router.ServeHTTP(w, req)
			var out map[string]interface{}
			_ = json.Unmarshal(w.Body.Bytes(), &out)
			msg, _ := out["error"].(string)
			mu.Lock()
			answers = append(answers, otpAnswer{status: w.Code, err: msg})
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()
	return answers
}

func TestConcurrentGuessesAtAnOTPChallengeAreLimited(t *testing.T) {
	h := newSelfServiceHarness(t)
	user := h.seedUser("otp-burst")
	bearer := h.bearer(user)
	h.seedEmailOTP(user)
	code := h.sendOTP(bearer)
	limit := h.count(`SELECT max_attempts FROM mfa_otp_challenges WHERE user_id = $1::uuid`, user)
	if limit < 1 {
		t.Fatalf("max_attempts = %d", limit)
	}

	const guesses = 24
	evaluated, refused := 0, 0
	for _, a := range h.burstOTP(bearer, otherCode(code), guesses) {
		switch {
		case a.status == http.StatusBadRequest && strings.HasPrefix(a.err, "invalid OTP code"):
			evaluated++ // the guess was compared with the code
		case a.status == http.StatusBadRequest && (a.err == "maximum attempts exceeded" || a.err == "no pending challenge found"):
			// Refused before the code was looked at: at the limit, or after
			// the challenge was closed for reaching it.
			refused++
		default:
			t.Errorf("unexpected answer: %d %q", a.status, a.err)
		}
	}
	if evaluated != limit || refused != guesses-limit {
		t.Fatalf("%d guesses sent at once: %d compared with the code and %d refused, want %d compared (max_attempts) and %d refused",
			guesses, evaluated, refused, limit, guesses-limit)
	}
	if n := h.count(`SELECT attempts FROM mfa_otp_challenges WHERE user_id = $1::uuid`, user); n != limit {
		t.Errorf("attempts = %d, want %d", n, limit)
	}
	if st := h.scalar(`SELECT status FROM mfa_otp_challenges WHERE user_id = $1::uuid`, user); st != "failed" {
		t.Errorf("status = %q after the limit, want failed", st)
	}

	// The right code, once the guesses are used up, is refused too.
	status, out := h.do(http.MethodPost, "/api/v1/identity/mfa/otp/verify", bearer, map[string]string{"method": "email", "code": code})
	if status == http.StatusOK {
		t.Fatalf("the right code after the limit was accepted: %v", out)
	}
}

func TestAnOTPCodeIsAcceptedWithinTheLimitAndOnce(t *testing.T) {
	h := newSelfServiceHarness(t)
	user := h.seedUser("otp-once")
	bearer := h.bearer(user)
	h.seedEmailOTP(user)
	verify := func(code string) (int, map[string]interface{}) {
		t.Helper()
		return h.do(http.MethodPost, "/api/v1/identity/mfa/otp/verify", bearer, map[string]string{"method": "email", "code": code})
	}

	// Wrong guesses short of the limit leave the right code working.
	code := h.sendOTP(bearer)
	limit := h.count(`SELECT max_attempts FROM mfa_otp_challenges WHERE user_id = $1::uuid`, user)
	for i := 1; i < limit; i++ {
		if status, out := verify(otherCode(code)); status != http.StatusBadRequest {
			t.Fatalf("wrong guess %d: status %d (%v), want 400", i, status, out)
		}
	}
	if status, out := verify(code); status != http.StatusOK || out["verified"] != true {
		t.Fatalf("the right code on the last attempt: status %d (%v), want 200 verified", status, out)
	}
	if status, out := verify(code); status == http.StatusOK {
		t.Fatalf("the same code a second time was accepted: %v", out)
	}

	// Sent together, the right code verifies once.
	code = h.sendOTP(bearer)
	accepted := 0
	for _, a := range h.burstOTP(bearer, code, 10) {
		if a.status == http.StatusOK {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("ten concurrent submissions of the right code: %d accepted, want exactly 1", accepted)
	}
}

// Two submissions of the right code, both counted before either spends the
// challenge: the interleaving the spend's condition exists for, made rather
// than hoped for. The challenge's row is held until both are queued to count
// themselves; let go, both are counted, both compare the code and find it
// right, and the spend decides that one verifies. The interleaving is checked
// (both counted) and, in the rare run where scheduling does not produce it,
// tried again with a new challenge.
func TestTwoRightCodesCountedTogetherVerifyOnce(t *testing.T) {
	h := newSelfServiceHarness(t)
	user := h.seedUser("otp-twice")
	bearer := h.bearer(user)
	h.seedEmailOTP(user)

	for try := 1; try <= 3; try++ {
		code := h.sendOTP(bearer)
		id := h.scalar(`SELECT id::text FROM mfa_otp_challenges WHERE user_id = $1::uuid ORDER BY created_at DESC LIMIT 1`, user)
		verify := func() (int, map[string]interface{}) {
			return h.do(http.MethodPost, "/api/v1/identity/mfa/otp/verify", bearer, map[string]string{"method": "email", "code": code})
		}
		answers := h.whileTheRowIsHeldFor("mfa_otp_challenges", "id = $1::uuid", "", []interface{}{id}, verify, verify)
		if n := h.count(`SELECT attempts FROM mfa_otp_challenges WHERE id = $1::uuid`, id); n != 2 {
			t.Logf("try %d: attempts = %d, the two were not both counted before a spend; again", try, n)
			continue
		}
		accepted := 0
		for _, a := range answers {
			if a.status == http.StatusOK {
				accepted++
			}
		}
		if accepted != 1 {
			t.Fatalf("two submissions of the right code, both counted: %d verified (%v), want exactly 1", accepted, answers)
		}
		return
	}
	t.Fatal("in three tries the two submissions were never both counted before a spend")
}
