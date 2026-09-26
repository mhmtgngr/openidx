package identity

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// A TOTP CODE IS ACCEPTED ONCE.
//
// VerifyTOTP accepted any code valid in its window -- its step and one either
// side, about 90 seconds -- and recorded only last_used_at, which nothing read.
// So the code a user had just signed in with signed in again, for anyone who
// saw it. The verifier now records the step each code belongs to and accepts a
// code only for a later step, in the UPDATE that records it.
//
// Driven through identity-service's route table as cmd/identity-service wires
// it: enrollment is POST /mfa/totp/enroll and verification POST
// /mfa/totp/verify, each with a signed token.

func TestATOTPCodeIsAcceptedOnce(t *testing.T) {
	h := newSelfServiceHarness(t)
	user := h.seedUser("totp-once")
	bearer := h.bearer(user)

	key, err := totp.Generate(totp.GenerateOpts{Issuer: "OpenIDX", AccountName: user})
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	secret := key.Secret()
	now := time.Now()
	enrollCode := totpCode(t, secret, now)

	status, body := h.do(http.MethodPost, "/api/v1/identity/mfa/totp/enroll", bearer,
		map[string]string{"secret": secret, "code": enrollCode})
	if status != http.StatusOK {
		t.Fatalf("enrolling the user's first factor: status %d (%v), want 200", status, body)
	}

	verify := func(code string) bool {
		t.Helper()
		status, body := h.do(http.MethodPost, "/api/v1/identity/mfa/totp/verify", bearer, map[string]string{"code": code})
		if status != http.StatusOK {
			t.Fatalf("verify: status %d (%v), want 200", status, body)
		}
		return body["valid"] == true
	}

	if verify(enrollCode) {
		t.Error("the code that confirmed the enrollment was accepted again")
	}

	next := totpCode(t, secret, now.Add(totpPeriod*time.Second))
	if !verify(next) {
		t.Fatal("the next step's code was refused: the legitimate next sign-in must work")
	}
	if verify(next) {
		t.Error("the same code was accepted twice")
	}
	if verify(enrollCode) {
		t.Error("an earlier step's code, still inside its window, was accepted after a later one")
	}

	// A refused replay is not a wrong guess: it does not count towards the
	// lockout, so a form submitted twice cannot lock its owner out.
	if n := h.count(`SELECT failed_attempts FROM mfa_totp WHERE user_id = $1::uuid`, user); n != 0 {
		t.Errorf("failed_attempts = %d after replays alone, want 0", n)
	}
}

func TestConcurrentUsesOfOneTOTPCodeAdmitExactlyOne(t *testing.T) {
	h := newSelfServiceHarness(t)
	user := h.seedUser("totp-race")
	secret := h.seedTOTP(user)
	bearer := h.bearer(user)
	code := totpCode(t, secret, time.Now())
	body, _ := json.Marshal(map[string]string{"code": code})

	const n = 12
	start := make(chan struct{})
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		admitted int
		refused  int
		other    []int
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			req := httptest.NewRequest(http.MethodPost, "/api/v1/identity/mfa/totp/verify", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+bearer)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.router.ServeHTTP(w, req)
			var out map[string]interface{}
			_ = json.Unmarshal(w.Body.Bytes(), &out)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case w.Code == http.StatusOK && out["valid"] == true:
				admitted++
			case w.Code == http.StatusOK && out["valid"] == false:
				refused++
			default:
				other = append(other, w.Code)
			}
		}()
	}
	close(start)
	wg.Wait()

	if len(other) != 0 {
		t.Fatalf("unexpected answers: %v", other)
	}
	if admitted != 1 || refused != n-1 {
		t.Fatalf("%d concurrent uses of one code: %d admitted, %d refused; want exactly 1 admitted", n, admitted, refused)
	}

	// The burst leaves the owner able to sign in with their next code.
	next := totpCode(t, secret, time.Now().Add(totpPeriod*time.Second))
	status, out := h.do(http.MethodPost, "/api/v1/identity/mfa/totp/verify", bearer, map[string]string{"code": next})
	if status != http.StatusOK || out["valid"] != true {
		t.Fatalf("the next step's code after the burst: status %d (%v), want valid", status, out)
	}
}
