package identity

import (
	"encoding/base32"
	"net/http"
	"testing"
	"time"

	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// A RIGHT CODE THAT ARRIVES AS A CONCURRENT FAILURE LOCKS THE FACTOR IS REFUSED.
//
// The TOTP and hardware-token verifiers refuse a locked factor in the read
// that fetches it. Their accepting write did not look at the lock, and cleared
// it, so among guesses sent together every one was tested against the factor
// however many failures locked it in the meantime, and a right one unlocked
// it. The lockout is now re-checked in the accepting write.
//
// The interleaving is made, not hoped for: the test holds the credential's
// row, sends a right code, waits until the request's accepting UPDATE is
// queued behind the held row, and then writes what a concurrent wrong guess
// reaching the threshold writes -- the lock -- and lets go. The other side
// lets go without the lock, and the code is accepted.

// whileTheRowIsHeld sends a request whose accepting UPDATE on table queues
// behind a transaction holding the row rowWhere selects; while the request
// waits, the transaction runs landing (unless it is empty) and commits.
func (h *selfServiceHarness) whileTheRowIsHeld(table, rowWhere, landing string, rowArgs []interface{}, send func() (int, map[string]interface{})) (int, map[string]interface{}) {
	h.t.Helper()
	a := h.whileTheRowIsHeldFor(table, rowWhere, landing, rowArgs, send)[0]
	return a.status, a.body
}

// heldAnswer is one response to a request sent while a row was held.
type heldAnswer struct {
	status int
	body   map[string]interface{}
}

// whileTheRowIsHeldFor sends every request at once while a transaction holds
// the row rowWhere selects, waits until each of them has an UPDATE of table
// queued behind it, then runs landing (unless it is empty), commits, and
// returns the answers in the order the requests were given.
func (h *selfServiceHarness) whileTheRowIsHeldFor(table, rowWhere, landing string, rowArgs []interface{}, sends ...func() (int, map[string]interface{})) []heldAnswer {
	h.t.Helper()
	ctx := h.seedCtx()
	tx, err := h.db.Pool.Begin(ctx)
	if err != nil {
		h.t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed
	if _, err := tx.Exec(ctx, "SELECT 1 FROM "+table+" WHERE "+rowWhere+" FOR UPDATE", rowArgs...); err != nil {
		h.t.Fatalf("hold the %s row: %v", table, err)
	}

	answers := make([]heldAnswer, len(sends))
	done := make(chan int, len(sends))
	for i, send := range sends {
		go func(i int, send func() (int, map[string]interface{})) {
			status, body := send()
			answers[i] = heldAnswer{status, body}
			done <- i
		}(i, send)
	}

	deadline := time.Now().Add(20 * time.Second)
	for {
		var waiting int
		if err := h.db.Pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM pg_stat_activity
			WHERE datname = current_database() AND wait_event_type = 'Lock'
			  AND query ILIKE '%UPDATE ' || $1 || '%'`, table).Scan(&waiting); err != nil {
			h.t.Fatalf("read pg_stat_activity: %v", err)
		}
		if waiting >= len(sends) {
			break
		}
		select {
		case i := <-done:
			h.t.Fatalf("request %d was answered without writing the held row: %d %v", i, answers[i].status, answers[i].body)
		default:
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("%d of %d requests' UPDATEs of %s queued behind the held row", waiting, len(sends), table)
		}
		time.Sleep(20 * time.Millisecond)
	}

	if landing != "" {
		if _, err := tx.Exec(ctx, landing, rowArgs...); err != nil {
			h.t.Fatalf("land the concurrent write: %v", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		h.t.Fatalf("commit: %v", err)
	}
	for range sends {
		<-done
	}
	return answers
}

func TestATOTPCodeArrivingAsAFailureLocksTheFactorIsRefused(t *testing.T) {
	h := newSelfServiceHarness(t)
	user := h.seedUser("totp-lock-race")
	bearer := h.bearer(user)
	secret := h.seedTOTP(user)
	const lock = `UPDATE mfa_totp SET failed_attempts = 5, last_failed_at = NOW(),
		locked_until = NOW() + INTERVAL '15 minutes' WHERE user_id = $1::uuid`
	verify := func(code string) func() (int, map[string]interface{}) {
		return func() (int, map[string]interface{}) {
			return h.do(http.MethodPost, "/api/v1/identity/mfa/totp/verify", bearer, map[string]string{"code": code})
		}
	}

	now := time.Now()
	status, out := h.whileTheRowIsHeld("mfa_totp", "user_id = $1::uuid", lock, []interface{}{user}, verify(totpCode(t, secret, now)))
	if status == http.StatusOK && out["valid"] == true {
		t.Fatal("a right code was accepted after a concurrent failure locked the factor")
	}
	if locked := h.scalar(`SELECT (locked_until > NOW())::text FROM mfa_totp WHERE user_id = $1::uuid`, user); locked != "true" {
		t.Fatal("the lock a concurrent failure set was cleared")
	}
	if n := h.count(`SELECT last_step FROM mfa_totp WHERE user_id = $1::uuid`, user); n != 0 {
		t.Fatalf("last_step = %d: the refused code was recorded as used", n)
	}

	// The other side: nothing lands while the code waits, and it is accepted.
	h.exec(`UPDATE mfa_totp SET failed_attempts = 0, last_failed_at = NULL, locked_until = NULL WHERE user_id = $1::uuid`, user)
	status, out = h.whileTheRowIsHeld("mfa_totp", "user_id = $1::uuid", "", []interface{}{user}, verify(totpCode(t, secret, now)))
	if status != http.StatusOK || out["valid"] != true {
		t.Fatalf("a right code with no failure landing: status %d (%v), want valid", status, out)
	}
}

func TestAHardwareTokenCodeArrivingAsAFailureLocksTheTokenIsRefused(t *testing.T) {
	h := newSelfServiceHarness(t)
	user := h.seedUser("hw-lock-race")
	admin := h.seedUser("hw-lock-admin")
	bearer := h.bearer(user)
	ctx := orgctx.With(h.seedCtx(), orgctx.Org{ID: middleware.DefaultOrgID})
	seed := []byte("12345678901234567890")
	token, err := h.svc.CreateHardwareToken(ctx, &CreateHardwareTokenRequest{
		SerialNumber: "HW-LOCK-RACE-" + h.suffix, Name: "race", TokenType: "oath-hotp",
		SecretKey: base32.StdEncoding.EncodeToString(seed),
	}, admin)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	if err := h.svc.AssignHardwareToken(ctx, token.ID, user, admin); err != nil {
		t.Fatalf("assign token: %v", err)
	}
	const lock = `UPDATE hardware_tokens SET failed_attempts = 5, last_failed_at = NOW(),
		locked_until = NOW() + INTERVAL '15 minutes' WHERE id = $1::uuid`
	verify := func(code string) func() (int, map[string]interface{}) {
		return func() (int, map[string]interface{}) {
			return h.do(http.MethodPost, "/api/v1/identity/mfa/hardware-token/verify", bearer, map[string]string{"otp": code})
		}
	}

	status, out := h.whileTheRowIsHeld("hardware_tokens", "id = $1::uuid", lock, []interface{}{token.ID}, verify(generateHOTP(seed, 0)))
	if status != http.StatusBadRequest || out["error"] != ErrHardwareTokenLockedOut.Error() {
		t.Fatalf("a right code after a concurrent failure locked the token: status %d (%v), want 400 %q",
			status, out, ErrHardwareTokenLockedOut.Error())
	}
	if locked := h.scalar(`SELECT (locked_until > NOW())::text FROM hardware_tokens WHERE id = $1::uuid`, token.ID); locked != "true" {
		t.Fatal("the lock a concurrent failure set was cleared")
	}
	if n := h.count(`SELECT COALESCE(counter, 0) FROM hardware_tokens WHERE id = $1::uuid`, token.ID); n != 0 {
		t.Fatalf("counter = %d: the refused code was spent", n)
	}

	// The other side.
	h.exec(`UPDATE hardware_tokens SET failed_attempts = 0, last_failed_at = NULL, locked_until = NULL WHERE id = $1::uuid`, token.ID)
	status, out = h.whileTheRowIsHeld("hardware_tokens", "id = $1::uuid", "", []interface{}{token.ID}, verify(generateHOTP(seed, 0)))
	if status != http.StatusOK || out["valid"] != true {
		t.Fatalf("a right code with no failure landing: status %d (%v), want valid", status, out)
	}
}
