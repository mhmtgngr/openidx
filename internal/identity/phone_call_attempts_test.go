package identity

import (
	"context"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// A six-digit code is worth three guesses. The counter that says so was read,
// compared, and then incremented by a statement whose error was discarded --
// so an increment the database refused left the counter where it was and the
// cap never arrived, and two verifications racing each other both read the
// same count before either wrote. Either way the guesses are free, and 10^6
// with no ceiling is a code an attacker walks through.
//
// The three tests below are the cap: a failed count refuses the guess, three
// wrong guesses close the challenge, and concurrent guesses are all counted.

const phoneCallSchema = `
CREATE TABLE users (
	id UUID PRIMARY KEY,
	email TEXT NOT NULL,
	enabled BOOLEAN NOT NULL DEFAULT true,
	org_id UUID NOT NULL);
CREATE TABLE phone_call_challenges (
	id UUID PRIMARY KEY,
	org_id UUID,
	user_id UUID NOT NULL,
	phone_number TEXT NOT NULL,
	code_hash TEXT NOT NULL,
	call_sid TEXT,
	call_type TEXT,
	status TEXT NOT NULL,
	attempts INT NOT NULL DEFAULT 0,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	expires_at TIMESTAMPTZ NOT NULL,
	verified_at TIMESTAMPTZ);
CREATE TABLE mfa_phone_call (
	id UUID PRIMARY KEY,
	org_id UUID,
	user_id UUID NOT NULL,
	phone_number TEXT NOT NULL,
	country_code TEXT,
	verified BOOLEAN NOT NULL DEFAULT false,
	enabled BOOLEAN NOT NULL DEFAULT true,
	voice_language TEXT,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	last_used_at TIMESTAMPTZ);
`

// phoneCallFixture seeds a user, an enrolment and one live challenge holding
// the given code, and returns the Service and the org-carrying context.
func phoneCallFixture(t *testing.T, orgID, userID, code string) (*Service, context.Context, func()) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	if db == nil {
		return nil, nil, func() {}
	}
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: orgID})
	if _, err := db.Pool.Exec(ctx, phoneCallSchema); err != nil {
		cleanup()
		t.Fatalf("create schema: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.MinCost)
	if err != nil {
		cleanup()
		t.Fatalf("hash the code: %v", err)
	}
	// One statement per Exec: pgx prepares anything given arguments, and a
	// prepared statement holds exactly one command.
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO users (id, email, org_id) VALUES ($1, 'call@example.test', $2)`,
		userID, orgID); err != nil {
		cleanup()
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO mfa_phone_call (id, org_id, user_id, phone_number, verified)
		 VALUES (gen_random_uuid(), $2, $1, '+15550000000', false)`,
		userID, orgID); err != nil {
		cleanup()
		t.Fatalf("seed enrolment: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO phone_call_challenges
			(id, org_id, user_id, phone_number, code_hash, call_type, status, attempts, expires_at)
		VALUES (gen_random_uuid(), $2, $1, '+15550000000', $3, 'mfa', 'calling', 0, NOW() + INTERVAL '5 minutes')`,
		userID, orgID, string(hash)); err != nil {
		cleanup()
		t.Fatalf("seed challenge: %v", err)
	}
	return &Service{db: db, logger: zap.NewNop()}, ctx, cleanup
}

func TestAGuessThatCannotBeCountedIsRefused(t *testing.T) {
	const orgID = "00000000-0000-0000-0000-000000000090"
	const userID = "aaaaaaaa-0000-0000-0000-000000000090"
	s, ctx, cleanup := phoneCallFixture(t, orgID, userID, "123456")
	if s == nil {
		return
	}
	defer cleanup()

	// Take the attempt counter away -- and ONLY the counter. A trigger that
	// refused every UPDATE on this table would also break the write that spends
	// the challenge, and the verification would fail for that reason instead,
	// leaving the counter untested. The WHEN clause fires on the increment and
	// nothing else.
	if _, err := s.db.Pool.Exec(ctx, `
		CREATE FUNCTION refuse_count() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'refusing the attempt count'; END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER refuse_count BEFORE UPDATE ON phone_call_challenges
		FOR EACH ROW WHEN (NEW.attempts IS DISTINCT FROM OLD.attempts)
		EXECUTE FUNCTION refuse_count();`); err != nil {
		t.Fatalf("install the failure: %v", err)
	}

	// Even the RIGHT code is refused: the product cannot tell how many guesses
	// have been made, so it must not hand out another free one.
	err := s.VerifyPhoneCallChallenge(ctx, userID, "123456")
	if err == nil {
		t.Fatal("a verification whose attempt could not be counted was accepted. The three-guess cap " +
			"on a six-digit code is only as real as the counter behind it.")
	}
	if !strings.Contains(err.Error(), "record the verification attempt") {
		t.Errorf("refused, but not because the attempt could not be counted: %v. This test only pins "+
			"the cap if the counter is what fails.", err)
	}

	var attempts int
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT attempts FROM phone_call_challenges WHERE user_id = $1`, userID).Scan(&attempts); err != nil {
		t.Fatalf("read the counter back: %v", err)
	}
	if attempts != 0 {
		t.Errorf("the failure injection did not take — attempts is %d, so this test is not exercising "+
			"the path it claims", attempts)
	}
}

func TestThreeWrongGuessesCloseThePhoneCallChallenge(t *testing.T) {
	const orgID = "00000000-0000-0000-0000-000000000091"
	const userID = "aaaaaaaa-0000-0000-0000-000000000091"
	s, ctx, cleanup := phoneCallFixture(t, orgID, userID, "123456")
	if s == nil {
		return
	}
	defer cleanup()

	for i := 1; i <= maxPhoneCallAttempts; i++ {
		err := s.VerifyPhoneCallChallenge(ctx, userID, "000000")
		if err == nil {
			t.Fatalf("guess %d: a wrong code was accepted", i)
		}
		if !strings.Contains(err.Error(), "invalid verification code") {
			t.Fatalf("guess %d refused for the wrong reason: %v", i, err)
		}
	}

	// The fourth guess is over the cap -- and the RIGHT code no longer helps.
	err := s.VerifyPhoneCallChallenge(ctx, userID, "123456")
	if err == nil {
		t.Fatal("the correct code was accepted after the challenge had been guessed at three times")
	}
	if !strings.Contains(err.Error(), "maximum attempts") {
		t.Errorf("refused for the wrong reason: %v", err)
	}

	var status string
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT status FROM phone_call_challenges WHERE user_id = $1`, userID).Scan(&status); err != nil {
		t.Fatalf("read the challenge back: %v", err)
	}
	if status != "failed" {
		t.Errorf("after exhausting the attempts the challenge is %q, want failed", status)
	}
}

func TestConcurrentGuessesAreEachCounted(t *testing.T) {
	const orgID = "00000000-0000-0000-0000-000000000092"
	const userID = "aaaaaaaa-0000-0000-0000-000000000092"
	s, ctx, cleanup := phoneCallFixture(t, orgID, userID, "123456")
	if s == nil {
		return
	}
	defer cleanup()

	// Eight wrong guesses at once.
	//
	// What is counted here is not how many rows were written but how many
	// guesses were compared against the code -- the number of tries an attacker
	// actually gets. Only a guess that passed the cap reaches
	// bcrypt.CompareHashAndPassword, and only that guess is answered "invalid
	// verification code"; the rest are turned away by the cap or find the
	// challenge already closed.
	//
	// The old code read `attempts`, compared it, and incremented separately, so
	// eight callers could all read 0 and all pass a cap of three. The
	// increment-and-return below locks the row, so the fourth caller reads 4.
	const guesses = 8
	var (
		mu       sync.Mutex
		compared int
		wg       sync.WaitGroup
	)
	for i := 0; i < guesses; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.VerifyPhoneCallChallenge(ctx, userID, "000000")
			if err != nil && strings.Contains(err.Error(), "invalid verification code") {
				mu.Lock()
				compared++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if compared > maxPhoneCallAttempts {
		t.Errorf("%d of %d concurrent guesses were compared against the code; the cap is %d. Racing the "+
			"check against the counter is how a six-digit code gets more tries than it is worth.",
			compared, guesses, maxPhoneCallAttempts)
	}
	if compared == 0 {
		t.Error("no guess was compared against the code, so this test is not exercising the cap")
	}

	// And the correct code is dead: the cap was reached.
	if err := s.VerifyPhoneCallChallenge(ctx, userID, "123456"); err == nil {
		t.Error("the correct code was accepted after eight guesses")
	}
}

func TestAVerifiedPhoneCallLeavesAUsableFactor(t *testing.T) {
	const orgID = "00000000-0000-0000-0000-000000000093"
	const userID = "aaaaaaaa-0000-0000-0000-000000000093"
	s, ctx, cleanup := phoneCallFixture(t, orgID, userID, "123456")
	if s == nil {
		return
	}
	defer cleanup()

	if err := s.VerifyPhoneCallChallenge(ctx, userID, "123456"); err != nil {
		t.Fatalf("the correct code must verify: %v", err)
	}

	var status string
	var verified bool
	if err := s.db.Pool.QueryRow(ctx, `
		SELECT c.status, m.verified FROM phone_call_challenges c, mfa_phone_call m
		WHERE c.user_id = $1 AND m.user_id = $1`, userID).Scan(&status, &verified); err != nil {
		t.Fatalf("read them back: %v", err)
	}
	if status != "completed" {
		t.Errorf("after a successful verification the challenge is %q, want completed", status)
	}
	if !verified {
		t.Error("the person was told their phone was verified and the enrolment says otherwise; " +
			"InitiatePhoneCall reads verified = true to find a number to ring, so the factor is dead")
	}

	// The same code cannot be presented again.
	if err := s.VerifyPhoneCallChallenge(ctx, userID, "123456"); err == nil {
		t.Error("a spent phone-call challenge was accepted a second time")
	}
}

// Neither half of the verification lands without the other.
func TestAVerificationThatCannotFinishLeavesTheChallengeSpendable(t *testing.T) {
	const orgID = "00000000-0000-0000-0000-000000000094"
	const userID = "aaaaaaaa-0000-0000-0000-000000000094"
	s, ctx, cleanup := phoneCallFixture(t, orgID, userID, "123456")
	if s == nil {
		return
	}
	defer cleanup()

	// The challenge can be spent; the enrolment cannot be marked verified.
	if _, err := s.db.Pool.Exec(ctx, `
		CREATE FUNCTION refuse_enrolment() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'refusing the enrolment write'; END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER refuse_enrolment BEFORE UPDATE ON mfa_phone_call
		FOR EACH ROW EXECUTE FUNCTION refuse_enrolment();`); err != nil {
		t.Fatalf("install the failure: %v", err)
	}

	if err := s.VerifyPhoneCallChallenge(ctx, userID, "123456"); err == nil {
		t.Error("a verification that could not make the factor usable reported success. The person is " +
			"told their phone is verified and the factor never works.")
	}

	// The transaction rolled back, so the challenge is still there to try again
	// once the enrolment write is possible.
	var status string
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT status FROM phone_call_challenges WHERE user_id = $1`, userID).Scan(&status); err != nil {
		t.Fatalf("read the challenge back: %v", err)
	}
	if status == "completed" {
		t.Error("the challenge was spent even though the verification failed — the person now has " +
			"neither a working factor nor a challenge to retry")
	}

	if _, err := s.db.Pool.Exec(ctx, `DROP TRIGGER refuse_enrolment ON mfa_phone_call`); err != nil {
		t.Fatalf("remove the failure: %v", err)
	}
	if err := s.VerifyPhoneCallChallenge(ctx, userID, "123456"); err != nil {
		t.Errorf("with the database working again the same challenge must verify: %v", err)
	}
}
