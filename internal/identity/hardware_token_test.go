package identity

import (
	"context"
	"encoding/base32"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/secretcrypt"
)

// The physical second factor, which had no test.
//
// A hardware token is a six-digit code against a shared HOTP/TOTP seed, and
// three things stand between it and an attacker: the counter that makes a code
// single-use, the lockout that makes guessing expensive, and the status that
// makes a revoked token dead. All three were broken or absent.

const (
	hwUser  = "00000000-0000-0000-0000-0000000000a1"
	hwOther = "00000000-0000-0000-0000-0000000000a2"
	hwOrg   = "00000000-0000-0000-0000-000000000010"
)

// The v54 table plus v139's throttling columns. Hand-rolled rather than
// migrated because this package's other DB tests are, and hardware_tokens has
// no dependency beyond users.
const hardwareTokenSchema = `
CREATE TABLE IF NOT EXISTS organizations (id UUID PRIMARY KEY, name TEXT);
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY, username TEXT, org_id UUID, enabled BOOLEAN DEFAULT TRUE);
CREATE TABLE IF NOT EXISTS hardware_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL,
    serial_number VARCHAR(50) NOT NULL,
    name VARCHAR(255),
    token_type VARCHAR(50) NOT NULL DEFAULT 'yubikey',
    secret_key VARCHAR(255) NOT NULL,
    counter BIGINT DEFAULT 0,
    manufacturer VARCHAR(100),
    model VARCHAR(100),
    firmware_version VARCHAR(50),
    status VARCHAR(20) DEFAULT 'available',
    assigned_to UUID REFERENCES users(id) ON DELETE SET NULL,
    assigned_at TIMESTAMPTZ,
    assigned_by UUID REFERENCES users(id),
    last_used_at TIMESTAMPTZ,
    use_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    notes TEXT,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    last_failed_at TIMESTAMPTZ,
    locked_until TIMESTAMPTZ
);
-- v145: the serial is unique per organization, not across the install.
CREATE UNIQUE INDEX IF NOT EXISTS idx_hardware_tokens_org_serial ON hardware_tokens(org_id, serial_number);
CREATE TABLE IF NOT EXISTS hardware_token_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL,
    token_id UUID REFERENCES hardware_tokens(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(50) NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    details JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);`

func newHardwareTokenService(t *testing.T) (*Service, context.Context) {
	t.Helper()

	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)

	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, hardwareTokenSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO organizations (id) VALUES ($1) ON CONFLICT DO NOTHING`, hwOrg); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	for id, name := range map[string]string{hwUser: "alice", hwOther: "bob"} {
		if _, err := db.Pool.Exec(ctx,
			`INSERT INTO users (id, username, org_id) VALUES ($1, $2, $3)`, id, name, hwOrg); err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
	}

	// A real AES-GCM cipher, not the Noop: the seed is stored encrypted and
	// read back on every verification, so a test on the Noop path would not
	// exercise the round trip a deployment uses.
	cipher, err := secretcrypt.New("hardware-token-test-key-32-bytes")
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}

	// Since v145 every query in hardware_token.go takes its tenant from the
	// context, so the harness has to supply one the way a request would.
	return &Service{db: db, cfg: &config.Config{}, logger: zap.NewNop(), idpCipher: cipher},
		orgctx.With(ctx, orgctx.Org{ID: hwOrg})
}

// issueToken registers a token with a known seed and assigns it, returning the
// token id and the raw base32 seed so the test can compute valid codes.
func issueToken(t *testing.T, s *Service, ctx context.Context, serial, tokenType, assignTo string) (string, []byte) {
	t.Helper()

	seed := []byte("12345678901234567890") // RFC 4226's test seed
	b32 := base32.StdEncoding.EncodeToString(seed)

	tok, err := s.CreateHardwareToken(ctx, &CreateHardwareTokenRequest{
		SerialNumber: serial,
		Name:         serial,
		TokenType:    tokenType,
		SecretKey:    b32,
	}, hwOther)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	if assignTo != "" {
		if err := s.AssignHardwareToken(ctx, tok.ID, assignTo, hwOther); err != nil {
			t.Fatalf("assign token: %v", err)
		}
	}
	return tok.ID, seed
}

func tokenColumn[T any](t *testing.T, s *Service, ctx context.Context, tokenID, column string) T {
	t.Helper()
	var v T
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT `+column+` FROM hardware_tokens WHERE id = $1`, tokenID).Scan(&v); err != nil {
		t.Fatalf("read %s: %v", column, err)
	}
	return v
}

// --------------------------------------------------------------------------
// Single use.
// --------------------------------------------------------------------------

// The counter is what makes an HOTP code single-use, and advancing it was a
// fire-and-forget Exec whose error was discarded. A failed write left the
// counter where it was and the same code kept working -- silently, for as long
// as the write kept failing. Verification now refuses when the code cannot be
// spent, because a code that cannot be spent has not been verified.
func TestHardwareTokenCodeIsSpentOnce(t *testing.T) {
	s, ctx := newHardwareTokenService(t)
	tokenID, seed := issueToken(t, s, ctx, "HW-ONCE", "oath-hotp", hwUser)

	code := generateHOTP(seed, 0)

	ok, err := s.VerifyHardwareToken(ctx, hwUser, code, "203.0.113.7", "ua")
	if err != nil || !ok {
		t.Fatalf("first use: ok=%v err=%v, want true/nil", ok, err)
	}
	if got := tokenColumn[int64](t, s, ctx, tokenID, "counter"); got != 1 {
		t.Errorf("counter = %d after one use, want 1", got)
	}

	ok, err = s.VerifyHardwareToken(ctx, hwUser, code, "203.0.113.7", "ua")
	if ok {
		t.Error("the same code verified twice; the counter did not spend it")
	}
	if err != nil {
		t.Errorf("a replayed code is a wrong code, not an error: %v", err)
	}
}

// The look-ahead exists for a token pressed while out of range of the server.
// It must move the counter PAST the code that matched, not to the code's own
// position, or every code in the window stays live.
func TestHardwareTokenLookAheadAdvancesPastTheMatch(t *testing.T) {
	s, ctx := newHardwareTokenService(t)
	tokenID, seed := issueToken(t, s, ctx, "HW-DRIFT", "oath-hotp", hwUser)

	// The user pressed the button six times out of range; the seventh reaches us.
	ok, err := s.VerifyHardwareToken(ctx, hwUser, generateHOTP(seed, 6), "203.0.113.7", "ua")
	if err != nil || !ok {
		t.Fatalf("a code inside the look-ahead must verify: ok=%v err=%v", ok, err)
	}
	if got := tokenColumn[int64](t, s, ctx, tokenID, "counter"); got != 7 {
		t.Errorf("counter = %d, want 7 (past the match, not at it)", got)
	}
	// And every skipped code is now behind the counter.
	for i := int64(0); i <= 6; i++ {
		if ok, _ := s.VerifyHardwareToken(ctx, hwUser, generateHOTP(seed, i), "203.0.113.7", "ua"); ok {
			t.Fatalf("code for counter %d still verifies after the window moved", i)
		}
	}
}

// --------------------------------------------------------------------------
// Throttling (migration v139).
// --------------------------------------------------------------------------

// Six digits, a look-ahead of ten counters and a +/-1 TOTP step: roughly eleven
// of a million values are live at any instant, and nothing counted failures.
// The mfa_totp factor has had a lockout for exactly this reason; this one did
// not, so the same account was throttled on one factor and not the other.
func TestHardwareTokenLocksOutAfterRepeatedFailures(t *testing.T) {
	s, ctx := newHardwareTokenService(t)
	tokenID, seed := issueToken(t, s, ctx, "HW-LOCK", "oath-hotp", hwUser)

	for i := 0; i < hardwareTokenMaxAttempts; i++ {
		ok, err := s.VerifyHardwareToken(ctx, hwUser, "000000", "203.0.113.7", "ua")
		if ok {
			t.Fatalf("attempt %d: a wrong code verified", i+1)
		}
		if err != nil {
			t.Fatalf("attempt %d: a wrong code is not an error: %v", i+1, err)
		}
	}
	if got := tokenColumn[int](t, s, ctx, tokenID, "failed_attempts"); got != hardwareTokenMaxAttempts {
		t.Errorf("failed_attempts = %d, want %d", got, hardwareTokenMaxAttempts)
	}

	// Locked. And a CORRECT code is refused too -- otherwise the lockout only
	// slows down someone who is already failing.
	ok, err := s.VerifyHardwareToken(ctx, hwUser, generateHOTP(seed, 0), "203.0.113.7", "ua")
	if ok {
		t.Fatal("a locked token verified a correct code")
	}
	if !errors.Is(err, ErrHardwareTokenLockedOut) {
		t.Fatalf("err = %v, want ErrHardwareTokenLockedOut so the caller can say 'wait' rather than 'wrong code'", err)
	}
	if until := tokenColumn[*time.Time](t, s, ctx, tokenID, "locked_until"); until == nil || !until.After(time.Now()) {
		t.Errorf("locked_until = %v, want a future time", until)
	}
}

// A success clears the counter, so an honest user who mistypes four times and
// then gets it right is not one typo from a lockout for the rest of the day.
func TestHardwareTokenSuccessClearsTheFailureCount(t *testing.T) {
	s, ctx := newHardwareTokenService(t)
	tokenID, seed := issueToken(t, s, ctx, "HW-CLEAR", "oath-hotp", hwUser)

	for i := 0; i < hardwareTokenMaxAttempts-1; i++ {
		if ok, _ := s.VerifyHardwareToken(ctx, hwUser, "000000", "203.0.113.7", "ua"); ok {
			t.Fatal("a wrong code verified")
		}
	}
	if ok, err := s.VerifyHardwareToken(ctx, hwUser, generateHOTP(seed, 0), "203.0.113.7", "ua"); !ok || err != nil {
		t.Fatalf("the correct code below the threshold must verify: ok=%v err=%v", ok, err)
	}
	if got := tokenColumn[int](t, s, ctx, tokenID, "failed_attempts"); got != 0 {
		t.Errorf("failed_attempts = %d after a success, want 0", got)
	}
}

// --------------------------------------------------------------------------
// Lifecycle: assignment and revocation.
// --------------------------------------------------------------------------

func TestHardwareTokenAssignmentIsExclusive(t *testing.T) {
	s, ctx := newHardwareTokenService(t)
	tokenID, _ := issueToken(t, s, ctx, "HW-EXCL", "oath-hotp", hwUser)

	// A token already assigned cannot be handed to someone else without being
	// unassigned first -- otherwise two people hold the same credential and the
	// audit trail names one of them.
	if err := s.AssignHardwareToken(ctx, tokenID, hwOther, hwOther); err == nil {
		t.Fatal("an assigned token was reassigned without being unassigned")
	}
	if err := s.UnassignHardwareToken(ctx, tokenID, hwOther); err != nil {
		t.Fatalf("unassign: %v", err)
	}
	if err := s.AssignHardwareToken(ctx, tokenID, hwOther, hwOther); err != nil {
		t.Fatalf("reassign after unassign: %v", err)
	}
}

// A revoked token is dead: verification finds no assigned token for the user
// even though assigned_to still names them.
func TestRevokedHardwareTokenCannotVerify(t *testing.T) {
	s, ctx := newHardwareTokenService(t)
	tokenID, seed := issueToken(t, s, ctx, "HW-REVOKE", "oath-hotp", hwUser)

	if ok, err := s.VerifyHardwareToken(ctx, hwUser, generateHOTP(seed, 0), "203.0.113.7", "ua"); !ok || err != nil {
		t.Fatalf("precondition: the token must work before revocation: ok=%v err=%v", ok, err)
	}
	if err := s.RevokeHardwareToken(ctx, tokenID, hwOther, "returned"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if ok, _ := s.VerifyHardwareToken(ctx, hwUser, generateHOTP(seed, 1), "203.0.113.7", "ua"); ok {
		t.Fatal("a revoked token still verifies")
	}
	if got := tokenColumn[string](t, s, ctx, tokenID, "status"); got != "revoked" {
		t.Errorf("status = %q, want revoked", got)
	}
}

// An UPDATE that matches no row succeeds, so revoking a token that is not there
// returned nil and wrote a "revoked" event for it. An administrator acting on a
// stale id -- or a typo'd one -- was told the credential was dead while it went
// on working. Both of these are red before the fix.
func TestRevokingAnUnknownHardwareTokenFails(t *testing.T) {
	s, ctx := newHardwareTokenService(t)
	const ghost = "00000000-0000-0000-0000-0000000000ff"

	if err := s.RevokeHardwareToken(ctx, ghost, hwOther, "typo"); !errors.Is(err, ErrHardwareTokenNotFound) {
		t.Errorf("revoke of an unknown token: err = %v, want ErrHardwareTokenNotFound", err)
	}
	if err := s.ReportTokenLost(ctx, ghost, hwOther); !errors.Is(err, ErrHardwareTokenNotFound) {
		t.Errorf("report-lost of an unknown token: err = %v, want ErrHardwareTokenNotFound", err)
	}

	var events int
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM hardware_token_events WHERE token_id = $1`, ghost).Scan(&events); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if events != 0 {
		t.Errorf("%d lifecycle events written for a token that does not exist", events)
	}
}

// A token nobody holds cannot be used, and a user with no token gets a refusal
// that does not depend on the code they supplied.
func TestVerifyWithoutAnAssignedHardwareToken(t *testing.T) {
	s, ctx := newHardwareTokenService(t)
	_, seed := issueToken(t, s, ctx, "HW-UNASSIGNED", "oath-hotp", "")

	ok, err := s.VerifyHardwareToken(ctx, hwUser, generateHOTP(seed, 0), "203.0.113.7", "ua")
	if ok {
		t.Fatal("an unassigned token verified for a user")
	}
	if err == nil {
		t.Fatal("want an error naming the missing assignment")
	}
}

// The fail-closed half of single use, forced.
//
// The counter advance used to be `s.db.Pool.Exec(...)` with the error dropped
// on the floor, so a write that failed left the counter untouched and returned
// true anyway -- the code stayed live and the caller was told the second factor
// had passed. A trigger stands in for whatever makes that write fail (a full
// disk, a lock timeout, a permissions change): the verification must refuse,
// not succeed with an unspent code.
func TestHardwareTokenRefusesWhenTheCodeCannotBeSpent(t *testing.T) {
	s, ctx := newHardwareTokenService(t)
	tokenID, seed := issueToken(t, s, ctx, "HW-NOSPEND", "oath-hotp", hwUser)

	for _, stmt := range []string{
		`CREATE OR REPLACE FUNCTION hw_block_counter() RETURNS trigger LANGUAGE plpgsql AS
		 'BEGIN RAISE EXCEPTION ''counter update blocked''; END;'`,
		`CREATE TRIGGER hw_block_counter_trg BEFORE UPDATE ON hardware_tokens
		 FOR EACH ROW WHEN (NEW.counter IS DISTINCT FROM OLD.counter)
		 EXECUTE FUNCTION hw_block_counter()`,
	} {
		if _, err := s.db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("install trigger: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = s.db.Pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS hw_block_counter_trg ON hardware_tokens`)
	})

	ok, err := s.VerifyHardwareToken(ctx, hwUser, generateHOTP(seed, 0), "203.0.113.7", "ua")
	if ok {
		t.Fatal("verification succeeded with a code it could not spend")
	}
	if err == nil {
		t.Fatal("want an error naming the failed counter advance")
	}
	if got := tokenColumn[int64](t, s, ctx, tokenID, "counter"); got != 0 {
		t.Errorf("counter = %d, want 0 (the write was blocked)", got)
	}
}
