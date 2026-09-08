package identity

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// The whole path, against a real database: a settings row the admin console
// would have written, through the watcher that reads it, to the values a minted
// OTP challenge actually carries.
//
// The unit tests beside this one pin SetOTPSettings and otpConfig. This pins the
// two joins between them and the product — checkAndReloadSMSConfig applying the
// row, and createOTPChallenge consulting the result — which are exactly the
// joins that were missing: both halves were internally consistent and the
// setting reached nothing.
func TestAnAdministratorsOTPSettingsReachTheCodeThatIsSent(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := orgctx.WithBypassRLS(context.Background())
	for _, stmt := range []string{
		`CREATE TABLE organizations (id UUID PRIMARY KEY, name TEXT NOT NULL)`,
		`CREATE TABLE users (id UUID PRIMARY KEY, org_id UUID NOT NULL, email TEXT NOT NULL)`,
		`CREATE TABLE system_settings (
			key TEXT PRIMARY KEY,
			value JSONB NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE mfa_otp_challenges (
			id UUID PRIMARY KEY,
			org_id UUID NOT NULL,
			user_id UUID NOT NULL,
			method TEXT NOT NULL,
			recipient TEXT NOT NULL,
			code_hash TEXT NOT NULL,
			attempts INT NOT NULL,
			max_attempts INT NOT NULL,
			status TEXT NOT NULL,
			ip_address TEXT,
			user_agent TEXT,
			created_at TIMESTAMPTZ NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			verified_at TIMESTAMPTZ
		)`,
	} {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("create fixture schema: %v\n%s", err, stmt)
		}
	}

	const orgID = "00000000-0000-0000-0000-000000000010"
	const userID = "00000000-0000-0000-0000-0000000000a1"
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO organizations (id, name) VALUES ($1, 'fixture')`, orgID); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO users (id, org_id, email) VALUES ($1, $2, 'otp@example.com')`, userID, orgID); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// The row the console's Settings → SMS page writes. Development, so the
	// mock provider is allowed to construct — the assertions below are about the
	// three numbers, not the transport.
	cfg := &config.Config{Environment: "development"}
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO system_settings (key, value) VALUES ('sms_config', $1::jsonb)`,
		`{"enabled":true,"provider":"mock","message_prefix":"OpenIDX",
		  "otp_length":8,"otp_expiry":60,"max_attempts":5,"credentials":{}}`); err != nil {
		t.Fatalf("store sms_config: %v", err)
	}

	s := &Service{db: db, cfg: cfg, logger: zap.NewNop()}

	if got := s.otpConfig(); got != DefaultOTPConfig() {
		t.Fatalf("before the watcher runs the settings must be the defaults, got %+v", got)
	}

	var last time.Time
	s.checkAndReloadSMSConfig(ctx, &last)

	applied := s.otpConfig()
	if applied.CodeLength != 8 || applied.ExpirationTime != 60*time.Second || applied.MaxAttempts != 5 {
		t.Fatalf("the stored settings did not reach the service: %+v", applied)
	}

	// And the join that was actually broken: a challenge minted now must carry
	// them. createOTPChallenge called DefaultOTPConfig() and nothing supplied
	// anything else, so this is the assertion that fails if that returns.
	code, err := s.createOTPChallenge(ctx, userID, "sms", "+15550100")
	if err != nil {
		t.Fatalf("createOTPChallenge: %v", err)
	}
	if len(code) != 8 {
		t.Errorf("the code is %d digits (%q); the administrator asked for 8", len(code), code)
	}

	var maxAttempts int
	var createdAt, expiresAt time.Time
	if err := db.Pool.QueryRow(ctx, `
		SELECT max_attempts, created_at, expires_at FROM mfa_otp_challenges WHERE user_id = $1`,
		userID).Scan(&maxAttempts, &createdAt, &expiresAt); err != nil {
		t.Fatalf("read back the challenge: %v", err)
	}
	if maxAttempts != 5 {
		t.Errorf("the challenge allows %d attempts; the administrator set 5", maxAttempts)
	}
	// Exactly 60s, not approximately: createOTPChallenge takes one clock reading
	// for both columns. It used to take two, so the stored lifetime carried
	// whatever elapsed between them — a microsecond on an idle machine, enough
	// to fail this assertion under the race detector, and never what was asked
	// for. The assertion is exact so that regression cannot come back as
	// "close enough".
	if lifetime := expiresAt.Sub(createdAt); lifetime != 60*time.Second {
		t.Errorf("the code lives %v; the administrator set 60s", lifetime)
	}
}
