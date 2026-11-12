package identity

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// Google and Microsoft Authenticator only honour SHA1, 30 s and 6 digits
// (others are ignored or rejected), so the otpauth URI must say exactly that,
// and a code an app computes from the secret with those parameters must enrol.
func TestGenerateTOTPSecretIsAuthenticatorCompatible(t *testing.T) {
	db, cleanup := setupMigratedDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	seed := orgctx.WithBypassRLS(context.Background())
	const org = "00000000-0000-0000-0000-000000000010"
	var userID string
	if err := db.Pool.QueryRow(seed,
		`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
		org, fmt.Sprintf("interop-%d", time.Now().UnixNano())).Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	svc := NewService(db, nil, &config.Config{}, zap.NewNop())
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: org})

	e, err := svc.GenerateTOTPSecret(ctx, userID)
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	u, err := url.Parse(e.QRCodeURL)
	if err != nil || u.Scheme != "otpauth" || u.Host != "totp" {
		t.Fatalf("not an otpauth://totp URI: %q", e.QRCodeURL)
	}
	q := u.Query()
	if q.Get("algorithm") != "SHA1" || q.Get("period") != "30" || q.Get("digits") != "6" {
		t.Fatalf("authenticator parameters = algorithm %q period %q digits %q, want SHA1/30/6", q.Get("algorithm"), q.Get("period"), q.Get("digits"))
	}
	if q.Get("secret") != e.Secret || e.ManualKey != e.Secret {
		t.Fatalf("URI secret, manual key and stored secret differ")
	}
	code, err := totp.GenerateCodeCustom(e.Secret, time.Now(), totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.EnrollTOTP(ContextWithActorID(ctx, userID), userID, e.Secret, code); err != nil {
		t.Fatalf("a SHA1/30s/6 code from the secret was refused: %v", err)
	}
}
