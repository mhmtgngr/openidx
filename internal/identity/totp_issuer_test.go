package identity

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
)

func TestSanitizeTOTPIssuer(t *testing.T) {
	for in, want := range map[string]string{
		"Acme Corp":        "Acme Corp",
		"  Acme: Corp \t":  "Acme- Corp",
		"a:b:c":            "a-b-c",
		"Line\nBreak":      "LineBreak",
		"":                 defaultTOTPIssuer,
		"   ":              defaultTOTPIssuer,
		"\x00\x01":         defaultTOTPIssuer,
		"Şirket Güvenliği": "Şirket Güvenliği",
	} {
		if got := sanitizeTOTPIssuer(in); got != want {
			t.Errorf("sanitizeTOTPIssuer(%q) = %q, want %q", in, got, want)
		}
	}
}

// With no organization or no database the issuer is the product name.
func TestTOTPIssuerFallsBackWithoutAnOrganization(t *testing.T) {
	svc := &Service{logger: zap.NewNop()}
	if got := svc.totpIssuer(context.Background()); got != defaultTOTPIssuer {
		t.Fatalf("no org: issuer = %q", got)
	}
	if got := svc.totpIssuer(orgctx.With(context.Background(), orgctx.Org{ID: "x"})); got != defaultTOTPIssuer {
		t.Fatalf("no database: issuer = %q", got)
	}
}

// The otpauth URI an enrollment hands the authenticator names the user's
// organization, sanitized, and falls back to the product name for an
// organization whose name is blank.
func TestGenerateTOTPSecretIssuerIsTheOrganization(t *testing.T) {
	db, cleanup := setupMigratedDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	seed := orgctx.WithBypassRLS(context.Background())
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	svc := NewService(db, nil, &config.Config{}, zap.NewNop())

	enroll := func(orgName string) (issuer string, label string) {
		t.Helper()
		var orgID, userID string
		if err := db.Pool.QueryRow(seed,
			`INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text`,
			orgName, "issuer-"+suffix+fmt.Sprint(len(orgName))).Scan(&orgID); err != nil {
			t.Fatalf("seed org: %v", err)
		}
		if err := db.Pool.QueryRow(seed,
			`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
			orgID, "issuer-user-"+orgID).Scan(&userID); err != nil {
			t.Fatalf("seed user: %v", err)
		}
		e, err := svc.GenerateTOTPSecret(orgctx.With(context.Background(), orgctx.Org{ID: orgID}), userID)
		if err != nil {
			t.Fatalf("GenerateTOTPSecret: %v", err)
		}
		key, err := otp.NewKeyFromURL(e.QRCodeURL)
		if err != nil {
			t.Fatalf("parse %q: %v", e.QRCodeURL, err)
		}
		u, _ := url.Parse(e.QRCodeURL)
		return key.Issuer(), u.Path
	}

	if issuer, label := enroll("Acme: Widgets"); issuer != "Acme- Widgets" {
		t.Fatalf("issuer = %q (label %q), want %q", issuer, label, "Acme- Widgets")
	}
	if issuer, _ := enroll("   "); issuer != defaultTOTPIssuer {
		t.Fatalf("blank org name: issuer = %q, want %q", issuer, defaultTOTPIssuer)
	}
}
