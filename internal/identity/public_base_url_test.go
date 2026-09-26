package identity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// Password reset, email verification and invitation links were hardcoded to
// http://localhost:3000 or http://localhost:<this service's port>. The second
// is wrong even in development — it addresses the API listener, not the browser
// app, so the recipient lands on a JSON 404. Both make the three flows unusable
// in any real deployment, which is why PUBLIC_BASE_URL now exists.

func TestPublicBaseURL(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{
			name: "uses the configured public base URL",
			cfg:  &config.Config{PublicBaseURL: "https://id.example.com"},
			want: "https://id.example.com",
		},
		{
			name: "trims a trailing slash so callers can append a rooted path",
			cfg:  &config.Config{PublicBaseURL: "https://id.example.com/"},
			want: "https://id.example.com",
		},
		{
			name: "does not fall back to the API port",
			cfg:  &config.Config{Port: 8001},
			want: "http://localhost:3000",
		},
		{
			name: "tolerates a nil config",
			cfg:  nil,
			want: "http://localhost:3000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Service{cfg: tt.cfg}
			if got := s.publicBaseURL(); got != tt.want {
				t.Errorf("publicBaseURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

// recordingEmailer captures the baseURL each send was given.
type recordingEmailer struct {
	resetBaseURL   string
	welcomeBaseURL string
	welcomeSent    bool
}

func (r *recordingEmailer) SendVerificationEmail(ctx context.Context, to, userName, token, baseURL string) error {
	return nil
}

func (r *recordingEmailer) SendInvitationEmail(ctx context.Context, to, inviterName, token, baseURL string) error {
	return nil
}

func (r *recordingEmailer) SendPasswordResetEmail(ctx context.Context, to, userName, token, baseURL string) error {
	r.resetBaseURL = baseURL
	return nil
}

func (r *recordingEmailer) SendWelcomeEmail(ctx context.Context, to, userName, baseURL string) error {
	r.welcomeBaseURL, r.welcomeSent = baseURL, true
	return nil
}

func (r *recordingEmailer) SendAsync(ctx context.Context, to, subject, templateName string, data map[string]interface{}) error {
	return nil
}

// TestForgotPasswordUsesPublicBaseURL is the end-to-end half: the configured
// origin has to survive all the way into the mail, not merely be readable.
func TestForgotPasswordUsesPublicBaseURL(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	defer cleanup()

	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, authTestSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	seedAuthUser(t, db, ctx, authOrgA, "linkuser", "link@example.com", authGoodPassword)

	mailer := &recordingEmailer{}
	s := NewService(db, nil, &config.Config{PublicBaseURL: "https://id.example.com/"}, zap.NewNop())
	s.emailService = mailer

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/forgot-password",
		strings.NewReader(`{"email":"link@example.com"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Request = c.Request.WithContext(orgctx.With(ctx, orgctx.Org{ID: authOrgA}))

	s.handleForgotPassword(c)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}
	if mailer.resetBaseURL != "https://id.example.com" {
		t.Errorf("reset email baseURL = %q, want %q (was hardcoded to localhost:3000)",
			mailer.resetBaseURL, "https://id.example.com")
	}
	if strings.Contains(mailer.resetBaseURL, "localhost") {
		t.Errorf("reset link still points at localhost: %q", mailer.resetBaseURL)
	}
}

// TestTheWelcomeMailSignsInAtThePublicBaseURL accepts a real invitation. The
// welcome mail linked every new user to a docs page on a domain the project
// does not own; its button now signs in at PUBLIC_BASE_URL, the origin the
// reset and invitation links use, so the mail has to be handed that origin.
func TestTheWelcomeMailSignsInAtThePublicBaseURL(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	defer cleanup()

	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	const org = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	const token = "welcome-link-invitation-token"
	if _, err := db.Pool.Exec(orgctx.WithBypassRLS(ctx), `
		INSERT INTO user_invitations (email, invited_by, roles, groups, token, status, expires_at, org_id)
		VALUES ('invitee@example.test', gen_random_uuid(), '{}', '{}', $1, 'pending', NOW() + INTERVAL '1 day', $2::uuid)`,
		token, org); err != nil {
		t.Fatalf("seed invitation: %v", err)
	}

	mailer := &recordingEmailer{}
	s := NewService(db, nil, &config.Config{PublicBaseURL: "https://id.example.com/"}, zap.NewNop())
	s.emailService = mailer

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/invitations/"+token+"/accept",
		strings.NewReader(`{"username":"invitee","password":"Welc0me!Link-2026","first_name":"Ada"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Request = c.Request.WithContext(orgctx.With(ctx, orgctx.Org{ID: org}))
	c.Params = gin.Params{{Key: "token", Value: token}}

	s.handleAcceptInvitation(c)

	if w.Code != http.StatusCreated {
		t.Fatalf("accept invitation: status %d, body %s", w.Code, w.Body.String())
	}
	if !mailer.welcomeSent {
		t.Fatal("no welcome mail was sent")
	}
	if mailer.welcomeBaseURL != "https://id.example.com" {
		t.Errorf("welcome mail baseURL = %q, want https://id.example.com", mailer.welcomeBaseURL)
	}
}
