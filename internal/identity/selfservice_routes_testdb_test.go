package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/auth"
	"github.com/openidx/openidx/internal/common/cell"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/pwhash"
	"github.com/openidx/openidx/internal/organization"
)

// selfServiceHarness is identity-service's route table wired the way
// cmd/identity-service wires it -- the tenant resolver on the engine, then
// RegisterRoutesForProfile with the cell guard -- over a migrated database and
// a miniredis, with a JWKS endpoint serving the key that signs each caller's
// token. Nothing below the router is stubbed: a request is authenticated by
// openIDXAuthMiddleware, tiered by requireAdminUnlessSelfService and answered
// by the real handler against the product's schema.
type selfServiceHarness struct {
	t      *testing.T
	db     *database.PostgresDB
	svc    *Service
	router *gin.Engine
	issuer string
	suffix string
	redis  *miniredis.Miniredis
	mailer *recordingMailer
}

const harnessPassword = "correct horse battery staple 42"

func newSelfServiceHarness(t *testing.T) *selfServiceHarness {
	t.Helper()
	db, cleanup := setupMigratedDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)
	gin.SetMode(gin.TestMode)

	mini := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rc.Close() })
	rdb := &database.RedisClient{Client: rc}

	jwks := jwksServer(t)
	cfg := &config.Config{Environment: "production", OAuthIssuer: "https://issuer.test", OAuthJWKSURL: jwks.URL}
	// Every factor the routes enroll is available: push, passkeys for the
	// console's origin, and (below) email and phone-call delivery.
	cfg.PushMFA.Enabled = true
	cfg.WebAuthn = config.WebAuthnConfig{RPID: "localhost", RPOrigins: []string{"http://localhost:3000"}, Timeout: 300}
	svc := NewService(db, rdb, cfg, zap.NewNop())
	mailer := &recordingMailer{}
	svc.SetEmailService(mailer)
	svc.SetPhoneCallProvider(&recordingCaller{})

	r := gin.New()
	r.Use(middleware.TenantResolver(
		organization.NewOrgLookup(organization.NewService(db, rdb, cfg, zap.NewNop())),
		middleware.TenantResolverConfig{
			DefaultOrgFallback:     true,
			DefaultOrgID:           middleware.DefaultOrgID,
			PlatformAdminPredicate: auth.SuperAdminPredicate,
		}))
	RegisterRoutesForProfile(r, svc, ProfileAll, cell.Guard(cfg.CellID, zap.NewNop()))

	return &selfServiceHarness{
		t: t, db: db, svc: svc, router: r, issuer: cfg.OAuthIssuer,
		suffix: fmt.Sprintf("%d", time.Now().UnixNano()), redis: mini, mailer: mailer,
	}
}

// seedUser creates an enabled user of the default organization whose password
// is harnessPassword.
func (h *selfServiceHarness) seedUser(name string) string {
	h.t.Helper()
	hash, err := pwhash.Hash(harnessPassword)
	if err != nil {
		h.t.Fatalf("hash password: %v", err)
	}
	var id string
	if err := h.db.Pool.QueryRow(h.seedCtx(), `
		INSERT INTO users (org_id, username, email, enabled, password_hash)
		VALUES ($1::uuid, $2, $3, true, $4) RETURNING id::text`,
		middleware.DefaultOrgID, name+"-"+h.suffix, name+"-"+h.suffix+"@example.test", hash).Scan(&id); err != nil {
		h.t.Fatalf("seed user %s: %v", name, err)
	}
	return id
}

// seedTOTP enrolls a TOTP credential for userID directly, as enrollment leaves
// one, and returns its secret.
func (h *selfServiceHarness) seedTOTP(userID string) string {
	h.t.Helper()
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "OpenIDX", AccountName: userID})
	if err != nil {
		h.t.Fatalf("generate TOTP key: %v", err)
	}
	h.exec(`INSERT INTO mfa_totp (user_id, secret, enabled, enrolled_at, org_id)
		VALUES ($1::uuid, $2, true, NOW(), $3::uuid)`, userID, key.Secret(), middleware.DefaultOrgID)
	return key.Secret()
}

func (h *selfServiceHarness) seedCtx() context.Context {
	return orgctx.WithBypassRLS(context.Background())
}

func (h *selfServiceHarness) exec(query string, args ...interface{}) {
	h.t.Helper()
	if _, err := h.db.Pool.Exec(h.seedCtx(), query, args...); err != nil {
		h.t.Fatalf("exec %q: %v", query, err)
	}
}

// scalar reads one value as text.
func (h *selfServiceHarness) scalar(query string, args ...interface{}) string {
	h.t.Helper()
	var v string
	if err := h.db.Pool.QueryRow(h.seedCtx(), query, args...).Scan(&v); err != nil {
		h.t.Fatalf("read %q: %v", query, err)
	}
	return v
}

func (h *selfServiceHarness) count(query string, args ...interface{}) int {
	h.t.Helper()
	var n int
	if err := h.db.Pool.QueryRow(h.seedCtx(), query, args...).Scan(&n); err != nil {
		h.t.Fatalf("count %q: %v", query, err)
	}
	return n
}

// bearer mints the access token a sign-in to the console gives userID.
func (h *selfServiceHarness) bearer(userID string) string {
	h.t.Helper()
	return h.bearerWithRoles(userID, "user")
}

func (h *selfServiceHarness) bearerWithRoles(userID string, roles ...string) string {
	h.t.Helper()
	return token(h.t, h.issuer, jwt.MapClaims{"sub": userID, "roles": roles})
}

// do sends one request through the route table and decodes a JSON answer.
func (h *selfServiceHarness) do(method, path, bearer string, body interface{}) (int, map[string]interface{}) {
	h.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			h.t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, reader)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	h.router.ServeHTTP(w, req)
	var out map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// totpCode is the code an authenticator holding secret shows at `at`.
func totpCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, at.UTC())
	if err != nil {
		t.Fatalf("generate TOTP code: %v", err)
	}
	return code
}

// recordingMailer stands in for the SMTP service: it accepts every message,
// and keeps the one-time codes it is asked to send.
type recordingMailer struct {
	mu    sync.Mutex
	sent  []string
	codes []string
}

func (m *recordingMailer) record(to string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, to)
	return nil
}

// lastCode is the code in the latest one-time-code message.
func (m *recordingMailer) lastCode() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.codes) == 0 {
		return ""
	}
	return m.codes[len(m.codes)-1]
}

func (m *recordingMailer) SendVerificationEmail(_ context.Context, to, _, _, _ string) error {
	return m.record(to)
}
func (m *recordingMailer) SendInvitationEmail(_ context.Context, to, _, _, _ string) error {
	return m.record(to)
}
func (m *recordingMailer) SendPasswordResetEmail(_ context.Context, to, _, _, _ string) error {
	return m.record(to)
}
func (m *recordingMailer) SendWelcomeEmail(_ context.Context, to, _, _ string) error {
	return m.record(to)
}
func (m *recordingMailer) SendAsync(_ context.Context, to, _, _ string, data map[string]interface{}) error {
	if code, ok := data["Code"].(string); ok {
		m.mu.Lock()
		m.codes = append(m.codes, code)
		m.mu.Unlock()
	}
	return m.record(to)
}

// recordingCaller stands in for the telephony provider: every call connects.
type recordingCaller struct{}

func (recordingCaller) InitiateCall(_, _, _ string) (string, error) { return "CA-test", nil }
func (recordingCaller) GetCallStatus(string) (string, error)        { return "completed", nil }
