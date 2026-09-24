package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/identity"
	"github.com/openidx/openidx/internal/migrations"
)

// sessionEndOrg is the default organization, seeded by migrations.
const sessionEndOrg = "00000000-0000-0000-0000-000000000010"

// sessionEndFixture is a signed-in world on the migrated schema: the identity
// and OAuth services wired to each other the way the product wires them, one
// confidential client that may hold refresh tokens, and an in-memory Redis a
// test can stop, restart and move forward in time.
//
// The tests that use it all have the same shape, the one
// TestAnEndedSessionCannotRefresh set: sessions are created the way login
// creates them, one is ended through the product path under test, and then
// the devices present their refresh tokens at the token endpoint. The ended
// session must be refused and an unrelated one must keep working.
type sessionEndFixture struct {
	db       *database.PostgresDB
	mini     *miniredis.Miniredis
	rc       *database.RedisClient
	cfg      *config.Config
	ids      *identity.Service
	svc      *Service
	orgCtx   context.Context
	clientID string
	secret   string
	suffix   string
	seq      int
}

func newSessionEndFixture(t *testing.T) *sessionEndFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, cleanup := ssfSetupTestDB(t)
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	f := &sessionEndFixture{
		db:     db,
		orgCtx: orgctx.With(ctx, orgctx.Org{ID: sessionEndOrg}),
		suffix: fmt.Sprintf("%d", time.Now().UnixNano()),
		secret: "s3cret",
	}
	f.clientID = "sess-app-" + f.suffix
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO oauth_clients (client_id, client_secret, name, type, allow_refresh_token, org_id)
		VALUES ($1, $2, $1, 'confidential', true, $3::uuid)`, f.clientID, f.secret, sessionEndOrg); err != nil {
		t.Fatalf("seed client: %v", err)
	}

	f.mini = miniredis.RunT(t)
	f.rc = &database.RedisClient{Client: redis.NewClient(&redis.Options{Addr: f.mini.Addr()})}
	f.cfg = &config.Config{OAuthIssuer: "https://session-end.test"}
	f.ids = identity.NewService(db, f.rc, f.cfg, zap.NewNop())
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	f.svc = &Service{
		db:              db,
		redis:           f.rc,
		config:          f.cfg,
		logger:          zap.NewNop(),
		privateKey:      key,
		publicKey:       &key.PublicKey,
		issuer:          f.cfg.OAuthIssuer,
		clients:         NewPostgresOAuthClientStore(db),
		identityService: f.ids,
	}
	return f
}

// seedUser inserts an enabled local user in the default organization.
func (f *sessionEndFixture) seedUser(t *testing.T, name string) string {
	t.Helper()
	var id string
	if err := f.db.Pool.QueryRow(context.Background(), `
		INSERT INTO users (org_id, username, email, first_name, last_name, enabled)
		VALUES ($1::uuid, $2, $3, 'Test', 'User', true) RETURNING id::text`,
		sessionEndOrg, name+"-"+f.suffix, name+"-"+f.suffix+"@example.test").Scan(&id); err != nil {
		t.Fatalf("seed user %s: %v", name, err)
	}
	return id
}

// newSession is a signed-in device: a session as login creates it and the
// refresh token issued to it.
func (f *sessionEndFixture) newSession(t *testing.T, userID string) (sessionID, refreshToken string) {
	t.Helper()
	sess, err := f.ids.CreateSession(f.orgCtx, userID, f.clientID, "203.0.113.9", "evidence-run", time.Hour)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return sess.ID, f.mintRefresh(t, userID, sess.ID)
}

// mintRefresh issues another refresh token, a chain of its own, bound to
// sessionID ("" for none, as the device authorization grant issues them).
func (f *sessionEndFixture) mintRefresh(t *testing.T, userID, sessionID string) string {
	t.Helper()
	f.seq++
	tok := fmt.Sprintf("rt-%d-%s", f.seq, sessionID)
	if sessionID == "" {
		tok = fmt.Sprintf("rt-%d-no-session-%s", f.seq, userID)
	}
	if err := f.svc.CreateRefreshToken(f.orgCtx, &RefreshToken{
		Token: tok, ClientID: f.clientID, UserID: userID, Scope: "openid offline_access",
		SessionID: sessionID, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("mint refresh token: %v", err)
	}
	return tok
}

// refresh presents the token at the token endpoint. On success it returns
// the rotated refresh token, which is what the device holds next.
func (f *sessionEndFixture) refresh(t *testing.T, tok string) (int, string, map[string]interface{}) {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	form := creds(f.clientID, f.secret, "grant_type", "refresh_token", "refresh_token", tok)
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.Request = req.WithContext(f.orgCtx)
	f.svc.handleRefreshTokenGrant(c)
	body := map[string]interface{}{}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	next, _ := body["refresh_token"].(string)
	return w.Code, next, body
}

// refreshes asserts that a device whose session is live can refresh, and
// returns the rotated token it holds next.
func (f *sessionEndFixture) refreshes(t *testing.T, tok, what string) string {
	t.Helper()
	code, next, body := f.refresh(t, tok)
	if code != http.StatusOK || body["access_token"] == nil || next == "" {
		t.Fatalf("%s must keep refreshing: %d %v", what, code, body)
	}
	return next
}

// cannotRefresh asserts that the token endpoint refuses tok.
func (f *sessionEndFixture) cannotRefresh(t *testing.T, tok, what string) {
	t.Helper()
	if code, _, body := f.refresh(t, tok); code != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Errorf("%s refreshed: status %d, access token issued: %t. A device on a session that was ended "+
			"keeps minting access tokens until its refresh token expires.", what, code, body["access_token"] != nil)
	}
}

// The Session row of docs/evidence/display-equals-enforcement.md, through the
// product: a session created the way login creates it, a refresh token bound to
// it, the session ended the way the Sessions pages end it, and then a refresh.
//
// A user who ends a session from their profile, or from the Sessions page
// without the admin role, calls DELETE /api/v1/identity/sessions/:id, which is
// identity.TerminateSession. The refresh grant decides on two things: the
// refresh token's own row, and the revoked_session:<id> marker in Redis. Ending
// a session has to reach one of them. Otherwise the device the user signed out
// keeps minting access tokens until its refresh token expires.
func TestAnEndedSessionCannotRefresh(t *testing.T) {
	f := newSessionEndFixture(t)
	userID := f.seedUser(t, "sess")
	sessionID, device := f.newSession(t, userID)
	_, otherDevice := f.newSession(t, userID)

	t.Run("a live session refreshes", func(t *testing.T) {
		code, next, body := f.refresh(t, device)
		if code != http.StatusOK || body["access_token"] == nil || next == "" {
			t.Fatalf("a live session must refresh: %d %v", code, body)
		}
		device = next
	})
	t.Run("the session the user ended does not", func(t *testing.T) {
		if err := f.ids.TerminateSession(f.orgCtx, sessionID); err != nil {
			t.Fatalf("end the session: %v", err)
		}
		if code, _, body := f.refresh(t, device); code != http.StatusBadRequest || body["error"] != "invalid_grant" {
			t.Errorf("the ended session refreshed: %d %v. The device that was signed out keeps "+
				"minting access tokens until its refresh token expires.", code, body)
		}
		if !f.mini.Exists("revoked_session:" + sessionID) {
			t.Error("no revoked_session marker was published, unlike every other path that ends a session")
		}
	})
	t.Run("the user's other session keeps refreshing", func(t *testing.T) {
		if code, _, body := f.refresh(t, otherDevice); code != http.StatusOK {
			t.Errorf("ending one session stopped another from refreshing: %d %v", code, body)
		}
	})
	// The marker lives in Redis, which can be down or restarted empty. The
	// refresh tokens' own rows are what has to hold then.
	t.Run("with Redis down, an ended session still does not refresh", func(t *testing.T) {
		sid, dev := f.newSession(t, userID)
		code, next, body := f.refresh(t, dev)
		if code != http.StatusOK || next == "" {
			t.Fatalf("a live session must refresh: %d %v", code, body)
		}
		f.mini.Close()
		if err := f.ids.TerminateSession(f.orgCtx, sid); err != nil {
			t.Fatalf("ending a session must not depend on Redis: %v", err)
		}
		if code, _, body := f.refresh(t, next); code != http.StatusBadRequest || body["error"] != "invalid_grant" {
			t.Errorf("with no marker to read, the ended session refreshed: %d %v", code, body)
		}
	})
}
