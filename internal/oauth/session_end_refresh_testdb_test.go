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
	gin.SetMode(gin.TestMode)
	db, cleanup := ssfSetupTestDB(t)
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const org = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	orgCtx := orgctx.With(ctx, orgctx.Org{ID: org})
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	var userID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO users (org_id, username, email, enabled)
		VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
		org, "sess-"+suffix, "sess-"+suffix+"@example.test").Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	clientID, secret := "sess-app-"+suffix, "s3cret"
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO oauth_clients (client_id, client_secret, name, type, allow_refresh_token, org_id)
		VALUES ($1, $2, $1, 'confidential', true, $3::uuid)`, clientID, secret, org); err != nil {
		t.Fatalf("seed client: %v", err)
	}

	mini := miniredis.RunT(t)
	rc := &database.RedisClient{Client: redis.NewClient(&redis.Options{Addr: mini.Addr()})}
	cfg := &config.Config{}
	ids := identity.NewService(db, rc, cfg, zap.NewNop())
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	svc := &Service{
		db:              db,
		redis:           rc,
		config:          cfg,
		logger:          zap.NewNop(),
		privateKey:      key,
		publicKey:       &key.PublicKey,
		issuer:          "https://session-end.test",
		clients:         NewPostgresOAuthClientStore(db),
		identityService: ids,
	}

	// newSession is a signed-in device: a session as login creates it and the
	// refresh token issued to it.
	newSession := func() (sessionID, refreshToken string) {
		t.Helper()
		sess, err := ids.CreateSession(orgCtx, userID, clientID, "203.0.113.9", "evidence-run", time.Hour)
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		refreshToken = "rt-" + sess.ID
		if err := svc.CreateRefreshToken(orgCtx, &RefreshToken{
			Token: refreshToken, ClientID: clientID, UserID: userID, Scope: "openid offline_access",
			SessionID: sess.ID, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("mint refresh token: %v", err)
		}
		return sess.ID, refreshToken
	}
	// refresh presents the token at the token endpoint. On success it returns
	// the rotated refresh token, which is what the device holds next.
	refresh := func(tok string) (int, string, map[string]interface{}) {
		t.Helper()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		form := creds(clientID, secret, "grant_type", "refresh_token", "refresh_token", tok)
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		c.Request = req.WithContext(orgCtx)
		svc.handleRefreshTokenGrant(c)
		body := map[string]interface{}{}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		next, _ := body["refresh_token"].(string)
		return w.Code, next, body
	}

	sessionID, device := newSession()
	_, otherDevice := newSession()

	t.Run("a live session refreshes", func(t *testing.T) {
		code, next, body := refresh(device)
		if code != http.StatusOK || body["access_token"] == nil || next == "" {
			t.Fatalf("a live session must refresh: %d %v", code, body)
		}
		device = next
	})
	t.Run("the session the user ended does not", func(t *testing.T) {
		if err := ids.TerminateSession(orgCtx, sessionID); err != nil {
			t.Fatalf("end the session: %v", err)
		}
		if code, _, body := refresh(device); code != http.StatusBadRequest || body["error"] != "invalid_grant" {
			t.Errorf("the ended session refreshed: %d %v. The device that was signed out keeps "+
				"minting access tokens until its refresh token expires.", code, body)
		}
		if !mini.Exists("revoked_session:" + sessionID) {
			t.Error("no revoked_session marker was published, unlike every other path that ends a session")
		}
	})
	t.Run("the user's other session keeps refreshing", func(t *testing.T) {
		if code, _, body := refresh(otherDevice); code != http.StatusOK {
			t.Errorf("ending one session stopped another from refreshing: %d %v", code, body)
		}
	})
	// The marker lives in Redis, which can be down or restarted empty. The
	// refresh tokens' own rows are what has to hold then.
	t.Run("with Redis down, an ended session still does not refresh", func(t *testing.T) {
		sid, dev := newSession()
		code, next, body := refresh(dev)
		if code != http.StatusOK || next == "" {
			t.Fatalf("a live session must refresh: %d %v", code, body)
		}
		mini.Close()
		if err := ids.TerminateSession(orgCtx, sid); err != nil {
			t.Fatalf("ending a session must not depend on Redis: %v", err)
		}
		if code, _, body := refresh(next); code != http.StatusBadRequest || body["error"] != "invalid_grant" {
			t.Errorf("with no marker to read, the ended session refreshed: %d %v", code, body)
		}
	})
}
