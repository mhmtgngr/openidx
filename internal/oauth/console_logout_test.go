package oauth

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// The admin console signs out by POSTing to /oauth/logout with its ACCESS
// token twice: as the bearer, and as id_token_hint in the form body
// (web/admin-console/src/lib/auth.tsx). Bearers presented to this service's
// endpoints are required to be access tokens; id_token_hint is not a bearer,
// and a hint that happens to be an access token has to keep ending the session
// it names. This pins that, through the mounted route and a real database.
func TestTheConsolesLogoutStillEndsItsSession(t *testing.T) {
	svc, db := ssoSetupDB(t)
	withSigningKey(t, svc)
	r := routedService(t, svc, ssoTestOrg, nil)
	ctx := context.Background()

	userID := uuid.New().String()
	sessionID, _ := ssoSession(t, svc, db, ssoTestOrg, userID, 0, time.Hour, false)
	access, err := svc.GenerateJWT(orgctx.With(ctx, orgctx.Org{ID: ssoTestOrg}), userID, "c", "openid", 300, sessionID)
	if err != nil {
		t.Fatalf("mint access token: %v", err)
	}

	w := serve(r, http.MethodPost, "/oauth/logout", formType,
		url.Values{"id_token_hint": {access}}.Encode(),
		"Authorization", "Bearer "+access)
	if w.Code != http.StatusOK {
		t.Fatalf("console logout answered %d: %s", w.Code, w.Body.String())
	}

	var revoked bool
	if err := db.Pool.QueryRow(ctx,
		`SELECT COALESCE(revoked, false) FROM sessions WHERE id = $1 AND org_id = $2`,
		sessionID, ssoTestOrg).Scan(&revoked); err != nil {
		t.Fatalf("read session: %v", err)
	}
	if !revoked {
		t.Fatal("the console's logout left its session live")
	}
	if !blacklistedToken(t, svc, access) {
		t.Fatal("the console's logout left its access token usable")
	}

	// The hint on its own, with no bearer to fall back on, still names the
	// user whose sessions end: parsing id_token_hint accepts an access token.
	other := uuid.New().String()
	otherSession, _ := ssoSession(t, svc, db, ssoTestOrg, other, 0, time.Hour, false)
	hint, err := svc.GenerateJWT(orgctx.With(ctx, orgctx.Org{ID: ssoTestOrg}), other, "c", "openid", 300, otherSession)
	if err != nil {
		t.Fatalf("mint access token: %v", err)
	}
	if w := serve(r, http.MethodPost, "/oauth/logout", formType, url.Values{"id_token_hint": {hint}}.Encode()); w.Code != http.StatusOK {
		t.Fatalf("hint-only logout answered %d: %s", w.Code, w.Body.String())
	}
	if err := db.Pool.QueryRow(ctx,
		`SELECT COALESCE(revoked, false) FROM sessions WHERE id = $1 AND org_id = $2`,
		otherSession, ssoTestOrg).Scan(&revoked); err != nil {
		t.Fatalf("read session: %v", err)
	}
	if !revoked {
		t.Fatal("an access token given as id_token_hint no longer names the session to end")
	}
}

func blacklistedToken(t *testing.T, svc *Service, token string) bool {
	t.Helper()
	n, err := svc.redis.Client.Exists(context.Background(), accessTokenBlacklistKey(token)).Result()
	if err != nil {
		t.Fatalf("redis exists: %v", err)
	}
	return n > 0
}
