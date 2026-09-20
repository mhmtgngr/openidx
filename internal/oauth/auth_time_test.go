package oauth

import (
	"context"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// auth_time (OIDC Core §2) is WHEN the user authenticated, which is the
// session's start — not the ID token's iat. Before this file existed the
// standard ID token carried no auth_time at all, although GenerateIDToken
// already read the session row for sid and amr. Single sign-on made the gap
// live: a token minted from a two-hour-old browser session said nothing about
// those two hours, and a client that had asked with max_age (which §3.1.2.1
// says MUST be answered with auth_time) got no answer.
//
// Against a real PostgreSQL: only the sessions table is needed — the user,
// role, group and permission lookups in GenerateIDToken swallow their errors.

func authTimeSetup(t *testing.T) (*Service, context.Context) {
	t.Helper()
	db, cleanup := ssfSetupTestDB(t)
	t.Cleanup(cleanup)
	if _, err := db.Pool.Exec(context.Background(), `CREATE TABLE sessions (
		id UUID PRIMARY KEY,
		user_id UUID NOT NULL,
		started_at TIMESTAMPTZ DEFAULT NOW(),
		expires_at TIMESTAMPTZ NOT NULL,
		org_id UUID NOT NULL,
		revoked BOOLEAN DEFAULT false,
		auth_methods TEXT[]
	)`); err != nil {
		t.Fatalf("schema: %v", err)
	}
	tctx := NewTestOIDCContext(t)
	t.Cleanup(tctx.Cleanup)
	svc := tctx.Service
	svc.db = db
	return svc, orgctx.With(context.Background(), orgctx.Org{ID: ssoTestOrg})
}

// idTokenClaims mints an ID token and returns its claims, parsed unverified
// (the signature is not what these tests are about).
func idTokenClaims(t *testing.T, svc *Service, ctx context.Context, userID string, sessionID ...string) jwt.MapClaims {
	t.Helper()
	tok, err := svc.GenerateIDToken(ctx, userID, "c", "n-1", "openid profile email", 3600, sessionID...)
	if err != nil {
		t.Fatalf("GenerateIDToken: %v", err)
	}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(tok, claims); err != nil {
		t.Fatalf("parse: %v", err)
	}
	return claims
}

func TestIDTokenAuthTimeIsTheSessionStartNotIat(t *testing.T) {
	svc, ctx := authTimeSetup(t)
	userID := uuid.New().String()
	sessionID := uuid.New().String()
	var startedAt int64
	if err := svc.db.Pool.QueryRow(ctx, `
		INSERT INTO sessions (id, user_id, started_at, expires_at, org_id, auth_methods)
		VALUES ($1, $2, NOW() - interval '2 hours', NOW() + interval '22 hours', $3, ARRAY['pwd','mfa'])
		RETURNING floor(extract(epoch from started_at))::bigint`,
		sessionID, userID, ssoTestOrg).Scan(&startedAt); err != nil {
		t.Fatalf("insert session: %v", err)
	}

	claims := idTokenClaims(t, svc, ctx, userID, sessionID)

	got, ok := claims["auth_time"].(float64)
	if !ok {
		t.Fatalf("auth_time missing from ID token; claims=%v", claims)
	}
	if int64(got) != startedAt {
		t.Fatalf("auth_time=%d, want the session start %d", int64(got), startedAt)
	}
	iat := int64(claims["iat"].(float64))
	if iat-int64(got) < 7000 {
		t.Fatalf("auth_time (%d) must be about two hours before iat (%d): the user authenticated then, not now", int64(got), iat)
	}
	// The same row still feeds sid and amr — one query, three claims.
	if claims["sid"] != sessionID {
		t.Fatalf("sid=%v, want %s", claims["sid"], sessionID)
	}
	amr, _ := claims["amr"].([]interface{})
	if len(amr) != 2 || amr[0] != "pwd" || amr[1] != "mfa" {
		t.Fatalf("amr=%v, want [pwd mfa]", claims["amr"])
	}
}

// No session, no claim: auth_time is never guessed from iat.
func TestIDTokenWithoutASessionHasNoAuthTime(t *testing.T) {
	svc, ctx := authTimeSetup(t)
	userID := uuid.New().String()

	for name, sid := range map[string][]string{
		"no session id":      nil,
		"blank session id":   {""},
		"unknown session id": {uuid.New().String()},
	} {
		t.Run(name, func(t *testing.T) {
			claims := idTokenClaims(t, svc, ctx, userID, sid...)
			if _, has := claims["auth_time"]; has {
				t.Fatalf("auth_time=%v present without a session row", claims["auth_time"])
			}
			if _, has := claims["amr"]; has {
				t.Fatalf("amr=%v present without a session row", claims["amr"])
			}
		})
	}

	// Another tenant's session is not this tenant's authentication.
	otherSession := uuid.New().String()
	if _, err := svc.db.Pool.Exec(ctx, `
		INSERT INTO sessions (id, user_id, started_at, expires_at, org_id, auth_methods)
		VALUES ($1, $2, NOW() - interval '1 hour', NOW() + interval '1 hour', $3, ARRAY['pwd'])`,
		otherSession, userID, ssoOtherOrg); err != nil {
		t.Fatal(err)
	}
	claims := idTokenClaims(t, svc, ctx, userID, otherSession)
	if _, has := claims["auth_time"]; has {
		t.Fatalf("auth_time=%v read from another tenant's session", claims["auth_time"])
	}
}

// A claim the token carries is a claim the discovery document advertises:
// auth_time and amr both.
func TestDiscoveryAdvertisesAuthTimeAndAmr(t *testing.T) {
	doc, _ := serveDiscovery(t, "https://test.openidx.org")
	claims := strs(t, doc, "claims_supported")
	for _, c := range []string{"auth_time", "amr"} {
		found := false
		for _, have := range claims {
			if have == c {
				found = true
			}
		}
		if !found {
			t.Errorf("claims_supported lacks %q, which GenerateIDToken emits; got %v", c, claims)
		}
	}
}

// Guard for sessionAuthContext's nil-safe paths, mirroring amr_test.go.
func TestSessionAuthContextGuards(t *testing.T) {
	s := &Service{}
	ctx := context.Background()
	for _, sid := range [][]string{nil, {""}, {"sid"}} {
		if m, at := s.sessionAuthContext(ctx, sid); m != nil || !at.IsZero() {
			t.Errorf("sid=%v: got (%v, %v), want (nil, zero)", sid, m, at)
		}
	}
}
