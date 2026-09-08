package oauth

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
)

// The IdP-initiated SLO used to clear the browser cookie and show "You have
// been logged out" whether or not the session row was actually deleted: the
// DELETE was a bare Exec inside an `if org, err := ...; err == nil` and neither
// error reached the response. A cleared cookie is not a logout -- it only stops
// THIS browser from presenting the token. Anyone else holding it (the shared
// machine the user walked away from, a proxy log, a shoulder-surfer) keeps a
// live session, and the user has been told the opposite.
//
// These two tests pin both halves: the delete happens on the good path, and a
// delete that cannot happen is refused rather than dressed up as a logout.

const (
	sloOrg   = "00000000-0000-0000-0000-0000000000s1"
	sloUser  = "00000000-0000-0000-0000-0000000000u1"
	sloToken = "session-token-under-test"
)

type sloFixture struct {
	t   *testing.T
	svc *Service
}

func newSLOFixture(t *testing.T) *sloFixture {
	t.Helper()
	db, cleanup := ssfSetupTestDB(t)
	t.Cleanup(cleanup)

	ctx := context.Background()
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS user_sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			session_token TEXT NOT NULL,
			org_id TEXT NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS saml_sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			sp_id TEXT NOT NULL,
			sp_entity_id TEXT NOT NULL,
			session_index TEXT NOT NULL,
			name_id TEXT NOT NULL,
			name_id_format TEXT NOT NULL,
			org_id TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			expires_at TIMESTAMPTZ NOT NULL
		)`,
		`INSERT INTO users (id, org_id) VALUES ('` + sloUser + `', '` + sloOrg + `')`,
		`INSERT INTO user_sessions (id, user_id, session_token, org_id, expires_at)
		 VALUES ('sess-1', '` + sloUser + `', '` + sloToken + `', '` + sloOrg + `', NOW() + INTERVAL '1 hour')`,
	} {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("fixture (%s): %v", stmt, err)
		}
	}

	return &sloFixture{
		t:   t,
		svc: &Service{db: db, logger: zap.NewNop(), config: &config.Config{}},
	}
}

// refuseSessionDeletes makes DELETE on user_sessions impossible while leaving
// SELECT working -- the handler resolves the user from the session first, so
// dropping or renaming the table would fail earlier and prove nothing.
func (f *sloFixture) refuseSessionDeletes() {
	f.t.Helper()
	for _, stmt := range []string{
		`CREATE OR REPLACE FUNCTION refuse_session_delete() RETURNS trigger AS $$
		 BEGIN RAISE EXCEPTION 'session deletes are refused in this test'; END; $$ LANGUAGE plpgsql`,
		`CREATE TRIGGER no_session_delete BEFORE DELETE ON user_sessions
		 FOR EACH ROW EXECUTE FUNCTION refuse_session_delete()`,
	} {
		if _, err := f.svc.db.Pool.Exec(context.Background(), stmt); err != nil {
			f.t.Fatalf("install the refusing trigger (%s): %v", stmt, err)
		}
	}
}

// logout runs handleIdPInitiatedSLO for the fixture's session token.
func (f *sloFixture) logout() *httptest.ResponseRecorder {
	f.t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/saml/slo", nil)
	req = req.WithContext(orgctx.With(context.Background(), orgctx.Org{ID: sloOrg}))
	c.Request = req
	f.svc.handleIdPInitiatedSLO(c, sloToken, "")
	return w
}

// sessionRows counts the session rows still holding the token under test.
func (f *sloFixture) sessionRows() int {
	f.t.Helper()
	var n int
	if err := f.svc.db.Pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM user_sessions WHERE session_token = $1`, sloToken).Scan(&n); err != nil {
		f.t.Fatalf("count sessions: %v", err)
	}
	return n
}

func TestIdPInitiatedLogoutEndsTheSession(t *testing.T) {
	f := newSLOFixture(t)

	w := f.logout()

	if w.Code != http.StatusOK {
		t.Fatalf("logout answered %d, want 200: %s", w.Code, w.Body.String())
	}
	if n := f.sessionRows(); n != 0 {
		t.Errorf("the session row survived a successful logout (%d rows); the user was told they were logged out", n)
	}
	if !strings.Contains(strings.Join(w.Header().Values("Set-Cookie"), " "), "openidx_session=;") {
		t.Errorf("the session cookie was not cleared: %v", w.Header().Values("Set-Cookie"))
	}
}

func TestIdPInitiatedLogoutThatCannotEndTheSessionIsRefused(t *testing.T) {
	f := newSLOFixture(t)
	f.refuseSessionDeletes()

	w := f.logout()

	if w.Code == http.StatusOK {
		t.Errorf("a logout that could not delete the session answered 200; the user was shown a logout confirmation for a session that is still live")
	}
	if n := f.sessionRows(); n != 1 {
		t.Fatalf("fixture broken: expected the session to survive the refused delete, found %d rows", n)
	}
	// The cookie must NOT be cleared here: a browser that has forgotten a token
	// the server still honours is the exact asymmetry this refusal exists to
	// avoid, and it costs the user the ability to retry.
	if strings.Contains(strings.Join(w.Header().Values("Set-Cookie"), " "), "openidx_session=;") {
		t.Errorf("the cookie was cleared even though the session survived: %v", w.Header().Values("Set-Cookie"))
	}
}
