package oauth

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/sessionend"
	"github.com/openidx/openidx/internal/migrations"
)

// THE SEAM, MEASURED END TO END against a real PostgreSQL and a real HTTP
// receiver: a path in another binary captures a session with sessionend,
// then DELETES the row the way the identity service does; the drainer, with
// the key, announces the session to every relying party it reached, and to
// nobody else.
//
// The pending table is created from the migration the loader ships (v198),
// not a copy, so an edit to the DDL that breaks the drainer's SQL fails here.

func drainSetup(t *testing.T) (*Service, *database.PostgresDB, context.Context) {
	t.Helper()
	svc, db, _ := bclSetup(t)
	var v198 string
	for _, m := range migrations.All() {
		if m.Version == 198 {
			v198 = m.UpSQL
		}
	}
	if v198 == "" {
		t.Fatal("migration v198 is not registered")
	}
	if _, err := db.Pool.Exec(context.Background(), v198); err != nil {
		t.Fatalf("apply v198: %v", err)
	}
	return svc, db, orgctx.WithBypassRLS(context.Background())
}

type pendingLogoutRow struct {
	sessionID string
	clientIDs []string
	published bool
	attempts  int
	delivered *int
	failed    *int
}

func pendingLogouts(t *testing.T, db *database.PostgresDB) []pendingLogoutRow {
	t.Helper()
	rows, err := db.Pool.Query(context.Background(), `
		SELECT session_id::text, client_ids, published_at IS NOT NULL, attempts, delivered, failed
		  FROM backchannel_logout_pending ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []pendingLogoutRow
	for rows.Next() {
		var r pendingLogoutRow
		if err := rows.Scan(&r.sessionID, &r.clientIDs, &r.published, &r.attempts, &r.delivered, &r.failed); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func deleteUserSessions(t *testing.T, db *database.PostgresDB, org, userID string) {
	t.Helper()
	// The identity service's shape: the row is gone before the drainer runs.
	if _, err := db.Pool.Exec(context.Background(),
		`DELETE FROM sessions WHERE user_id = $1 AND org_id = $2`, userID, org); err != nil {
		t.Fatal(err)
	}
}

func TestASessionEndedByAnotherBinaryIsAnnouncedToEveryRelyingPartyItReached(t *testing.T) {
	svc, db, bypass := drainSetup(t)
	rpA, rpB := newRelyingParty(t, http.StatusOK), newRelyingParty(t, http.StatusOK)
	registerRP(t, db, ssoTestOrg, "rp-a", rpA.srv.URL+"/a")
	registerRP(t, db, ssoTestOrg, "rp-b", rpB.srv.URL+"/b")
	registerRP(t, db, ssoTestOrg, "rp-silent", "")
	userID := uuid.New().String()
	sid := liveSession(t, db, ssoTestOrg, userID, "rp-a")
	bindRefreshToken(t, db, ssoTestOrg, userID, "rp-b", sid)
	bindRefreshToken(t, db, ssoTestOrg, userID, "rp-silent", sid)

	if err := sessionend.ForUser(context.Background(), db.Pool, ssoTestOrg, userID); err != nil {
		t.Fatal(err)
	}
	deleteUserSessions(t, db, ssoTestOrg, userID)

	n, err := svc.drainBackchannelLogouts(bypass)
	if err != nil || n != 1 {
		t.Fatalf("drain: n=%d err=%v, want one claimed row", n, err)
	}
	for name, rp := range map[string]*relyingParty{"rp-a": rpA, "rp-b": rpB} {
		got := rp.tokens()
		if len(got) != 1 {
			t.Fatalf("%s received %d tokens, want 1", name, len(got))
		}
		_, claims := parseLogoutToken(t, svc, got[0].token)
		if claims["sid"] != sid || claims["aud"] != name || claims["sub"] != userID {
			t.Fatalf("%s token claims=%v", name, claims)
		}
	}
	rows := pendingLogouts(t, db)
	if len(rows) != 1 || !rows[0].published || rows[0].delivered == nil || *rows[0].delivered != 2 || *rows[0].failed != 0 {
		t.Fatalf("pending rows=%+v, want one published row delivered=2 failed=0", rows)
	}
	if n, err := svc.drainBackchannelLogouts(bypass); err != nil || n != 0 {
		t.Fatalf("a published row must not be drained again: n=%d err=%v", n, err)
	}
}

func TestForSessionCapturesTheNamedLiveSessionOnly(t *testing.T) {
	svc, db, bypass := drainSetup(t)
	rp := newRelyingParty(t, http.StatusOK)
	registerRP(t, db, ssoTestOrg, "rp-a", rp.srv.URL+"/a")
	userID := uuid.New().String()
	s1 := liveSession(t, db, ssoTestOrg, userID, "rp-a")
	s2 := liveSession(t, db, ssoTestOrg, userID, "rp-a")
	// s2 was already revoked by oauth-service (and announced from its funnel).
	if _, err := db.Pool.Exec(context.Background(), `UPDATE sessions SET revoked = true WHERE id = $1`, s2); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if err := sessionend.ForSession(ctx, db.Pool, ssoTestOrg, s1); err != nil {
		t.Fatal(err)
	}
	if err := sessionend.ForSession(ctx, db.Pool, ssoTestOrg, s2); err != nil {
		t.Fatal(err)
	}
	// The producer's own statement, then a second capture of the same
	// session by a later path: nothing live is left to capture.
	if _, err := db.Pool.Exec(ctx, `UPDATE sessions SET revoked = true WHERE id = $1`, s1); err != nil {
		t.Fatal(err)
	}
	if err := sessionend.ForSession(ctx, db.Pool, ssoTestOrg, s1); err != nil {
		t.Fatal(err)
	}
	rows := pendingLogouts(t, db)
	if len(rows) != 1 || rows[0].sessionID != s1 {
		t.Fatalf("pending rows=%+v, want exactly one, for the live session s1", rows)
	}
	if _, err := svc.drainBackchannelLogouts(bypass); err != nil {
		t.Fatal(err)
	}
	got := rp.tokens()
	if len(got) != 1 {
		t.Fatalf("relying party received %d tokens, want 1 (s1 only)", len(got))
	}
	if _, claims := parseLogoutToken(t, svc, got[0].token); claims["sid"] != s1 {
		t.Fatalf("sid=%v, want %s", claims["sid"], s1)
	}
}

func TestASessionNoClientReachedIsNotCaptured(t *testing.T) {
	_, db, _ := drainSetup(t)
	userID := uuid.New().String()
	liveSession(t, db, ssoTestOrg, userID, "")
	if err := sessionend.ForUser(context.Background(), db.Pool, ssoTestOrg, userID); err != nil {
		t.Fatal(err)
	}
	if rows := pendingLogouts(t, db); len(rows) != 0 {
		t.Fatalf("pending rows=%+v, want none: nobody to tell", rows)
	}
}

func TestTheDrainResolvesCandidatesInTheCaptureTenantOnly(t *testing.T) {
	svc, db, bypass := drainSetup(t)
	otherOrg := uuid.New().String()
	foreign := newRelyingParty(t, http.StatusOK)
	// Same client_id registered WITH a URI in another tenant; none in ours.
	registerRP(t, db, otherOrg, "rp-a", foreign.srv.URL+"/a")
	registerRP(t, db, ssoTestOrg, "rp-a", "")
	userID := uuid.New().String()
	liveSession(t, db, ssoTestOrg, userID, "rp-a")

	if err := sessionend.ForUser(context.Background(), db.Pool, ssoTestOrg, userID); err != nil {
		t.Fatal(err)
	}
	deleteUserSessions(t, db, ssoTestOrg, userID)
	if n, err := svc.drainBackchannelLogouts(bypass); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if got := foreign.tokens(); len(got) != 0 {
		t.Fatalf("the other tenant's relying party was told: %v", got)
	}
	rows := pendingLogouts(t, db)
	if len(rows) != 1 || !rows[0].published || *rows[0].delivered != 0 || *rows[0].failed != 0 {
		t.Fatalf("rows=%+v, want one published row with nothing delivered and nothing failed", rows)
	}
}

func TestARefusingRelyingPartyIsCountedFailedAndTheRowIsDone(t *testing.T) {
	svc, db, bypass := drainSetup(t)
	rp := newRelyingParty(t, http.StatusInternalServerError)
	registerRP(t, db, ssoTestOrg, "rp-a", rp.srv.URL+"/a")
	userID := uuid.New().String()
	liveSession(t, db, ssoTestOrg, userID, "rp-a")
	if err := sessionend.ForUser(context.Background(), db.Pool, ssoTestOrg, userID); err != nil {
		t.Fatal(err)
	}
	deleteUserSessions(t, db, ssoTestOrg, userID)
	if _, err := svc.drainBackchannelLogouts(bypass); err != nil {
		t.Fatal(err)
	}
	rows := pendingLogouts(t, db)
	if len(rows) != 1 || !rows[0].published || *rows[0].delivered != 0 || *rows[0].failed != 1 {
		t.Fatalf("rows=%+v, want one published row delivered=0 failed=1", rows)
	}
	if n, _ := svc.drainBackchannelLogouts(bypass); n != 0 {
		t.Fatal("a refused delivery is done, not retried forever: the spec says the OP MAY retry, and this one does not")
	}
}

func TestAStaleClaimIsHandedBackAndAPoisonedRowIsLeftAlone(t *testing.T) {
	svc, db, bypass := drainSetup(t)
	ctx := context.Background()
	stale, poisoned := uuid.New().String(), uuid.New().String()
	for _, ins := range []struct {
		sid      string
		claimed  string
		attempts int
	}{
		{stale, "NOW() - interval '10 minutes'", 1},
		{poisoned, "NULL", backchannelDrainMaxAttempt},
	} {
		if _, err := db.Pool.Exec(ctx, `
			INSERT INTO backchannel_logout_pending (org_id, session_id, user_id, client_ids, claimed_at, attempts)
			VALUES ($1, $2, $3, ARRAY['rp-a'], `+ins.claimed+`, $4)`,
			ssoTestOrg, ins.sid, uuid.New().String(), ins.attempts); err != nil {
			t.Fatal(err)
		}
	}
	n, err := svc.drainBackchannelLogouts(bypass)
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v: the stale claim is anybody's again, the poisoned row is nobody's", n, err)
	}
	for _, r := range pendingLogouts(t, db) {
		switch r.sessionID {
		case stale:
			if !r.published || r.attempts != 2 {
				t.Fatalf("stale row=%+v, want published on its second attempt", r)
			}
		case poisoned:
			if r.published || r.attempts != backchannelDrainMaxAttempt {
				t.Fatalf("poisoned row=%+v, want left alone", r)
			}
		}
	}
}

// A drainer that exists and is never started is the capability advertised
// and absent all over again.
func TestTheOAuthServiceMainStartsTheDrainer(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "cmd", "oauth-service", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "StartBackchannelLogoutDrainer(ctx)") {
		t.Fatal("cmd/oauth-service/main.go does not start the back-channel logout drainer; captures from the other binaries would never be announced")
	}
}
