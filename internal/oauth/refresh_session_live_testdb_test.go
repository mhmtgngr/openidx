package oauth

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// The refresh grant used to decide on two things only: the refresh token's own
// row and the revoked_session marker in Redis. A session that ended without
// its refresh tokens being revoked -- before this release, every session the
// sweeps, the console, containment or a password change ended, once the
// marker had expired -- kept refreshing, because nothing asked whether the
// session itself was still there.
//
// It asks now: a token bound to a session refreshes only while that session's
// row exists in the token's organization, is not revoked and has not expired.
// A token bound to no session (the device authorization grant) is not
// affected.
func TestTheRefreshGrantRequiresALiveSession(t *testing.T) {
	f := newSessionEndFixture(t)
	user := f.seedUser(t, "live-check")
	exec := func(t *testing.T, sql string, args ...interface{}) {
		t.Helper()
		if _, err := f.db.Pool.Exec(context.Background(), sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	// refusedAndRevoked presents tok, which no path has revoked, and expects
	// the grant to refuse it as session_revoked and to revoke its row.
	refusedAndRevoked := func(t *testing.T, tok, what string) {
		t.Helper()
		if f.revokedInDB(t, tok) {
			t.Fatalf("%s: the token was revoked before it was presented; the case proves nothing", what)
		}
		code, _, body := f.refresh(t, tok)
		if code != http.StatusBadRequest || body["error"] != "invalid_grant" || body["error_description"] != "session_revoked" {
			t.Errorf("%s: status %d, body %v; want 400 invalid_grant session_revoked", what, code, body)
		}
		if body["access_token"] != nil {
			t.Errorf("%s: an access token was minted", what)
		}
		if !f.revokedInDB(t, tok) {
			t.Errorf("%s: the refused token's row was left unrevoked", what)
		}
	}

	t.Run("a live session refreshes", func(t *testing.T) {
		_, device := f.newSession(t, user)
		f.refreshes(t, device, "a live session")
	})
	t.Run("a session revoked with no marker and its refresh tokens left live is refused", func(t *testing.T) {
		// What a session ended before this release looks like once its
		// marker has expired.
		sid, device := f.newSession(t, user)
		exec(t, `UPDATE sessions SET revoked = true, revoked_at = NOW() WHERE id = $1::uuid`, sid)
		refusedAndRevoked(t, device, "a revoked session")
	})
	t.Run("an expired session no sweep has reached is refused", func(t *testing.T) {
		sid, device := f.newSession(t, user)
		exec(t, `UPDATE sessions SET expires_at = NOW() - interval '1 minute' WHERE id = $1::uuid`, sid)
		refusedAndRevoked(t, device, "an expired session")
	})
	t.Run("a deleted session is refused", func(t *testing.T) {
		sid, device := f.newSession(t, user)
		exec(t, `DELETE FROM sessions WHERE id = $1::uuid`, sid)
		refusedAndRevoked(t, device, "a deleted session")
	})
	t.Run("a session of another organization is refused", func(t *testing.T) {
		otherOrg := uuid.NewString()
		exec(t, `INSERT INTO organizations (id, name, slug) VALUES ($1::uuid, $2, $2)`, otherOrg, "live-check-"+f.suffix)
		sid := uuid.NewString()
		exec(t, `INSERT INTO sessions (id, user_id, client_id, expires_at, org_id)
		         VALUES ($1::uuid, $2::uuid, $3, NOW() + interval '1 hour', $4::uuid)`, sid, user, f.clientID, otherOrg)
		refusedAndRevoked(t, f.mintRefresh(t, user, sid), "a session of another organization")
	})
	t.Run("a token bound to no session refreshes", func(t *testing.T) {
		f.refreshes(t, f.mintRefresh(t, user, ""), "a refresh token bound to no session")
	})
	t.Run("when the session cannot be read, nothing is minted", func(t *testing.T) {
		_, device := f.newSession(t, user)
		exec(t, `ALTER TABLE sessions RENAME TO sessions_unreadable`)
		renamed := true
		restore := func() {
			if renamed {
				exec(t, `ALTER TABLE sessions_unreadable RENAME TO sessions`)
				renamed = false
			}
		}
		defer restore()
		code, _, body := f.refresh(t, device)
		if code != http.StatusInternalServerError || body["error"] != "server_error" {
			t.Errorf("status %d, body %v; want 500 server_error", code, body)
		}
		if body["access_token"] != nil {
			t.Error("an access token was minted while the session could not be read")
		}
		restore()
		// The failure consumed nothing: once the session reads again, the
		// same token refreshes.
		f.refreshes(t, device, "the same token once the session reads again")
	})
	t.Run("a refresh keeps the session alive", func(t *testing.T) {
		// The idle sweep ends a session whose last_seen_at is older than the
		// idle timeout. The refresh grant is what moves it; if the move is
		// lost, an active session is ended as idle.
		sid, device := f.newSession(t, user)
		exec(t, `UPDATE sessions SET last_seen_at = NOW() - interval '20 minutes' WHERE id = $1::uuid`, sid)
		f.refreshes(t, device, "a live session")
		deadline := time.Now().Add(8 * time.Second)
		for {
			var fresh bool
			if err := f.db.Pool.QueryRow(context.Background(),
				`SELECT last_seen_at > NOW() - interval '1 minute' FROM sessions WHERE id = $1::uuid`, sid).Scan(&fresh); err != nil {
				t.Fatalf("read the session: %v", err)
			}
			if fresh {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("a refresh did not move the session's last_seen_at, so the inactivity sweep ends a session " +
					"that is in use")
			}
			time.Sleep(50 * time.Millisecond)
		}
		// And so the sweep, which ends sessions idle for longer than the
		// default 30 minutes, leaves it alone.
		f.svc.processExpiredSessions(orgctx.WithBypassRLS(context.Background()))
		if live, err := f.svc.sessionIsLive(f.orgCtx, sid); err != nil || !live {
			t.Errorf("the inactivity sweep ended a session refreshed a moment ago (live=%v err=%v)", live, err)
		}
	})
}

// A session id that is not a UUID cannot name a session row, so it is not live,
// and the answer needs no query.
func TestASessionIDThatIsNotAUUIDIsNotLive(t *testing.T) {
	s := &Service{}
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: sessionEndOrg})
	for _, id := range []string{"not-a-uuid", "session-revoked-1", "' OR 1=1 --"} {
		live, err := s.sessionIsLive(ctx, id)
		if err != nil || live {
			t.Errorf("sessionIsLive(%q) = %v, %v; want false, nil", id, live, err)
		}
	}
}
