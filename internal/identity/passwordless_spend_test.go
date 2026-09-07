package identity

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// The passwordless flows hand out credentials that are meant to be spent once
// and to stop working after a few minutes. Three writes decided whether that
// was true, and all three discarded their error or were never made at all.
//
//   - CreateMagicLink retires the links already outstanding before minting a
//     new one. That write's error was dropped, so a failure handed out a second
//     live link while the first stayed redeemable -- the opposite of what a
//     person is doing when they request a fresh link because the old one went
//     somewhere it should not have.
//
//   - ApproveQRLoginSession checked the session was 'scanned' and never checked
//     it was still inside its five-minute window. Once a phone had scanned, the
//     window never closed: GetQRLoginSession only marks a session expired while
//     it is still 'pending'. A session scanned and left alone stayed approvable
//     until the seven-day cleanup deleted the row.
//
//   - CleanupExpiredPasswordlessSessions ran four statements, discarded four
//     errors and returned nil, so a sweep that had stopped collecting spent
//     credentials was indistinguishable from one that worked.

const passwordlessSchema = `
CREATE TABLE users (
	id UUID PRIMARY KEY,
	email TEXT NOT NULL,
	enabled BOOLEAN NOT NULL DEFAULT true,
	org_id UUID NOT NULL);
CREATE TABLE magic_links (
	id UUID PRIMARY KEY,
	org_id UUID NOT NULL,
	user_id UUID NOT NULL,
	email TEXT NOT NULL,
	token_hash TEXT NOT NULL,
	purpose TEXT NOT NULL,
	redirect_url TEXT,
	ip_address TEXT,
	user_agent TEXT,
	status TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	expires_at TIMESTAMPTZ NOT NULL,
	used_at TIMESTAMPTZ);
CREATE TABLE qr_login_sessions (
	id UUID PRIMARY KEY,
	session_token TEXT NOT NULL,
	qr_code_data TEXT,
	status TEXT NOT NULL,
	user_id UUID,
	browser_info JSONB,
	mobile_info JSONB,
	ip_address TEXT,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	expires_at TIMESTAMPTZ NOT NULL,
	scanned_at TIMESTAMPTZ,
	approved_at TIMESTAMPTZ,
	org_id UUID NOT NULL);
CREATE TABLE passwordless_preferences (
	id UUID PRIMARY KEY,
	user_id UUID NOT NULL,
	webauthn_only BOOLEAN NOT NULL DEFAULT false,
	magic_link_enabled BOOLEAN NOT NULL DEFAULT true,
	qr_login_enabled BOOLEAN NOT NULL DEFAULT true,
	preferred_method TEXT,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	org_id UUID NOT NULL);
`

// passwordlessFixture builds the schema and one enabled user, and returns a
// Service and a context carrying the org.
func passwordlessFixture(t *testing.T, orgID, userID, email string) (*Service, context.Context, func()) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	if db == nil {
		return nil, nil, func() {}
	}
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: orgID})
	if _, err := db.Pool.Exec(ctx, passwordlessSchema); err != nil {
		cleanup()
		t.Fatalf("create schema: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO users (id, email, enabled, org_id) VALUES ($1, $2, true, $3)`,
		userID, email, orgID); err != nil {
		cleanup()
		t.Fatalf("seed user: %v", err)
	}
	return &Service{db: db, logger: zap.NewNop()}, ctx, cleanup
}

func TestANewMagicLinkIsNotMintedWhileTheOldOneStandsUnretired(t *testing.T) {
	const orgID = "00000000-0000-0000-0000-000000000080"
	const userID = "aaaaaaaa-0000-0000-0000-000000000080"
	s, ctx, cleanup := passwordlessFixture(t, orgID, userID, "spend@example.test")
	if s == nil {
		return
	}
	defer cleanup()

	// A first link, so there is something outstanding to retire.
	first, err := s.CreateMagicLink(ctx, "spend@example.test", "login", "", "10.0.0.1", "test")
	if err != nil {
		t.Fatalf("mint the first link: %v", err)
	}

	// The second mint retires the first. Make that retirement fail.
	if _, err := s.db.Pool.Exec(ctx, `
		CREATE FUNCTION refuse_retire() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'refusing to retire the outstanding link'; END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER refuse_retire BEFORE UPDATE ON magic_links
		FOR EACH ROW EXECUTE FUNCTION refuse_retire();`); err != nil {
		t.Fatalf("install the failure: %v", err)
	}

	second, err := s.CreateMagicLink(ctx, "spend@example.test", "login", "", "10.0.0.1", "test")
	if err == nil {
		t.Errorf("a second magic link was minted while the first could not be retired. The person "+
			"asked for a replacement and now holds two live sign-in links (%s and %s), one of them "+
			"the very link they wanted retired.", first.ID, second.ID)
	}

	// The failure injection must have taken, or this test proves nothing.
	var pending int
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM magic_links WHERE user_id = $1 AND status = 'pending'`, userID).Scan(&pending); err != nil {
		t.Fatalf("count the outstanding links: %v", err)
	}
	if pending != 1 {
		t.Errorf("expected the first link to still be pending (the injection refusing its retirement); "+
			"found %d pending links, so this test is not exercising the path it claims", pending)
	}
}

// The happy path still works: minting a second link retires the first.
func TestMintingAMagicLinkRetiresTheOutstandingOnes(t *testing.T) {
	const orgID = "00000000-0000-0000-0000-000000000081"
	const userID = "aaaaaaaa-0000-0000-0000-000000000081"
	s, ctx, cleanup := passwordlessFixture(t, orgID, userID, "retire@example.test")
	if s == nil {
		return
	}
	defer cleanup()

	first, err := s.CreateMagicLink(ctx, "retire@example.test", "login", "", "10.0.0.1", "test")
	if err != nil {
		t.Fatalf("mint the first link: %v", err)
	}
	if _, err := s.CreateMagicLink(ctx, "retire@example.test", "login", "", "10.0.0.1", "test"); err != nil {
		t.Fatalf("mint the second link: %v", err)
	}

	var status string
	if err := s.db.Pool.QueryRow(ctx, `SELECT status FROM magic_links WHERE id = $1`, first.ID).Scan(&status); err != nil {
		t.Fatalf("read the first link back: %v", err)
	}
	if status != "expired" {
		t.Errorf("after minting a replacement the first link is %q, want expired", status)
	}

	// And the replacement is redeemable, so retirement did not take the new one with it.
	if _, _, err := s.VerifyMagicLink(ctx, first.Token, "10.0.0.1", "test"); err == nil {
		t.Error("the retired link was still redeemable")
	}
}

// seedScannedQRSession puts a session in the state ApproveQRLoginSession
// accepts, expiring at the given time.
func seedScannedQRSession(t *testing.T, s *Service, ctx context.Context, orgID, userID, token string, expiresAt time.Time) {
	t.Helper()
	if _, err := s.db.Pool.Exec(ctx, `
		INSERT INTO qr_login_sessions (id, session_token, status, user_id, expires_at, scanned_at, org_id)
		VALUES (gen_random_uuid(), $1, 'scanned', $2, $3, NOW(), $4)`,
		token, userID, expiresAt, orgID); err != nil {
		t.Fatalf("seed the scanned session: %v", err)
	}
}

func TestAQRSessionPastItsWindowCannotBeApproved(t *testing.T) {
	const orgID = "00000000-0000-0000-0000-000000000082"
	const userID = "aaaaaaaa-0000-0000-0000-000000000082"
	s, ctx, cleanup := passwordlessFixture(t, orgID, userID, "qr@example.test")
	if s == nil {
		return
	}
	defer cleanup()

	// Scanned an hour ago, on a five-minute window: long dead.
	seedScannedQRSession(t, s, ctx, orgID, userID, "stale-token", time.Now().Add(-55*time.Minute))

	err := s.ApproveQRLoginSession(ctx, "stale-token", userID)
	if err == nil {
		t.Fatal("a QR session an hour past its five-minute expiry was approved. The window a scanned " +
			"session appears to have never actually closes, and the browser holding that token is signed in.")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("refused for the wrong reason: %v", err)
	}

	var status string
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT status FROM qr_login_sessions WHERE session_token = $1`, "stale-token").Scan(&status); err != nil {
		t.Fatalf("read the session back: %v", err)
	}
	if status == "approved" {
		t.Error("the refusal was reported but the session is approved")
	}
}

func TestAQRSessionIsApprovedOnce(t *testing.T) {
	const orgID = "00000000-0000-0000-0000-000000000083"
	const userID = "aaaaaaaa-0000-0000-0000-000000000083"
	s, ctx, cleanup := passwordlessFixture(t, orgID, userID, "once@example.test")
	if s == nil {
		return
	}
	defer cleanup()

	seedScannedQRSession(t, s, ctx, orgID, userID, "live-token", time.Now().Add(5*time.Minute))

	if err := s.ApproveQRLoginSession(ctx, "live-token", userID); err != nil {
		t.Fatalf("approving a scanned, unexpired session must succeed: %v", err)
	}
	var status string
	var approvedAt *time.Time
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT status, approved_at FROM qr_login_sessions WHERE session_token = $1`, "live-token").
		Scan(&status, &approvedAt); err != nil {
		t.Fatalf("read the session back: %v", err)
	}
	if status != "approved" || approvedAt == nil {
		t.Fatalf("after approval the session is status=%q approved_at=%v", status, approvedAt)
	}

	// The second approval finds nothing to claim: the UPDATE requires 'scanned'.
	if err := s.ApproveQRLoginSession(ctx, "live-token", userID); err == nil {
		t.Error("the same QR session was approved twice")
	}
}

func TestApprovingAnotherUsersQRSessionIsRefused(t *testing.T) {
	const orgID = "00000000-0000-0000-0000-000000000084"
	const userID = "aaaaaaaa-0000-0000-0000-000000000084"
	const otherID = "aaaaaaaa-0000-0000-0000-000000000085"
	s, ctx, cleanup := passwordlessFixture(t, orgID, userID, "mine@example.test")
	if s == nil {
		return
	}
	defer cleanup()

	seedScannedQRSession(t, s, ctx, orgID, userID, "someone-elses", time.Now().Add(5*time.Minute))

	err := s.ApproveQRLoginSession(ctx, "someone-elses", otherID)
	if err == nil {
		t.Fatal("a user approved a QR session scanned by somebody else")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

func TestACleanupThatCleanedNothingIsNotReportedAsSuccess(t *testing.T) {
	const orgID = "00000000-0000-0000-0000-000000000086"
	const userID = "aaaaaaaa-0000-0000-0000-000000000086"
	s, ctx, cleanup := passwordlessFixture(t, orgID, userID, "sweep@example.test")
	if s == nil {
		return
	}
	defer cleanup()

	// A spent-and-stale row of each kind, the sort the sweep exists to collect.
	if _, err := s.db.Pool.Exec(ctx, `
		INSERT INTO magic_links (id, org_id, user_id, email, token_hash, purpose, status, created_at, expires_at)
		VALUES (gen_random_uuid(), $1, $2, 'sweep@example.test', 'x', 'login', 'pending',
		        NOW() - INTERVAL '8 days', NOW() - INTERVAL '8 days')`, orgID, userID); err != nil {
		t.Fatalf("seed a stale magic link: %v", err)
	}

	// Clean sweep first, so the test knows the statements themselves work.
	if err := s.CleanupExpiredPasswordlessSessions(ctx); err != nil {
		t.Fatalf("a sweep with nothing in its way must succeed: %v", err)
	}
	var left int
	if err := s.db.Pool.QueryRow(ctx, `SELECT count(*) FROM magic_links`).Scan(&left); err != nil {
		t.Fatalf("count what is left: %v", err)
	}
	if left != 0 {
		t.Fatalf("the sweep reported success and left %d week-old links behind", left)
	}

	// Now take the DELETE away and run it again.
	if _, err := s.db.Pool.Exec(ctx, `
		CREATE FUNCTION refuse_sweep() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'refusing the sweep'; END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER refuse_sweep BEFORE DELETE ON magic_links
		FOR EACH ROW EXECUTE FUNCTION refuse_sweep();`); err != nil {
		t.Fatalf("install the failure: %v", err)
	}
	if _, err := s.db.Pool.Exec(ctx, `
		INSERT INTO magic_links (id, org_id, user_id, email, token_hash, purpose, status, created_at, expires_at)
		VALUES (gen_random_uuid(), $1, $2, 'sweep@example.test', 'x', 'login', 'expired',
		        NOW() - INTERVAL '8 days', NOW() - INTERVAL '8 days')`, orgID, userID); err != nil {
		t.Fatalf("seed a second stale magic link: %v", err)
	}

	if err := s.CleanupExpiredPasswordlessSessions(ctx); err == nil {
		t.Error("a cleanup run that collected nothing reported success. The scheduler that calls this " +
			"every night is never told it has stopped collecting spent sign-in credentials.")
	}

	// The injection must have taken.
	if err := s.db.Pool.QueryRow(ctx, `SELECT count(*) FROM magic_links`).Scan(&left); err != nil {
		t.Fatalf("count what is left: %v", err)
	}
	if left == 0 {
		t.Error("the failure injection did not take — the row was deleted anyway, so this test is not " +
			"exercising the path it claims")
	}
}
