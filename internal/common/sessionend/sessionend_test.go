package sessionend

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

type recorder struct {
	sql  string
	args []any
	err  error
}

func (r *recorder) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	r.sql, r.args = sql, args
	return pgconn.CommandTag{}, r.err
}

func TestCapturesRefuseAnEmptyTenantOrSubject(t *testing.T) {
	r := &recorder{}
	ctx := context.Background()
	if err := ForUser(ctx, r, "", "u"); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("ForUser without tenant: %v", err)
	}
	if err := ForUser(ctx, r, "o", ""); !errors.Is(err, ErrNoSubject) {
		t.Fatalf("ForUser without user: %v", err)
	}
	if err := ForSession(ctx, r, "o", ""); !errors.Is(err, ErrNoSubject) {
		t.Fatalf("ForSession without session: %v", err)
	}
	if err := ForSessions(ctx, r, "", []string{"s"}); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("ForSessions without tenant: %v", err)
	}
	if r.sql != "" {
		t.Fatalf("a refused capture must not reach the database: %q", r.sql)
	}
}

func TestAnEmptySessionListCapturesNothingAndIsNotAnError(t *testing.T) {
	r := &recorder{}
	if err := ForSessions(context.Background(), r, "o", nil); err != nil {
		t.Fatal(err)
	}
	if r.sql != "" {
		t.Fatalf("nothing to capture must issue no statement: %q", r.sql)
	}
}

// The capture's shape is what the drainer relies on: it writes BEFORE the
// sever, from the sessions table, only live rows, only rows some client
// reached, scoped to the tenant it was given. The live database measurement
// is in internal/oauth (backchannel_logout_drain_test.go); this pins the
// statement so a rewrite has to argue with each clause.
func TestTheCaptureSelectsLiveReachedSessionsOfTheTenant(t *testing.T) {
	r := &recorder{}
	if err := ForUser(context.Background(), r, "org-1", "user-1"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"INSERT INTO backchannel_logout_pending (org_id, session_id, user_id, client_ids)",
		"FROM sessions s",
		"s.org_id = $1",
		"(s.revoked IS NULL OR s.revoked = false)",
		"oauth_refresh_tokens r",
		"r.session_id = s.id AND r.org_id = s.org_id",
		"COALESCE(c, '') <> ''",
		"s.user_id = $2",
	} {
		if !strings.Contains(r.sql, want) {
			t.Errorf("capture lacks %q", want)
		}
	}
	if len(r.args) != 2 || r.args[0] != "org-1" || r.args[1] != "user-1" {
		t.Fatalf("args=%v", r.args)
	}
	r = &recorder{}
	if err := ForSession(context.Background(), r, "org-1", "sess-1"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.sql, "s.id::text = ANY($2)") {
		t.Fatalf("session capture lacks the id predicate: %s", r.sql)
	}
}

func TestTheDatabaseErrorSurfaces(t *testing.T) {
	r := &recorder{err: errors.New("boom")}
	if err := ForUser(context.Background(), r, "o", "u"); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err=%v", err)
	}
	if _, err := RevokeRefreshTokens(context.Background(), r, "o", []string{"3f0c2b4e-8a57-4c52-9d1e-2b7d9a4c6e10"}); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("RevokeRefreshTokens err=%v", err)
	}
	if _, err := RevokeUserRefreshTokens(context.Background(), r, "o", "u", ""); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("RevokeUserRefreshTokens err=%v", err)
	}
}

// The refresh-token revocations are measured end to end in internal/oauth,
// where each session-ending path is driven and its refresh token presented at
// the token endpoint. These pin what the statements may touch: one tenant,
// the named sessions or the named user, and rows not already revoked.
func TestTheRevocationsRefuseAnEmptyTenantOrSubject(t *testing.T) {
	r := &recorder{}
	ctx := context.Background()
	if _, err := RevokeRefreshTokens(ctx, r, "", []string{"3f0c2b4e-8a57-4c52-9d1e-2b7d9a4c6e10"}); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("RevokeRefreshTokens without tenant: %v", err)
	}
	if _, err := RevokeUserRefreshTokens(ctx, r, "", "u", ""); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("RevokeUserRefreshTokens without tenant: %v", err)
	}
	if _, err := RevokeUserRefreshTokens(ctx, r, "o", "", ""); !errors.Is(err, ErrNoSubject) {
		t.Fatalf("RevokeUserRefreshTokens without user: %v", err)
	}
	if r.sql != "" {
		t.Fatalf("a refused revocation must not reach the database: %q", r.sql)
	}
}

func TestSessionRevocationSkipsIdsNoTokenCanCarry(t *testing.T) {
	r := &recorder{}
	n, err := RevokeRefreshTokens(context.Background(), r, "o", []string{"", "not-a-uuid"})
	if err != nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if r.sql != "" {
		t.Fatalf("no id a token can be bound to must issue no statement: %q", r.sql)
	}

	const sid = "3f0c2b4e-8a57-4c52-9d1e-2b7d9a4c6e10"
	if _, err := RevokeRefreshTokens(context.Background(), r, "org-1", []string{"not-a-uuid", sid}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"UPDATE oauth_refresh_tokens SET revoked_at = NOW()",
		"org_id = $1",
		"session_id = ANY($2::text[]::uuid[])",
		"revoked_at IS NULL",
	} {
		if !strings.Contains(r.sql, want) {
			t.Errorf("session revocation lacks %q", want)
		}
	}
	ids, _ := r.args[1].([]string)
	if r.args[0] != "org-1" || len(ids) != 1 || ids[0] != sid {
		t.Fatalf("args=%v", r.args)
	}
}

func TestUserRevocationIsTheUsersAndSparesOnlyTheKeptSession(t *testing.T) {
	r := &recorder{}
	if _, err := RevokeUserRefreshTokens(context.Background(), r, "org-1", "user-1", "sess-kept"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"UPDATE oauth_refresh_tokens SET revoked_at = NOW()",
		"org_id = $1 AND user_id = $2 AND revoked_at IS NULL",
		"$3::text = '' OR session_id IS NULL OR session_id::text <> $3::text",
	} {
		if !strings.Contains(r.sql, want) {
			t.Errorf("user revocation lacks %q", want)
		}
	}
	if len(r.args) != 3 || r.args[0] != "org-1" || r.args[1] != "user-1" || r.args[2] != "sess-kept" {
		t.Fatalf("args=%v", r.args)
	}
}
