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
}
