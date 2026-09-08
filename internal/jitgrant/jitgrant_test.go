package jitgrant

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// The end-to-end behaviour of this package is covered where it is used, against
// a real database: internal/access/kill_switch_test.go, its lifecycle-sweep
// case, and internal/identity/deprovision_pam_test.go each grant a real
// time-bound elevation and require it to be gone. What those cannot reach is
// the failure path -- a database that refuses one of the writes half way
// through a run -- so it is driven here with a stub.

// stubQuerier fails the nth Exec (1-based) and returns a fixed set of
// elevations from Query.
type stubQuerier struct {
	elevations [][]any
	failExecAt int
	execs      int
	execSQL    []string
}

func (s *stubQuerier) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	s.execs++
	s.execSQL = append(s.execSQL, sql)
	if s.execs == s.failExecAt {
		return pgconn.CommandTag{}, errors.New("database said no")
	}
	return pgconn.CommandTag{}, nil
}

func (s *stubQuerier) Query(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
	return &stubRows{rows: s.elevations}, nil
}

type stubRows struct {
	rows [][]any
	i    int
}

func (r *stubRows) Next() bool {
	r.i++
	return r.i <= len(r.rows)
}

func (r *stubRows) Scan(dest ...any) error {
	row := r.rows[r.i-1]
	for i := range dest {
		p, ok := dest[i].(*string)
		if !ok {
			return errors.New("stub only scans strings")
		}
		*p = row[i].(string)
	}
	return nil
}

func (r *stubRows) Close()                                       {}
func (r *stubRows) Err() error                                   { return nil }
func (r *stubRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *stubRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *stubRows) Values() ([]any, error)                       { return nil, nil }
func (r *stubRows) RawValues() [][]byte                          { return nil }
func (r *stubRows) Conn() *pgx.Conn                              { return nil }

func elevation(id, rtype, rid string) []any {
	return []any{id, rtype, rid, "some-resource", "org-1"}
}

func TestRevokeRefusesAnUnknownResourceType(t *testing.T) {
	// A caller that marks an elevation ended for a type this does not handle
	// would leave the access in place under a record saying it was removed.
	// That is the silent hole access reviews exist to close, so it is an error,
	// not a no-op.
	err := Revoke(context.Background(), &stubQuerier{}, "widget", "u-1", "r-1", "org-1")
	if err == nil {
		t.Fatal("an unknown resource type was accepted; a caller would record a revocation that did not happen")
	}
	if !strings.Contains(err.Error(), "widget") {
		t.Errorf("the error does not name the type it could not handle: %v", err)
	}
}

func TestEndingAnElevationStopsRatherThanMarkingItExpiredOverLiveAccess(t *testing.T) {
	// Two elevations. The first one's assignment DELETE succeeds; its "mark
	// expired" UPDATE fails. The run must stop there and report one ended, and
	// must NOT go on to the second: a request marked expired while the role it
	// granted is still held is the exact lie this package exists to prevent,
	// and continuing past a database that is refusing writes would multiply it.
	q := &stubQuerier{
		elevations: [][]any{
			elevation("req-1", "role", "role-a"),
			elevation("req-2", "role", "role-b"),
		},
		failExecAt: 2, // 1 = the DELETE, 2 = the UPDATE
	}

	ended, err := EndAllForUser(context.Background(), q, "u-1", "org-1")
	if err == nil {
		t.Fatal("a failed write was reported as success")
	}
	if !strings.Contains(err.Error(), "req-1") {
		t.Errorf("the error does not name the elevation it could not finish: %v", err)
	}
	if ended != 0 {
		t.Errorf("ended = %d, want 0: the first elevation did not finish", ended)
	}
	if q.execs != 2 {
		t.Errorf("%d statements ran, want 2: the run continued past a refused write", q.execs)
	}
}

func TestEndingElevationsRemovesTheAssignmentBeforeMarkingTheRequest(t *testing.T) {
	// Order is the guarantee. If the request were marked expired first and the
	// assignment removal then failed, the record would say the access was taken
	// away while it was still held -- and nothing would ever look again.
	q := &stubQuerier{elevations: [][]any{elevation("req-1", "role", "role-a")}}

	ended, err := EndAllForUser(context.Background(), q, "u-1", "org-1")
	if err != nil {
		t.Fatalf("EndAllForUser: %v", err)
	}
	if ended != 1 {
		t.Fatalf("ended = %d, want 1", ended)
	}
	if len(q.execSQL) != 2 {
		t.Fatalf("%d statements, want 2", len(q.execSQL))
	}
	if !strings.Contains(q.execSQL[0], "DELETE FROM user_roles") {
		t.Errorf("first statement is not the assignment removal: %s", q.execSQL[0])
	}
	if !strings.Contains(q.execSQL[1], "UPDATE access_requests") {
		t.Errorf("second statement is not the request update: %s", q.execSQL[1])
	}
}

func TestTheActivePredicateExcludesVaultCredentials(t *testing.T) {
	// A vault checkout's authorization is the vault grant's own expires_at;
	// there is no assignment row to delete, and the callers that care about it
	// expire vault_access_grants directly. Including it here would make
	// EndAllForUser fail on an unsupported resource type for every user who has
	// ever checked out a credential -- which would take the kill switch down
	// with it.
	for _, s := range []string{activeForUser, ActiveForUserPredicate} {
		if !strings.Contains(s, "resource_type <> 'vault_credential'") {
			t.Errorf("the active-elevation definition does not exclude vault credentials:\n%s", s)
		}
		if !strings.Contains(s, "status = 'fulfilled'") || !strings.Contains(s, "expires_at IS NOT NULL") {
			t.Errorf("the active-elevation definition is not 'fulfilled and time-bound':\n%s", s)
		}
	}
}
