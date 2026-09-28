package pamgrant

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// stubExecer records every statement and answers each with a canned row count
// or error, keyed by the table the statement updates. The SQL itself runs
// against a real schema in internal/access (the kill switch and the lifecycle
// sweep tests) and internal/identity (deprovisioning); what this pins is the
// contract the callers rely on: five writes, each scoped to the user and the
// organization, each attempted whatever the earlier ones did, each reported
// by name when it fails.
type stubExecer struct {
	calls []call
	rows  map[string]int64
	fail  map[string]error
}

type call struct {
	sql  string
	args []any
}

func (s *stubExecer) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	s.calls = append(s.calls, call{sql: sql, args: args})
	table := tableOf(sql)
	if err := s.fail[table]; err != nil {
		return pgconn.CommandTag{}, err
	}
	return pgconn.NewCommandTag("UPDATE " + itoa(s.rows[table])), nil
}

func tableOf(sql string) string {
	fields := strings.Fields(sql)
	for i, f := range fields {
		if f == "UPDATE" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

var tables = []string{"pam_entry_grants", "pam_entry_access_requests", "pam_active_checkouts", "temp_access_links", "brokered_sessions"}

func TestEndForUserWritesEveryTableScopedToTheUserAndOrg(t *testing.T) {
	q := &stubExecer{rows: map[string]int64{
		"pam_entry_grants": 1, "pam_entry_access_requests": 2, "pam_active_checkouts": 3,
		"temp_access_links": 4, "brokered_sessions": 5,
	}}
	c, errs := EndForUser(context.Background(), q, "user-1", "org-1")
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	want := Counts{GrantsExpired: 1, ApprovalsRevoked: 2, LeasesReleased: 3, TempLinksRevoked: 4, BrokeredEnded: 5}
	if c != want {
		t.Errorf("counts = %+v, want %+v", c, want)
	}
	if c.Total() != 15 {
		t.Errorf("Total() = %d, want 15", c.Total())
	}
	if len(q.calls) != len(tables) {
		t.Fatalf("%d statements, want %d", len(q.calls), len(tables))
	}
	for i, table := range tables {
		got := q.calls[i]
		if tableOf(got.sql) != table {
			t.Errorf("statement %d updates %q, want %q", i, tableOf(got.sql), table)
		}
		if len(got.args) != 2 || got.args[0] != "user-1" || got.args[1] != "org-1" {
			t.Errorf("statement %d args = %v, want [user-1 org-1]", i, got.args)
		}
		if !strings.Contains(got.sql, "org_id = $2") {
			t.Errorf("statement %d carries no organization term:\n%s", i, got.sql)
		}
		// Only live rows: a repeat is a no-op, and a row already ended keeps
		// its own timestamp.
		if !strings.Contains(got.sql, "status = 'active'") && !strings.Contains(got.sql, "status IN ('pending', 'approved')") &&
			!strings.Contains(got.sql, "expires_at > NOW()") {
			t.Errorf("statement %d is not limited to live rows:\n%s", i, got.sql)
		}
	}
	// Grants held through a role or a group are that principal's, not the
	// user's, and the grant statement must say so.
	if !strings.Contains(q.calls[0].sql, "principal_type = 'user'") {
		t.Errorf("the grant statement does not restrict itself to user principals:\n%s", q.calls[0].sql)
	}
}

func TestEndForUserAttemptsEveryTableAndNamesTheOneThatFailed(t *testing.T) {
	boom := errors.New("relation is locked")
	q := &stubExecer{
		rows: map[string]int64{"pam_entry_grants": 1, "brokered_sessions": 1},
		fail: map[string]error{"pam_entry_access_requests": boom},
	}
	c, errs := EndForUser(context.Background(), q, "user-1", "org-1")
	if len(q.calls) != len(tables) {
		t.Fatalf("a failing step stopped the pass: %d statements, want %d", len(q.calls), len(tables))
	}
	if len(errs) != 1 {
		t.Fatalf("errors = %v, want exactly one", errs)
	}
	var step *StepError
	if !errors.As(errs[0], &step) {
		t.Fatalf("error %v is not a StepError", errs[0])
	}
	if step.Step != "revoke_pam_entry_approvals" || !errors.Is(step, boom) {
		t.Errorf("StepError = %q / %v, want revoke_pam_entry_approvals / %v", step.Step, step.Err, boom)
	}
	if c.GrantsExpired != 1 || c.BrokeredEnded != 1 || c.ApprovalsRevoked != 0 {
		t.Errorf("counts after a failing step = %+v", c)
	}
}

func TestEndForDisabledUsersWritesEveryTableWithNoTenantTermAndAnEnabledUserGuard(t *testing.T) {
	q := &stubExecer{rows: map[string]int64{"temp_access_links": 2}}
	c, errs := EndForDisabledUsers(context.Background(), q)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if c.TempLinksRevoked != 2 || c.Total() != 2 {
		t.Errorf("counts = %+v", c)
	}
	if len(q.calls) != len(tables) {
		t.Fatalf("%d statements, want %d", len(q.calls), len(tables))
	}
	for i, table := range tables {
		got := q.calls[i]
		if tableOf(got.sql) != table {
			t.Errorf("statement %d updates %q, want %q", i, tableOf(got.sql), table)
		}
		if len(got.args) != 0 {
			t.Errorf("statement %d takes arguments %v; the install-wide sweep takes none", i, got.args)
		}
		if !strings.Contains(got.sql, "u.enabled = true") || !strings.Contains(got.sql, "NOT EXISTS") {
			t.Errorf("statement %d does not guard on a still-enabled user:\n%s", i, got.sql)
		}
	}
}
