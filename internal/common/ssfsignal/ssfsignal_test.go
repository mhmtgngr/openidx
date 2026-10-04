package ssfsignal

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

type recording struct {
	sql  string
	args []any
	err  error
}

func (r *recording) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	r.sql, r.args = sql, args
	return pgconn.CommandTag{}, r.err
}

func TestEnqueueWritesOneRowIntoThePendingTable(t *testing.T) {
	rec := &recording{}
	err := Enqueue(context.Background(), rec, Signal{
		OrgID: "org-1", SubjectID: "u-1", SubjectEmail: "ada@example.test",
		Claims: map[string]any{"reason": "hris_terminated"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rec.sql, "INSERT INTO ssf_pending_events") {
		t.Fatalf("wrote somewhere else: %s", rec.sql)
	}
	if rec.args[0] != "org-1" || rec.args[1] != AccountDisabled || rec.args[2] != "u-1" || rec.args[3] != "ada@example.test" {
		t.Fatalf("args: %v", rec.args)
	}
	if !strings.Contains(string(rec.args[4].([]byte)), `"reason":"hris_terminated"`) {
		t.Fatalf("claims not carried: %s", rec.args[4])
	}
}

// The transmitter refuses an empty tenant because it once meant "everyone";
// the producer refuses the same case at the door, before it becomes a row.
func TestEnqueueRefusesASignalWithoutATenantOrASubject(t *testing.T) {
	rec := &recording{}
	if err := Enqueue(context.Background(), rec, Signal{SubjectID: "u-1"}); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("empty org: %v", err)
	}
	if err := Enqueue(context.Background(), rec, Signal{OrgID: "org-1"}); !errors.Is(err, ErrNoSubject) {
		t.Fatalf("empty subject: %v", err)
	}
	if rec.sql != "" {
		t.Fatal("a refused signal still reached the database")
	}
}

func TestEnqueueSurfacesTheDatabaseError(t *testing.T) {
	rec := &recording{err: errors.New("boom")}
	err := Enqueue(context.Background(), rec, Signal{OrgID: "org-1", SubjectID: "u-1"})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("database error swallowed: %v", err)
	}
}

type counting struct {
	subjects []any
	failFor  string
}

func (c *counting) Exec(_ context.Context, _ string, args ...any) (pgconn.CommandTag, error) {
	if args[2] == c.failFor {
		return pgconn.CommandTag{}, errors.New("boom")
	}
	if args[1] != TokenClaimsChange {
		return pgconn.CommandTag{}, errors.New("wrong event type")
	}
	c.subjects = append(c.subjects, args[2])
	return pgconn.CommandTag{}, nil
}

// One token-claims-change per distinct user, none for an empty id, and a
// failure for one user neither stops the others nor goes unreported.
func TestEnqueueClaimsChangeTellsEachUserOnce(t *testing.T) {
	c := &counting{failFor: "u-bad"}
	err := EnqueueClaimsChange(context.Background(), c, "org-1", "bulk remove_role", "u-1", "", "u-bad", "u-2", "u-1")
	if err == nil {
		t.Error("a failed enqueue was not reported")
	}
	if len(c.subjects) != 2 || c.subjects[0] != "u-1" || c.subjects[1] != "u-2" {
		t.Errorf("enqueued for %v; want u-1 and u-2, once each", c.subjects)
	}
	if err := EnqueueClaimsChange(context.Background(), c, "", "x", "u-3"); !errors.Is(err, ErrNoTenant) {
		t.Errorf("an empty tenant: %v; want ErrNoTenant", err)
	}
}
