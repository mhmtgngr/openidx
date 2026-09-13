package main

import (
	"strings"
	"testing"
)

// rawHeader is a fixture shaped like the real thing: a pool with the scoped
// query methods and a Raw() that hands back an unscoped one.
const rawHeader = `package fixture

import "context"

type RawPool interface {
	Exec(ctx context.Context, sql string, args ...any) error
	Query(ctx context.Context, sql string, args ...any) error
	QueryRow(ctx context.Context, sql string, args ...any) error
}

type ScopedPool interface {
	Exec(ctx context.Context, sql string, args ...any) error
	Query(ctx context.Context, sql string, args ...any) error
	QueryRow(ctx context.Context, sql string, args ...any) error
	Raw() RawPool
}

type DB struct{ Pool ScopedPool }

func (d DB) Reader() ScopedPool { return d.Pool }

func takesAPool(p RawPool) {}
`

func findingsFor(t *testing.T, body string) []Finding {
	t.Helper()
	dir := writeGoFixture(t, rawHeader+body)
	findings, err := scanDir(dir)
	if err != nil {
		t.Fatalf("scanDir: %v", err)
	}
	return findings
}

func onlyKind(findings []Finding, kind string) []Finding {
	var out []Finding
	for _, f := range findings {
		if f.Kind == kind {
			out = append(out, f)
		}
	}
	return out
}

// The rule the plan asked for: a tenant table reached through Raw().
func TestRaw_scopedTableThroughRawIsFlagged(t *testing.T) {
	body := "var _ = func(db DB, ctx context.Context) { db.Pool.Raw().Query(ctx, `SELECT id FROM users WHERE org_id = $1`, \"a\") }\n"
	got := onlyKind(findingsFor(t, body), rawKindQuery)
	if len(got) != 1 {
		t.Fatalf("got %d raw-query findings, want 1: %+v", len(got), got)
	}
	if got[0].Table != "users" {
		t.Errorf("Table = %q, want users", got[0].Table)
	}
}

// The half that makes this rule different from the missing-predicate rule, and
// the reason it cannot just reuse it: the query above ALREADY says
// `org_id = $1`. The RLS policy compares org_id to
// current_setting('app.org_id'), so with no scope set the row is invisible
// whatever the WHERE clause says. If this ever stops being flagged, the rule
// has quietly become "remember to write org_id", which is not the property.
func TestRaw_orgIDInTheSQLDoesNotClearIt(t *testing.T) {
	body := "var _ = func(db DB, ctx context.Context) { db.Pool.Raw().QueryRow(ctx, `SELECT secret FROM sessions WHERE org_id = $1 AND id = $2`, \"a\", \"b\") }\n"
	got := onlyKind(findingsFor(t, body), rawKindQuery)
	if len(got) != 1 {
		t.Fatalf("an org_id in the SQL cleared a Raw() finding; got %d, want 1: %+v", len(got), got)
	}
	if !strings.Contains(got[0].Reason, "does not help") {
		t.Errorf("the message should say an org_id does not help; got %q", got[0].Reason)
	}
}

// Reader() is a pool too. It returned the bare pgx pool for one commit after
// task 2.1b, which is the defect this whole rule exists to make loud.
func TestRaw_throughReaderIsFlaggedToo(t *testing.T) {
	body := "var _ = func(db DB, ctx context.Context) { db.Reader().Raw().Query(ctx, `SELECT id FROM users`) }\n"
	if got := onlyKind(findingsFor(t, body), rawKindQuery); len(got) != 1 {
		t.Fatalf("got %d raw-query findings through Reader().Raw(), want 1: %+v", len(got), got)
	}
}

// An install-wide table through Raw() is the CORRECT use, and must stay quiet.
// A lint that cries on the legitimate path gets an //orgscope:ignore stapled
// to every call and stops meaning anything.
func TestRaw_installWideTableThroughRawIsFine(t *testing.T) {
	body := "var _ = func(db DB, ctx context.Context) { db.Pool.Raw().Query(ctx, `SELECT kid FROM oauth_signing_keys`) }\n"
	if got := findingsFor(t, body); len(got) != 0 {
		t.Fatalf("an install-wide table through Raw() was flagged: %+v", got)
	}
}

// The same query NOT through Raw() is the scoped path; it is the
// missing-predicate rule's business, not this one's.
func TestRaw_scopedPoolIsNotARawFinding(t *testing.T) {
	body := "var _ = func(db DB, ctx context.Context) { db.Pool.Query(ctx, `SELECT id FROM users WHERE org_id = $1`, \"a\") }\n"
	if got := findingsFor(t, body); len(got) != 0 {
		t.Fatalf("the scoped path was flagged: %+v", got)
	}
}

// The hazard travels: a raw pool handed to a function queries whatever that
// function queries, and nothing at the call site says which tables those are.
func TestRaw_handoffToAnUnvettedFunctionIsFlagged(t *testing.T) {
	body := "var _ = func(db DB) { takesAPool(db.Pool.Raw()) }\n"
	got := onlyKind(findingsFor(t, body), rawKindHandoff)
	if len(got) != 1 {
		t.Fatalf("got %d raw-handoff findings, want 1: %+v", len(got), got)
	}
	if !strings.Contains(got[0].Reason, "rawHandoffAllowed") {
		t.Errorf("the message should name the register to add it to; got %q", got[0].Reason)
	}
}

// ...and an allowlisted one is silent, because its reason is recorded once in
// rawHandoffAllowed rather than at every call site.
func TestRaw_allowlistedHandoffIsSilent(t *testing.T) {
	body := "var _ = func(db DB) { metrics.NewTracedPool(db.Pool.Raw(), \"svc\") }\nvar metrics struct{ NewTracedPool func(RawPool, string) }\n"
	if got := onlyKind(findingsFor(t, body), rawKindHandoff); len(got) != 0 {
		t.Fatalf("an allowlisted handoff was flagged: %+v", got)
	}
}

// An ordinary method on the raw pool (Stat, Ping, Close) is not a handoff.
func TestRaw_methodOnTheRawPoolIsNotAHandoff(t *testing.T) {
	body := "var _ = func(db DB, ctx context.Context) { db.Pool.Raw().Query(ctx, `SELECT kid FROM oauth_signing_keys`) }\n"
	if got := onlyKind(findingsFor(t, body), rawKindHandoff); len(got) != 0 {
		t.Fatalf("a method call on the raw pool was reported as a handoff: %+v", got)
	}
}

// The escape hatch is the same one the rest of the tool uses, and it still
// demands a reason.
func TestRaw_ignoreDirectiveSuppressesAHandoff(t *testing.T) {
	body := "var _ = func(db DB) {\n\t//orgscope:ignore statistics only, runs no query\n\ttakesAPool(db.Pool.Raw())\n}\n"
	if got := onlyKind(findingsFor(t, body), rawKindHandoff); len(got) != 0 {
		t.Fatalf("a directive with a reason did not suppress the finding: %+v", got)
	}
}

func TestRaw_reasonlessDirectiveDoesNotSuppress(t *testing.T) {
	body := "var _ = func(db DB) {\n\t//orgscope:ignore\n\ttakesAPool(db.Pool.Raw())\n}\n"
	if got := onlyKind(findingsFor(t, body), rawKindHandoff); len(got) != 1 {
		t.Fatalf("a reason-less directive suppressed a finding; got %d, want 1: %+v", len(got), got)
	}
}

// Every entry in the allowlist must say why, the same rule the table registers
// follow. init() panics on a blank one; this proves the map as committed
// satisfies it rather than trusting that init ran.
func TestRaw_everyAllowlistEntryHasAReason(t *testing.T) {
	if len(rawHandoffAllowed) == 0 {
		t.Fatal("rawHandoffAllowed is empty; the real call sites should be in it")
	}
	for fn, reason := range rawHandoffAllowed {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("rawHandoffAllowed[%q] has no reason", fn)
		}
	}
}

// Most of this repo assigns its SQL to a variable first, so the tool usually
// cannot read the query at the call site. It must not conclude "fine" from
// that: it cannot tell whether the tables are tenant ones, and the one call
// that deliberately leaves the belt behind is the wrong place to guess.
func TestRaw_unreadableSQLThroughRawFailsClosed(t *testing.T) {
	body := "var _ = func(db DB, ctx context.Context, query string) { db.Pool.Raw().QueryRow(ctx, query, 1) }\n"
	got := onlyKind(findingsFor(t, body), rawKindOpaque)
	if len(got) != 1 {
		t.Fatalf("an unreadable Raw() query was not flagged; got %d, want 1: %+v", len(got), got)
	}
}

// A transaction opened on the raw pool is unscoped for every statement inside
// it, so Begin has the same hazard with none of the SQL visible.
func TestRaw_beginOnTheRawPoolIsFlagged(t *testing.T) {
	body := "var _ = func(db DB, ctx context.Context) { db.Pool.Raw().Begin(ctx) }\n"
	if got := onlyKind(findingsFor(t, body), rawKindOpaque); len(got) != 1 {
		t.Fatalf("Begin() on the raw pool was not flagged; got %d, want 1: %+v", len(got), got)
	}
}

// The same call on the SCOPED pool is the normal path and must stay quiet.
func TestRaw_unreadableSQLOnTheScopedPoolIsFine(t *testing.T) {
	body := "var _ = func(db DB, ctx context.Context, query string) { db.Pool.QueryRow(ctx, query, 1) }\n"
	if got := findingsFor(t, body); len(got) != 0 {
		t.Fatalf("an unreadable query on the SCOPED pool was flagged: %+v", got)
	}
}

// A value DERIVED from a Raw() call is not a pool being handed off. The
// read-path repositories are written as scanUser(r.db.Reader().QueryRow(...)),
// and reporting scanUser as receiving a pool would bury the real finding (the
// QueryRow) under a wrong one.
func TestRaw_aValueDerivedFromRawIsNotAHandoff(t *testing.T) {
	body := "var _ = func(db DB, ctx context.Context, query string) { takesARow(db.Pool.Raw().QueryRow(ctx, query)) }\nfunc takesARow(v any) {}\n"
	for _, f := range onlyKind(findingsFor(t, body), rawKindHandoff) {
		t.Errorf("a query RESULT was reported as a pool handoff: %s", f)
	}
	if got := onlyKind(findingsFor(t, body), rawKindOpaque); len(got) != 1 {
		t.Fatalf("the real finding (the QueryRow itself) is missing; got %d, want 1: %+v", len(got), got)
	}
}

// The findings must read as what they are. "used without org_id" would send a
// reader to add an org_id, which fixes nothing here — and for the opaque kind
// it would also print an empty table name.
func TestRaw_messagesDoNotSayUsedWithoutOrgID(t *testing.T) {
	bodies := []string{
		"var _ = func(db DB, ctx context.Context) { db.Pool.Raw().Query(ctx, `SELECT id FROM users`) }\n",
		"var _ = func(db DB, ctx context.Context, query string) { db.Pool.Raw().QueryRow(ctx, query) }\n",
		"var _ = func(db DB) { takesAPool(db.Pool.Raw()) }\n",
	}
	for _, body := range bodies {
		for _, f := range findingsFor(t, body) {
			if strings.Contains(f.String(), "used without org_id") {
				t.Errorf("a Raw() finding borrowed the missing-predicate wording: %s", f)
			}
			if strings.Contains(f.String(), `table ""`) {
				t.Errorf("a Raw() finding printed an empty table name: %s", f)
			}
		}
	}
}
