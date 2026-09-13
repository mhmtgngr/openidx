package provisioning

import (
	"context"
	"os"
	"regexp"
	"testing"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// The ordering is a DECISION, so it is pinned here rather than left to whoever
// edits the query next. The behaviour tests below cannot do this job on their
// own: Postgres returns tied rows in whatever order the plan it chose happens
// to produce, and with the v191 index that order carries id anyway -- so
// deleting the tie-break leaves them green while the guarantee is gone. The
// guarantee has to come from the ORDER BY, because the planner is free to pick
// a sort instead, and on that day the ties arrive in heap order.
//
// This is the same shape, and the same reason, as TestEventOrderingIsTotal in
// internal/audit.
func TestSCIMOrderingIsTotal(t *testing.T) {
	for name, ordering := range map[string]string{
		"users":  scimUserOrdering,
		"groups": scimGroupOrdering,
	} {
		if ordering != "ORDER BY created_at, id" {
			t.Errorf("%s ordering is %q; created_at alone is not a total order -- it defaults to NOW(), which is the TRANSACTION timestamp, so every row one transaction writes ties exactly", name, ordering)
		}
	}
}

// THE PREMISE, MEASURED RATHER THAN ASSUMED.
//
// The tie-break is only worth having if the ties are real. They are not a rare
// microsecond collision here: NOW() is the transaction timestamp, so a SCIM
// bulk create, a directory sync or a CSV import writes a whole block of rows
// carrying one identical created_at.
func TestSCIMTiesAreGuaranteedNotRare(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	if _, err := db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`); err != nil {
		t.Fatalf("pgcrypto: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, inboundUsersSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}

	const org = "11111111-1111-4111-8111-111111111111"
	// One statement, therefore one transaction, therefore one NOW().
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO users (username, email, org_id)
		SELECT 'tie-' || g, 'tie-' || g || '@example.test', $1::uuid
		  FROM generate_series(1, 200) g`, org); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var distinct, rows int
	if err := db.Pool.QueryRow(ctx,
		`SELECT count(DISTINCT created_at), count(*) FROM users WHERE org_id = $1`, org).
		Scan(&distinct, &rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 200 {
		t.Fatalf("seeded %d rows, want 200", rows)
	}
	if distinct != 1 {
		t.Errorf("200 rows written in one transaction carry %d distinct created_at values, want 1. "+
			"If this ever stops being 1 the tie-break is still correct, but the argument for it in "+
			"scim_ordering.go needs rewriting", distinct)
	}
	t.Logf("200 rows written in one transaction share %d distinct created_at value(s)", distinct)
}

// AND THE CONSEQUENCE: with the total order, paging the whole directory returns
// every user exactly once. This drives ListSCIMUsers itself, page by page, the
// way a provisioning client syncing a directory does.
func TestSCIMUserPagingVisitsEveryUserExactlyOnce(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	if _, err := db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`); err != nil {
		t.Fatalf("pgcrypto: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, inboundUsersSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}

	const orgID = "22222222-2222-4222-8222-222222222222"
	const total = 200
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO users (username, email, org_id)
		SELECT 'page-' || g, 'page-' || g || '@example.test', $1::uuid
		  FROM generate_series(1, $2) g`, orgID, total); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// A second tenant, whose rows must never appear: the ordering fix must not
	// cost the tenant scope.
	const otherOrg = "33333333-3333-4333-8333-333333333333"
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO users (username, email, org_id)
		SELECT 'other-' || g, 'other-' || g || '@example.test', $1::uuid
		  FROM generate_series(1, 50) g`, otherOrg); err != nil {
		t.Fatalf("seed other tenant: %v", err)
	}

	svc := &Service{db: db}
	scoped := orgctx.With(ctx, orgctx.Org{ID: orgID})

	const pageSize = 25
	seen := map[string]int{}
	var order []string
	for start := 1; start <= total; start += pageSize {
		resp, err := svc.ListSCIMUsers(scoped, start, pageSize, "")
		if err != nil {
			t.Fatalf("page at startIndex %d: %v", start, err)
		}
		if resp.TotalResults != total {
			t.Errorf("startIndex %d: totalResults = %d, want %d (RFC 7644 requires it and the filter must not change it)",
				start, resp.TotalResults, total)
		}
		if resp.StartIndex != start {
			t.Errorf("startIndex echoed as %d, want %d", resp.StartIndex, start)
		}
		page, ok := resp.Resources.([]SCIMUser)
		if !ok {
			t.Fatalf("startIndex %d: Resources is %T, want []SCIMUser", start, resp.Resources)
		}
		for _, u := range page {
			seen[u.ID]++
			order = append(order, u.ID)
		}
	}

	if len(order) != total {
		t.Errorf("walking the directory returned %d rows, want %d", len(order), total)
	}
	var dupes, missing int
	for _, n := range seen {
		if n > 1 {
			dupes++
		}
	}
	if dupes > 0 {
		t.Errorf("%d user(s) appeared on more than one page; a provisioning client would create them twice downstream", dupes)
	}
	if err := db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM users u WHERE u.org_id = $1 AND NOT (u.id::text = ANY($2::text[]))`,
		orgID, order).Scan(&missing); err != nil {
		t.Fatalf("missing check: %v", err)
	}
	if missing > 0 {
		t.Errorf("%d user(s) never appeared on any page; each is an account that silently never reaches a downstream application", missing)
	}
	if len(seen) != total {
		t.Errorf("saw %d distinct users, want %d", len(seen), total)
	}
	t.Logf("%d pages of %d: %d rows, %d distinct, 0 duplicated, 0 missing", total/pageSize, pageSize, len(order), len(seen))
}

// The ordering must be the one the query actually runs, not one a reader
// assumes. This drives the real query and checks the rows come back in
// (created_at, id) order -- so a tie-break spelled in the constant but dropped
// from the SQL is caught.
func TestSCIMUserPagingIsOrderedByCreatedAtThenID(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	if _, err := db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`); err != nil {
		t.Fatalf("pgcrypto: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, inboundUsersSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	const orgID = "44444444-4444-4444-8444-444444444444"
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO users (username, email, org_id)
		SELECT 'ord-' || g, 'ord-' || g || '@example.test', $1::uuid
		  FROM generate_series(1, 60) g`, orgID); err != nil {
		t.Fatalf("seed: %v", err)
	}

	svc := &Service{db: db}
	scoped := orgctx.With(ctx, orgctx.Org{ID: orgID})
	resp, err := svc.ListSCIMUsers(scoped, 1, 60, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	page, ok := resp.Resources.([]SCIMUser)
	if !ok {
		t.Fatalf("Resources is %T, want []SCIMUser", resp.Resources)
	}
	if len(page) != 60 {
		t.Fatalf("got %d rows, want 60", len(page))
	}

	var want []string
	rows, err := db.Pool.Query(ctx,
		`SELECT id::text FROM users WHERE org_id = $1 ORDER BY created_at, id`, orgID)
	if err != nil {
		t.Fatalf("expected order: %v", err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			t.Fatalf("scan: %v", err)
		}
		want = append(want, id)
	}
	rows.Close()

	for i, u := range page {
		if u.ID != want[i] {
			t.Fatalf("row %d is %s, want %s -- the list is not ordered by (created_at, id)", i, u.ID, want[i])
		}
	}
	t.Log("60 rows returned in (created_at, id) order")
}

// A FINDING THIS FILE MADE WHILE TESTING SOMETHING ELSE.
//
// users.first_name, last_name and email are all nullable, and the list scanned
// them into plain strings. Every row for a user without a name failed
// rows.Scan -- and the loop answered that with `continue`. The response then
// carried totalResults = N with none of the N users in it, 200 OK, nothing
// logged. A SCIM client reads a short page as the whole page: those accounts
// simply do not exist as far as every downstream application is concerned.
//
// It is the same failure as a paging defect and worse, because it needs no
// concurrency and no tie to happen -- only a user with no surname.
func TestSCIMUserListDoesNotSilentlyDropRows(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	if _, err := db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`); err != nil {
		t.Fatalf("pgcrypto: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, inboundUsersSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}

	const orgID = "55555555-5555-4555-8555-555555555555"
	// Deliberately the awkward shapes: no name at all, no email, and one
	// fully-populated row so the test cannot pass by returning nothing.
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO users (username, email, first_name, last_name, org_id) VALUES
			('no-name',    'no-name@example.test', NULL,   NULL,  $1::uuid),
			('no-email',   NULL,                   'Ada',  'L',   $1::uuid),
			('no-surname', 'ada@example.test',     'Ada',  NULL,  $1::uuid),
			('complete',   'c@example.test',       'Cee',  'Dee', $1::uuid)`, orgID); err != nil {
		t.Fatalf("seed: %v", err)
	}

	svc := &Service{db: db}
	resp, err := svc.ListSCIMUsers(orgctx.With(ctx, orgctx.Org{ID: orgID}), 1, 100, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	page, ok := resp.Resources.([]SCIMUser)
	if !ok {
		t.Fatalf("Resources is %T, want []SCIMUser", resp.Resources)
	}

	if resp.TotalResults != 4 {
		t.Fatalf("totalResults = %d, want 4", resp.TotalResults)
	}
	// The invariant, stated: a response that counts rows it cannot return is a
	// lie the client has no way to detect.
	if len(page) != resp.TotalResults {
		t.Errorf("the list returned %d of %d users and reported success; the missing ones have no name or no email, "+
			"and a SCIM client reads a short page as the whole directory", len(page), resp.TotalResults)
	}
	if resp.ItemsPerPage != len(page) {
		t.Errorf("itemsPerPage = %d but %d resources were returned", resp.ItemsPerPage, len(page))
	}

	byName := map[string]SCIMUser{}
	for _, u := range page {
		byName[u.UserName] = u
	}
	for _, want := range []string{"no-name", "no-email", "no-surname", "complete"} {
		if _, ok := byName[want]; !ok {
			t.Errorf("user %q is missing from the list", want)
		}
	}
}

// The two halves of that fix overlap, and the overlap hides one of them.
//
// With COALESCE in the SELECT no scan fails, so putting `continue` back in the
// loop changes nothing a behaviour test can see -- the mutation stays green.
// The `continue` is still wrong: it turns "this row did not read" into "this
// row does not exist", and it would come back the moment a column is added,
// widened or made nullable. So it is pinned where it lives, in the source.
func TestSCIMListLoopsDoNotSwallowScanErrors(t *testing.T) {
	src, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatalf("read service.go: %v", err)
	}

	// Every scan in a SCIM list loop, and what the next statement does with a
	// failure. A `continue` there is a short page reported as a whole one.
	scan := regexp.MustCompile(`if err := rows\.Scan\(&id, &(username|name),[^)]*\); err != nil \{\s*\n\s*(\w+)`)
	matches := scan.FindAllStringSubmatch(string(src), -1)
	if len(matches) < 2 {
		t.Fatalf("found %d SCIM list scan loops in service.go, want at least 2 (users and groups); "+
			"this guard is checking almost nothing", len(matches))
	}
	for _, m := range matches {
		if m[2] == "continue" {
			t.Errorf("a SCIM list loop answers a failed scan with `continue`: the caller gets a short page and a " +
				"success, which on a provisioning API is an account that never reaches a downstream application")
		}
	}
}
