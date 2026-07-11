package provisioning

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestListSCIMUsers_Filter guards the SCIM Users existence/dedup lookup. Before
// this fix ListSCIMUsers accepted a `filter` argument but never applied it (the
// SQL was a constant WHERE org_id=$3), while ServiceProviderConfig advertises
// filter.supported=true — so an IdP's GET /Users?filter=userName eq "x" always
// returned the whole first page and totalResults for the whole org, breaking
// Okta/Entra dedup. Now the parsed `attr eq "value"` predicate is applied to
// both the COUNT and the SELECT, org-scoped, and an unsupported filter fails
// loud. DB-backed because it exercises the real parameterized queries.
func TestListSCIMUsers_Filter(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	const (
		orgA = "00000000-0000-0000-0000-00000000000a"
		orgB = "00000000-0000-0000-0000-00000000000b"
	)
	ctxA := orgctx.With(context.Background(), orgctx.Org{ID: orgA})

	if _, err := db.Pool.Exec(ctxA, `
		CREATE TABLE users (
			id UUID PRIMARY KEY, username VARCHAR(255), email VARCHAR(255),
			first_name VARCHAR(255), last_name VARCHAR(255), external_id VARCHAR(255),
			enabled BOOLEAN DEFAULT true, org_id UUID NOT NULL,
			created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now());
	`); err != nil {
		t.Fatalf("schema: %v", err)
	}
	user := func(id, username, email, ext, org string) {
		if _, err := db.Pool.Exec(ctxA, `
			INSERT INTO users (id, username, email, first_name, last_name, external_id, enabled, org_id)
			VALUES ($1,$2,$3,'F','L',$4,true,$5)`, id, username, email, ext, org); err != nil {
			t.Fatalf("seed user %s: %v", username, err)
		}
	}
	user("11111111-0000-0000-0000-00000000000a", "alice", "alice@x.io", "EXT-A", orgA)
	user("11111111-0000-0000-0000-00000000000b", "bob", "bob@x.io", "EXT-B", orgA)
	// Same userName in another org must never leak into org A's filtered list.
	user("22222222-0000-0000-0000-00000000000b", "alice", "alice@other.io", "EXT-Z", orgB)

	s := &Service{db: db, logger: zap.NewNop()}

	scimUsers := func(r *SCIMListResponse) []SCIMUser {
		t.Helper()
		us, ok := r.Resources.([]SCIMUser)
		if !ok {
			t.Fatalf("Resources is %T, want []SCIMUser", r.Resources)
		}
		return us
	}

	// userName eq matches exactly one, org-scoped, and totalResults reflects the filter.
	resp, err := s.ListSCIMUsers(ctxA, 1, 50, `userName eq "alice"`)
	if err != nil {
		t.Fatalf("filter userName eq alice: %v", err)
	}
	if us := scimUsers(resp); resp.TotalResults != 1 || len(us) != 1 {
		t.Fatalf(`userName eq "alice": want 1 result, got total=%d len=%d`, resp.TotalResults, len(us))
	} else if us[0].UserName != "alice" || us[0].ID != "11111111-0000-0000-0000-00000000000a" {
		t.Fatalf("want org A's alice, got %+v", us[0])
	}

	// Case-insensitive per RFC 7644.
	if resp, err := s.ListSCIMUsers(ctxA, 1, 50, `userName eq "ALICE"`); err != nil || resp.TotalResults != 1 {
		t.Fatalf(`userName eq "ALICE" (case-insensitive): total=%d err=%v`, respTotal(resp), err)
	}

	// externalId is compared exactly.
	if resp, err := s.ListSCIMUsers(ctxA, 1, 50, `externalId eq "EXT-B"`); err != nil || resp.TotalResults != 1 {
		t.Fatalf(`externalId eq "EXT-B": total=%d err=%v`, respTotal(resp), err)
	}

	// A filter that matches nobody yields an empty, well-formed list (not the whole org).
	if resp, err := s.ListSCIMUsers(ctxA, 1, 50, `userName eq "nobody"`); err != nil || resp.TotalResults != 0 || len(scimUsers(resp)) != 0 {
		t.Fatalf(`userName eq "nobody": want empty, total=%d err=%v`, respTotal(resp), err)
	}

	// No filter still returns the whole org (2 users), proving the filter is additive.
	if resp, err := s.ListSCIMUsers(ctxA, 1, 50, ""); err != nil || resp.TotalResults != 2 {
		t.Fatalf("no filter: want 2 org-A users, total=%d err=%v", respTotal(resp), err)
	}

	// An unsupported filter must fail loud (→ 400 invalidFilter), never silently unfiltered.
	if _, err := s.ListSCIMUsers(ctxA, 1, 50, `userName co "ali"`); !errors.Is(err, errUnsupportedFilter) {
		t.Fatalf("unsupported operator: want errUnsupportedFilter, got %v", err)
	}
}

// TestListSCIMGroups_Filter is the Group-side twin of the Users filter test.
func TestListSCIMGroups_Filter(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	const org = "00000000-0000-0000-0000-00000000000a"
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: org})

	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE groups (
			id UUID PRIMARY KEY, name VARCHAR(255), description TEXT,
			external_id VARCHAR(255), org_id UUID NOT NULL,
			created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now());
	`); err != nil {
		t.Fatalf("schema: %v", err)
	}
	group := func(id, name string) {
		// description must be non-NULL: the SELECT scans it into a non-pointer string.
		if _, err := db.Pool.Exec(ctx, `INSERT INTO groups (id, name, description, org_id) VALUES ($1,$2,'',$3)`, id, name, org); err != nil {
			t.Fatalf("seed group %s: %v", name, err)
		}
	}
	group("33333333-0000-0000-0000-000000000001", "Engineering")
	group("33333333-0000-0000-0000-000000000002", "Sales")

	s := &Service{db: db, logger: zap.NewNop()}

	resp, err := s.ListSCIMGroups(ctx, 1, 50, `displayName eq "Engineering"`)
	if err != nil {
		t.Fatalf("filter displayName eq Engineering: %v", err)
	}
	gs, ok := resp.Resources.([]SCIMGroup)
	if !ok {
		t.Fatalf("Resources is %T, want []SCIMGroup", resp.Resources)
	}
	if resp.TotalResults != 1 || len(gs) != 1 {
		t.Fatalf(`displayName eq "Engineering": want 1, got total=%d len=%d`, resp.TotalResults, len(gs))
	}
	if gs[0].DisplayName != "Engineering" {
		t.Fatalf("want Engineering group, got %+v", gs[0])
	}

	if resp, err := s.ListSCIMGroups(ctx, 1, 50, `displayName eq "Marketing"`); err != nil || resp.TotalResults != 0 {
		t.Fatalf(`displayName eq "Marketing": want 0, total=%d err=%v`, respTotal(resp), err)
	}
	if _, err := s.ListSCIMGroups(ctx, 1, 50, `displayName sw "Eng"`); !errors.Is(err, errUnsupportedFilter) {
		t.Fatalf("unsupported operator: want errUnsupportedFilter, got %v", err)
	}
}

func respTotal(r *SCIMListResponse) int {
	if r == nil {
		return -1
	}
	return r.TotalResults
}
