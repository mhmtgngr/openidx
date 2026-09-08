package identity

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// The two defects pinned here were both found by making the package's
// benchmark suite run for the first time (it had a DSN naming a database
// nothing creates, and every seed insert was invalid besides). Neither had a
// test, and neither is exotic:
//
//  1. Searching users returned a 500 on EVERY call. The query ends
//     `ILIKE $1 ESCAPE '\\'` inside a Go RAW string, so the SQL text carries
//     two backslashes where Postgres allows exactly one character --
//     "ERROR: invalid escape string ... Escape string must be empty or one
//     character" (SQLSTATE 22025). The console's user-search box could never
//     have worked.
//
//  2. Listing users failed entirely if ANY user had a NULL first_name or
//     last_name. Both columns are nullable; UserDB scans them into plain
//     strings, so one such row failed the whole call with "cannot scan NULL
//     into *string" -- not a bad row, a bad page. The product's own create
//     path writes "", which is why this stayed hidden: it takes a user from
//     directory sync, a SCIM import or a pre-column row to produce one.

// listUsersFixture builds the users table this file needs and returns an
// org-scoped context. It creates the table directly rather than running the
// migration chain, matching how the rest of this package's DB tests work.
func listUsersFixture(t *testing.T) (*Service, context.Context, func()) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	ctx := orgctx.With(context.Background(), orgctx.Org{
		ID:   "00000000-0000-0000-0000-000000000010",
		Slug: "default",
	})

	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE users (
			id UUID PRIMARY KEY,
			username VARCHAR(255) NOT NULL UNIQUE,
			email VARCHAR(255),
			first_name VARCHAR(255),
			last_name VARCHAR(255),
			password_hash TEXT,
			enabled BOOLEAN NOT NULL DEFAULT true,
			email_verified BOOLEAN NOT NULL DEFAULT false,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			last_login_at TIMESTAMPTZ,
			password_changed_at TIMESTAMPTZ,
			password_must_change BOOLEAN NOT NULL DEFAULT false,
			failed_login_count INT NOT NULL DEFAULT 0,
			last_failed_login_at TIMESTAMPTZ,
			locked_until TIMESTAMPTZ,
			org_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000010'
		)`); err != nil {
		cleanup()
		t.Fatalf("create users: %v", err)
	}

	svc := &Service{db: db, logger: zap.NewNop()}
	return svc, ctx, cleanup
}

func seedListUser(t *testing.T, svc *Service, ctx context.Context, username string, first, last interface{}) {
	t.Helper()
	if _, err := svc.db.Pool.Exec(ctx, `
		INSERT INTO users (id, username, email, first_name, last_name)
		VALUES ($1, $2, $3, $4, $5)`,
		uuid.NewString(), username, username+"@example.test", first, last); err != nil {
		t.Fatalf("seed %s: %v", username, err)
	}
}

// TestListUsersSearchIsNotAnInvalidEscapeString is the regression guard for the
// 500. It asserts the search RUNS and that the escaping it exists for actually
// escapes: a search for "a_b" must not match "axb", because `_` is a LIKE
// wildcard and the ESCAPE clause is what makes it a literal.
func TestListUsersSearchIsNotAnInvalidEscapeString(t *testing.T) {
	svc, ctx, cleanup := listUsersFixture(t)
	defer cleanup()

	seedListUser(t, svc, ctx, "alice", "Alice", "Anderson")
	seedListUser(t, svc, ctx, "a_b", "Under", "Score")
	seedListUser(t, svc, ctx, "axb", "Wild", "Card")

	t.Run("a plain search returns its match rather than an error", func(t *testing.T) {
		users, total, err := svc.ListUsers(ctx, 0, 20, "alice")
		if err != nil {
			t.Fatalf("search errored: %v", err)
		}
		if total != 1 || len(users) != 1 {
			t.Fatalf("total=%d len=%d, want 1 and 1", total, len(users))
		}
		if users[0].UserName != "alice" {
			t.Fatalf("matched %q, want alice", users[0].UserName)
		}
	})

	t.Run("an underscore in the term is a literal, not a wildcard", func(t *testing.T) {
		users, total, err := svc.ListUsers(ctx, 0, 20, "a_b")
		if err != nil {
			t.Fatalf("search errored: %v", err)
		}
		// Without a working ESCAPE clause this matches axb as well, which is
		// the reason the clause is in the query at all.
		if total != 1 || len(users) != 1 {
			t.Fatalf("total=%d len=%d, want 1 and 1 — `_` was treated as a wildcard", total, len(users))
		}
		if users[0].UserName != "a_b" {
			t.Fatalf("matched %q, want a_b", users[0].UserName)
		}
	})

	t.Run("a percent in the term is a literal too", func(t *testing.T) {
		seedListUser(t, svc, ctx, "100%sure", "Per", "Cent")
		users, _, err := svc.ListUsers(ctx, 0, 20, "100%s")
		if err != nil {
			t.Fatalf("search errored: %v", err)
		}
		if len(users) != 1 || users[0].UserName != "100%sure" {
			t.Fatalf("got %d users, want just 100%%sure", len(users))
		}
	})
}

// TestListUsersToleratesNullNames is the regression guard for the whole-page
// failure. One user with no first name must not take the list down.
func TestListUsersToleratesNullNames(t *testing.T) {
	svc, ctx, cleanup := listUsersFixture(t)
	defer cleanup()

	seedListUser(t, svc, ctx, "has-names", "Given", "Family")
	seedListUser(t, svc, ctx, "no-names", nil, nil) // e.g. a directory-synced user

	users, total, err := svc.ListUsers(ctx, 0, 20)
	if err != nil {
		t.Fatalf("listing errored on a user with NULL names: %v", err)
	}
	if total != 2 || len(users) != 2 {
		t.Fatalf("total=%d len=%d, want 2 and 2", total, len(users))
	}

	// The NULL reads as empty, which is what the SCIM shape expects.
	var found bool
	for _, u := range users {
		if u.UserName == "no-names" {
			found = true
			if u.Name != nil {
				if g := u.Name.GivenName; g != nil && *g != "" {
					t.Fatalf("NULL first_name came back as %q, want empty", *g)
				}
				if f := u.Name.FamilyName; f != nil && *f != "" {
					t.Fatalf("NULL last_name came back as %q, want empty", *f)
				}
			}
		}
	}
	if !found {
		t.Fatal("the user with NULL names is missing from the page")
	}

	// And through the search path, which selects the same columns.
	users, _, err = svc.ListUsers(ctx, 0, 20, "no-names")
	if err != nil {
		t.Fatalf("search errored on a user with NULL names: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("search returned %d users, want 1", len(users))
	}
}
