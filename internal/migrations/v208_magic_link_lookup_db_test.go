// Package migrations_test, not migrations, so that it can reach
// adminPoolOrSkip in least_privilege_owner_test.go.
package migrations_test

import (
	"context"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

// TestV208LeavesOldLinksUnfoundAndLooksUpNewOnes applies v208 over an install
// with a pending magic link, and checks that the link keeps a NULL lookup -- so
// the verifier, which looks links up by it, does not find it -- that a link
// minted afterwards is found by its lookup through the index, that two links
// cannot share a lookup, and that rolling back removes the column and index.
func TestV208LeavesOldLinksUnfoundAndLooksUpNewOnes(t *testing.T) {
	db, _, cleanup := adminPoolOrSkip(t)
	defer cleanup()
	ctx := context.Background()
	pool := db.Pool

	for _, stmt := range []string{"DROP SCHEMA public CASCADE", "CREATE SCHEMA public"} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("reset schema (%s): %v", stmt, err)
		}
	}
	m := migrations.NewMigrator(pool.Raw(), zap.NewNop())
	if err := m.MigrateTo(ctx, 207); err != nil {
		t.Fatalf("migrate to the version before it: %v", err)
	}

	var org, user string
	if err := pool.QueryRow(ctx,
		"SELECT id::text FROM organizations ORDER BY created_at ASC LIMIT 1").Scan(&org); err != nil {
		t.Fatalf("read the oldest org: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO users (org_id, username, email, enabled) VALUES ($1::uuid, 'v208-user', 'v208-user@example.test', true)
		RETURNING id::text`, org).Scan(&user); err != nil {
		t.Fatalf("seed a user: %v", err)
	}
	link := func(tokenHash string) string {
		t.Helper()
		var id string
		if err := pool.QueryRow(ctx, `
			INSERT INTO magic_links (org_id, user_id, email, token_hash, status, expires_at)
			VALUES ($1::uuid, $2::uuid, 'v208-user@example.test', $3, 'pending', NOW() + INTERVAL '15 minutes')
			RETURNING id::text`, org, user, tokenHash).Scan(&id); err != nil {
			t.Fatalf("seed a magic link: %v", err)
		}
		return id
	}
	old := link("$2a$12$an-old-bcrypt-hash")

	if err := m.MigrateTo(ctx, 208); err != nil {
		t.Fatalf("migrate to 208: %v", err)
	}

	var lookup *string
	if err := pool.QueryRow(ctx, `SELECT token_lookup FROM magic_links WHERE id = $1::uuid`, old).Scan(&lookup); err != nil {
		t.Fatalf("read the old link's lookup: %v", err)
	}
	if lookup != nil {
		t.Fatalf("a link minted before v208 has lookup %q, want NULL (it is not found, and stops working)", *lookup)
	}

	// A link minted afterwards, as CreateMagicLink writes it.
	digest := strings.Repeat("ab", 32)
	fresh := link("$2a$12$a-new-bcrypt-hash")
	if _, err := pool.Exec(ctx, `UPDATE magic_links SET token_lookup = $2 WHERE id = $1::uuid`, fresh, digest); err != nil {
		t.Fatalf("store a lookup: %v", err)
	}
	var found string
	if err := pool.QueryRow(ctx, `SELECT id::text FROM magic_links WHERE token_lookup = $1 AND org_id = $2::uuid`, digest, org).Scan(&found); err != nil || found != fresh {
		t.Fatalf("look the new link up: %q, %v; want %s", found, err, fresh)
	}
	// A handful of rows can make a sequential scan the cheaper plan, so the
	// planner is asked not to take one: the index must then be there to use.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL enable_seqscan = off`); err != nil {
		t.Fatalf("disable seqscan: %v", err)
	}
	var plan string
	if err := tx.QueryRow(ctx, `EXPLAIN (COSTS OFF) SELECT id FROM magic_links WHERE token_lookup = '`+digest+`'`).Scan(&plan); err != nil {
		t.Fatalf("explain: %v", err)
	}
	_ = tx.Rollback(ctx)
	if !strings.Contains(plan, "idx_magic_links_token_lookup") {
		t.Fatalf("the lookup does not use idx_magic_links_token_lookup: %s", plan)
	}

	second := link("$2a$12$another-bcrypt-hash")
	if _, err := pool.Exec(ctx, `UPDATE magic_links SET token_lookup = $2 WHERE id = $1::uuid`, second, digest); err == nil {
		t.Fatal("two links took the same lookup")
	}

	if err := m.RollbackTo(ctx, 207); err != nil {
		t.Fatalf("roll back past 208: %v", err)
	}
	var columns, indexes int
	if err := pool.QueryRow(ctx, `
		SELECT (SELECT COUNT(*) FROM information_schema.columns
		         WHERE table_name = 'magic_links' AND column_name = 'token_lookup'),
		       (SELECT COUNT(*) FROM pg_indexes WHERE indexname = 'idx_magic_links_token_lookup')`).Scan(&columns, &indexes); err != nil {
		t.Fatalf("look for the column and index: %v", err)
	}
	if columns != 0 || indexes != 0 {
		t.Errorf("rolling back v208 left %d column(s) and %d index(es) behind", columns, indexes)
	}
}
