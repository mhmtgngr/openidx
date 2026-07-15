//go:build integration

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openidx/openidx/internal/common/secretcrypt"
)

// testPool connects to the integration DB (DATABASE_URL), skipping if unusable —
// same convention as test/integration.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping rekey integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Skipf("cannot connect to test DB: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("test DB not reachable: %v", err)
	}
	return pool
}

// TestRekeyReSealsEncv1UnderActiveKEK is the end-to-end proof: seed a table with
// values sealed under the old key (encv1), run rekeyColumn with a keyring whose
// active KEK is 2 and whose legacy reader is the old key, and confirm every value
// is re-sealed as encv2:2 and still decrypts to the original plaintext. Also
// checks dry-run writes nothing and the run is idempotent.
func TestRekeyReSealsEncv1UnderActiveKEK(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	ctx := context.Background()
	_, _ = pool.Exec(ctx, "SELECT set_config('app.bypass_rls','on',false)")

	tbl := fmt.Sprintf("rekey_it_%d", time.Now().UnixNano())
	_, err := pool.Exec(ctx, fmt.Sprintf(
		"CREATE TABLE %s (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), secret text)", tbl))
	if err != nil {
		t.Fatalf("create table: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DROP TABLE IF EXISTS "+tbl) })

	// Old key seals encv1 (single-key mode).
	oldKey := "0123456789abcdef0123456789abcdef"
	single, err := secretcrypt.New(oldKey)
	if err != nil {
		t.Fatal(err)
	}
	secrets := []string{"alpha-secret", "beta-secret", "gamma-secret"}
	for _, s := range secrets {
		ct, err := single.Encrypt(s)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(ct, "encv1:") {
			t.Fatalf("expected encv1 seed, got %q", ct)
		}
		if _, err := pool.Exec(ctx, fmt.Sprintf("INSERT INTO %s (secret) VALUES ($1)", tbl), ct); err != nil {
			t.Fatal(err)
		}
	}

	// Keyring: active KEK 2, KEK 1 retained, old key as encv1 legacy reader.
	ring, err := secretcrypt.NewKeyring(
		map[int][]byte{1: key32(1), 2: key32(2)}, 2, []byte(oldKey))
	if err != nil {
		t.Fatal(err)
	}
	ref := colRef{table: tbl, col: "secret", pk: "id"}

	// Dry-run: reports all rows, writes nothing.
	n, errs := rekeyColumn(ctx, pool, ring, ref, 2, 1000, true)
	if n != len(secrets) || errs != 0 {
		t.Fatalf("dry-run: resealed=%d errs=%d, want %d/0", n, errs, len(secrets))
	}
	if got := countPrefix(t, ctx, pool, tbl, "encv1:"); got != len(secrets) {
		t.Fatalf("dry-run must not write: encv1 count=%d, want %d", got, len(secrets))
	}

	// Apply.
	n, errs = rekeyColumn(ctx, pool, ring, ref, 2, 1000, false)
	if n != len(secrets) || errs != 0 {
		t.Fatalf("apply: resealed=%d errs=%d, want %d/0", n, errs, len(secrets))
	}
	if got := countPrefix(t, ctx, pool, tbl, "encv2:2:"); got != len(secrets) {
		t.Fatalf("after apply: encv2:2 count=%d, want %d", got, len(secrets))
	}
	if got := countPrefix(t, ctx, pool, tbl, "encv1:"); got != 0 {
		t.Fatalf("after apply: %d encv1 values remain, want 0", got)
	}

	// Every value still decrypts to its original plaintext under the ring.
	rows, err := pool.Query(ctx, fmt.Sprintf("SELECT secret FROM %s ORDER BY secret", tbl))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		pt, err := ring.Decrypt(v)
		if err != nil {
			t.Fatalf("decrypt resealed value: %v", err)
		}
		got = append(got, pt)
	}
	rows.Close()
	want := []string{"alpha-secret", "beta-secret", "gamma-secret"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("plaintext after rekey = %v, want %v", got, want)
	}

	// Idempotent: a second apply reseals nothing.
	n, errs = rekeyColumn(ctx, pool, ring, ref, 2, 1000, false)
	if n != 0 || errs != 0 {
		t.Fatalf("second apply should be a no-op, got resealed=%d errs=%d", n, errs)
	}

	// The enumerator finds our column (single-PK text column in public schema).
	cols, err := textColumns(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range cols {
		if c.table == tbl && c.col == "secret" && c.pk == "id" {
			found = true
		}
	}
	if !found {
		t.Fatalf("textColumns did not enumerate %s.secret", tbl)
	}
}

func countPrefix(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tbl, prefix string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx,
		fmt.Sprintf("SELECT count(*) FROM %s WHERE secret LIKE $1", tbl), prefix+"%").
		Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// key32 mirrors the secretcrypt test helper: a deterministic 32-byte key.
func key32(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b + byte(i)
	}
	return k
}
