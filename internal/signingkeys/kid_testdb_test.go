package signingkeys

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

// THE KEY SAYS WHICH CELL MINTED IT (plan 4.4, code half).
//
// Against the real oauth_signing_keys table from the registered v79 DDL: a
// store serving cell eu-1 generates and rotates kids under "eu-1-key-", a
// store on a single-cell install keeps "openidx-key-", and the legacy import
// keeps its original kid whatever cell it is imported into -- tokens minted
// before the upgrade carry that kid and must go on verifying.
func TestGeneratedKidsCarryTheCellAndTheLegacyImportKeepsItsName(t *testing.T) {
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set; skipping the cell kid test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	var v79 string
	for _, m := range migrations.All() {
		if m.Version == 79 {
			v79 = m.UpSQL
		}
	}
	if v79 == "" {
		t.Fatal("migration v79 (oauth_signing_keys) is not registered")
	}
	reset := func() {
		if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS oauth_signing_keys`); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, v79); err != nil {
			t.Fatal(err)
		}
	}
	reset()
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DROP TABLE IF EXISTS oauth_signing_keys`) })

	// A named cell: generated on first boot, and again on rotation.
	eu := NewStore(pool, testEncryptionKey, "eu-1", zap.NewNop())
	first, err := eu.EnsureActive(ctx, nil)
	if err != nil {
		t.Fatalf("EnsureActive: %v", err)
	}
	if !strings.HasPrefix(first.Kid, "eu-1-key-") || len(first.Kid) <= len("eu-1-key-") {
		t.Fatalf("first kid = %q, want eu-1-key-<hex>", first.Kid)
	}
	rotated, err := eu.Rotate(ctx, DefaultGrace)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if !strings.HasPrefix(rotated.Kid, "eu-1-key-") || rotated.Kid == first.Kid {
		t.Fatalf("rotated kid = %q, want a fresh eu-1-key-<hex> (first was %q)", rotated.Kid, first.Kid)
	}

	// EnsureActive on a later boot returns the key that is there, not a new one.
	again, err := eu.EnsureActive(ctx, nil)
	if err != nil || again.Kid != rotated.Kid {
		t.Fatalf("EnsureActive after rotation = %v/%v, want the active %s", again, err, rotated.Kid)
	}

	// A single-cell install keeps the historical prefix.
	reset()
	single := NewStore(pool, testEncryptionKey, "", zap.NewNop())
	solo, err := single.EnsureActive(ctx, nil)
	if err != nil {
		t.Fatalf("EnsureActive (single cell): %v", err)
	}
	if !strings.HasPrefix(solo.Kid, "openidx-key-") || solo.Kid == LegacyKid {
		t.Fatalf("single-cell kid = %q, want openidx-key-<hex>", solo.Kid)
	}

	// The legacy import keeps its name in a named cell: pre-upgrade tokens
	// carry kid openidx-key-1 and must keep verifying.
	reset()
	legacy, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	imported, err := NewStore(pool, testEncryptionKey, "eu-1", zap.NewNop()).EnsureActive(ctx, legacy)
	if err != nil {
		t.Fatalf("EnsureActive (legacy import): %v", err)
	}
	if imported.Kid != LegacyKid {
		t.Fatalf("legacy import kid = %q, want %q", imported.Kid, LegacyKid)
	}
}
