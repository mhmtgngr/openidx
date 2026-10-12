package testsupport

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// PostgresEnv is the one environment variable that points the test suites at
// a PostgreSQL server: a DSN for a database the tests may build tables in.
//
// There used to be two. TEST_POSTGRES_DSN was read by the suites that build
// their own tables (and, as an unprivileged role, by the row-level-security
// belts); OPENIDX_TEST_DATABASE_URL by the suites that build the whole schema
// from the registered migrations, which DROPPED that database's public schema
// on every call. CI set only the first, in one job, for hand-picked -run
// patterns, so most suites reading it were skipped in the unit matrix.
const PostgresEnv = "TEST_POSTGRES_DSN"

// SuperuserPostgresEnv optionally names a superuser on the same server. Tests
// that need superuser powers read it -- creating roles, and here creating the
// scratch databases ScratchDatabase hands out -- so that PostgresEnv can be an
// unprivileged role, which the row-level-security belts require (a superuser
// passes them by bypassing). With only PostgresEnv set, and set to a role that
// may create databases, ScratchDatabase uses that.
const SuperuserPostgresEnv = "TEST_POSTGRES_SUPERUSER_DSN"

// LegacyPostgresEnv is the deprecated alias for PostgresEnv, honoured when
// PostgresEnv is unset. Remove after the v1.47 release.
const LegacyPostgresEnv = "OPENIDX_TEST_DATABASE_URL"

// PostgresDSN returns the test PostgreSQL DSN, or "" when none is configured.
// It reads PostgresEnv, then the deprecated LegacyPostgresEnv. Every test that
// wants a configured server reads it through here, so there is one name to set.
func PostgresDSN() string {
	if dsn := os.Getenv(PostgresEnv); dsn != "" {
		return dsn
	}
	return os.Getenv(LegacyPostgresEnv)
}

// ScratchDatabase gives the calling test an empty database of its own on the
// configured server: it creates one with a random name, returns a DSN for it,
// and drops it when the test ends. The server is SuperuserPostgresEnv's when that
// is set, else PostgresEnv's. ok is false when neither is set, or when the role
// may not create databases (CREATEDB); the caller then
// falls back to starting a container, exactly as it does with no server at all.
// Any other failure is fatal: a configured server that cannot be reached is a
// broken setup, not a reason to skip.
//
// This replaces "DROP SCHEMA public CASCADE" on the configured database. That
// reset made the server usable by one package at a time, wiped whatever else
// lived there, and -- once CI points the unit matrix at a shared, unprivileged
// role -- would have let one test drop another's tables mid-run.
func ScratchDatabase(t testing.TB) (dsn string, ok bool) {
	t.Helper()
	base := os.Getenv(SuperuserPostgresEnv)
	if base == "" {
		base = PostgresDSN()
	}
	if base == "" {
		return "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("%s is set but unreachable: %v", PostgresEnv, err)
	}
	defer admin.Close(context.Background())

	var canCreate bool
	if err := admin.QueryRow(ctx, `SELECT rolsuper OR rolcreatedb FROM pg_roles WHERE rolname = current_user`).Scan(&canCreate); err != nil {
		t.Fatalf("read the test role's privileges: %v", err)
	}
	if !canCreate {
		return "", false
	}

	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatalf("random database name: %v", err)
	}
	name := "openidx_t_" + hex.EncodeToString(suffix)
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+name); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "42501" { // insufficient_privilege
			return "", false
		}
		t.Fatalf("create scratch database %s: %v", name, err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c, err := pgx.Connect(ctx, base)
		if err != nil {
			t.Logf("drop scratch database %s: connect: %v", name, err)
			return
		}
		defer c.Close(context.Background())
		// FORCE ends any connection a test left open (PostgreSQL 13+).
		if _, err := c.Exec(ctx, `DROP DATABASE IF EXISTS `+name+` WITH (FORCE)`); err != nil {
			t.Logf("drop scratch database %s: %v", name, err)
		}
	})

	out, err := withDatabase(base, name)
	if err != nil {
		t.Fatalf("%s: %v", PostgresEnv, err)
	}
	return out, true
}

// withDatabase returns dsn pointed at database name. It accepts both DSN forms
// pgx does: a postgres:// URL and a key=value string.
func withDatabase(dsn, name string) (string, error) {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return "", err
		}
		u.Path = "/" + name
		return u.String(), nil
	}
	var kept []string
	for _, f := range strings.Fields(dsn) {
		if !strings.HasPrefix(f, "dbname=") {
			kept = append(kept, f)
		}
	}
	return strings.Join(append(kept, "dbname="+name), " "), nil
}
