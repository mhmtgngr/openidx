package migrations

import (
	"context"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/testsupport"
)

// The rollback path, run end to end for the first time.
//
// Every migration in this chain carries a Down half, and RollbackTo exists to
// run them: it is what an operator reaches for when an upgrade goes wrong at
// three in the morning. Nothing had ever executed the chain in that direction.
// Measured on a fresh PostgreSQL 16, rolling back from v179 one version at a
// time, it stopped at v29 with
//
//	statement failed: DROP TABLE IF NOT EXISTS posture_check_types;
//	ERROR: syntax error at or near "NOT" (SQLSTATE 42601)
//
// -- a spelling PostgreSQL has never accepted (the keyword is IF EXISTS), in
// five statements across three migrations. Behind it, at v13 and v10, nine more
// statements matched a UUID primary key with LIKE, which raises
// `operator does not exist: uuid ~~ unknown` (42883). So the rollback path was
// blocked at v29 for every install, and the migrations below it had never been
// reachable in reverse at all.
//
// This test is the reason it cannot happen again. It is slow -- a full chain up,
// 179 rollbacks, and a full chain up again -- and it is the only thing that can
// see this class: a Down half is dead code until the day it is the only thing
// standing between an operator and a restore from backup.

// downSweepDB starts a throwaway PostgreSQL for the round trip.
//
// It ALWAYS uses its own container and never OPENIDX_TEST_DATABASE_URL, which
// the rest of the DB-gated suites honour. Migration v53's Down drops the
// openidx_app role, and a role is cluster-wide: run against a server that holds
// any other database with this chain applied, the DROP ROLE fails with
//
//	role "openidx_app" cannot be dropped because some objects depend on it
//
// -- a failure of the shared server, not of the migration. That was measured
// too, on a sandbox cluster with five migrated databases, and it is why this
// one insists on a cluster of its own.
func downSweepDB(t *testing.T) (*database.PostgresDB, func()) {
	t.Helper()
	ctx := context.Background()

	// OPENIDX_DOWNSWEEP_DATABASE_URL, deliberately NOT the variable the other
	// suites read: it must point at a cluster with no other migrated database
	// in it, for the reason above. CI does not set it and uses the container.
	if url := os.Getenv("OPENIDX_DOWNSWEEP_DATABASE_URL"); url != "" {
		db, err := database.NewPostgres(url)
		if err != nil {
			t.Skipf("OPENIDX_DOWNSWEEP_DATABASE_URL set but unreachable: %v", err)
			return nil, func() {}
		}
		return db, func() { db.Close() }
	}

	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env:          map[string]string{"POSTGRES_USER": "test", "POSTGRES_PASSWORD": "test", "POSTGRES_DB": "testdb"},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).WithStartupTimeout(60 * time.Second),
	}
	container := testsupport.RunOrSkip(t, req.Image, func() (testcontainers.Container, error) {
		return testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: req,
			Started:          true,
		})
	})
	host, _ := container.Host(ctx)
	port, _ := container.MappedPort(ctx, "5432")
	db, err := database.NewPostgres("postgres://test:test@" + host + ":" + port.Port() + "/testdb?sslmode=disable")
	if err != nil {
		_ = container.Terminate(ctx)
		t.Skipf("connect: %v", err)
		return nil, func() {}
	}
	return db, func() { db.Close(); _ = container.Terminate(ctx) }
}

// afterFullRollback is what the schema legitimately still holds once every
// migration has been rolled back.
//
// The two schema_* tables are the migrator's own bookkeeping and are created
// outside the chain. zt_policies and zt_policy_versions are there because v51
// DROPS them and its Down therefore RE-CREATES them: on an install that had
// them, that is correct reversibility; on one that never did, rolling back past
// v51 conjures two tables that were not there before. Recorded rather than
// papered over, and this set is asserted exactly so a new leftover shows up as
// a failure instead of as two more rows nobody counts.
var afterFullRollback = []string{
	"schema_migration_lock",
	"schema_migrations",
	"zt_policies",
	"zt_policy_versions",
}

func TestMigrationChainRollsBackAndForwardAgain(t *testing.T) {
	if testing.Short() {
		t.Skip("full chain round trip")
	}
	db, cleanup := downSweepDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	m := NewMigrator(db.Pool, zap.NewNop())
	if err := m.MigrateTo(ctx, -1); err != nil {
		t.Fatalf("apply the chain: %v", err)
	}

	versions := make([]int, 0, len(All()))
	for _, mig := range All() {
		versions = append(versions, mig.Version)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(versions)))

	for i, v := range versions {
		target := 0
		if i+1 < len(versions) {
			target = versions[i+1]
		}
		if err := m.RollbackTo(ctx, target); err != nil {
			t.Fatalf("rolling back v%d (the chain is blocked here, and every "+
				"migration below it is unreachable in reverse): %v", v, err)
		}
	}

	left := publicTables(t, db)
	if strings.Join(left, ",") != strings.Join(afterFullRollback, ",") {
		t.Errorf("after a full rollback the schema holds %v, want exactly %v", left, afterFullRollback)
	}

	// And forward again: an operator who rolls back to fix something rolls
	// forward afterwards, and a chain that only goes one way is half a chain.
	if err := m.MigrateTo(ctx, -1); err != nil {
		t.Fatalf("re-apply the chain after a full rollback: %v", err)
	}
	if n := len(publicTables(t, db)); n < 200 {
		t.Errorf("re-applied chain produced %d tables; the schema did not come back", n)
	}
}

func publicTables(t *testing.T, db *database.PostgresDB) []string {
	t.Helper()
	rows, err := db.Pool.Query(context.Background(),
		`SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY 1`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, name)
	}
	return out
}

// The fast half of the same guard, with no database at all: DROP ... IF NOT
// EXISTS is not a spelling PostgreSQL has ever accepted, in either direction of
// any migration. Five of them sat in this chain's Down halves and blocked every
// rollback at v29.
func TestNoMigrationSpellsDropIfNotExists(t *testing.T) {
	bad := regexp.MustCompile(`(?i)\bDROP\s+(TABLE|INDEX|VIEW|TYPE|POLICY|FUNCTION|SEQUENCE|SCHEMA|TRIGGER|ROLE)\s+IF\s+NOT\s+EXISTS\b`)
	for _, mig := range All() {
		for half, sql := range map[string]string{"Up": mig.UpSQL, "Down": mig.DownSQL} {
			if match := bad.FindString(sql); match != "" {
				t.Errorf("v%d (%s) %s half contains %q: the keyword is IF EXISTS, and this "+
					"statement raises a syntax error every time it runs",
					mig.Version, mig.Name, half, strings.Join(strings.Fields(match), " "))
			}
		}
	}
}

// WHY THERE IS NO STATIC CHECK FOR THE SECOND CLASS. Nine statements in v10's
// and v13's Down halves matched a UUID primary key with LIKE and raised
// `operator does not exist: uuid ~~ unknown` (42883). The obvious guard -- flag
// any `<something>id LIKE '...'` -- was written, and its first run reported
// v49's `client_id LIKE 'proxy-app-%'`, which is correct: oauth_clients.client_id
// is a VARCHAR holding a client identifier, not a uuid. Deciding this
// statically needs the column's declared type, and a guard that fires on
// correct code is one somebody turns off. The round trip above is what catches
// this class, because it asks the database rather than guessing.
