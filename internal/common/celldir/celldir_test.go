package celldir

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/openidx/openidx/internal/migrations"
)

// These run against a real PostgreSQL with migration v195 applied, because the
// three things worth knowing here are all the database's behaviour and not this
// package's: that the belt isolates one tenant's placement from another's, that
// the CHECK refuses an empty cell, and that a placement survives for an org the
// organizations table does not have. A stub would answer whatever this file
// told it to.
// openDirectory connects as the unprivileged application role and applies the
// REGISTERED v195 SQL itself.
//
// Applying the migration here rather than depending on a pre-migrated database
// is the repo's existing pattern (internal/common/events does the same for
// v192) and it buys three things. The suite tests what the loader actually
// ships, so a v195 that is edited or unregistered fails here instead of passing
// against a copy. It needs no second DSN. And it is immune to the hazard that
// cost this file an afternoon: OPENIDX_TEST_DATABASE_URL is wiped mid-run by
// any package whose fixtures call DROP SCHEMA public CASCADE, so tests hanging
// off it pass or fail on filename order.
//
// THE ROLE MUST NOT BYPASS RLS, and it is checked rather than trusted.
// PostgreSQL's FORCE ROW LEVEL SECURITY extends a policy to the table's OWNER
// and does nothing about a superuser, who bypasses RLS outright -- so run as
// `postgres`, the isolation assertion below reads every tenant's rows. That is
// the lucky direction; written the other way round ("I can see my own row") it
// would have passed as superuser forever while proving nothing. A bypassing
// role therefore FAILS this suite rather than skipping it: a skip is how a
// guard quietly stops running. ci.yml makes the same point one step earlier for
// the RLS suite next door.
//
// Connecting as the role that also OWNS the table is deliberate: it is the only
// configuration in which FORCE is observable at all.
func openDirectory(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set; skipping the tenant-directory tests (they need a real Postgres)")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, pool.Ping(ctx))

	var super, bypassRLS bool
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user").Scan(&super, &bypassRLS))
	require.False(t, super || bypassRLS,
		"TEST_POSTGRES_DSN connects as a role that bypasses RLS; an isolation test it can pass is not a test")

	_, err = pool.Exec(ctx, registeredMigrationSQL(t, 195))
	require.NoError(t, err, "apply v195")
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DROP TABLE IF EXISTS org_cells") })

	// The control plane's scope, which is how a placement is written at all.
	_, err = pool.Exec(ctx, "SET app.bypass_rls = 'on'")
	require.NoError(t, err)
	return pool
}

// registeredMigrationSQL applies what the loader actually ships, not a copy of
// it. A v195 that stops being registered -- or whose SQL is edited without these
// tests being looked at -- fails here rather than passing against a duplicate.
func registeredMigrationSQL(t *testing.T, version int) string {
	t.Helper()
	for _, m := range migrations.All() {
		if m.Version == version {
			return m.UpSQL
		}
	}
	t.Fatalf("migration v%d is not registered", version)
	return ""
}

const (
	orgA = "aaaaaaaa-0000-0000-0000-00000000000a"
	orgB = "bbbbbbbb-0000-0000-0000-00000000000b"
)

func TestAPlacementRoundTrips(t *testing.T) {
	pool := openDirectory(t)
	ctx := context.Background()
	_, err := pool.Exec(ctx, "DELETE FROM org_cells WHERE org_id = ANY($1)", []string{orgA, orgB})
	require.NoError(t, err)

	require.NoError(t, Place(ctx, pool, Placement{
		OrgID: orgA, CellID: "us-1", Region: "us-east-1", Residency: "us",
	}))

	got, err := Lookup(ctx, pool, orgA)
	require.NoError(t, err)
	require.Equal(t, "us-1", got.CellID)
	require.Equal(t, "us-east-1", got.Region)
	require.Equal(t, "us", got.Residency)
	require.Equal(t, StatusActive, got.Status, "an unset status must land as active, not as empty")

	// A move is the same operation. created_at must survive it: the record of
	// when a tenant was FIRST placed is the thing a residency audit reads.
	var firstCreated, firstUpdated string
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT created_at::text, updated_at::text FROM org_cells WHERE org_id=$1", orgA).
		Scan(&firstCreated, &firstUpdated))

	require.NoError(t, Place(ctx, pool, Placement{OrgID: orgA, CellID: "eu-1", Region: "eu-west-1"}))
	moved, err := Lookup(ctx, pool, orgA)
	require.NoError(t, err)
	require.Equal(t, "eu-1", moved.CellID)

	var afterCreated string
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT created_at::text FROM org_cells WHERE org_id=$1", orgA).Scan(&afterCreated))
	require.Equal(t, firstCreated, afterCreated, "a move must not rewrite when the tenant was first placed")
}

func TestAnUnplacedOrgIsNotAnEmptyPlacement(t *testing.T) {
	pool := openDirectory(t)
	ctx := context.Background()
	_, err := pool.Exec(ctx, "DELETE FROM org_cells WHERE org_id=$1", orgB)
	require.NoError(t, err)

	_, err = Lookup(ctx, pool, orgB)
	require.ErrorIs(t, err, ErrNotPlaced)

	cell, ok, err := HomeCell(ctx, pool, orgB)
	require.False(t, ok, "an unplaced org must not report a home cell")
	require.Empty(t, cell)
	require.ErrorIs(t, err, ErrNotPlaced,
		"the caller has to be able to tell 'nobody placed this tenant' from 'the directory is down'")
}

// An empty cell is refused by BOTH the function and the schema. Downstream,
// cell.Misdirected reads an empty cell as "this token predates the claim" and
// SERVES the request, so a placement naming no cell would be a tenant placed
// nowhere and refused by nobody.
func TestAnEmptyCellIsRefusedTwice(t *testing.T) {
	pool := openDirectory(t)
	ctx := context.Background()

	err := Place(ctx, pool, Placement{OrgID: orgB, CellID: ""})
	require.Error(t, err, "Place must refuse before the database has to")
	require.Contains(t, err.Error(), "empty cell")

	_, dbErr := pool.Exec(ctx, "INSERT INTO org_cells (org_id, cell_id) VALUES ($1, '')", orgB)
	require.Error(t, dbErr, "the CHECK constraint is the backstop for a writer that is not this package")
}

// THE BELT. org_cells is org_id-scoped and FORCE RLS, so a tenant reads its own
// placement and nothing else. This is asserted against the database rather than
// argued from the DDL, because "the policy exists" and "the policy applies" are
// different claims, and it runs as an unprivileged role because a superuser
// makes both of them unobservable.
//
// WHAT THIS TEST CANNOT SEE, measured rather than assumed. Dropping the policy
// on the live table turns it red, so it does watch the policy. Removing FORCE
// leaves it GREEN -- because the role it connects as is not the table's owner,
// and ordinary RLS already applies to a non-owner. FORCE is what extends the
// policy to the OWNER, which is the account migrations and admin tooling use,
// and no test connecting as openidx_app can observe its absence. That half is
// pinned at the source instead, in migrations' TestV195PinsTheDirectorys-
// SchemaDecisions, and the two together cover what neither does alone.
func TestOneTenantCannotReadAnothersPlacement(t *testing.T) {
	pool := openDirectory(t)
	ctx := context.Background()

	// Seeded under the control plane's bypass, which openDirectory already set.
	require.NoError(t, Place(ctx, pool, Placement{OrgID: orgA, CellID: "us-1"}))
	require.NoError(t, Place(ctx, pool, Placement{OrgID: orgB, CellID: "eu-1"}))

	// Then drop it and take orgA's scope, the way a request-scoped pool does.
	_, err := pool.Exec(ctx, "SET app.bypass_rls = 'off'")
	require.NoError(t, err)
	_, err = pool.Exec(ctx, "SET app.org_id = '"+orgA+"'")
	require.NoError(t, err)
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, "SET app.bypass_rls = 'on'")
		_, _ = pool.Exec(bg, "DELETE FROM org_cells WHERE org_id = ANY($1)", []string{orgA, orgB})
		_, _ = pool.Exec(bg, "RESET app.org_id")
		_, _ = pool.Exec(bg, "RESET app.bypass_rls")
	})

	mine, err := Lookup(ctx, pool, orgA)
	require.NoError(t, err, "a tenant must still read its own placement")
	require.Equal(t, "us-1", mine.CellID)

	_, err = Lookup(ctx, pool, orgB)
	require.True(t, errors.Is(err, ErrNotPlaced),
		"orgB's placement was readable under orgA's scope; the belt is not applying (got %v)", err)
}

// The directory must be able to name an org this database does not hold: in a
// celled deployment it is global and organizations is per-cell, so the row that
// says "org X lives in us-1" is exactly a row about an org that is not here.
// A foreign key would make that impossible, so there is none -- measured, not
// assumed, because a later migration could add one without anybody noticing
// that it had taken the table's purpose away.
func TestAPlacementCanNameAnOrgThisCellDoesNotHave(t *testing.T) {
	pool := openDirectory(t)
	ctx := context.Background()

	const stranger = "cccccccc-0000-0000-0000-00000000000c"
	var orgRows int
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT count(*) FROM organizations WHERE id=$1", stranger).Scan(&orgRows))
	require.Zero(t, orgRows, "fixture problem: this org was supposed to be absent")

	require.NoError(t, Place(ctx, pool, Placement{OrgID: stranger, CellID: "us-1"}),
		"the directory refused a tenant this cell does not hold, which is the only kind it exists to record")
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM org_cells WHERE org_id=$1", stranger) })

	var fks int
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT count(*) FROM pg_constraint WHERE conrelid='org_cells'::regclass AND contype='f'").Scan(&fks))
	require.Zero(t, fks, "a foreign key to organizations would make the directory unable to record a tenant in another cell")
}
