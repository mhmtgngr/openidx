package commands

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openidx/openidx/internal/common/celldir"
	"github.com/openidx/openidx/internal/migrations"
)

// THE PLACEMENT TOOL, DRIVEN AGAINST A REAL BELTED TABLE.
//
// Everything interesting about this command is a property of the DATABASE, not
// of the Go: org_cells is org-scoped and FORCE-belted, so whether a write lands
// depends on a setting no unit test can stand in for. The two facts worth
// having are that the command CAN write (with the control-plane bypass it takes
// in a transaction) and that it could NOT without it -- and the second is the
// one that says the belt is real rather than decorative.
//
// The role matters as much as the schema. A superuser, or any role with
// BYPASSRLS, passes an isolation test by not being subject to isolation, so
// this fails rather than skips when handed one.

func openDirectoryDB(t *testing.T) (string, *pgx.Conn) {
	t.Helper()
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set; skipping the placement-tool tests (they need a real Postgres)")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(context.Background()) })

	var super, bypassRLS bool
	require.NoError(t, conn.QueryRow(ctx,
		"SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user").Scan(&super, &bypassRLS))
	require.False(t, super || bypassRLS,
		"TEST_POSTGRES_DSN connects as a role that bypasses RLS; a belt it cannot feel is a belt this test cannot measure")

	// The schema the loader actually ships, not a copy: a v195 whose SQL is
	// edited without this test being looked at fails here.
	var up string
	for _, m := range migrations.All() {
		if m.Version == 195 {
			up = m.UpSQL
		}
	}
	require.NotEmpty(t, up, "migration v195 is not registered")
	_, err = conn.Exec(ctx, up)
	require.NoError(t, err, "apply v195")
	t.Cleanup(func() { _, _ = conn.Exec(context.Background(), "DROP TABLE IF EXISTS org_cells") })

	return dsn, conn
}

func runCell(t *testing.T, dsn string, args ...string) (string, error) {
	t.Helper()
	cmd := NewCellCommand()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs(append(args, "--db-url", dsn))
	err := cmd.Execute()
	return out.String(), err
}

const (
	placedOrg = "11111111-2222-3333-4444-555555555555"
	otherOrg  = "99999999-8888-7777-6666-555555555555"
)

func TestThePlacementToolWritesTheDirectory(t *testing.T) {
	dsn, conn := openDirectoryDB(t)
	ctx := context.Background()

	_, err := runCell(t, dsn, "place", "--org", placedOrg, "--cell", "eu-1",
		"--region", "eu-central-1", "--residency", "eu")
	require.NoError(t, err, "the placement tool could not write the directory")

	// Read it back the way a reader with the control-plane scope would.
	tx, err := conn.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(context.Background()) }()
	_, err = tx.Exec(ctx, `SELECT set_config('app.bypass_rls', 'on', true)`)
	require.NoError(t, err)

	p, err := celldir.Lookup(ctx, tx, placedOrg)
	require.NoError(t, err, "the row the command claims to have written is not there")
	assert.Equal(t, "eu-1", p.CellID)
	assert.Equal(t, "eu-central-1", p.Region)
	assert.Equal(t, "eu", p.Residency)
	assert.Equal(t, celldir.StatusActive, p.Status, "status defaults to active")
}

// Placing twice is a MOVE, not an error, and the first placement's timestamp
// survives it: created_at is when the tenant was first put somewhere, which is
// a different fact from when it last moved.
func TestPlacingTwiceMovesTheTenantAndKeepsItsHistory(t *testing.T) {
	dsn, conn := openDirectoryDB(t)
	ctx := context.Background()

	_, err := runCell(t, dsn, "place", "--org", placedOrg, "--cell", "eu-1")
	require.NoError(t, err)

	read := func() (cell string, created, updated string) {
		tx, terr := conn.Begin(ctx)
		require.NoError(t, terr)
		defer func() { _ = tx.Rollback(context.Background()) }()
		_, terr = tx.Exec(ctx, `SELECT set_config('app.bypass_rls', 'on', true)`)
		require.NoError(t, terr)
		require.NoError(t, tx.QueryRow(ctx,
			`SELECT cell_id, created_at::text, updated_at::text FROM org_cells WHERE org_id = $1`,
			placedOrg).Scan(&cell, &created, &updated))
		return cell, created, updated
	}

	firstCell, firstCreated, _ := read()
	require.Equal(t, "eu-1", firstCell)

	_, err = runCell(t, dsn, "place", "--org", placedOrg, "--cell", "us-1", "--region", "us-east-1")
	require.NoError(t, err)

	movedCell, movedCreated, movedUpdated := read()
	assert.Equal(t, "us-1", movedCell, "re-placing must move the tenant")
	assert.Equal(t, firstCreated, movedCreated, "created_at is when the tenant was FIRST placed and must survive a move")
	assert.NotEqual(t, movedCreated, movedUpdated, "updated_at must record the move")
}

// THE ONE THAT SAYS THE BELT IS REAL. The same insert, from the same role,
// without the transaction-local bypass the command takes: the policy refuses
// it. If this ever passes, withDirectory's set_config line has stopped being
// load-bearing and the directory is writable by anything holding the DSN.
func TestWithoutTheControlPlaneBypassTheBeltRefusesTheWrite(t *testing.T) {
	_, conn := openDirectoryDB(t)
	ctx := context.Background()

	tx, err := conn.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(context.Background()) }()

	err = celldir.Place(ctx, tx, celldir.Placement{OrgID: otherOrg, CellID: "eu-1"})
	require.Error(t, err, "org_cells accepted a placement from a connection carrying no tenant scope and no bypass")
	assert.Contains(t, strings.ToLower(err.Error()), "row-level security",
		"expected the row-level security policy to be what refused it; got: %v", err)
}

// A placement with no cell is refused before it reaches the database, so the
// operator is told which flag is wrong rather than which constraint fired.
func TestAnEmptyCellIsRefusedByTheTool(t *testing.T) {
	dsn, _ := openDirectoryDB(t)

	_, err := runCell(t, dsn, "place", "--org", placedOrg, "--cell", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--cell",
		"the message should name the flag; an empty cell is served rather than refused by cell.Misdirected, "+
			"so a blank placement would put a tenant nowhere and be invisible")
}

// An unplaced org is an ANSWER, not a failure: it is the answer for every
// tenant in a single-cell install, which is every install today.
func TestShowingAnUnplacedOrgIsNotAnError(t *testing.T) {
	dsn, _ := openDirectoryDB(t)

	_, err := runCell(t, dsn, "show", "--org", otherOrg)
	assert.NoError(t, err, "an unplaced tenant is a state the directory can be in, not an error")
}
