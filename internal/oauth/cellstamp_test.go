package oauth

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// THE DEFECT THIS CLOSES, stated once so the cases below read as what they are.
//
// The issuer used to stamp its OWN cell. That catches a token carried from one
// cell to another; it cannot catch a login that REACHED the wrong cell, because
// the wrong cell then stamps itself and every guard in it compares that value
// against itself and agrees. The tenant's rows are elsewhere, so the request is
// served a confident 404 -- the outcome cell.Guard exists to replace, arriving
// through the one door the guard cannot watch.
//
// WHY THESE USE FAKE QUERIERS AND THE DIRECTORY TESTS USE REAL POSTGRESQL.
// There are two different things to measure and they are not in the same place.
// Whether the DATABASE holds and returns a placement -- the round trip, the
// CHECK on an empty cell, the RLS belt, the absence of a foreign key -- is
// PostgreSQL's behaviour, and internal/common/celldir measures it against a
// real server with its own DSN. What is left here is a branch table over what
// the directory answered: placed, not placed, unreadable. A real server cannot
// make that more true, and HomeCell is the single seam both halves meet at.
//
// It is also the only way these can run at all. internal/oauth's SSF tests call
// ssfSetupTestDB, which executes DROP SCHEMA public CASCADE whenever
// OPENIDX_TEST_DATABASE_URL is set -- its own comment says "Run ONE package at a
// time against this variable". Tests here that needed migrated tables passed or
// failed on FILENAME ORDER relative to ssf_test.go. Measured the hard way: four
// mutations of this file reported red while the code was untouched, because the
// schema had been dropped by a previous run.
// fakeDir answers HomeCell the three ways the directory can.
type fakeDir struct {
	cell string
	err  error
}

func (f fakeDir) QueryRow(context.Context, string, ...interface{}) pgx.Row {
	return fakeRow{cell: f.cell, err: f.err}
}

type fakeRow struct {
	cell string
	err  error
}

// Scan fills the five columns Lookup selects, in order.
func (r fakeRow) Scan(dest ...interface{}) error {
	if r.err != nil {
		return r.err
	}
	vals := []string{"org", r.cell, "", "", "active"}
	for i := range dest {
		if i >= len(vals) {
			break
		}
		if p, ok := dest[i].(*string); ok {
			*p = vals[i]
		}
	}
	return nil
}

var (
	placedInUS   = fakeDir{cell: "us-1"}
	notPlaced    = fakeDir{err: pgx.ErrNoRows}
	directoryOut = fakeDir{err: errors.New("directory unreachable")}
)

// countingDir records whether the directory was consulted at all. An assertion
// on the RETURNED VALUE cannot answer that question when the serving cell is
// empty, because the answer is "" either way -- measured: the mutation that
// deleted the early return left the previous version of this test green.
type countingDir struct{ calls *int }

func (c countingDir) QueryRow(context.Context, string, ...interface{}) pgx.Row {
	*c.calls++
	return fakeRow{err: pgx.ErrNoRows}
}

const placedOrg = "dddddddd-0000-0000-0000-00000000000d"

func TestTheStampIsTheTenantsCellNotTheServingCell(t *testing.T) {
	ctx := context.Background()

	// The whole point: this process serves eu-1, the tenant lives in us-1.
	require.Equal(t, "us-1", cellStamp(ctx, placedInUS, "eu-1", zap.NewNop(), placedOrg),
		"a login that reached eu-1 for a us-1 tenant was stamped eu-1; every eu-1 guard would then agree with "+
			"itself and serve the request from a database that does not hold this tenant")

	// And in the ordinary case the two agree, so nothing changes.
	require.Equal(t, "us-1", cellStamp(ctx, placedInUS, "us-1", zap.NewNop(), placedOrg))
}

// CELL_ID unset is every install today: no claim, and -- just as important --
// no lookup, so an uncelled install does not pay a directory read per token.
// The querier fails on any call, which is what proves the read did not happen.
func TestAnUninvolvedInstallIsUntouched(t *testing.T) {
	calls := 0
	got := cellStamp(context.Background(), countingDir{calls: &calls}, "", zap.NewNop(), placedOrg)

	require.Empty(t, got, "an uncelled install must emit no cell claim at all")
	require.Zero(t, calls,
		"an uncelled install queried the tenant directory; every install today is uncelled, so that is a "+
			"database read per token minted for a feature nobody has switched on")
}

// A directory is filled in over a migration, not in one transaction, and a
// tenant nobody has placed yet is being served here by definition.
func TestAnUnplacedTenantKeepsTodaysBehaviour(t *testing.T) {
	require.Equal(t, "eu-1", cellStamp(context.Background(), notPlaced, "eu-1", zap.NewNop(), placedOrg))
}

// A DIRECTORY OUTAGE MUST NOT BECOME AN AUTHENTICATION OUTAGE. This is plan
// task 4.1's own acceptance criterion -- "directory down 10 min, zero effect for
// existing tenants" -- and the tempting alternative (refuse to mint when the
// placement cannot be read) would convert a control-plane outage into an
// inability to log in anywhere.
func TestADirectoryOutageStillMintsTokens(t *testing.T) {
	got := cellStamp(context.Background(), directoryOut, "eu-1", zap.NewNop(), placedOrg)
	require.Equal(t, "eu-1", got,
		"an unreadable directory stopped the stamp; a directory outage must degrade to today's behaviour, not to no tokens")
}
