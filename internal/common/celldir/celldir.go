// Package celldir reads and writes the tenant directory: which cell serves
// which org (migration v195, global-scale plan task 4.1).
//
// WHY THIS IS A SEPARATE PACKAGE FROM internal/common/cell. cell holds the
// claim name, the 421 and the guard, and it is deliberately free of pgx --
// measured with `go list -deps`, because it is mounted in five binaries and one
// of them may one day be as thin as verify-service. A directory lookup is a
// database read. Putting it next to the guard would put pgx behind every import
// of the guard, so the two live apart and the guard takes what it needs as a
// value rather than as a dependency.
//
// WHAT A PLACEMENT IS FOR. The edge reads it to decide which cell serves a
// request; the issuer reads it to stamp a token with the tenant's HOME cell
// rather than with whichever cell happened to mint it. That second reader is
// the one that closes a real gap: a login that reaches the wrong cell produces,
// without this, a token stamped with the wrong cell and accepted by every guard
// in it.
package celldir

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// StatusActive is the placement of a tenant that is served by its cell today.
// Anything else is a placement in motion, and the readers here return the row
// with its status rather than deciding for the caller what a move means --
// the move itself is not built, and a package that pretended to know would be
// describing a product that does not exist.
const StatusActive = "active"

// ErrNotPlaced is returned when the directory holds no row for an org.
//
// It is an ERROR rather than an empty Placement because the two answers are
// different and the difference matters at exactly one place: "this tenant lives
// in cell X" and "nobody has said where this tenant lives" lead to different
// behaviour in a celled install, and a zero value would collapse them into the
// second one silently. Callers that want today's behaviour for an unplaced
// tenant say so, in one line, at the call site.
var ErrNotPlaced = errors.New("celldir: no placement recorded for this org")

// Placement is one row of the directory.
type Placement struct {
	OrgID     string
	CellID    string
	Region    string
	Residency string
	Status    string
}

// Querier is the read surface this package needs. database.ScopedPool and
// pgxpool.Pool both satisfy it, which is what lets the RLS-scoped pool be
// passed in by a service and a bypass-scoped one by the control plane.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Execer adds the write surface, for the placement tool.
type Execer interface {
	Querier
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Lookup returns where an org lives, or ErrNotPlaced.
//
// The query is a primary-key lookup by design: this runs on the token-minting
// path, where the alternative to one indexed read is the wrong cell stamped
// into every token the cell issues.
//
// RLS APPLIES. org_cells is belted org_id-scoped and forced, so a caller
// holding an ordinary tenant scope reads its OWN placement and nothing else.
// A caller that must read across tenants -- the edge resolver, a placement
// tool, a drain -- passes a pool whose context carries orgctx.WithBypassRLS,
// the same way the outbox relay and the SSF transmitter reach their rows. That
// is not a hole to be closed: it is the one place the directory is legitimately
// global, and it is named at the call site rather than granted to everybody by
// leaving the table unbelted.
func Lookup(ctx context.Context, q Querier, orgID string) (Placement, error) {
	var p Placement
	err := q.QueryRow(ctx, `
		SELECT org_id::text, cell_id, region, residency, status
		FROM org_cells
		WHERE org_id = $1
	`, orgID).Scan(&p.OrgID, &p.CellID, &p.Region, &p.Residency, &p.Status)
	if errors.Is(err, pgx.ErrNoRows) {
		return Placement{}, ErrNotPlaced
	}
	if err != nil {
		return Placement{}, fmt.Errorf("celldir: lookup %s: %w", orgID, err)
	}
	return p, nil
}

// HomeCell is Lookup reduced to the one field the issuer and the guard need,
// with "not placed" folded into a false rather than an error.
//
// It exists because the token-minting path has exactly one sensible thing to do
// with ErrNotPlaced -- carry on with today's behaviour -- and spelling that out
// at each call site invites one of them to get it wrong in the other direction.
// A lookup that FAILS (the database is down, the query is wrong) also returns
// false, and that is deliberate: an issuer that refused to mint tokens because
// the directory was unreachable would turn a directory outage into an
// authentication outage, which is the failure mode plan task 4.1 explicitly
// budgets against ("directory down 10 min -> zero effect for existing
// tenants"). The cost is that a real outage looks like an unplaced tenant; the
// caller logs the error it is handed so the two are still distinguishable in
// the record.
func HomeCell(ctx context.Context, q Querier, orgID string) (cell string, ok bool, err error) {
	p, lookupErr := Lookup(ctx, q, orgID)
	if lookupErr != nil {
		return "", false, lookupErr
	}
	if p.CellID == "" {
		// Unreachable while the CHECK constraint holds; if it is ever dropped,
		// an empty cell reads downstream as "this token predates the claim"
		// and is SERVED, so it must not be mistaken for a placement here.
		return "", false, ErrNotPlaced
	}
	return p.CellID, true, nil
}

// Place records or moves a tenant's placement.
//
// It is an upsert because the control plane has exactly two operations --
// register a tenant into a cell, and move it -- and they differ only in whether
// a row was already there. updated_at moves on both; created_at does not, so
// the record keeps when the tenant was first placed.
func Place(ctx context.Context, e Execer, p Placement) error {
	if p.CellID == "" {
		// Checked here as well as in the schema so the caller gets a message
		// naming the argument rather than a constraint violation naming a row.
		return fmt.Errorf("celldir: refusing to place org %s in an empty cell", p.OrgID)
	}
	status := p.Status
	if status == "" {
		status = StatusActive
	}
	_, err := e.Exec(ctx, `
		INSERT INTO org_cells (org_id, cell_id, region, residency, status)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (org_id) DO UPDATE SET
			cell_id    = EXCLUDED.cell_id,
			region     = EXCLUDED.region,
			residency  = EXCLUDED.residency,
			status     = EXCLUDED.status,
			updated_at = NOW()
	`, p.OrgID, p.CellID, p.Region, p.Residency, status)
	if err != nil {
		return fmt.Errorf("celldir: place %s in %s: %w", p.OrgID, p.CellID, err)
	}
	return nil
}
