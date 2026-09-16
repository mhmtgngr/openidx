package commands

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/spf13/cobra"

	"github.com/openidx/openidx/internal/common/celldir"
)

// THE TENANT DIRECTORY'S WRITE PATH, WHICH DID NOT EXIST.
//
// internal/common/celldir has held a Place since the directory landed, and its
// own package comment calls Execer "the write surface, for the placement tool".
// Measured across internal/ and cmd/: NOTHING CALLED IT. The read half is live
// -- the issuer looks up a tenant's home cell to stamp a token with it -- so
// the directory was a table that could only ever answer "not placed", and every
// token fell back to the cell that happened to mint it. A capability that is
// declared and cannot be exercised is the shape this branch keeps finding; this
// is that shape with the tool missing rather than the claim wrong.
//
// WHY A CLI AND NOT AN ENDPOINT. Placing a tenant is a CONTROL-PLANE act, and
// the control plane is not inside a cell. An admin-api in eu-1 deciding that a
// tenant lives in us-1 is the wrong process holding the pen: it is one cell's
// view of a directory that spans all of them, and every cell would need the
// same write. A command run against the directory database by whoever is moving
// the tenant is the honest shape, and it is also the only one that can run
// before any cell serves the tenant at all.
//
// WHAT THE BELT COSTS THIS TOOL, and why that is right. org_cells is org-scoped
// and FORCE-belted, so a connection carrying no tenant scope reads nothing and
// writes nothing -- including this one. The placement runs inside a transaction
// that sets app.bypass_rls LOCALLY, which is the same door the outbox relay and
// the SSF transmitter go through, named at the call site rather than granted to
// everybody by leaving the table unbelted. Drop that one line and the INSERT is
// refused by the policy; cell_place_testdb_test.go measures exactly that,
// against a real PostgreSQL, because a belt nobody has tried is a belt nobody
// has measured.

// NewCellCommand creates the tenant-directory command group.
func NewCellCommand() *cobra.Command {
	var dbURL string

	cmd := &cobra.Command{
		Use:   "cell",
		Short: "Tenant directory: which cell serves which organization",
		Long: `Read and write the tenant directory (org_cells, migration v195).

The directory is the control plane's record of where each tenant lives. The
edge reads it to route, and the issuer reads it to stamp a token with the
tenant's HOME cell rather than with whichever cell minted it.

Commands:
  place   Place an organization in a cell (idempotent; re-placing moves it)
  show    Show where an organization lives`,
	}
	cmd.PersistentFlags().StringVar(&dbURL, "db-url", "", "Directory database URL (defaults to DATABASE_URL)")

	var orgID, cellID, region, residency, status string

	placeCmd := &cobra.Command{
		Use:   "place",
		Short: "Place an organization in a cell",
		Long: `Place an organization in a cell, or move one that is already placed.

The write is an upsert keyed on the organization, so running it twice is not an
error and the second run is a move. created_at records the first placement and
survives; updated_at records the move.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(orgID) == "" {
				return errors.New("--org is required")
			}
			if strings.TrimSpace(cellID) == "" {
				// Refused here as well as by celldir and by the schema's CHECK.
				// An empty cell is not a tenant with no home: cell.Misdirected
				// reads an empty cell as "predates the claim" and SERVES, so a
				// blank row would place a tenant nowhere and be invisible.
				return errors.New("--cell is required and must not be empty")
			}
			return withDirectory(cmd.Context(), dbURL, func(ctx context.Context, tx pgx.Tx) error {
				p := celldir.Placement{
					OrgID:     strings.TrimSpace(orgID),
					CellID:    strings.TrimSpace(cellID),
					Region:    strings.TrimSpace(region),
					Residency: strings.TrimSpace(residency),
					Status:    strings.TrimSpace(status),
				}
				if err := celldir.Place(ctx, tx, p); err != nil {
					return err
				}
				placed, err := celldir.Lookup(ctx, tx, p.OrgID)
				if err != nil {
					return fmt.Errorf("placed, but reading it back failed: %w", err)
				}
				printPlacement(placed)
				return nil
			})
		},
	}
	placeCmd.Flags().StringVar(&orgID, "org", "", "Organization UUID")
	placeCmd.Flags().StringVar(&cellID, "cell", "", "Cell this organization is served by (e.g. eu-1)")
	placeCmd.Flags().StringVar(&region, "region", "", "Cloud region the cell runs in (informational)")
	placeCmd.Flags().StringVar(&residency, "residency", "", "Data-residency commitment this placement satisfies")
	placeCmd.Flags().StringVar(&status, "status", celldir.StatusActive, "Placement status")
	cmd.AddCommand(placeCmd)

	var showOrg string
	showCmd := &cobra.Command{
		Use:   "show",
		Short: "Show where an organization lives",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(showOrg) == "" {
				return errors.New("--org is required")
			}
			return withDirectory(cmd.Context(), dbURL, func(ctx context.Context, tx pgx.Tx) error {
				p, err := celldir.Lookup(ctx, tx, strings.TrimSpace(showOrg))
				if errors.Is(err, celldir.ErrNotPlaced) {
					// Not an error to the shell: "nobody has said where this
					// tenant lives" is an answer, and it is the answer for
					// every tenant in a single-cell install.
					fmt.Printf("%s is not placed; a token minted for it carries the cell that minted it\n",
						strings.TrimSpace(showOrg))
					return nil
				}
				if err != nil {
					return err
				}
				printPlacement(p)
				return nil
			})
		},
	}
	showCmd.Flags().StringVar(&showOrg, "org", "", "Organization UUID")
	cmd.AddCommand(showCmd)

	return cmd
}

func printPlacement(p celldir.Placement) {
	fmt.Printf("org %s -> cell %s", p.OrgID, p.CellID)
	if p.Region != "" {
		fmt.Printf(" (region %s)", p.Region)
	}
	if p.Residency != "" {
		fmt.Printf(" [residency %s]", p.Residency)
	}
	fmt.Printf(" status=%s\n", p.Status)
}

// withDirectory runs fn inside a transaction that carries the control-plane
// bypass, which is what lets a connection with no tenant scope touch a belted,
// org-scoped table at all.
//
// set_config's third argument is true: the bypass is LOCAL to this transaction
// and ends with it, rather than a session-wide SET that would stay on for
// whatever the connection did next.
//
// THAT CHOICE IS NOT MEASURED AND IS NOT CLAIMED TO BE. This function opens a
// connection, runs one transaction and closes it, so from outside there is no
// difference between the two spellings today -- the session ends either way.
// The local scope is here for the day the command grows a second statement, or
// keeps a connection, which is exactly when a session-wide bypass stops being
// harmless and starts being a door somebody left open.
func withDirectory(ctx context.Context, dbURL string, fn func(context.Context, pgx.Tx) error) error {
	if strings.TrimSpace(dbURL) == "" {
		dbURL = os.Getenv("DATABASE_URL")
	}
	if strings.TrimSpace(dbURL) == "" {
		return errors.New("DATABASE_URL environment variable or --db-url flag is required")
	}

	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("connect to the directory database: %w", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()

	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if _, err := tx.Exec(ctx, `SELECT set_config('app.bypass_rls', 'on', true)`); err != nil {
		return fmt.Errorf("take the control-plane bypass: %w", err)
	}
	if err := fn(ctx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
