package database

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Tenant scope, transaction-local (global-scale plan task 2.1, design B1/ADR-4).
//
// THE PROBLEM THIS EXISTS FOR. rls.go stamps the tenant onto the CONNECTION at
// pool checkout with session-scoped set_config(..., false). That is correct and
// it is also a hard ceiling on scale: session state belongs to a connection, so
// every service replica must hold its own connections to Postgres and the fleet
// total is services × replicas × DB_MAX_CONNS. Autoscaling multiplies it. A
// transaction pooler (pgcat/pgbouncer) is the standard answer and is FORBIDDEN
// here, for the reason docs/architecture/db-pooling.md spells out: transaction
// pooling multiplexes many clients over few backends and does not carry session
// state, so app.org_id set at checkout would apply to the wrong backend or be
// lost. A query would then run under another tenant's scope. That is a
// cross-tenant leak, which is the worst thing this product can do.
//
// THE FIX. Set the scope with set_config(..., TRUE) — transaction-local —
// INSIDE the transaction that runs the query. Postgres resets it at COMMIT or
// ROLLBACK, so a backend handed to another client carries nothing, and
// transaction pooling becomes safe. The cost is that every query must now run
// inside a transaction, which is what this file provides.
//
// STAGED. RLS_MODE selects which belt is live:
//
//	session (default) — today's behaviour exactly: the checkout hook stamps the
//	                    connection, and these wrappers add nothing but a
//	                    pass-through. Nothing changes for any deployment that
//	                    does not opt in.
//	local             — the checkout hook stamps nothing; these wrappers open a
//	                    transaction and set the scope inside it.
//
// Both modes are exercised by the same tests (rls_local_test.go), and a cell
// runs `local` for two weeks with a leak test before pgcat is put in front of
// it. The flag is how a bad refactor is reverted in one restart rather than one
// release.
type RLSMode string

const (
	// RLSModeSession stamps the connection at checkout (session GUC).
	RLSModeSession RLSMode = "session"
	// RLSModeLocal stamps the transaction (SET LOCAL), which a transaction
	// pooler can safely multiplex.
	RLSModeLocal RLSMode = "local"
)

// ParseRLSMode reads RLS_MODE. Anything unrecognised is `session`: a typo in a
// deployment variable must fail toward today's behaviour, never silently into a
// new one. The same rule the product's other gates follow.
func ParseRLSMode(v string) RLSMode {
	if strings.EqualFold(strings.TrimSpace(v), string(RLSModeLocal)) {
		return RLSModeLocal
	}
	return RLSModeSession
}

var (
	rlsModeMu  sync.RWMutex
	rlsModeVal = RLSModeSession
	rlsModeSet bool
)

// SetRLSMode sets the process-wide mode. Called once at startup from config;
// tests call it directly. It is process-wide rather than per-pool because the
// checkout hook and the query wrappers must agree — a pool stamping sessions
// while its callers also open scoped transactions would set the scope twice and
// hide which one is actually doing the work.
func SetRLSMode(m RLSMode) {
	rlsModeMu.Lock()
	defer rlsModeMu.Unlock()
	rlsModeVal = m
	rlsModeSet = true
}

// CurrentRLSMode reports the mode. Before SetRLSMode is called it reads
// RLS_MODE from the environment once, so a binary that forgets to wire config
// still behaves like its deployment says rather than like the zero value.
func CurrentRLSMode() RLSMode {
	rlsModeMu.RLock()
	if rlsModeSet {
		defer rlsModeMu.RUnlock()
		return rlsModeVal
	}
	rlsModeMu.RUnlock()

	rlsModeMu.Lock()
	defer rlsModeMu.Unlock()
	if !rlsModeSet {
		rlsModeVal = ParseRLSMode(os.Getenv("RLS_MODE"))
		rlsModeSet = true
	}
	return rlsModeVal
}

// setScopeLocalSQL is the transaction-local twin of rls.go's checkout
// statement. The only difference is the third argument: true = reset at end of
// transaction. It stays parameterised because `SET LOCAL app.org_id = $1` is
// not valid SQL — SET takes no parameters — and building that string by
// concatenation is how an injection gets into the one statement that decides
// which tenant's rows a query can see.
const setScopeLocalSQL = `select set_config('app.org_id', $1, true), set_config('app.bypass_rls', $2, true)`

// applyScopeLocal stamps the tenant scope onto an open transaction.
func applyScopeLocal(ctx context.Context, tx pgx.Tx) error {
	orgID, bypass := rlsValuesFromContext(ctx)
	if _, err := tx.Exec(ctx, setScopeLocalSQL, orgID, bypass); err != nil {
		return fmt.Errorf("apply tenant scope: %w", err)
	}
	return nil
}

// WithTx runs fn inside a transaction carrying the request's tenant scope.
//
// It is the shape every multi-statement operation should take in `local` mode,
// and it is safe in `session` mode too (the scope is already on the connection;
// stamping it again transaction-locally is the same value). So call sites can
// migrate before the mode is flipped, which is the whole point of staging this.
//
// fn must not commit or roll back: WithTx owns the lifecycle and rolls back on
// any error or panic.
func (db *PostgresDB) WithTx(ctx context.Context, fn func(pgx.Tx) error) error {
	return withTxOn(ctx, db.Pool, fn)
}

// WithReadTx is WithTx against the read-replica pool (Reader()). Read-only and
// lag-tolerant queries only; a write here fails on a replica, and a read that
// must see its own prior write must use WithTx.
func (db *PostgresDB) WithReadTx(ctx context.Context, fn func(pgx.Tx) error) error {
	return withTxOn(ctx, db.Reader(), fn)
}

func withTxOn(ctx context.Context, pool *pgxpool.Pool, fn func(pgx.Tx) error) (err error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback(ctx)
			panic(p)
		}
		if err != nil {
			_ = tx.Rollback(ctx)
		}
	}()

	if err = applyScopeLocal(ctx, tx); err != nil {
		return err
	}
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Exec runs one statement under the request's tenant scope.
//
// In `session` mode it goes straight to the pool, byte-for-byte today's path.
// In `local` mode it is wrapped in a scoped transaction, because a bare
// statement on a pooled connection has no scope at all once the checkout hook
// stops stamping.
func (db *PostgresDB) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if CurrentRLSMode() == RLSModeSession {
		return db.Pool.Exec(ctx, sql, args...)
	}
	var tag pgconn.CommandTag
	err := db.WithTx(ctx, func(tx pgx.Tx) error {
		var e error
		tag, e = tx.Exec(ctx, sql, args...)
		return e
	})
	return tag, err
}

// QueryRow runs one row-returning statement under the request's tenant scope.
//
// In `local` mode the transaction must outlive this call — the row is not read
// until Scan — so the returned Row owns the transaction and ends it when Scan
// returns. A Row that is never scanned would hold a transaction open; every
// pgx.Row contract already requires Scan to be called exactly once, and that is
// the contract this relies on.
func (db *PostgresDB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if CurrentRLSMode() == RLSModeSession {
		return db.Pool.QueryRow(ctx, sql, args...)
	}
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return errRow{err}
	}
	if err := applyScopeLocal(ctx, tx); err != nil {
		_ = tx.Rollback(ctx)
		return errRow{err}
	}
	return &txRow{ctx: ctx, tx: tx, row: tx.QueryRow(ctx, sql, args...)}
}

// Query runs a row-returning statement under the request's tenant scope.
//
// Same lifetime problem as QueryRow and the same answer: in `local` mode the
// returned Rows owns the transaction and commits when the caller closes it.
// Callers already must close Rows; pgx's own contract makes that a defer.
func (db *PostgresDB) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if CurrentRLSMode() == RLSModeSession {
		return db.Pool.Query(ctx, sql, args...)
	}
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if err := applyScopeLocal(ctx, tx); err != nil {
		_ = tx.Rollback(ctx)
		return nil, err
	}
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		_ = tx.Rollback(ctx)
		return nil, err
	}
	return &txRows{ctx: ctx, tx: tx, Rows: rows}, nil
}

// txRow ends the transaction when the single row is scanned.
type txRow struct {
	ctx context.Context
	tx  pgx.Tx
	row pgx.Row
}

func (r *txRow) Scan(dest ...any) error {
	err := r.row.Scan(dest...)
	// The read is done either way; a failed Scan (including pgx.ErrNoRows) must
	// still end the transaction, or the connection never goes back to the pool.
	if err != nil {
		_ = r.tx.Rollback(r.ctx)
		return err
	}
	return r.tx.Commit(r.ctx)
}

// txRows ends the transaction when the caller closes the rows.
type txRows struct {
	ctx  context.Context
	tx   pgx.Tx
	done bool
	pgx.Rows
}

func (r *txRows) Close() {
	r.Rows.Close()
	if r.done {
		return
	}
	r.done = true
	// Err() reports whether iteration failed; a failed read must not commit.
	if r.Rows.Err() != nil {
		_ = r.tx.Rollback(r.ctx)
		return
	}
	_ = r.tx.Commit(r.ctx)
}

// errRow carries a setup failure to the caller's Scan, so QueryRow keeps its
// signature and callers keep their one error path.
type errRow struct{ err error }

func (e errRow) Scan(...any) error { return e.err }
