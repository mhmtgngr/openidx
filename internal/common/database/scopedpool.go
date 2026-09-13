package database

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ScopedPool is the pool every service already talks to, with the tenant scope
// applied for it (global-scale plan task 2.1b).
//
// WHY A TYPE RATHER THAN A MIGRATION. Task 2.1a made a transaction-local tenant
// scope possible; using it everywhere is the hard part. There are ~1,950 places
// in this repo that call db.Pool.Query / QueryRow / Exec, and hand-editing them
// was the plan: eight weeks of mechanical edits in which EVERY missed line is a
// query that runs with no tenant scope at all once RLS_MODE=local stops the
// checkout hook from stamping the connection. A missed line would not fail a
// test or a build; under FORCE RLS it would quietly return zero rows, and the
// reviewer's eye is the only thing standing between that and a leak in the
// other direction if a policy is ever relaxed.
//
// So the scope moves into the type instead. db.Pool keeps its name and its
// method set, every one of those call sites keeps compiling and reading
// exactly as it did, and each one now routes through the scoped path when the
// mode says to. What used to be "did we remember this line?" becomes "does it
// compile?", which is a question with a reliable answer.
//
// Raw() is the deliberate exit: a caller that genuinely wants the unscoped pool
// (install-wide tables, pool statistics, migrations) asks for it by name, and
// that name is greppable.
type ScopedPool struct {
	pool *pgxpool.Pool
}

// NewScopedPool wraps a pgx pool. Exported for tests and for callers that own a
// pool of their own; services get theirs from NewPostgres.
func NewScopedPool(pool *pgxpool.Pool) *ScopedPool {
	if pool == nil {
		return nil
	}
	return &ScopedPool{pool: pool}
}

// Raw returns the underlying pgx pool, with NO tenant scope applied.
//
// Correct for: install-wide tables (oauth_signing_keys, system settings,
// migrations), pool statistics, and anything running before a tenant exists.
// Wrong for anything reading or writing a tenant table — in RLS_MODE=local that
// query carries no scope and FORCE RLS answers it with zero rows.
func (p *ScopedPool) Raw() *pgxpool.Pool {
	if p == nil {
		return nil
	}
	return p.pool
}

// Query runs a row-returning query under the request's tenant scope.
func (p *ScopedPool) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if CurrentRLSMode() == RLSModeSession {
		return p.pool.Query(ctx, sql, args...)
	}
	tx, err := p.pool.Begin(ctx)
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

// QueryRow runs a single-row query under the request's tenant scope. The
// returned Row owns the transaction until Scan is called, which pgx's contract
// already requires exactly once.
func (p *ScopedPool) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if CurrentRLSMode() == RLSModeSession {
		return p.pool.QueryRow(ctx, sql, args...)
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return errRow{err}
	}
	if err := applyScopeLocal(ctx, tx); err != nil {
		_ = tx.Rollback(ctx)
		return errRow{err}
	}
	return &txRow{ctx: ctx, tx: tx, row: tx.QueryRow(ctx, sql, args...)}
}

// Exec runs a statement under the request's tenant scope.
func (p *ScopedPool) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if CurrentRLSMode() == RLSModeSession {
		return p.pool.Exec(ctx, sql, args...)
	}
	var tag pgconn.CommandTag
	err := withTxOn(ctx, p.pool, func(tx pgx.Tx) error {
		var e error
		tag, e = tx.Exec(ctx, sql, args...)
		return e
	})
	return tag, err
}

// Begin opens a transaction that already carries the request's tenant scope, so
// the ~25 call sites that manage their own transaction get the scope without
// changing a line. The caller still owns Commit and Rollback.
func (p *ScopedPool) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if CurrentRLSMode() == RLSModeLocal {
		if err := applyScopeLocal(ctx, tx); err != nil {
			_ = tx.Rollback(ctx)
			return nil, err
		}
	}
	return tx, nil
}

// BeginTx is Begin with explicit transaction options.
func (p *ScopedPool) BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	tx, err := p.pool.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	if CurrentRLSMode() == RLSModeLocal {
		if err := applyScopeLocal(ctx, tx); err != nil {
			_ = tx.Rollback(ctx)
			return nil, err
		}
	}
	return tx, nil
}

// SendBatch runs a batch under the request's tenant scope. pgx runs a batch on
// one connection, so in local mode the scope is prepended as the batch's first
// statement rather than opening a transaction around it — same effect, one
// round trip.
func (p *ScopedPool) SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults {
	if CurrentRLSMode() == RLSModeSession || b == nil {
		return p.pool.SendBatch(ctx, b)
	}
	orgID, bypass := rlsValuesFromContext(ctx)
	scoped := &pgx.Batch{}
	scoped.Queue(setScopeLocalSQL, orgID, bypass)
	scoped.QueuedQueries = append(scoped.QueuedQueries, b.QueuedQueries...)
	return &skipFirstBatchResults{BatchResults: p.pool.SendBatch(ctx, scoped)}
}

// skipFirstBatchResults hides the scope statement's result, so the caller reads
// its own queries in the order it queued them.
type skipFirstBatchResults struct {
	pgx.BatchResults
	skipped bool
}

func (r *skipFirstBatchResults) ensureSkipped() {
	if !r.skipped {
		r.skipped = true
		// The scope statement is a SELECT; draining its rows advances the
		// batch to the caller's first query.
		rows, err := r.BatchResults.Query()
		if err == nil {
			rows.Close()
		}
	}
}

func (r *skipFirstBatchResults) Exec() (pgconn.CommandTag, error) {
	r.ensureSkipped()
	return r.BatchResults.Exec()
}

func (r *skipFirstBatchResults) Query() (pgx.Rows, error) {
	r.ensureSkipped()
	return r.BatchResults.Query()
}

func (r *skipFirstBatchResults) QueryRow() pgx.Row {
	r.ensureSkipped()
	return r.BatchResults.QueryRow()
}

func (r *skipFirstBatchResults) Close() error { return r.BatchResults.Close() }

// Acquire hands out a raw connection. It carries NO tenant scope in local mode:
// a caller holding its own connection is doing something the scope cannot be
// inferred for (LISTEN/NOTIFY, COPY, advisory locks). Scope it yourself with a
// transaction if it touches a tenant table.
func (p *ScopedPool) Acquire(ctx context.Context) (*pgxpool.Conn, error) {
	return p.pool.Acquire(ctx)
}

// Ping, Close and Stat are pool operations with no tenant dimension.
func (p *ScopedPool) Ping(ctx context.Context) error { return p.pool.Ping(ctx) }
func (p *ScopedPool) Close()                         { p.pool.Close() }
func (p *ScopedPool) Stat() *pgxpool.Stat            { return p.pool.Stat() }
func (p *ScopedPool) Config() *pgxpool.Config        { return p.pool.Config() }
