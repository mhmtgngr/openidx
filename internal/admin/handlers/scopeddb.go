package handlers

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ScopedDB is the database surface these handlers need, as an interface rather
// than *pgxpool.Pool so a scope-applying pool (database.ScopedPool) can be
// passed (global-scale plan task 2.1b).
//
// It matters here: the dashboard and settings handlers read tenant tables
// (users, user_sessions, applications). Given a raw pool under RLS_MODE=local
// they would carry no tenant scope, and FORCE RLS would answer every count
// with zero — a dashboard of zeros rather than an error, which is the quiet
// kind of wrong.
type ScopedDB interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}
