package database

import (
	"context"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// v1.8.0 RLS belt: every pooled connection carries the request's tenant scope
// as Postgres GUCs (app.org_id / app.bypass_rls) so the FORCE'd row-level
// security policies (migration v37) filter by org_id even if an app-layer
// filter is missing. The scope is derived from the context that the tenant
// resolver attached and applied at pool checkout — no query call-site changes.

// rlsValuesFromContext maps a request context to the (app.org_id, app.bypass_rls)
// GUC values. Precedence: an explicit bypass marker (background/cross-org work)
// wins; otherwise the resolved org; otherwise empty — which makes the RLS
// predicate `org_id = NULL` and returns no rows (fail-closed).
func rlsValuesFromContext(ctx context.Context) (orgID, bypass string) {
	if orgctx.IsBypassRLS(ctx) {
		return "", "on"
	}
	if org, err := orgctx.From(ctx); err == nil {
		return org.ID, "off"
	}
	return "", "off"
}

type rlsState struct{ orgID, bypass string }

// rlsApplier sets the tenant GUCs on each connection at checkout, skipping the
// round-trip when the connection already carries the desired scope (connections
// are reused, so most acquires are no-ops for a stable org).
type rlsApplier struct {
	mu   sync.Mutex
	last map[*pgx.Conn]rlsState
}

func newRLSApplier() *rlsApplier {
	return &rlsApplier{last: make(map[*pgx.Conn]rlsState)}
}

func (a *rlsApplier) beforeAcquire(ctx context.Context, conn *pgx.Conn) bool {
	orgID, bypass := rlsValuesFromContext(ctx)
	want := rlsState{orgID: orgID, bypass: bypass}

	a.mu.Lock()
	cur, ok := a.last[conn]
	a.mu.Unlock()
	if ok && cur == want {
		return true
	}

	if _, err := conn.Exec(ctx,
		`select set_config('app.org_id', $1, false), set_config('app.bypass_rls', $2, false)`,
		orgID, bypass); err != nil {
		// Could not establish the tenant scope on this connection — discard it
		// rather than hand out a wrongly-scoped (or unscoped) connection.
		a.mu.Lock()
		delete(a.last, conn)
		a.mu.Unlock()
		return false
	}

	a.mu.Lock()
	a.last[conn] = want
	a.mu.Unlock()
	return true
}

func (a *rlsApplier) beforeClose(conn *pgx.Conn) {
	a.mu.Lock()
	delete(a.last, conn)
	a.mu.Unlock()
}

// configureRLS installs the tenant-scope checkout hook on the pool config.
func configureRLS(config *pgxpool.Config) {
	a := newRLSApplier()
	// PrepareConn (pgx v5.9+) supersedes the deprecated BeforeAcquire — same
	// before-acquire hook, now returning an error alongside the keep/destroy
	// bool. The adapter preserves beforeAcquire's exact semantics.
	config.PrepareConn = func(ctx context.Context, conn *pgx.Conn) (bool, error) {
		return a.beforeAcquire(ctx, conn), nil
	}
	config.BeforeClose = a.beforeClose
}
