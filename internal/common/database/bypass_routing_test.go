package database

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// lazyPool is a pool that never connects: pgxpool dials on first acquire, so
// two of them are enough to tell which one a call would have used.
func lazyPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig("postgres://nobody@127.0.0.1:1/nowhere?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	p, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

// A bypass-marked context runs on the bypass pool and nothing else does;
// without a bypass pool everything stays on the application pool.
func TestBypassContextRoutesToTheBypassPool(t *testing.T) {
	app, bypass := lazyPool(t), lazyPool(t)
	p := NewScopedPool(app).withBypass(bypass)

	plain := orgctx.With(context.Background(), orgctx.Org{ID: "11111111-1111-1111-1111-111111111111"})
	if got := p.target(plain); got != app {
		t.Error("a tenant-scoped call left the application pool")
	}
	if got := p.target(orgctx.WithBypassRLS(context.Background())); got != bypass {
		t.Error("a bypass-marked call did not go to the bypass pool")
	}
	if got := NewScopedPool(app).target(orgctx.WithBypassRLS(context.Background())); got != app {
		t.Error("with no bypass pool, a bypass-marked call must stay on the application pool")
	}
}

// Once routing exists, the application pool is never asked to turn the GUC
// on, even by a stray bypass-marked call that reaches it.
func TestTheGUCIsNeverOnOnceRoutingExists(t *testing.T) {
	was := bypassRouting.Load()
	t.Cleanup(func() { bypassRouting.Store(was) })
	ctx := orgctx.WithBypassRLS(context.Background())

	bypassRouting.Store(false)
	if _, b := rlsValuesFromContext(ctx); b != "on" {
		t.Errorf("without a bypass pool the GUC is the mechanism; got %q", b)
	}
	bypassRouting.Store(true)
	if org, b := rlsValuesFromContext(ctx); b != "off" || org != "" {
		t.Errorf("with a bypass pool a bypass context must read as no tenant and GUC off; got org=%q bypass=%q", org, b)
	}
}
