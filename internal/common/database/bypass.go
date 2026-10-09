package database

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// A BYPASS OF ROW-LEVEL SECURITY IS A ROLE, NOT A SETTING.
//
// Background work (sweeps, directory sync, cross-tenant lookups before the
// tenant is known) runs with orgctx.WithBypassRLS. Until now that marker made
// the checkout hook run set_config('app.bypass_rls', 'on') on a connection of
// the ordinary application role, and every policy let a session with that
// setting through. The setting is a GUC any session may set, so one SQL
// injection on the application role lifted the tenant boundary for the whole
// install (issue #964, docs/SECURITY-TENANCY.md).
//
// DATABASE_BYPASS_URL names a second credential: a role with the BYPASSRLS
// attribute and nothing else special (deployments/docker/bootstrap.sql,
// the Helm bootstrap job, docs/runbooks/enforce-rollout.md). With it set,
// ScopedPool routes every bypass-marked call to that pool, the application
// pool never carries the GUC, and migration 228 removes the GUC clause from
// every policy so that setting it is nothing more than a harmless string.
// Without it, the GUC stays the mechanism, and production refuses to start
// (config.ValidateProduction).

// bypassRoleCheckSQL asks the database whether the credential it was given is
// what the deployment promised. A DSN that quietly points at the application
// role would make every background job see no rows after migration 228.
const bypassRoleCheckSQL = `SELECT rolbypassrls OR rolsuper FROM pg_roles WHERE rolname = current_user`

// openBypassPool opens DATABASE_BYPASS_URL and verifies the role behind it.
func openBypassPool(ctx context.Context, url string, tlsCfg []PostgresTLSConfig) (*pgxpool.Pool, error) {
	if len(tlsCfg) > 0 {
		url = applyPostgresTLS(url, tlsCfg[0])
	}
	cfg, err := buildPoolConfig(url)
	if err != nil {
		return nil, fmt.Errorf("DATABASE_BYPASS_URL: %w", err)
	}
	// The bypass pool serves background work, not request fan-out.
	if cfg.MaxConns > 8 {
		cfg.MaxConns = 8
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("DATABASE_BYPASS_URL: open pool: %w", err)
	}
	var canBypass bool
	if err := pool.QueryRow(ctx, bypassRoleCheckSQL).Scan(&canBypass); err != nil {
		pool.Close()
		return nil, fmt.Errorf("DATABASE_BYPASS_URL: verify role: %w", err)
	}
	if !canBypass {
		pool.Close()
		return nil, fmt.Errorf("DATABASE_BYPASS_URL: the role it connects as has no BYPASSRLS attribute; it must be the bypass role the bootstrap created, not the application role")
	}
	return pool, nil
}

// bypassURLFromEnv is DATABASE_BYPASS_URL, "" when unset.
func bypassURLFromEnv() string { return os.Getenv("DATABASE_BYPASS_URL") }

// HasBypassPool reports whether bypass-marked work runs as the bypass role.
func (db *PostgresDB) HasBypassPool() bool { return db != nil && db.bypassPool != nil }

// PingBypass checks the bypass pool, for health reporting.
func (db *PostgresDB) PingBypass() error {
	if db == nil || db.bypassPool == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return db.bypassPool.Ping(ctx)
}
