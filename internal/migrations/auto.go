// Package migrations provides database migration support for OpenIDX
package migrations

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// AutoMigrate runs pending migrations automatically
// This is intended to be called from service startup
func AutoMigrate(ctx context.Context, db *pgxpool.Pool, log *zap.Logger) error {
	// Migrations are install-wide DDL/DML run as the table owner. Once v37 turns
	// on FORCE row-level security, the pool's checkout hook would otherwise scope
	// the migrator's connections to an (empty) org and filter their rows — so the
	// migrator runs with the explicit RLS bypass.
	ctx = orgctx.WithBypassRLS(ctx)

	migrator := NewMigrator(db, log)

	// Check current state
	currentVersion, err := migrator.Version(ctx)
	if err != nil {
		return fmt.Errorf("failed to get current migration version: %w", err)
	}

	log.Info("Database migration check", zap.Int("current_version", currentVersion))

	// Run pending migrations
	if err := migrator.Migrate(ctx); err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	newVersion, _ := migrator.Version(ctx)
	if newVersion > currentVersion {
		log.Info("Migrations applied",
			zap.Int("previous_version", currentVersion),
			zap.Int("new_version", newVersion))
	} else {
		log.Info("No pending migrations", zap.Int("current_version", currentVersion))
	}

	return nil
}

// MustAutoMigrate runs migrations and panics on failure
// Use this during service initialization for fail-fast behavior
func MustAutoMigrate(ctx context.Context, db *pgxpool.Pool, log *zap.Logger) {
	if err := AutoMigrate(ctx, db, log); err != nil {
		log.Fatal("Auto-migration failed", zap.Error(err))
	}
}
