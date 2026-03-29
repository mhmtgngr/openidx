// Package migrations provides database schema migration support for OpenIDX
package migrations

import (
	"context"
	"embed"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

//go:embed *.sql
var sqlFiles embed.FS

// Migration represents a single database migration
type Migration struct {
	Version     int
	Name        string
	Description string
	UpSQL       string
	DownSQL     string
}

// Migrator handles database migrations
type Migrator struct {
	db     *pgxpool.Pool
	logger *zap.Logger
	dir    string // Optional: directory to load migrations from (instead of embed)
}

// NewMigrator creates a new migration runner
func NewMigrator(db *pgxpool.Pool, logger *zap.Logger) *Migrator {
	return &Migrator{
		db:     db,
		logger: logger,
	}
}

// SetDir sets the directory to load migrations from (for testing/local development)
func (m *Migrator) SetDir(dir string) {
	m.dir = dir
}

// ensureSchemaTable creates the schema_migrations table if it doesn't exist
func (m *Migrator) ensureSchemaTable(ctx context.Context) error {
	sql := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			description TEXT,
			applied_at TIMESTAMP WITH TIME ZONE NOT NULL,
			duration_ms INTEGER
		);

		CREATE TABLE IF NOT EXISTS schema_migration_lock (
			id INTEGER PRIMARY KEY DEFAULT 1,
			locked BOOLEAN DEFAULT false,
			locked_at TIMESTAMP WITH TIME ZONE,
			locked_by VARCHAR(255)
		);

		INSERT INTO schema_migration_lock (id, locked, locked_by)
		VALUES (1, false, 'system')
		ON CONFLICT (id) DO NOTHING;
	`
	_, err := m.db.Exec(ctx, sql)
	return err
}

// getCurrentVersion returns the currently applied migration version
func (m *Migrator) getCurrentVersion(ctx context.Context) (int, error) {
	err := m.ensureSchemaTable(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to ensure schema table: %w", err)
	}

	var version int
	err = m.db.QueryRow(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("failed to get current version: %w", err)
	}
	return version, nil
}

// getAppliedMigrations returns all applied migrations
func (m *Migrator) getAppliedMigrations(ctx context.Context) (map[int]bool, error) {
	err := m.ensureSchemaTable(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure schema table: %w", err)
	}

	rows, err := m.db.Query(ctx, "SELECT version FROM schema_migrations ORDER BY version")
	if err != nil {
		return nil, fmt.Errorf("failed to query applied migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[int]bool)
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("failed to scan version: %w", err)
		}
		applied[version] = true
	}
	return applied, rows.Err()
}

// registerMigration records a migration as applied
func (m *Migrator) registerMigration(ctx context.Context, mig *Migration, durationMs int) error {
	sql := `
		INSERT INTO schema_migrations (version, name, description, applied_at, duration_ms)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err := m.db.Exec(ctx, sql, mig.Version, mig.Name, mig.Description, time.Now(), durationMs)
	return err
}

// unregisterMigration removes a migration record (for rollback)
func (m *Migrator) unregisterMigration(ctx context.Context, version int) error {
	sql := `DELETE FROM schema_migrations WHERE version = $1`
	_, err := m.db.Exec(ctx, sql, version)
	return err
}

// acquireLock attempts to acquire the migration lock
func (m *Migrator) acquireLock(ctx context.Context, identifier string) error {
	sql := `
		UPDATE schema_migration_lock
		SET locked = true, locked_at = $1, locked_by = $2
		WHERE id = 1 AND locked = false
	`
	result, err := m.db.Exec(ctx, sql, time.Now(), identifier)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	rows := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("migration lock is already held by another process")
	}
	return nil
}

// releaseLock releases the migration lock
func (m *Migrator) releaseLock(ctx context.Context) error {
	sql := `UPDATE schema_migration_lock SET locked = false, locked_at = NULL, locked_by = NULL WHERE id = 1`
	_, err := m.db.Exec(ctx, sql)
	return err
}

// Migrate runs all pending migrations
func (m *Migrator) Migrate(ctx context.Context) error {
	return m.MigrateTo(ctx, -1)
}

// MigrateTo runs migrations up to the specified version (-1 for all)
func (m *Migrator) MigrateTo(ctx context.Context, targetVersion int) error {
	const lockID = "migrate-up"

	// Get all available migrations
	migrations, err := m.LoadMigrations()
	if err != nil {
		return fmt.Errorf("failed to load migrations: %w", err)
	}

	// Get applied migrations
	applied, err := m.getAppliedMigrations(ctx)
	if err != nil {
		return fmt.Errorf("failed to get applied migrations: %w", err)
	}

	// Filter pending migrations
	var pending []*Migration
	for _, mig := range migrations {
		if !applied[mig.Version] {
			if targetVersion == -1 || mig.Version <= targetVersion {
				pending = append(pending, mig)
			}
		}
	}

	if len(pending) == 0 {
		m.logger.Info("No pending migrations to apply")
		return nil
	}

	// Acquire lock
	if err := m.acquireLock(ctx, lockID); err != nil {
		return fmt.Errorf("failed to acquire migration lock: %w", err)
	}
	defer m.releaseLock(ctx)

	m.logger.Info("Starting migration", zap.Int("pending", len(pending)))

	// Apply migrations in order
	for _, mig := range pending {
		start := time.Now()
		m.logger.Info("Applying migration",
			zap.Int("version", mig.Version),
			zap.String("name", mig.Name))

		if err := m.applyMigration(ctx, mig); err != nil {
			return fmt.Errorf("migration %d (%s) failed: %w", mig.Version, mig.Name, err)
		}

		duration := time.Since(start)
		if err := m.registerMigration(ctx, mig, int(duration.Milliseconds())); err != nil {
			return fmt.Errorf("failed to register migration %d: %w", mig.Version, err)
		}

		m.logger.Info("Migration applied successfully",
			zap.Int("version", mig.Version),
			zap.Duration("duration", duration))
	}

	m.logger.Info("All migrations applied successfully", zap.Int("count", len(pending)))
	return nil
}

// applyMigration executes a single migration within a transaction
func (m *Migrator) applyMigration(ctx context.Context, mig *Migration) error {
	tx, err := m.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Split SQL by semicolons and execute each statement
	statements := m.splitSQL(mig.UpSQL)
	for _, stmt := range statements {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("statement failed: %s\nerror: %w", stmt, err)
		}
	}
	return tx.Commit(ctx)
}

// Rollback rolls back the most recent migration
func (m *Migrator) Rollback(ctx context.Context) error {
	return m.RollbackTo(ctx, -1)
}

// RollbackTo rolls back migrations to the specified version (-1 for one step back)
func (m *Migrator) RollbackTo(ctx context.Context, targetVersion int) error {
	const lockID = "migrate-down"

	// Get current version
	current, err := m.getCurrentVersion(ctx)
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	if current == 0 {
		m.logger.Info("No migrations to rollback")
		return nil
	}

	// Load all migrations
	migrations, err := m.LoadMigrations()
	if err != nil {
		return fmt.Errorf("failed to load migrations: %w", err)
	}

	// Determine which migrations to rollback
	var toRollback []*Migration
	for _, mig := range migrations {
		if mig.Version > current {
			continue
		}
		if targetVersion == -1 {
			// Rollback one migration (the current one)
			if mig.Version == current {
				toRollback = append(toRollback, mig)
				break
			}
		} else {
			// Rollback to target version
			if mig.Version > targetVersion {
				toRollback = append(toRollback, mig)
			}
		}
	}

	// Reverse order for rollback
	sort.Slice(toRollback, func(i, j int) bool {
		return toRollback[i].Version > toRollback[j].Version
	})

	if len(toRollback) == 0 {
		m.logger.Info("No migrations to rollback")
		return nil
	}

	// Acquire lock
	if err := m.acquireLock(ctx, lockID); err != nil {
		return fmt.Errorf("failed to acquire migration lock: %w", err)
	}
	defer m.releaseLock(ctx)

	m.logger.Info("Rolling back migrations", zap.Int("count", len(toRollback)))

	// Rollback migrations
	for _, mig := range toRollback {
		m.logger.Info("Rolling back migration",
			zap.Int("version", mig.Version),
			zap.String("name", mig.Name))

		if err := m.rollbackMigration(ctx, mig); err != nil {
			return fmt.Errorf("rollback of migration %d (%s) failed: %w", mig.Version, mig.Name, err)
		}

		if err := m.unregisterMigration(ctx, mig.Version); err != nil {
			return fmt.Errorf("failed to unregister migration %d: %w", mig.Version, err)
		}

		m.logger.Info("Migration rolled back successfully", zap.Int("version", mig.Version))
	}

	m.logger.Info("Rollback completed", zap.Int("count", len(toRollback)))
	return nil
}

// rollbackMigration executes the down migration within a transaction
func (m *Migrator) rollbackMigration(ctx context.Context, mig *Migration) error {
	tx, err := m.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Split SQL by semicolons and execute each statement
	statements := m.splitSQL(mig.DownSQL)
	for _, stmt := range statements {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("statement failed: %s\nerror: %w", stmt, err)
		}
	}
	return tx.Commit(ctx)
}

// Status returns the current migration status
func (m *Migrator) Status(ctx context.Context) (*Status, error) {
	status := &Status{
		CurrentVersion: 0,
		Migrations:     []*MigrationStatus{},
	}

	// Get current version
	current, err := m.getCurrentVersion(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get current version: %w", err)
	}
	status.CurrentVersion = current

	// Load all migrations
	migrations, err := m.LoadMigrations()
	if err != nil {
		return nil, fmt.Errorf("failed to load migrations: %w", err)
	}

	// Get applied migrations with metadata
	type appliedInfo struct {
		Version    int
		Name       string
		AppliedAt  time.Time
		DurationMs int
	}

	appliedInfoMap := make(map[int]*appliedInfo)
	err = m.ensureSchemaTable(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure schema table: %w", err)
	}

	rows, err := m.db.Query(ctx, `
		SELECT version, name, applied_at, duration_ms
		FROM schema_migrations
		ORDER BY version
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query applied migrations: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var info appliedInfo
		if err := rows.Scan(&info.Version, &info.Name, &info.AppliedAt, &info.DurationMs); err != nil {
			return nil, fmt.Errorf("failed to scan migration info: %w", err)
		}
		appliedInfoMap[info.Version] = &info
	}

	// Build status list
	for _, mig := range migrations {
		ms := &MigrationStatus{
			Version:     mig.Version,
			Name:        mig.Name,
			Description: mig.Description,
			Applied:     appliedInfoMap[mig.Version] != nil,
		}
		if info, ok := appliedInfoMap[mig.Version]; ok {
			ms.AppliedAt = &info.AppliedAt
			ms.DurationMs = info.DurationMs
		}
		status.Migrations = append(status.Migrations, ms)
	}

	return status, nil
}

// Version returns the current migration version
func (m *Migrator) Version(ctx context.Context) (int, error) {
	return m.getCurrentVersion(ctx)
}

// Status represents migration status
type Status struct {
	CurrentVersion int
	Migrations     []*MigrationStatus
}

// MigrationStatus represents the status of a single migration
type MigrationStatus struct {
	Version     int
	Name        string
	Description string
	Applied     bool
	AppliedAt   *time.Time
	DurationMs  int
}

// splitSQL splits SQL statements by semicolon, handling dollar-quoted strings
func (m *Migrator) splitSQL(sql string) []string {
	// Simple implementation - split by semicolon
	// A more sophisticated version would handle dollar quotes, etc.
	var statements []string
	var current strings.Builder
	inDollarQuote := false
	dollarTag := ""

	lines := strings.Split(sql, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments
		if strings.HasPrefix(trimmed, "--") {
			continue
		}

		// Check for dollar quote start/end
		if !inDollarQuote && strings.HasPrefix(trimmed, "$$") {
			inDollarQuote = true
			dollarTag = "$$"
		} else if inDollarQuote && strings.HasPrefix(trimmed, dollarTag) {
			inDollarQuote = false
			dollarTag = ""
		}

		current.WriteString(line)
		current.WriteString("\n")

		// Check for statement terminator
		if !inDollarQuote && strings.HasSuffix(trimmed, ";") {
			stmt := current.String()
			statements = append(statements, stmt)
			current.Reset()
		}
	}

	// Add any remaining content
	if current.Len() > 0 {
		statements = append(statements, current.String())
	}

	return statements
}
