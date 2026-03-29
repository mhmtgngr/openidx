// Package main provides the database migration CLI tool
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/logger"
	"github.com/openidx/openidx/internal/migrations"
)

var (
	// Version information (set by build)
	Version = "dev"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Initialize logger
	log := logger.New()
	defer log.Sync()

	// Load database URL from environment or config
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		cfg, err := config.Load("migrate")
		if err != nil {
			log.Fatal("Failed to load config", zap.Error(err))
		}
		dbURL = cfg.DatabaseURL
	}

	if dbURL == "" {
		log.Fatal("DATABASE_URL environment variable or config must be set")
	}

	// Connect to database
	db, err := database.NewPostgres(dbURL)
	if err != nil {
		log.Fatal("Failed to connect to database", zap.Error(err))
	}
	defer db.Close()

	// Create migrator
	migrator := migrations.NewMigrator(db.Pool, log)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// Execute command
	command := os.Args[1]
	switch command {
	case "up", "migrate":
		// Optional version argument
		targetVersion := -1
		if len(os.Args) > 2 {
			_, err := fmt.Sscanf(os.Args[2], "%d", &targetVersion)
			if err != nil {
				log.Fatal("Invalid version number", zap.Error(err))
			}
		}
		if err := migrator.MigrateTo(ctx, targetVersion); err != nil {
			log.Fatal("Migration failed", zap.Error(err))
		}
		fmt.Println("Migrations completed successfully")

	case "down", "rollback":
		// Optional version argument
		targetVersion := -1
		if len(os.Args) > 2 {
			_, err := fmt.Sscanf(os.Args[2], "%d", &targetVersion)
			if err != nil {
				log.Fatal("Invalid version number", zap.Error(err))
			}
		}
		if err := migrator.RollbackTo(ctx, targetVersion); err != nil {
			log.Fatal("Rollback failed", zap.Error(err))
		}
		fmt.Println("Rollback completed successfully")

	case "status":
		status, err := migrator.Status(ctx)
		if err != nil {
			log.Fatal("Failed to get status", zap.Error(err))
		}
		printStatus(status)

	case "version":
		version, err := migrator.Version(ctx)
		if err != nil {
			log.Fatal("Failed to get version", zap.Error(err))
		}
		fmt.Printf("Current migration version: %d\n", version)

	case "create":
		if len(os.Args) < 3 {
			log.Fatal("Usage: migrate create <migration_name>")
		}
		name := os.Args[2]
		if err := createMigration(name); err != nil {
			log.Fatal("Failed to create migration", zap.Error(err))
		}

	case "help", "-h", "--help":
		printUsage()

	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`OpenIDX Database Migration Tool (v%s)

Usage:
    migrate [command] [arguments]

Commands:
    up [version]         Run all pending migrations (or up to specific version)
    down [version]       Rollback one migration (or to specific version)
    status               Show migration status
    version              Show current migration version
    create <name>        Create a new migration file
    help                 Show this help message

Environment Variables:
    DATABASE_URL         PostgreSQL connection string

Examples:
    migrate up                    # Run all pending migrations
    migrate up 5                  # Run migrations up to version 5
    migrate down                  # Rollback last migration
    migrate down 3                # Rollback to version 3
    migrate status                # Show migration status
    migrate version               # Show current version
    migrate create add_user_table # Create new migration

`, Version)
}

func printStatus(status *migrations.Status) {
	fmt.Printf("\nCurrent Version: %d\n", status.CurrentVersion)
	fmt.Printf("Total Migrations: %d\n\n", len(status.Migrations))

	fmt.Println("Migration Status:")
	fmt.Println("────────────────────────────────────────────────────────────────────────")

	for _, m := range status.Migrations {
		applied := "  "
		statusText := "pending"
		if m.Applied {
			applied = "✓"
			statusText = "applied"
		}

		duration := ""
		if m.DurationMs > 0 {
			duration = fmt.Sprintf(" (%dms)", m.DurationMs)
		}

		appliedAt := ""
		if m.AppliedAt != nil {
			appliedAt = " " + m.AppliedAt.Format("2006-01-02 15:04:05")
		}

		fmt.Printf("%s [%03d] %-30s %s%s%s\n",
			applied, m.Version, m.Name, statusText, duration, appliedAt)
	}

	fmt.Println("────────────────────────────────────────────────────────────────────────")
}

func createMigration(name string) error {
	// This would create new migration files
	// For now, it's a placeholder
	fmt.Printf("Creating migration: %s\n", name)
	fmt.Println("Note: Please create migration files manually in the migrations/ directory")
	fmt.Println("Format: XXX_name.up.sql and XXX_name.down.sql")
	return nil
}

// connectDB creates a database connection from URL string
func connectDB(dbURL string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection string: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Test connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return pool, nil
}
