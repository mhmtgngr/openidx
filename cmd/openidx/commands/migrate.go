package commands

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/spf13/cobra"
)

// NewMigrateCommand creates the migrate command
func NewMigrateCommand() *cobra.Command {
	var dbURL string

	cmd := &cobra.Command{
		Use:   "migrate [command]",
		Short: "Database migrations",
		Long: `Run database migrations to manage schema changes.

Commands:
  up [version]    Run all pending migrations (or up to specific version)
  down [version]  Rollback one migration (or to specific version)
  status          Show migration status
  version         Show current migration version
  create <name>   Create a new migration file`,
		Aliases: []string{"db", "migration"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			return nil
		},
	}

	cmd.PersistentFlags().StringVar(&dbURL, "db-url", "", "Database URL (defaults to DATABASE_URL env var)")

	// Add subcommands
	upCmd := &cobra.Command{
		Use:   "up [version]",
		Short: "Run migrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			targetVersion := -1
			if len(args) > 0 {
				fmt.Sscanf(args[0], "%d", &targetVersion)
			}
			return runMigrate(ctx, dbURL, "up", targetVersion)
		},
	}
	cmd.AddCommand(upCmd)

	downCmd := &cobra.Command{
		Use:   "down [version]",
		Short: "Rollback migrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			targetVersion := -1
			if len(args) > 0 {
				fmt.Sscanf(args[0], "%d", &targetVersion)
			}
			return runMigrate(ctx, dbURL, "down", targetVersion)
		},
	}
	cmd.AddCommand(downCmd)

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show migration status",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			return runMigrate(ctx, dbURL, "status", 0)
		},
	}
	cmd.AddCommand(statusCmd)

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Show current version",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			return runMigrate(ctx, dbURL, "version", 0)
		},
	}
	cmd.AddCommand(versionCmd)

	createCmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new migration",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			return createMigration(ctx, args[0])
		},
	}
	cmd.AddCommand(createCmd)

	redoCmd := &cobra.Command{
		Use:   "redo",
		Short: "Rollback and re-run last migration",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, errColor, _, _, _ := ctx.GetColors()

			success.Println("🔄 Rolling back last migration...")
			if e := runMigrate(ctx, dbURL, "down", 0); e != nil {
				errColor.Printf("Rollback failed: %v\n", e)
				return e
			}

			success.Println("✅ Running migration again...")
			if e := runMigrate(ctx, dbURL, "up", 0); e != nil {
				errColor.Printf("Migration failed: %v\n", e)
				return e
			}

			success.Println("✅ Migration redone")
			return nil
		},
	}
	cmd.AddCommand(redoCmd)

	resetCmd := &cobra.Command{
		Use:   "reset",
		Short: "Rollback all migrations and re-run them",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, errColor, warning, _, _ := ctx.GetColors()

			warning.Println("⚠️  This will rollback all migrations and re-run them")
			warning.Println("   This may result in data loss!")

			// Simple confirmation
			fmt.Print("Are you sure? [y/N] ")
			var response string
			fmt.Scanln(&response)
			if response != "y" && response != "Y" {
				fmt.Println("Aborted")
				return nil
			}

			success.Println("🔄 Rolling back all migrations...")
			if e := runMigrate(ctx, dbURL, "down", 0); e != nil {
				errColor.Printf("Rollback failed: %v\n", e)
				return e
			}

			success.Println("✅ Running all migrations...")
			if e := runMigrate(ctx, dbURL, "up", 0); e != nil {
				errColor.Printf("Migration failed: %v\n", e)
				return e
			}

			success.Println("✅ Migrations reset complete")
			return nil
		},
	}
	cmd.AddCommand(resetCmd)

	return cmd
}

func runMigrate(ctx *CommandContext, dbURL, command string, version int) error {
	success, errColor, _, _, _ := ctx.GetColors()

	// Get database URL
	if dbURL == "" {
		dbURL = os.Getenv("DATABASE_URL")
	}
	if dbURL == "" {
		return fmt.Errorf("DATABASE_URL environment variable or --db-url flag is required")
	}

	// Verify database connection
	if e := verifyDBConnection(dbURL); e != nil {
		errColor.Printf("Cannot connect to database: %v\n", e)
		return e
	}

	// Build the migrate command
	args := []string{"run", ctx.Path("cmd", "migrate"), command}
	if version > 0 {
		args = append(args, fmt.Sprintf("%d", version))
	}

	// Set DATABASE_URL for the subprocess
	env := append(os.Environ(), "DATABASE_URL="+dbURL)

	// Run migrate command
	success.Printf("Running migration: %s\n", command)
	if e := ctx.RunCommandInDirWithEnv(ctx.RootDir, env, "go", args...); e != nil {
		return e
	}

	success.Println("✅ Migration complete")
	return nil
}

func (c *CommandContext) RunCommandInDirWithEnv(dir string, env []string, name string, args ...string) error {
	cmd := NewCommand(dir, name, args...)
	cmd.Env = env
	return cmd.Run()
}

// verifyDBConnection checks if we can connect to the database
func verifyDBConnection(dbURL string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	return conn.Ping(ctx)
}

func createMigration(ctx *CommandContext, name string) error {
	success, errColor, _, _, _ := ctx.GetColors()

	// List existing migrations to determine next number
	migrationsDir := ctx.Path("migrations")
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		errColor.Printf("Failed to read migrations directory: %v\n", err)
		return err
	}

	// Find the highest migration number
	maxNum := 0
	for _, entry := range entries {
		var num int
		if _, err := fmt.Sscanf(entry.Name(), "%d_", &num); err == nil {
			if num > maxNum {
				maxNum = num
			}
		}
	}

	nextNum := maxNum + 1
	prefix := fmt.Sprintf("%03d", nextNum)

	upFile := fmt.Sprintf("%s_%s.up.sql", prefix, name)
	downFile := fmt.Sprintf("%s_%s.down.sql", prefix, name)

	upPath := ctx.Path("migrations", upFile)
	downPath := ctx.Path("migrations", downFile)

	// Create up migration
	if err := os.WriteFile(upPath, []byte(fmt.Sprintf("-- Migration %s: %s\n-- Up\n\n", prefix, name)), 0644); err != nil {
		return err
	}

	// Create down migration
	if err := os.WriteFile(downPath, []byte(fmt.Sprintf("-- Migration %s: %s\n-- Down\n\n", prefix, name)), 0644); err != nil {
		return err
	}

	success.Printf("✅ Created migration files:\n")
	success.Printf("   %s\n", upFile)
	success.Printf("   %s\n", downFile)

	return nil
}

// NewDbCommand creates the database command group
func NewDbCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "db",
		Short: "Database operations",
		Long:  `Commands for database operations including migrations, seeds, and connections.`,
	}

	// Add migrate as a subcommand
	cmd.AddCommand(NewMigrateCommand())
	cmd.AddCommand(NewSeedCommand())
	cmd.AddCommand(NewDbShellCommand())
	cmd.AddCommand(NewDbResetCommand())
	cmd.AddCommand(NewDbDropCommand())

	return cmd
}

// NewDbShellCommand creates the database shell command
func NewDbShellCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "shell",
		Short: "Open database shell",
		Long:  `Open a PostgreSQL shell connected to the database.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			errColor, _, _, _, _ := ctx.GetColors()

			dbURL := os.Getenv("DATABASE_URL")
			if dbURL == "" {
				return fmt.Errorf("DATABASE_URL environment variable is required")
			}

			// Use psql to connect
			if e := ctx.RunCommand("psql", dbURL); e != nil {
				errColor.Printf("Failed to open database shell: %v\n", e)
				return e
			}

			return nil
		},
	}

	return cmd
}

// NewDbResetCommand creates the database reset command
func NewDbResetCommand() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Reset database (drop and recreate)",
		Long:  `Drop the database, recreate it, and run all migrations.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, _, warning, _, _ := ctx.GetColors()

			if !force {
				warning.Println("⚠️  This will drop and recreate the database")
				warning.Println("   All data will be lost!")

				fmt.Print("Are you sure? [y/N] ")
				var response string
				fmt.Scanln(&response)
				if response != "y" && response != "Y" {
					fmt.Println("Aborted")
					return nil
				}
			}

			success.Println("🔄 Resetting database...")

			// This would need to be implemented with proper SQL commands
			// For now, we'll show a message
			warning.Println("⚠️  Database reset requires manual implementation")
			warning.Println("   Use docker compose down -v to reset volumes")

			return nil
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation")

	return cmd
}

// NewDbDropCommand creates the database drop command
func NewDbDropCommand() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "drop",
		Short: "Drop database tables",
		Long:  `Drop all database tables. Use with caution!`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			warning, errColor, _, _, _ := ctx.GetColors()

			if !force {
				warning.Println("⚠️  This will drop all database tables!")
				warning.Println("   All data will be lost!")

				fmt.Print("Are you sure? [y/N] ")
				var response string
				fmt.Scanln(&response)
				if response != "y" && response != "Y" {
					fmt.Println("Aborted")
					return nil
				}
			}

			warning.Println("💥 Dropping database...")

			// Stop services first
			if e := ctx.RunMake("dev-stop"); e != nil {
				errColor.Printf("Failed to stop services: %v\n", e)
			}

			// Drop volumes
			if e := ctx.RunCommand("docker", "compose", "-f",
				ctx.Path("deployments", "docker", "docker-compose.yml"),
				"down", "-v"); e != nil {
				errColor.Printf("Failed to drop volumes: %v\n", e)
				return e
			}

			warning.Println("✅ Database dropped")
			return nil
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation")

	return cmd
}
