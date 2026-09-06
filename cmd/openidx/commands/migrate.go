package commands

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/spf13/cobra"

	"github.com/openidx/openidx/internal/migrations"
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

// nextMigrationVersion is one past the highest version the registry really
// carries. It reads the registry rather than a directory listing: the registry
// is what every service applies, and it is the only thing that knows how far
// the schema has actually got.
func nextMigrationVersion() int {
	highest := 0
	for _, m := range migrations.All() {
		if m.Version > highest {
			highest = m.Version
		}
	}
	return highest + 1
}

// sqlConstIdent turns a migration name into the Go identifier its SQL
// constants are declared under: "add_widget_table" -> "addWidgetTable".
func sqlConstIdent(name string) string {
	var b strings.Builder
	upperNext := false
	for _, r := range name {
		switch {
		case r == '_' || r == '-' || r == ' ' || r == '.':
			upperNext = b.Len() > 0
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			if upperNext {
				b.WriteRune(unicode.ToUpper(r))
				upperNext = false
			} else if b.Len() == 0 {
				b.WriteRune(unicode.ToLower(r))
			} else {
				b.WriteRune(r)
			}
		}
	}
	if b.Len() == 0 || (b.String()[0] >= '0' && b.String()[0] <= '9') {
		return "migration" + b.String()
	}
	return b.String()
}

// createMigration writes the file the product actually applies.
//
// It used to write migrations/NNN_<name>.up.sql and .down.sql — a numbered
// pair in a directory nothing read. Every service applies the registry in
// internal/migrations: Go string constants in sql_v<N>.go, listed in
// loader.go. The loose SQL tree stopped tracking that registry at 52 of 172
// migrations and nobody noticed, precisely because nothing read it. A
// contributor who followed this command wrote SQL that never ran, and then
// watched `openidx migrate up` report success — it had applied the registry.
//
// So it now writes internal/migrations/sql_v<N>.go and prints the loader entry
// to add. Registering stays a deliberate edit rather than a generated append:
// loader.go is the list tools/orgscope derives the tenant-scope census from,
// and a machine appending to it is one bad merge away from reordering the
// schema.
func createMigration(ctx *CommandContext, name string) error {
	success, errColor, _, _, _ := ctx.GetColors()

	version := nextMigrationVersion()
	ident := sqlConstIdent(name)
	rel := filepath.Join("internal", "migrations", fmt.Sprintf("sql_v%d.go", version))
	path := ctx.Path("internal", "migrations", fmt.Sprintf("sql_v%d.go", version))

	if _, err := os.Stat(path); err == nil {
		errColor.Printf("%s already exists — v%d is taken; check internal/migrations/loader.go\n", rel, version)
		return fmt.Errorf("migration v%d already has a file at %s", version, rel)
	}

	body := fmt.Sprintf(`package migrations

// Migration v%d — %s.
//
// Say here what this migration changes and why the change is needed. A
// migration is the one place a schema decision is written down for good.
//
// Plain statements only, no DO $$ blocks: the migrator runs each statement in
// its own round trip. A table holding tenant data needs org_id, an index on
// it, a policy, and ENABLE + FORCE ROW LEVEL SECURITY — tools/orgscope fails
// the build for a table that carries org_id without the belt, and for a
// scoped table whose queries do not name it.
const %sUp = `+"`"+`
`+"`"+`

// The reverse of %sUp. Down migrations are run in tests, so this has to work.
const %sDown = `+"`"+`
`+"`"+`
`, version, name, ident, ident, ident)

	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		errColor.Printf("Failed to write %s: %v\n", rel, err)
		return err
	}

	success.Printf("✅ Created %s\n\n", rel)
	fmt.Printf("Now register it in internal/migrations/loader.go, after v%d:\n\n", version-1)
	fmt.Printf("\t\t{\n")
	fmt.Printf("\t\t\tVersion:     %d,\n", version)
	fmt.Printf("\t\t\tName:        %q,\n", name)
	fmt.Printf("\t\t\tDescription: \"\",\n")
	fmt.Printf("\t\t\tUpSQL:       %sUp,\n", ident)
	fmt.Printf("\t\t\tDownSQL:     %sDown,\n", ident)
	fmt.Printf("\t\t},\n\n")
	fmt.Println("Until it is in that list, nothing applies it.")

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
