package commands

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/spf13/cobra"
)

// NewSeedCommand creates the seed command
func NewSeedCommand() *cobra.Command {
	var dbURL string

	cmd := &cobra.Command{
		Use:   "seed",
		Short: "Seed database with test data",
		Long: `Populate the database with test data for development.

This creates sample users, roles, policies, and other data for testing
the application.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, errColor, _, _, _ := ctx.GetColors()

			// Get database URL
			if dbURL == "" {
				dbURL = os.Getenv("DATABASE_URL")
			}
			if dbURL == "" {
				return fmt.Errorf("DATABASE_URL environment variable is required")
			}

			// Verify database connection
			if e := verifyDBConnection(dbURL); e != nil {
				errColor.Printf("Cannot connect to database: %v\n", e)
				return e
			}

			success.Println("🌱 Seeding database with test data...")

			// Run seed script
			seedScript := ctx.Path("scripts", "seed.sh")
			if ctx.Exists(seedScript) {
				if e := ctx.RunCommand(seedScript); e != nil {
					errColor.Printf("Seed script failed: %v\n", e)
					return e
				}
			} else {
				// Fallback to SQL file
				seedFile := ctx.Path("migrations", "010_seed_data.up.sql")
				if ctx.Exists(seedFile) {
					if e := runSQLFile(ctx, dbURL, seedFile); e != nil {
						errColor.Printf("Failed to run seed file: %v\n", e)
						return e
					}
				} else {
					success.Println("No seed data found (skipping)")
				}
			}

			success.Println("✅ Database seeded")
			printSeedData()
			return nil
		},
	}

	cmd.Flags().StringVar(&dbURL, "db-url", "", "Database URL (defaults to DATABASE_URL env var)")

	return cmd
}

func runSQLFile(ctx *CommandContext, dbURL, file string) error {
	// Read SQL file
	sql, err := os.ReadFile(file)
	if err != nil {
		return err
	}

	// Connect to database
	ctxDB, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	conn, err := pgx.Connect(ctxDB, dbURL)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())

	// Execute SQL
	_, err = conn.Exec(context.Background(), string(sql))
	return err
}

func printSeedData() {
	fmt.Println("\n📋 Seed data created:")
	fmt.Println("   Admin user:     admin@openidx.local / admin123")
	fmt.Println("   Test user:      user@openidx.local / user123")
	fmt.Println("   Test roles:     Admin, User, Auditor")
	fmt.Println("   Test policies:  Default access policies")
}

const dbTimeout = 30 * 1000000000 // 30 seconds in nanoseconds

// NewSeedListCommand creates the seed-list command
func NewSeedListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "seed-list",
		Short: "List available seed datasets",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			_, _, _, _, header := ctx.GetColors()

			header.Println("\nAvailable Seed Datasets:")

			rows := [][]string{
				{"users", "Sample users (admin, test, regular)"},
				{"roles", "Default roles (Admin, User, Auditor)"},
				{"policies", "Sample access policies"},
				{"applications", "Test applications"},
				{"full", "Complete seed data set"},
			}

			fmt.Print(FormatTable([]string{"Dataset", "Description"}, rows))
			fmt.Println("\nUsage: openidx seed [dataset]")

			return nil
		},
	}

	return cmd
}

// NewSeedResetCommand creates the seed-reset command
func NewSeedResetCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "seed-reset",
		Short: "Reset and reseed database",
		Long: `Drop all data and reseed the database from scratch.

This is useful for resetting the development environment to a clean state.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, errColor, warning, _, _ := ctx.GetColors()

			warning.Println("⚠️  This will delete all data and reseed the database")
			fmt.Print("Continue? [y/N] ")
			var response string
			fmt.Scanln(&response)
			if response != "y" && response != "Y" {
				fmt.Println("Aborted")
				return nil
			}

			// Reset migrations
			success.Println("🔄 Resetting migrations...")
			if e := runMigrate(ctx, "", "reset", 0); e != nil {
				errColor.Printf("Migration reset failed: %v\n", e)
				return e
			}

			// Seed database
			success.Println("🌱 Seeding database...")
			if e := NewSeedCommand().RunE(cmd, args); e != nil {
				return e
			}

			success.Println("✅ Database reset and seeded")
			return nil
		},
	}

	return cmd
}
