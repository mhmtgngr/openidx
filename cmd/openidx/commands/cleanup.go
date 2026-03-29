package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

// NewCleanupCommand creates the cleanup command
func NewCleanupCommand() *cobra.Command {
	var volumes, force bool

	cmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Clean up development environment",
		Long: `Stop and clean up all development resources.

This stops all containers, removes volumes (with --volumes flag),
and cleans up temporary files.`,
		Aliases: []string{"clean", "down"},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, errColor, warning, _, _ := ctx.GetColors()

			if !force {
				warning.Println("⚠️  This will stop all services and remove containers")
				if volumes {
					warning.Println("   Data volumes will also be deleted!")
				}
				fmt.Print("\nContinue? [y/N] ")
				var response string
				fmt.Scanln(&response)
				if response != "y" && response != "Y" {
					fmt.Println("Aborted")
					return nil
				}
			}

			success.Println("🧹 Cleaning up development environment...")

			// Stop and remove containers
			if e := ctx.RunMake("dev-stop"); e != nil {
				errColor.Printf("Failed to stop services: %v\n", e)
			}

			if volumes {
				warning.Println("💾 Removing volumes...")
				if e := ctx.RunCommand("docker", "compose",
					"-f", ctx.Path("deployments", "docker", "docker-compose.yml"),
					"down", "-v"); e != nil {
					errColor.Printf("Failed to remove volumes: %v\n", e)
				}
			}

			// Clean build artifacts
			success.Println("🧹 Cleaning build artifacts...")
			if e := ctx.RunMake("clean"); e != nil {
				errColor.Printf("Failed to clean build artifacts: %v\n", e)
			}

			// Remove orphaned containers
			if e := ctx.RunCommand("docker", "compose",
				"-f", ctx.Path("deployments", "docker", "docker-compose.yml"),
				"down", "--remove-orphans"); e != nil {
				errColor.Printf("Failed to remove orphans: %v\n", e)
			}

			success.Println("✅ Cleanup complete")
			return nil
		},
	}

	cmd.Flags().BoolVarP(&volumes, "volumes", "v", false, "Also remove data volumes")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation")

	return cmd
}

// NewPurgeCommand creates the purge command
func NewPurgeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "purge",
		Short: "Completely remove OpenIDX from the system",
		Long: `Remove all OpenIDX containers, images, volumes, networks, and build artifacts.

Use with extreme caution - this deletes all data!`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			warning, _, _, _, _ := ctx.GetColors()

			warning.Println("⚠️  ⚠️  ⚠️  DANGER ZONE ⚠️  ⚠️  ⚠️")
			warning.Println("This will COMPLETELY remove OpenIDX from your system:")
			warning.Println("  - All containers will be stopped and removed")
			warning.Println("  - All Docker images will be removed")
			warning.Println("  - All volumes will be deleted (DATA LOSS!)")
			warning.Println("  - All networks will be removed")
			warning.Println("  - All build artifacts will be deleted")
			warning.Println("")
			warning.Println("There is NO undo for this operation!")
			fmt.Println()

			// Double confirmation
			fmt.Print("Type 'PURGE' to confirm: ")
			var response string
			fmt.Scanln(&response)
			if response != "PURGE" {
				fmt.Println("Aborted")
				return nil
			}

			fmt.Print("\nAre you REALLY sure? [yes/NO] ")
			fmt.Scanln(&response)
			if response != "yes" {
				fmt.Println("Aborted")
				return nil
			}

			warning.Println("💀 Purging OpenIDX...")

			// Stop everything
			ctx.RunCommand("docker", "compose",
				"-f", ctx.Path("deployments", "docker", "docker-compose.yml"),
				"down", "-v", "--remove-orphans")

			// Remove images
			ctx.RunCommand("sh", "-c", "docker images openidx* --format '{{.ID}}' 2>/dev/null | xargs -r docker rmi -f 2>/dev/null || true")

			// Clean artifacts
			ctx.RunMake("clean")

			warning.Println("✅ Purge complete")
			fmt.Println("\nTo reinstall OpenIDX, run: make deps && openidx dev")

			return nil
		},
	}

	return cmd
}

// NewPruneCommand creates the prune command
func NewPruneCommand() *cobra.Command {
	var all bool

	cmd := &cobra.Command{
		Use:   "prune",
		Short: "Prune unused Docker resources",
		Long: `Remove unused Docker containers, networks, and images.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, _, warning, _, _ := ctx.GetColors()

			warning.Println("🧹 Pruning unused Docker resources...")

			if all {
				warning.Println("⚠️  This will remove all unused Docker data")
			}

			// Prune containers
			success.Println("Pruning containers...")
			ctx.RunCommand("docker", "container", "prune", "-f")

			// Prune networks
			success.Println("Pruning networks...")
			ctx.RunCommand("docker", "network", "prune", "-f")

			// Prune images
			if all {
				warning.Println("Pruning images...")
				ctx.RunCommand("docker", "image", "prune", "-a", "-f")
			} else {
				success.Println("Pruning dangling images...")
				ctx.RunCommand("docker", "image", "prune", "-f")
			}

			// Prune volumes
			if all {
				warning.Println("Pruning volumes...")
				ctx.RunCommand("docker", "volume", "prune", "-f")
			}

			success.Println("✅ Prune complete")
			return nil
		},
	}

	cmd.Flags().BoolVarP(&all, "all", "a", false, "Prune all unused resources including volumes and non-dangling images")

	return cmd
}

// NewResetCommand creates the reset command
func NewResetCommand() *cobra.Command {
	var hard bool

	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Reset development environment",
		Long: `Reset the development environment to a clean state.

This stops services, removes containers, and optionally resets the database.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, errColor, warning, _, _ := ctx.GetColors()

			warning.Println("🔄 Resetting development environment...")

			// Stop services
			success.Println("Stopping services...")
			if e := ctx.RunMake("dev-stop"); e != nil {
				errColor.Printf("Failed to stop services: %v\n", e)
			}

			if hard {
				// Remove volumes
				warning.Println("Removing data volumes...")
				if e := ctx.RunCommand("docker", "compose",
					"-f", ctx.Path("deployments", "docker", "docker-compose.yml"),
					"down", "-v"); e != nil {
					errColor.Printf("Failed to remove volumes: %v\n", e)
				}
			}

			// Clean artifacts
			success.Println("Cleaning build artifacts...")
			if e := ctx.RunMake("clean"); e != nil {
				errColor.Printf("Failed to clean: %v\n", e)
			}

			success.Println("✅ Reset complete")
			fmt.Println("\nRun 'openidx dev' to start fresh")

			return nil
		},
	}

	cmd.Flags().BoolVarP(&hard, "hard", "H", false, "Hard reset - also remove data volumes")

	return cmd
}

// NewCacheClearCommand creates the cache-clear command
func NewCacheClearCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cache-clear",
		Short: "Clear various caches",
		Long: `Clear Go build cache, module cache, npm cache, etc.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, _, _, _, _ := ctx.GetColors()

			success.Println("🧹 Clearing caches...")

			// Go build cache
			success.Println("Clearing Go build cache...")
			ctx.RunCommand("go", "clean", "-cache")

			// Go module cache
			success.Println("Clearing Go module cache...")
			ctx.RunCommand("go", "clean", "-modcache")

			// Test cache
			success.Println("Clearing Go test cache...")
			ctx.RunCommand("go", "clean", "-testcache")

			// NPM cache
			success.Println("Clearing npm cache...")
			ctx.RunCommandInDir(ctx.Path("web", "admin-console"), "npm", "cache", "clean", "--force")

			// Docker build cache
			success.Println("Clearing Docker build cache...")
			ctx.RunCommand("docker", "builder", "prune", "-f")

			success.Println("✅ Caches cleared")
			return nil
		},
	}

	return cmd
}
