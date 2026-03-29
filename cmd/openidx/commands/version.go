package commands

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

// Version info set by build
var (
	CLIVersion   = "dev"
	CLIBuildTime = "unknown"
	CLICommit    = "unknown"
)

// NewVersionCommand creates the version command
func NewVersionCommand() *cobra.Command {
	var json, short bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Long: `Display version information for the OpenIDX CLI and related services.

This shows the CLI version, build information, and versions of
installed tools.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			_, _, _, info, header := ctx.GetColors()

			if json {
				printVersionJSON()
				return nil
			}

			if short {
				fmt.Println(CLIVersion)
				return nil
			}

			header.Println("📋 OpenIDX CLI")

			rows := [][]string{
				{"CLI Version", CLIVersion},
				{"Build Time", CLIBuildTime},
				{"Git Commit", CLICommit},
				{"Go Version", runtime.Version()},
				{"OS/Arch", fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)},
			}

			fmt.Print(FormatTable([]string{"Setting", "Value"}, rows))

			// Show service versions if services are running
			info.Println("\n💡 Run 'openidx status' to see service versions")

			return nil
		},
	}

	cmd.Flags().BoolVar(&json, "json", false, "Output in JSON format")
	cmd.Flags().BoolVar(&short, "short", false, "Show only version number")

	return cmd
}

func printVersionJSON() {
	fmt.Printf(`{
  "cli": {
    "version": "%s",
    "buildTime": "%s",
    "commit": "%s"
  },
  "runtime": {
    "goVersion": "%s",
    "os": "%s",
    "arch": "%s"
  }
}
`, CLIVersion, CLIBuildTime, CLICommit, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

// NewInfoCommand creates the info command
func NewInfoCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info",
		Short: "Show project information",
		Long:  `Display detailed information about the OpenIDX project.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			_, _, _, info, header := ctx.GetColors()

			header.Println("📖 About OpenIDX")

			info.Println("OpenIDX is an open-source Zero Trust Access Platform (ZTAP)")
			info.Println("that provides enterprise-grade Identity and Access Management.")
			fmt.Println()

			rows := [][]string{
				{"Description", "Zero Trust Access Platform"},
				{"Repository", "github.com/openidx/openidx"},
				{"License", "MIT"},
				{"Documentation", "docs.openidx.io"},
				{"Go Version", "1.24+"},
				{"Node Version", "18+"},
			}

			fmt.Print(FormatTable([]string{"Setting", "Value"}, rows))

			fmt.Println("\n🔗 Links:")
			info.Println("   Website:       https://openidx.io")
			info.Println("   GitHub:        https://github.com/openidx/openidx")
			info.Println("   Documentation: https://docs.openidx.io")
			info.Println("   Community:     https://discord.gg/openidx")

			fmt.Println("\n🙏 Acknowledgments:")
			info.Println("   Built with Gin, React, and amazing open-source tools")

			return nil
		},
	}

	return cmd
}

// NewUpdateCommand creates the update command
func NewUpdateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update OpenIDX to the latest version",
		Long: `Update the OpenIDX CLI and project dependencies.

This will:
1. Pull latest changes from git
2. Update Go modules
3. Update npm dependencies
4. Rebuild the CLI`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, errColor, warning, _, _ := ctx.GetColors()

			warning.Println("⚠️  This will update OpenIDX to the latest version")
			fmt.Print("Continue? [y/N] ")
			var response string
			fmt.Scanln(&response)
			if response != "y" && response != "Y" {
				fmt.Println("Aborted")
				return nil
			}

			// Check for uncommitted changes
			output, _ := ctx.RunCommandOutput("git", "status", "--porcelain")
			if strings.TrimSpace(output) != "" {
				warning.Println("⚠️  You have uncommitted changes")
				fmt.Print("Continue anyway? [y/N] ")
				fmt.Scanln(&response)
				if response != "y" && response != "Y" {
					fmt.Println("Aborted")
					return nil
				}
			}

			// Pull latest changes
			success.Println("📥 Pulling latest changes...")
			if e := ctx.RunCommand("git", "pull"); e != nil {
				errColor.Printf("Failed to pull changes: %v\n", e)
				return e
			}

			// Update Go modules
			success.Println("📦 Updating Go modules...")
			if e := ctx.RunCommand("go", "mod", "download"); e != nil {
				errColor.Printf("Failed to download modules: %v\n", e)
			}
			if e := ctx.RunCommand("go", "mod", "tidy"); e != nil {
				errColor.Printf("Failed to tidy modules: %v\n", e)
			}

			// Update npm dependencies
			success.Println("📦 Updating npm dependencies...")
			if e := ctx.RunCommandInDir(ctx.Path("web", "admin-console"), "npm", "update"); e != nil {
				errColor.Printf("Failed to update npm dependencies: %v\n", e)
			}

			// Rebuild CLI
			success.Println("🔨 Rebuilding CLI...")
			if e := ctx.RunCommand("go", "build", "-o", ctx.Path("bin", "openidx"), ctx.Path("cmd", "openidx")); e != nil {
				errColor.Printf("Failed to rebuild CLI: %v\n", e)
				return e
			}

			success.Println("✅ Update complete!")
			fmt.Println("\nRun 'openidx doctor' to verify your environment")

			return nil
		},
	}

	return cmd
}
