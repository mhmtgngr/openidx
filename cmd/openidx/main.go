// Package main is the entry point for the OpenIDX developer CLI tool
// This tool provides a unified interface for common development tasks
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/openidx/openidx/cmd/openidx/commands"
	"github.com/spf13/cobra"
)

var (
	// Version information (set by build)
	Version   = "dev"
	BuildTime = "unknown"
	Commit    = "unknown"
)

func main() {
	// Get the root directory of the project
	rootDir := getProjectRoot()

	// Create root command
	rootCmd := &cobra.Command{
		Use:   "openidx",
		Short: "OpenIDX Developer CLI Tool",
		Long: `OpenIDX is an open-source Zero Trust Access Platform (ZTAP).

The developer CLI tool provides a unified interface for common development tasks
including building, testing, running migrations, and managing the development environment.`,
		Version: fmt.Sprintf("%s (built %s, commit %s)", Version, BuildTime, Commit),
	}

	// Persistent flags
	rootCmd.PersistentFlags().StringP("dir", "d", rootDir, "Project root directory")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().Bool("no-color", false, "Disable colored output")

	// Add commands
	rootCmd.AddCommand(
		commands.NewDevCommand(),
		commands.NewDevStopCommand(),
		commands.NewBuildCommand(),
		commands.NewCleanCommand(),
		commands.NewInstallCommand(),
		commands.NewDockerCommand(),
		commands.NewGenerateCommand(),
		commands.NewLintCommand(),
		commands.NewTestCommand(),
		commands.NewTestUnitCommand(),
		commands.NewTestIntegrationCommand(),
		commands.NewTestE2ECommand(),
		commands.NewBenchCommand(),
		commands.NewTestWatchCommand(),
		commands.NewDbCommand(),
		commands.NewSeedCommand(),
		commands.NewLogsCommand(),
		commands.NewLogsFilterCommand(),
		commands.NewLogsErrorsCommand(),
		commands.NewLogsStatsCommand(),
		commands.NewStatusCommand(),
		commands.NewHealthCheckCommand(),
		commands.NewTopCommand(),
		commands.NewCleanupCommand(),
		commands.NewPurgeCommand(),
		commands.NewPruneCommand(),
		commands.NewResetCommand(),
		commands.NewCacheClearCommand(),
		commands.NewDoctorCommand(),
		commands.NewFixCommand(),
		commands.NewPathsCommand(),
		commands.NewConfigCommand(),
		commands.NewVersionCommand(),
		commands.NewInfoCommand(),
		commands.NewUpdateCommand(),
		commands.NewCompletionCommand(),
		commands.NewInstallCompletionCommand(),
		commands.NewServicesCommand(),
	)

	// Execute
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// getProjectRoot finds the project root directory by looking for go.mod
func getProjectRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root
			return "."
		}
		dir = parent
	}
}

// GetVersionInfo returns version information
func GetVersionInfo() map[string]string {
	return map[string]string{
		"version":   Version,
		"buildTime": BuildTime,
		"commit":    Commit,
		"goVersion": runtime.Version(),
		"os":        runtime.GOOS,
		"arch":      runtime.GOARCH,
	}
}
