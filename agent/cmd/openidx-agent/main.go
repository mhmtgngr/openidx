package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/agent"
	"github.com/openidx/openidx/agent/internal/enrollment"
	"github.com/openidx/openidx/agent/internal/winservice"
)

// defaultConfigDir returns the platform-appropriate config/credential directory:
// %ProgramData%\OpenIDX\agent on Windows, /etc/openidx-agent elsewhere.
func defaultConfigDir() string {
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "OpenIDX", "agent")
	}
	return "/etc/openidx-agent"
}

// Version information injected via ldflags at build time.
var (
	Version   = "dev"
	BuildTime = "unknown"
	Commit    = "none"
)

var (
	configDir string
	verbose   bool
	logger    *zap.Logger
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "openidx-agent",
	Short: "OpenIDX endpoint agent",
	Long: `openidx-agent is the endpoint agent for the OpenIDX Zero Trust Access Platform.
It enrolls devices, enforces access policies, and reports health status back to the platform.`,
	Version: fmt.Sprintf("%s (commit: %s, built: %s)", Version, Commit, BuildTime),
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		var err error
		if verbose {
			logger, err = zap.NewDevelopment()
		} else {
			logger, err = zap.NewProduction()
		}
		if err != nil {
			return fmt.Errorf("initializing logger: %w", err)
		}
		return nil
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		if logger != nil {
			_ = logger.Sync()
		}
	},
}

var enrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Enroll this endpoint with an OpenIDX server",
	Long: `Enroll this endpoint with an OpenIDX server using a one-time enrollment token.
The agent will contact the specified server, validate the token, and store the
resulting credentials in the config directory for subsequent runs.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		token, _ := cmd.Flags().GetString("token")
		server, _ := cmd.Flags().GetString("server")

		logger.Info("enrolling agent",
			zap.String("server", server),
			zap.String("config_dir", configDir),
		)

		result, err := enrollment.Enroll(logger, server, token, configDir)
		if err != nil {
			return fmt.Errorf("enrollment failed: %w", err)
		}

		cfg := result.AgentConfig

		fmt.Printf("Enrollment successful!\n")
		fmt.Printf("  Server:    %s\n", cfg.ServerURL)
		fmt.Printf("  Agent ID:  %s\n", cfg.AgentID)
		fmt.Printf("  Device ID: %s\n", cfg.DeviceID)
		fmt.Printf("  Config:    %s\n", configDir)
		if result.ZitiIdentity != "" {
			fmt.Printf("  Ziti:      %s\n", result.ZitiIdentity)
		}

		return nil
	},
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the endpoint agent",
	Long: `Start the OpenIDX endpoint agent. The agent will load its enrollment credentials
from the config directory, establish a secure connection to the OpenIDX server, and
begin enforcing access policies and reporting health checks.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		logger.Info("starting agent",
			zap.String("config_dir", configDir),
		)

		a, err := agent.NewAgent(logger, configDir)
		if err != nil {
			return fmt.Errorf("creating agent: %w", err)
		}

		a.RegisterBuiltinChecks()
		a.LoadPlugins()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			sig := <-sigCh
			logger.Info("received signal, shutting down", zap.String("signal", sig.String()))
			cancel()
		}()

		if err := a.Run(ctx); err != nil && err != context.Canceled {
			return fmt.Errorf("agent run failed: %w", err)
		}

		return nil
	},
}

// serviceCmd groups Windows-service lifecycle subcommands.
var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Manage the OpenIDX agent Windows service",
	Long:  "Install, uninstall, or run the OpenIDX agent as a Windows service (Windows only).",
}

var serviceRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run under the Windows Service control manager (invoked by the SCM)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return winservice.Run(logger, configDir)
	},
}

var serviceInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install and start the OpenIDX agent service (LocalSystem, auto-start)",
	RunE: func(cmd *cobra.Command, args []string) error {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("resolving executable path: %w", err)
		}
		if err := winservice.Install(exe, configDir); err != nil {
			return err
		}
		logger.Info("service installed", zap.String("name", winservice.ServiceName))
		return nil
	},
}

var serviceUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Stop and remove the OpenIDX agent service",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := winservice.Uninstall(); err != nil {
			return err
		}
		logger.Info("service uninstalled", zap.String("name", winservice.ServiceName))
		return nil
	},
}

func init() {
	// Persistent flags available to all subcommands.
	rootCmd.PersistentFlags().StringVar(&configDir, "config-dir", defaultConfigDir(),
		"directory for agent configuration and credentials")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false,
		"enable verbose (debug) logging")

	// enroll-specific flags.
	enrollCmd.Flags().String("token", "", "one-time enrollment token (required)")
	enrollCmd.Flags().String("server", "https://openidx.example.com", "OpenIDX server URL")
	_ = enrollCmd.MarkFlagRequired("token")

	serviceCmd.AddCommand(serviceRunCmd)
	serviceCmd.AddCommand(serviceInstallCmd)
	serviceCmd.AddCommand(serviceUninstallCmd)

	rootCmd.AddCommand(enrollCmd)
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(serviceCmd)
}
