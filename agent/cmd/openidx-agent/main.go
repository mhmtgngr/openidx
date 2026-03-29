package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/agent"
	"github.com/openidx/openidx/agent/internal/transport"
)

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

		client := transport.NewClient(server, "")

		resp, err := client.Enroll(token)
		if err != nil {
			return fmt.Errorf("enrollment failed: %w", err)
		}

		cfg := &agent.AgentConfig{
			ServerURL:  server,
			AgentID:    resp.AgentID,
			DeviceID:   resp.DeviceID,
			AuthToken:  resp.AuthToken,
			EnrolledAt: time.Now().UTC().Format(time.RFC3339),
		}

		if err := cfg.Save(configDir); err != nil {
			return fmt.Errorf("saving agent config: %w", err)
		}

		fmt.Printf("Enrollment successful!\n")
		fmt.Printf("  Server:    %s\n", server)
		fmt.Printf("  Agent ID:  %s\n", resp.AgentID)
		fmt.Printf("  Device ID: %s\n", resp.DeviceID)
		fmt.Printf("  Config:    %s\n", configDir)

		logger.Info("enrollment complete",
			zap.String("agent_id", resp.AgentID),
			zap.String("device_id", resp.DeviceID),
		)

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

func init() {
	// Persistent flags available to all subcommands.
	rootCmd.PersistentFlags().StringVar(&configDir, "config-dir", "/etc/openidx-agent",
		"directory for agent configuration and credentials")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false,
		"enable verbose (debug) logging")

	// enroll-specific flags.
	enrollCmd.Flags().String("token", "", "one-time enrollment token (required)")
	enrollCmd.Flags().String("server", "https://openidx.example.com", "OpenIDX server URL")
	_ = enrollCmd.MarkFlagRequired("token")

	rootCmd.AddCommand(enrollCmd)
	rootCmd.AddCommand(runCmd)
}
