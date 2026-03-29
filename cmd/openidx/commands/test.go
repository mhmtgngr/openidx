package commands

import (
	"fmt"
	"strings"

	"github.com/briandowns/spinner"
	"github.com/spf13/cobra"
)

// NewTestCommand creates the test command
func NewTestCommand() *cobra.Command {
	var coverage, verbose, race bool
	var run string
	var timeout int

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Run tests",
		Long: `Run tests for the OpenIDX project.

Supports unit tests, integration tests, and coverage reports.`,
		Aliases: []string{"t"},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, errColor, _, _, _ := ctx.GetColors()

			success.Println("🧪 Running tests...")

			// Build test command
			args = []string{"test"}
			if verbose {
				args = append(args, "-v")
			}
			if race {
				args = append(args, "-race")
			}
			if coverage {
				args = append(args, "-coverprofile=coverage.out", "-covermode=atomic")
			}
			if run != "" {
				args = append(args, fmt.Sprintf("-run=%s", run))
			}
			args = append(args, "./...")
			if timeout > 0 {
				args = append(args, fmt.Sprintf("-timeout=%dm", timeout))
			}

			// Run tests
			if e := ctx.RunCommand("go", args...); e != nil {
				errColor.Printf("Tests failed: %v\n", e)
				return e
			}

			if coverage {
				success.Println("📊 Generating coverage report...")
				if e := ctx.RunCommand("go", "tool", "cover", "-html=coverage.out", "-o", "coverage.html"); e != nil {
					errColor.Printf("Failed to generate coverage report: %v\n", e)
					return e
				}
				success.Println("✅ Coverage report: coverage.html")
			}

			success.Println("✅ Tests passed")
			return nil
		},
	}

	cmd.Flags().BoolVarP(&coverage, "coverage", "c", false, "Generate coverage report")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	cmd.Flags().BoolVar(&race, "race", false, "Enable race detection")
	cmd.Flags().StringVarP(&run, "run", "r", "", "Run only tests matching regex")
	cmd.Flags().IntVarP(&timeout, "timeout", "t", 10, "Test timeout in minutes")

	return cmd
}

// NewTestUnitCommand creates the test-unit command
func NewTestUnitCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test-unit",
		Short: "Run unit tests only",
		Long:  `Run unit tests excluding integration tests.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, errColor, _, _, _ := ctx.GetColors()

			success.Println("🧪 Running unit tests...")

			// Exclude integration tests
			if e := ctx.RunCommand("go", "test", "-v", "-race", "-cover", "./..."); e != nil {
				errColor.Printf("Unit tests failed: %v\n", e)
				return e
			}

			success.Println("✅ Unit tests passed")
			return nil
		},
	}

	return cmd
}

// NewTestIntegrationCommand creates the test-integration command
func NewTestIntegrationCommand() *cobra.Command {
	var verbose bool

	cmd := &cobra.Command{
		Use:   "test-integration",
		Short: "Run integration tests",
		Long: `Run integration tests.

Note: Integration tests require infrastructure services to be running.
Use 'openidx dev --infra' to start required services.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, errColor, warning, _, _ := ctx.GetColors()

			// Check if infrastructure is running
			if !isInfraRunning(ctx) {
				warning.Println("⚠️  Infrastructure services may not be running")
				warning.Println("   Run 'openidx dev --infra' first")
			}

			success.Println("🔗 Running integration tests...")

			args = []string{"test", "-tags=integration"}
			if verbose {
				args = append(args, "-v")
			}
			args = append(args, "./test/integration/...")

			if e := ctx.RunCommand("go", args...); e != nil {
				errColor.Printf("Integration tests failed: %v\n", e)
				return e
			}

			success.Println("✅ Integration tests passed")
			return nil
		},
	}

	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	return cmd
}

// NewTestE2ECommand creates the test-e2e command
func NewTestE2ECommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test-e2e",
		Short: "Run end-to-end tests",
		Long: `Run end-to-end tests using the test suite.

Note: E2E tests require the full development environment running.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, errColor, warning, _, _ := ctx.GetColors()

			// Check if services are running
			if !areServicesRunning(ctx) {
				warning.Println("⚠️  Services may not be running")
				warning.Println("   Run 'openidx dev' first")
			}

			success.Println("🎭 Running end-to-end tests...")

			if e := ctx.RunMake("test-e2e"); e != nil {
				errColor.Printf("E2E tests failed: %v\n", e)
				return e
			}

			success.Println("✅ E2E tests passed")
			return nil
		},
	}

	return cmd
}

// isInfraRunning checks if infrastructure services are running
func isInfraRunning(ctx *CommandContext) bool {
	// Simple check: try to connect to common ports
	output, _ := ctx.RunCommandOutput("docker", "ps", "--filter", "name=openidx", "--format", "{{.Names}}")
	return strings.Contains(output, "postgres") || strings.Contains(output, "redis")
}

// areServicesRunning checks if application services are running
func areServicesRunning(ctx *CommandContext) bool {
	output, _ := ctx.RunCommandOutput("docker", "ps", "--filter", "name=openidx", "--format", "{{.Names}}")
	return strings.Contains(output, "identity") || strings.Contains(output, "oauth")
}

// NewBenchCommand creates the benchmark command
func NewBenchCommand() *cobra.Command {
	var bench string

	cmd := &cobra.Command{
		Use:   "bench",
		Short: "Run benchmarks",
		Long:  `Run benchmark tests to measure performance.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, errColor, _, _, _ := ctx.GetColors()

			success.Println("📊 Running benchmarks...")

			args = []string{"test", "-bench=.", "-benchmem"}
			if bench != "" {
				args = append(args, fmt.Sprintf("-run=^$"), fmt.Sprintf("-bench=%s", bench))
			}
			args = append(args, "./...")

			if e := ctx.RunCommand("go", args...); e != nil {
				errColor.Printf("Benchmarks failed: %v\n", e)
				return e
			}

			success.Println("✅ Benchmarks complete")
			return nil
		},
	}

	cmd.Flags().StringVarP(&bench, "bench", "b", ".", "Benchmark regex pattern")

	return cmd
}

// NewTestWatchCommand creates the test-watch command
func NewTestWatchCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test-watch",
		Short: "Watch files and re-run tests",
		Long: `Run tests continuously when files change.

This requires 'gotestsum' to be installed.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, errColor, _, _, _ := ctx.GetColors()

			// Check for gotestsum
			if _, err := ctx.RunCommandOutput("which", "gotestsum"); err != nil {
				errColor.Println("❌ 'gotestsum' not found")
				errColor.Println("   Install with: go install gotest.tools/gotestsum@latest")
				return err
			}

			success.Println("🔄 Watching files and running tests...")

			// Run gotestsum with watch mode
			if e := ctx.RunCommand("gotestsum", "--format=short-verbose", "--watch", "./..."); e != nil {
				errColor.Printf("Watch mode failed: %v\n", e)
				return e
			}

			return nil
		},
	}

	return cmd
}

// Spinner helper for long-running operations
func startSpinner(message string) *spinner.Spinner {
	return StartSpinner(message)
}
