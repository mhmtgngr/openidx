package commands

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

// NewLogsCommand creates the logs command
func NewLogsCommand() *cobra.Command {
	var follow, all bool
	var tail int
	var since string

	cmd := &cobra.Command{
		Use:   "logs [service]",
		Short: "View service logs",
		Long: `View logs from running services.

If no service is specified, shows logs from all services.

Services: identity, governance, provisioning, audit, admin, oauth, gateway, access`,
		Aliases: []string{"log"},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, errColor, _, _, _ := ctx.GetColors()

			service := ""
			if len(args) > 0 {
				service = expandServiceName(args[0])
			}

			if all {
				service = ""
			}

			success.Printf("📋 Viewing logs%s...\n", getServiceLabel(service))

			// Use docker compose logs
			composeFile := ctx.Path("deployments", "docker", "docker-compose.yml")

			logArgs := []string{"-f", composeFile, "logs"}
			if follow {
				logArgs = append(logArgs, "-f")
			}
			if tail > 0 {
				logArgs = append(logArgs, "--tail", fmt.Sprintf("%d", tail))
			}
			if since != "" {
				logArgs = append(logArgs, "--since", since)
			}
			if service != "" {
				logArgs = append(logArgs, service)
			}

			// Run logs command
			logArgsFlat := []string{"compose"}
			logArgsFlat = append(logArgsFlat, logArgs...)
			logCmd := exec.Command("docker", logArgsFlat...)
			logCmd.Stdout = os.Stdout
			logCmd.Stderr = os.Stderr

			if err := logCmd.Run(); err != nil {
				errColor.Printf("Failed to view logs: %v\n", err)
				return err
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&follow, "follow", "f", true, "Follow log output")
	cmd.Flags().BoolVarP(&all, "all", "a", false, "Show logs from all services")
	cmd.Flags().IntVarP(&tail, "tail", "n", 100, "Number of lines to show")
	cmd.Flags().StringVar(&since, "since", "", "Show logs since timestamp (e.g., 10m, 1h)")

	// Add shell completion for services
	cmd.ValidArgsFunction = completeServices

	return cmd
}

func expandServiceName(name string) string {
	// Map short names to service names
	serviceMap := map[string]string{
		"identity":     "identity-service",
		"id":           "identity-service",
		"governance":   "governance-service",
		"gov":          "governance-service",
		"provisioning": "provisioning-service",
		"prov":         "provisioning-service",
		"audit":        "audit-service",
		"admin":        "admin-api",
		"admin-api":    "admin-api",
		"oauth":        "oauth-service",
		"gateway":      "gateway-service",
		"access":       "access-service",
		"postgres":     "postgres",
		"db":           "postgres",
		"redis":        "redis",
		"elasticsearch": "elasticsearch",
		"es":           "elasticsearch",
	}

	if expanded, ok := serviceMap[strings.ToLower(name)]; ok {
		return expanded
	}
	return name
}

func getServiceLabel(service string) string {
	if service == "" {
		return ""
	}
	return fmt.Sprintf(" for %s", service)
}

// NewLogsFilterCommand creates the logs-filter command
func NewLogsFilterCommand() *cobra.Command {
	var level, pattern string
	var follow bool

	cmd := &cobra.Command{
		Use:   "logs-filter [service]",
		Short: "Filter logs by level or pattern",
		Long: `View and filter logs by log level or text pattern.

Examples:
  openidx logs-filter identity --level error
  openidx logs-filter --pattern "ERROR|WARN"
  openidx logs-filter --pattern "user.*login"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, errColor, _, _, _ := ctx.GetColors()

			service := ""
			if len(args) > 0 {
				service = expandServiceName(args[0])
			}

			// Build filter pattern
			filterPattern := pattern
			if level != "" {
				levelPattern := fmt.Sprintf("(?i)%s", strings.ToUpper(level))
				if filterPattern != "" {
					filterPattern = fmt.Sprintf("(%s|%s)", filterPattern, levelPattern)
				} else {
					filterPattern = levelPattern
				}
			}

			success.Printf("🔍 Filtering logs%s by: %s\n", getServiceLabel(service), filterPattern)

			// Get logs
			logs, err := getServiceLogs(ctx, service, false)
			if err != nil {
				errColor.Printf("Failed to get logs: %v\n", err)
				return err
			}

			// Filter and print
			re, err := regexp.Compile(filterPattern)
			if err != nil {
				errColor.Printf("Invalid pattern: %v\n", err)
				return err
			}

			scanner := bufio.NewScanner(strings.NewReader(logs))
			for scanner.Scan() {
				line := scanner.Text()
				if re.MatchString(line) {
					fmt.Println(line)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&level, "level", "l", "", "Filter by log level (debug, info, warn, error)")
	cmd.Flags().StringVarP(&pattern, "pattern", "p", "", "Filter by regex pattern")
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow log output")

	return cmd
}

func getServiceLogs(ctx *CommandContext, service string, follow bool) (string, error) {
	composeFile := ctx.Path("deployments", "docker", "docker-compose.yml")

	args := []string{"compose", "-f", composeFile, "logs"}
	if follow {
		args = append(args, "-f")
	}
	args = append(args, "--no-log-prefix")
	if service != "" {
		args = append(args, service)
	}

	cmd := exec.Command("docker", args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// NewLogsErrorsCommand creates the logs-errors command
func NewLogsErrorsCommand() *cobra.Command {
	var follow bool

	cmd := &cobra.Command{
		Use:   "logs-errors [service]",
		Short: "Show only error logs",
		Long:  `View only error and warning logs from services.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, errColor, _, _, _ := ctx.GetColors()

			service := ""
			if len(args) > 0 {
				service = expandServiceName(args[0])
			}

			success.Printf("🚨 Viewing error logs%s...\n", getServiceLabel(service))

			logs, err := getServiceLogs(ctx, service, follow)
			if err != nil {
				errColor.Printf("Failed to get logs: %v\n", err)
				return err
			}

			// Filter for errors and warnings
			scanner := bufio.NewScanner(strings.NewReader(logs))
			errorCount := 0
			warnCount := 0

			for scanner.Scan() {
				line := scanner.Text()
				lower := strings.ToLower(line)
				if strings.Contains(lower, "error") || strings.Contains(lower, "fatal") || strings.Contains(lower, "panic") {
					fmt.Println(line)
					errorCount++
				} else if strings.Contains(lower, "warn") {
					fmt.Println(line)
					warnCount++
				}
			}

			fmt.Printf("\nFound %d errors and %d warnings\n", errorCount, warnCount)

			return nil
		},
	}

	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow log output")

	return cmd
}

// NewLogsStatsCommand creates the logs-stats command
func NewLogsStatsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logs-stats [service]",
		Short: "Show log statistics",
		Long:  `Show statistics about logs including error counts, warnings, etc.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, errColor, _, _, _ := ctx.GetColors()

			service := ""
			if len(args) > 0 {
				service = expandServiceName(args[0])
			}

			s := startSpinner("Analyzing logs...")
			defer s.Stop()

			logs, err := getServiceLogs(ctx, service, false)
			if err != nil {
				errColor.Printf("Failed to get logs: %v\n", err)
				return err
			}

			// Analyze logs
			stats := analyzeLogs(logs)

			s.Stop()

			success.Println("\n📊 Log Statistics:")

			rows := [][]string{
				{"Total Lines", fmt.Sprintf("%d", stats.totalLines)},
				{"Errors", fmt.Sprintf("%d", stats.errors)},
				{"Warnings", fmt.Sprintf("%d", stats.warnings)},
				{"Info Messages", fmt.Sprintf("%d", stats.info)},
				{"Debug Messages", fmt.Sprintf("%d", stats.debug)},
			}

			fmt.Print(FormatTable([]string{"Metric", "Count"}, rows))

			if stats.errors > 0 || stats.warnings > 0 {
				errColor.Printf("\n⚠️  Found %d errors and %d warnings\n", stats.errors, stats.warnings)
			} else {
				success.Println("\n✅ No errors or warnings found")
			}

			return nil
		},
	}

	return cmd
}

type logStats struct {
	totalLines int
	errors     int
	warnings   int
	info       int
	debug      int
}

func analyzeLogs(logs string) logStats {
	stats := logStats{}
	scanner := bufio.NewScanner(strings.NewReader(logs))

	for scanner.Scan() {
		line := scanner.Text()
		stats.totalLines++

		lower := strings.ToLower(line)
		switch {
		case strings.Contains(lower, "error") || strings.Contains(lower, "fatal") || strings.Contains(lower, "panic"):
			stats.errors++
		case strings.Contains(lower, "warn"):
			stats.warnings++
		case strings.Contains(lower, "info"):
			stats.info++
		case strings.Contains(lower, "debug"):
			stats.debug++
		}
	}

	return stats
}
