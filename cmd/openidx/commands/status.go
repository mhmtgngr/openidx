package commands

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// ServiceStatus represents the status of a service
type ServiceStatus struct {
	Name     string
	Port     string
	URL      string
	Healthy  bool
	Response time.Duration
}

// NewStatusCommand creates the status command
func NewStatusCommand() *cobra.Command {
	var watch bool
	var interval int

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show service status",
		Long: `Show the status of all OpenIDX services.

Displays health check results, port bindings, and connection status for
all services.`,
		Aliases: []string{"ps", "health"},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)

			if watch {
				// Watch mode - refresh status every interval seconds
				ticker := time.NewTicker(time.Duration(interval) * time.Second)
				defer ticker.Stop()

				for {
					// Clear screen
					printStatus(ctx)
					select {
					case <-ticker.C:
						continue
					case <-time.After(100 * time.Millisecond):
						// Check for interrupt
					}
				}
			}

			return printStatus(ctx)
		},
	}

	cmd.Flags().BoolVarP(&watch, "watch", "w", false, "Watch mode - refresh status periodically")
	cmd.Flags().IntVarP(&interval, "interval", "i", 5, "Refresh interval for watch mode (seconds)")

	return cmd
}

func printStatus(ctx *CommandContext) error {
	success, errColor, warning, info, header := ctx.GetColors()

	// Clear screen in watch mode
	// fmt.Print("\033[H\033[2J")

	header.Println("\n╔════════════════════════════════════════════════════════════════╗")
	header.Println("║                  OpenIDX Service Status                       ║")
	header.Println("╚════════════════════════════════════════════════════════════════╝")

	// Check Docker containers
	dockerStatus, _ := ctx.RunCommandOutput("docker", "compose",
		"-f", ctx.Path("deployments", "docker", "docker-compose.yml"),
		"ps", "--format", "json")

	// Parse Docker status
	containers := parseDockerStatus(dockerStatus)

	// Check service health
	s := startSpinner("Checking service health...")
	defer s.Stop()

	services := checkAllServices()

	s.Stop()

	// Print container status
	header.Println("\n📦 Containers:")
	if len(containers) > 0 {
		rows := make([][]string, 0, len(containers))
		for _, c := range containers {
			statusIcon := "✓"
			if c.State != "running" {
				statusIcon = "✗"
			}
			rows = append(rows, []string{
				c.Name,
				fmt.Sprintf("%s %s", statusIcon, c.State),
				c.Ports,
				fmt.Sprintf("%s ago", formatUptime(c.Uptime)),
			})
		}
		fmt.Print(FormatTable([]string{"Container", "State", "Ports", "Uptime"}, rows))
	} else {
		warning.Println("  No containers running")
		warning.Println("  Run 'openidx dev' to start services")
	}

	// Print service health
	header.Println("\n🏥 Service Health:")

	allHealthy := true
	rows := make([][]string, 0, len(services))
	for _, svc := range services {
		status := "✓ Healthy"
		if !svc.Healthy {
			status = "✗ Unhealthy"
			allHealthy = false
		}

		responseTime := ""
		if svc.Response > 0 {
			responseTime = svc.Response.String()
		}

		rows = append(rows, []string{
			svc.Name,
			status,
			svc.Port,
			responseTime,
		})
	}

	fmt.Print(FormatTable([]string{"Service", "Status", "Port", "Response"}, rows))

	// Print infrastructure status
	header.Println("\n🏗️  Infrastructure:")
	infra := checkInfrastructure(ctx)
	fmt.Printf("   PostgreSQL:   %s\n", getStatusIcon(infra["postgres"], success, errColor, warning))
	fmt.Printf("   Redis:        %s\n", getStatusIcon(infra["redis"], success, errColor, warning))
	fmt.Printf("   Elasticsearch: %s\n", getStatusIcon(infra["elasticsearch"], success, errColor, warning))
	fmt.Printf("   OPA:          %s\n", getStatusIcon(infra["opa"], success, errColor, warning))

	// Print URLs
	header.Println("\n🔗 Service URLs:")
	info.Println("   Admin Console:   http://localhost:3000")
	info.Println("   API Gateway:     http://localhost:8088")
	info.Println("   APISIX Dashboard: http://localhost:9000")
	info.Println("   Grafana:         http://localhost:3001")

	// Summary
	if allHealthy && len(containers) > 0 {
		success.Println("\n✅ All services healthy")
	} else if len(containers) > 0 {
		warning.Println("\n⚠️  Some services are unhealthy or not running")
	} else {
		warning.Println("\n⚠️  No services running")
		warning.Println("   Run 'openidx dev' to start the development environment")
	}

	fmt.Println()

	return nil
}

type DockerContainer struct {
	Name   string
	State  string
	Ports  string
	Uptime string
}

func parseDockerStatus(output string) []DockerContainer {
	containers := []DockerContainer{}
	if output == "" {
		return containers
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Simple parsing (in production, use proper JSON parser)
		if strings.Contains(line, "openidx") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				name := parts[0]
				state := "unknown"
				ports := ""
				uptime := ""

				for i, p := range parts {
					if strings.Contains(p, "Up") {
						state = "running"
						if i+1 < len(parts) {
							uptime = parts[i+1]
						}
					}
					if strings.Contains(p, "->") {
						ports = p
					}
				}

				containers = append(containers, DockerContainer{
					Name:   name,
					State:  state,
					Ports:  ports,
					Uptime: uptime,
				})
			}
		}
	}

	return containers
}

func checkAllServices() []ServiceStatus {
	services := []ServiceStatus{
		{Name: "Identity", Port: "8001", URL: "http://localhost:8001/health"},
		{Name: "Governance", Port: "8002", URL: "http://localhost:8002/health"},
		{Name: "Provisioning", Port: "8003", URL: "http://localhost:8003/health"},
		{Name: "Audit", Port: "8004", URL: "http://localhost:8004/health"},
		{Name: "Admin API", Port: "8005", URL: "http://localhost:8005/health"},
		{Name: "OAuth", Port: "8006", URL: "http://localhost:8006/.well-known/openid-configuration"},
		{Name: "Gateway", Port: "8007", URL: "http://localhost:8007/health"},
		{Name: "APISIX", Port: "8088", URL: "http://localhost:8088/"},
		{Name: "Frontend", Port: "3000", URL: "http://localhost:3000"},
	}

	client := &http.Client{Timeout: 2 * time.Second}

	for i := range services {
		start := time.Now()
		req, _ := http.NewRequestWithContext(context.Background(), "GET", services[i].URL, nil)
		resp, err := client.Do(req)
		services[i].Response = time.Since(start)

		if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			services[i].Healthy = true
			resp.Body.Close()
		}
	}

	return services
}

func checkInfrastructure(ctx *CommandContext) map[string]bool {
	status := make(map[string]bool)

	// Check PostgreSQL
	if output, _ := ctx.RunCommandOutput("docker", "ps", "--filter", "name=postgres", "--format", "{{.Status}}"); strings.Contains(output, "Up") {
		status["postgres"] = true
	}

	// Check Redis
	if output, _ := ctx.RunCommandOutput("docker", "ps", "--filter", "name=redis", "--format", "{{.Status}}"); strings.Contains(output, "Up") {
		status["redis"] = true
	}

	// Check Elasticsearch
	if output, _ := ctx.RunCommandOutput("docker", "ps", "--filter", "name=elasticsearch", "--format", "{{.Status}}"); strings.Contains(output, "Up") {
		status["elasticsearch"] = true
	}

	// Check OPA
	if output, _ := ctx.RunCommandOutput("docker", "ps", "--filter", "name=opa", "--format", "{{.Status}}"); strings.Contains(output, "Up") {
		status["opa"] = true
	}

	return status
}

func getStatusIcon(status bool, success, errColor, warning *color.Color) string {
	if status {
		return success.Sprint("✓ Running")
	}
	return errColor.Sprint("✗ Stopped")
}

func formatUptime(uptime string) string {
	// Parse uptime like "2 hours" or "30 minutes"
	if uptime == "" {
		return "unknown"
	}
	return uptime
}

// NewHealthCheckCommand creates the health-check command
func NewHealthCheckCommand() *cobra.Command {
	var detailed bool

	cmd := &cobra.Command{
		Use:   "health-check [service]",
		Short: "Run health check on services",
		Long: `Run health checks on one or all services.

Exits with code 1 if any service is unhealthy. Useful for CI/CD pipelines.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			errColor, _, _, _, _ := ctx.GetColors()

			service := ""
			if len(args) > 0 {
				service = expandServiceName(args[0])
			}

			services := checkAllServices()

			allHealthy := true
			for _, svc := range services {
				if service != "" && !strings.EqualFold(svc.Name, service) {
					continue
				}

				if svc.Healthy {
					fmt.Printf("✓ %s: healthy (%s)\n", svc.Name, svc.Response)
				} else {
					fmt.Printf("✗ %s: unhealthy\n", svc.Name)
					allHealthy = false
				}
			}

			if !allHealthy {
				errColor.Println("\n❌ Some services are unhealthy")
				return fmt.Errorf("health check failed")
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&detailed, "detailed", "d", false, "Show detailed health information")

	return cmd
}

// NewTopCommand creates the top command
func NewTopCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "top",
		Short: "Show resource usage",
		Long: `Show CPU and memory usage for running containers.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, errColor, _, _, _ := ctx.GetColors()

			success.Println("📊 Resource Usage:")
			fmt.Println()

			if e := ctx.RunCommand("docker", "stats",
				"--format", "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"); e != nil {
				errColor.Printf("Failed to get stats: %v\n", e)
				return e
			}

			return nil
		},
	}

	return cmd
}
