package commands

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

// CheckResult represents the result of a health check
type CheckResult struct {
	Name    string
	Status  bool
	Message string
	Details string
}

// NewDoctorCommand creates the doctor command
func NewDoctorCommand() *cobra.Command {
	var fix bool

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check environment and dependencies",
		Long: `Check that all required tools and dependencies are installed and
configured correctly for OpenIDX development.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, errColor, warning, info, header := ctx.GetColors()

			header.Println("🏥 OpenIDX Environment Check")

			// Run all checks
			checks := []CheckResult{}

			// System checks
			checks = append(checks, checkOS())
			checks = append(checks, checkGoVersion())
			checks = append(checks, checkDocker())
			checks = append(checks, checkDockerCompose())
			checks = append(checks, checkNode())
			checks = append(checks, checkNpm())
			checks = append(checks, checkMake())

			// Optional tools
			checks = append(checks, checkGolangciLint())
			checks = append(checks, checkKubectl())
			checks = append(checks, checkHelm())
			checks = append(checks, checkTerraform())
			checks = append(checks, checkTrivy())

			// Port checks
			checks = append(checks, checkPorts(ctx))

			// Environment checks
			checks = append(checks, checkEnvVars())

			// Print results
			passCount := 0
			warnCount := 0
			failCount := 0

			for _, check := range checks {
				switch {
				case check.Status:
					success.Printf("✓ %s", check.Name)
					if check.Details != "" {
						info.Printf(" (%s)", check.Details)
					}
					fmt.Println()
					passCount++
				case strings.Contains(check.Message, "warning"):
					warning.Printf("⚠ %s\n", check.Name)
					if check.Message != "" {
						warning.Printf("  %s\n", check.Message)
					}
					warnCount++
				default:
					errColor.Printf("✗ %s\n", check.Name)
					if check.Message != "" {
						errColor.Printf("  %s\n", check.Message)
					}
					if check.Details != "" {
						info.Printf("  %s\n", check.Details)
					}
					failCount++
				}
			}

			// Summary
			fmt.Println()
			header.Println("Summary:")
			fmt.Printf("  Passed:  %d\n", passCount)
			fmt.Printf("  Warnings: %d\n", warnCount)
			fmt.Printf("  Failed:  %d\n", failCount)

			// Suggestions
			if failCount > 0 {
				fmt.Println()
				warning.Println("💡 Suggestions:")
				if !checkGoVersion().Status {
					fmt.Println("   - Install Go: https://go.dev/doc/install")
				}
				if !checkDocker().Status {
					fmt.Println("   - Install Docker: https://docs.docker.com/get-docker/")
				}
				if !checkNode().Status {
					fmt.Println("   - Install Node.js: https://nodejs.org/")
				}
				fmt.Println()
				errColor.Println("❌ Some checks failed. Please install missing dependencies.")
				return fmt.Errorf("doctor checks failed")
			} else if warnCount > 0 {
				warning.Println("\n⚠️  Some optional tools are missing, but core requirements are met.")
			} else {
				success.Println("\n✅ All checks passed! Your environment is ready.")
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&fix, "fix", false, "Attempt to fix issues automatically")

	return cmd
}

func checkOS() CheckResult {
	return CheckResult{
		Name:    "Operating System",
		Status:  true,
		Details: fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}

func checkGoVersion() CheckResult {
	// Check Go version
	output, err := exec.Command("go", "version").Output()
	if err != nil {
		return CheckResult{
			Name:    "Go",
			Status:  false,
			Message: "Go is not installed",
		}
	}

	version := strings.TrimSpace(string(output))
	// Parse version - we need Go 1.22+
	if !strings.Contains(version, "go1.2") && !strings.Contains(version, "go1.3") && !strings.Contains(version, "go1.4") {
		return CheckResult{
			Name:    "Go",
			Status:  true,
			Details: strings.Fields(version)[2],
		}
	}

	return CheckResult{
		Name:    "Go",
		Status:  true,
		Details: strings.Fields(version)[2],
	}
}

func checkDocker() CheckResult {
	output, err := exec.Command("docker", "--version").Output()
	if err != nil {
		return CheckResult{
			Name:    "Docker",
			Status:  false,
			Message: "Docker is not installed or not running",
		}
	}

	// Check if Docker daemon is running
	if err := exec.Command("docker", "info").Run(); err != nil {
		return CheckResult{
			Name:    "Docker",
			Status:  false,
			Message: "Docker is installed but daemon is not running",
		}
	}

	return CheckResult{
		Name:    "Docker",
		Status:  true,
		Details: strings.TrimSpace(strings.TrimPrefix(string(output), "Docker version ")),
	}
}

func checkDockerCompose() CheckResult {
	// Check for docker compose (v2) or docker-compose (v1)
	if _, err := exec.LookPath("docker"); err == nil {
		if output, err := exec.Command("docker", "compose", "version").Output(); err == nil {
			return CheckResult{
				Name:    "Docker Compose",
				Status:  true,
				Details: strings.TrimSpace(strings.TrimPrefix(string(output), "Docker Compose version ")),
			}
		}
	}

	if _, err := exec.LookPath("docker-compose"); err == nil {
		output, _ := exec.Command("docker-compose", "--version").Output()
		return CheckResult{
			Name:    "Docker Compose",
			Status:  true,
			Details: strings.TrimSpace(string(output)),
		}
	}

	return CheckResult{
		Name:    "Docker Compose",
		Status:  false,
		Message: "Docker Compose is not installed",
	}
}

func checkNode() CheckResult {
	output, err := exec.Command("node", "--version").Output()
	if err != nil {
		return CheckResult{
			Name:    "Node.js",
			Status:  false,
			Message: "Node.js is not installed",
		}
	}

	return CheckResult{
		Name:    "Node.js",
		Status:  true,
		Details: strings.TrimSpace(string(output)),
	}
}

func checkNpm() CheckResult {
	output, err := exec.Command("npm", "--version").Output()
	if err != nil {
		return CheckResult{
			Name:    "npm",
			Status:  false,
			Message: "npm is not installed",
		}
	}

	return CheckResult{
		Name:    "npm",
		Status:  true,
		Details: "v" + strings.TrimSpace(string(output)),
	}
}

func checkMake() CheckResult {
	if _, err := exec.LookPath("make"); err != nil {
		return CheckResult{
			Name:    "Make",
			Status:  false,
			Message: "Make is not installed",
		}
	}

	return CheckResult{
		Name:   "Make",
		Status: true,
	}
}

func checkGolangciLint() CheckResult {
	if _, err := exec.LookPath("golangci-lint"); err != nil {
		return CheckResult{
			Name:    "golangci-lint",
			Status:  false,
			Message: "warning",
		}
	}

	output, _ := exec.Command("golangci-lint", "--version").Output()
	return CheckResult{
		Name:    "golangci-lint",
		Status:  true,
		Details: strings.Split(strings.TrimSpace(string(output)), " ")[2],
	}
}

func checkKubectl() CheckResult {
	if _, err := exec.LookPath("kubectl"); err != nil {
		return CheckResult{
			Name:    "kubectl",
			Status:  false,
			Message: "warning",
		}
	}

	output, _ := exec.Command("kubectl", "version", "--client", "--short").Output()
	return CheckResult{
		Name:    "kubectl",
		Status:  true,
		Details: strings.TrimSpace(string(output)),
	}
}

func checkHelm() CheckResult {
	if _, err := exec.LookPath("helm"); err != nil {
		return CheckResult{
			Name:    "Helm",
			Status:  false,
			Message: "warning",
		}
	}

	output, _ := exec.Command("helm", "version", "--short").Output()
	return CheckResult{
		Name:    "Helm",
		Status:  true,
		Details: strings.TrimSpace(string(output)),
	}
}

func checkTerraform() CheckResult {
	if _, err := exec.LookPath("terraform"); err != nil {
		return CheckResult{
			Name:    "Terraform",
			Status:  false,
			Message: "warning",
		}
	}

	output, _ := exec.Command("terraform", "version").Output()
	lines := strings.Split(string(output), "\n")
	if len(lines) > 0 {
		return CheckResult{
			Name:    "Terraform",
			Status:  true,
			Details: strings.TrimSpace(lines[0]),
		}
	}

	return CheckResult{
		Name:    "Terraform",
		Status:  false,
		Message: "warning",
	}
}

func checkTrivy() CheckResult {
	if _, err := exec.LookPath("trivy"); err != nil {
		return CheckResult{
			Name:    "Trivy",
			Status:  false,
			Message: "warning",
		}
	}

	output, _ := exec.Command("trivy", "--version").Output()
	return CheckResult{
		Name:    "Trivy",
		Status:  true,
		Details: strings.TrimSpace(string(output)),
	}
}

func checkPorts(ctx *CommandContext) CheckResult {
	// Check if common ports are available
	ports := []string{"3000", "5432", "6379", "8001", "8006", "8088", "9200"}
	inUse := []string{}

	for _, port := range ports {
		// Try to bind to the port
		l, err := exec.Command("lsof", "-i", ":"+port).Output()
		if err == nil && len(l) > 0 {
			inUse = append(inUse, port)
		}
	}

	if len(inUse) > 0 {
		return CheckResult{
			Name:    "Port Availability",
			Status:  false,
			Message: fmt.Sprintf("warning: Ports in use: %s", strings.Join(inUse, ", ")),
		}
	}

	return CheckResult{
		Name:   "Port Availability",
		Status: true,
		Details: "All required ports available",
	}
}

func checkEnvVars() CheckResult {
	// Check for critical environment variables
	vars := []string{"DATABASE_URL", "REDIS_URL"}
	missing := []string{}

	for _, v := range vars {
		if os.Getenv(v) == "" {
			missing = append(missing, v)
		}
	}

	if len(missing) > 0 {
		return CheckResult{
			Name:    "Environment Variables",
			Status:  false,
			Message: "warning: Some env vars not set: " + strings.Join(missing, ", "),
			Details: "Set via .env file or docker-compose",
		}
	}

	return CheckResult{
		Name:   "Environment Variables",
		Status: true,
	}
}

// NewFixCommand creates the fix command
func NewFixCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fix",
		Short: "Attempt to fix common issues",
		Long: `Automatically fix common development environment issues.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, errColor, _, _, _ := ctx.GetColors()

			success.Println("🔧 Attempting to fix common issues...")

			// Fix Go modules
			success.Println("Tidying Go modules...")
			if e := ctx.RunCommand("go", "mod", "tidy"); e != nil {
				errColor.Printf("Failed to tidy modules: %v\n", e)
			}

			// Install npm dependencies
			success.Println("Installing npm dependencies...")
			if e := ctx.RunCommandInDir(ctx.Path("web", "admin-console"), "npm", "install"); e != nil {
				errColor.Printf("Failed to install npm dependencies: %v\n", e)
			}

			// Generate code
			success.Println("Generating code...")
			if e := ctx.RunCommand("go", "generate", "./..."); e != nil {
				errColor.Printf("Failed to generate code: %v\n", e)
			}

			success.Println("✅ Fix attempts complete")
			success.Println("   Run 'openidx doctor' to verify")
			return nil
		},
	}

	return cmd
}

// NewPathsCommand creates the paths command
func NewPathsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "paths",
		Short: "Show important paths",
		Long:  `Show the paths to important files and directories.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			_, _, _, _, header := ctx.GetColors()

			header.Println("📁 OpenIDX Paths:")

			rows := [][]string{
				{"Project Root", ctx.RootDir},
				{"Go Services", ctx.Path("cmd")},
				{"Web Console", ctx.Path("web", "admin-console")},
				{"Migrations", ctx.Path("migrations")},
				{"Deployments", ctx.Path("deployments")},
				{"Config", ctx.Path("configs")},
				{"Scripts", ctx.Path("scripts")},
				{"Build Output", ctx.Path("bin")},
			}

			fmt.Print(FormatTable([]string{"Path", "Location"}, rows))

			fmt.Println("\n💡 Use 'openidx services' to see available services")

			return nil
		},
	}

	return cmd
}

// NewConfigCommand creates the config command
func NewConfigCommand() *cobra.Command {
	var showAll bool

	cmd := &cobra.Command{
		Use:   "config",
		Short: "Show configuration",
		Long:  `Show current configuration values.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			errColor, _, _, info, header := ctx.GetColors()

			header.Println("⚙️  Configuration:")

			// Show environment variables
			envVars := []string{
				"APP_ENV",
				"LOG_LEVEL",
				"DATABASE_URL",
				"REDIS_URL",
				"ELASTICSEARCH_URL",
				"OPA_URL",
				"JWT_SECRET",
				"OAUTH_ISSUER",
			}

			if showAll {
				envVars = append(envVars, []string{
					"SMTP_HOST",
					"VITE_API_URL",
					"GRAFANA_ADMIN_PASSWORD",
					"ZITI_PWD",
				}...)
			}

			for _, env := range envVars {
				val := os.Getenv(env)
				if val != "" {
					// Mask sensitive values
					if strings.Contains(strings.ToLower(env), "secret") ||
						strings.Contains(strings.ToLower(env), "password") ||
						strings.Contains(strings.ToLower(env), "token") ||
						strings.Contains(env, "JWT") {
						val = "***masked***"
					}
					info.Printf("%s=%s\n", env, val)
				} else if showAll {
					errColor.Printf("%s=(not set)\n", env)
				}
			}

			// Show config file location
			configFile := ctx.Path(".env")
			if _, err := os.Stat(configFile); err == nil {
				fmt.Printf("\nConfig file: %s\n", configFile)
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&showAll, "all", "a", false, "Show all configuration values")

	return cmd
}
