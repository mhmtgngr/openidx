package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// NewBuildCommand creates the build command
func NewBuildCommand() *cobra.Command {
	var services, web, all bool
	var output string

	cmd := &cobra.Command{
		Use:   "build",
		Short: "Build services and applications",
		Long: `Build OpenIDX services and/or web applications.

Builds the Go services and/or React frontend. Can build specific services
or all of them.`,
		Aliases: []string{"compile"},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, errColor, _, _, _ := ctx.GetColors()

			// Determine what to build
			if !services && !web && !all {
				// Default: build all
				all = true
			}

			if all {
				success.Println("🔨 Building all services and applications...")
				if e := ctx.RunMake("build"); e != nil {
					errColor.Printf("Build failed: %v\n", e)
					return e
				}
				success.Println("✅ Build complete")
				return nil
			}

			if services {
				if output != "" {
					// Build specific service
					success.Printf("🔨 Building service: %s\n", output)
					if e := buildService(ctx, output); e != nil {
						errColor.Printf("Build failed: %v\n", e)
						return e
					}
					success.Printf("✅ Built %s\n", output)
					return nil
				}

				// Build all services
				success.Println("🔨 Building services...")
				if e := ctx.RunMake("build-services"); e != nil {
					errColor.Printf("Build failed: %v\n", e)
					return e
				}
				success.Println("✅ Services built")
			}

			if web {
				success.Println("🌐 Building web applications...")
				if e := ctx.RunMake("build-web"); e != nil {
					errColor.Printf("Build failed: %v\n", e)
					return e
				}
				success.Println("✅ Web applications built")
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&services, "services", "s", false, "Build Go services")
	cmd.Flags().BoolVarP(&web, "web", "w", false, "Build web applications")
	cmd.Flags().BoolVarP(&all, "all", "a", false, "Build everything")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Build specific service")

	return cmd
}

// Available services to build
var availableServices = []string{
	"identity-service",
	"governance-service",
	"provisioning-service",
	"audit-service",
	"gateway-service",
	"admin-api",
	"oauth-service",
	"access-service",
}

func buildService(ctx *CommandContext, service string) error {
	// Check if service exists
	found := false
	for _, s := range availableServices {
		if s == service {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("unknown service: %s", service)
	}

	// Build the service
	cmdDir := ctx.Path("cmd", service)
	if !ctx.Exists(cmdDir) {
		return fmt.Errorf("service directory not found: %s", cmdDir)
	}

	// Create bin directory if needed
	binDir := ctx.Path("bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return err
	}

	// Build output path
	outputPath := filepath.Join(binDir, service)

	// Run go build
	return ctx.RunCommandInDir(ctx.RootDir,
		"go", "build",
		"-o", outputPath,
		fmt.Sprintf("./cmd/%s", service),
	)
}

// NewCleanCommand creates the clean command
func NewCleanCommand() *cobra.Command {
	var all bool

	cmd := &cobra.Command{
		Use:   "clean",
		Short: "Clean build artifacts",
		Long: `Remove build artifacts including binaries, coverage files, and
temporary build files.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, _, warning, _, _ := ctx.GetColors()

			if all {
				warning.Println("🧹 Cleaning all artifacts including Docker resources...")
				if e := ctx.RunMake("clean-docker"); e != nil {
					return e
				}
			} else {
				success.Println("🧹 Cleaning build artifacts...")
			}

			if e := ctx.RunMake("clean"); e != nil {
				return e
			}

			success.Println("✅ Clean complete")
			return nil
		},
	}

	cmd.Flags().BoolVarP(&all, "all", "a", false, "Also clean Docker resources")

	return cmd
}

// NewInstallCommand creates the install command
func NewInstallCommand() *cobra.Command {
	var deps, tools bool

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install dependencies",
		Long: `Install project dependencies including Go modules, npm packages,
and development tools.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, errColor, _, _, _ := ctx.GetColors()

			if deps || (!deps && !tools) {
				success.Println("📦 Installing dependencies...")
				if e := ctx.RunMake("deps"); e != nil {
					errColor.Printf("Failed to install dependencies: %v\n", e)
					return e
				}
			}

			if tools {
				success.Println("🔧 Installing development tools...")
				if e := ctx.RunMake("deps-tools"); e != nil {
					errColor.Printf("Failed to install tools: %v\n", e)
					return e
				}
			}

			success.Println("✅ Installation complete")
			return nil
		},
	}

	cmd.Flags().BoolVar(&deps, "deps", false, "Install dependencies")
	cmd.Flags().BoolVar(&tools, "tools", false, "Install development tools")

	return cmd
}

// NewDockerCommand creates the docker command group
func NewDockerCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "docker",
		Short: "Docker operations",
		Long:  `Commands for building and pushing Docker images.`,
	}

	// Build subcommand
	buildCmd := &cobra.Command{
		Use:   "build",
		Short: "Build Docker images",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, errColor, _, _, _ := ctx.GetColors()

			success.Println("🐳 Building Docker images...")
			if e := ctx.RunMake("docker-build"); e != nil {
				errColor.Printf("Docker build failed: %v\n", e)
				return e
			}

			success.Println("✅ Docker images built")
			return nil
		},
	}
	cmd.AddCommand(buildCmd)

	// Push subcommand
	pushCmd := &cobra.Command{
		Use:   "push",
		Short: "Push Docker images to registry",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, errColor, _, _, _ := ctx.GetColors()

			success.Println("📤 Pushing Docker images...")
			if e := ctx.RunMake("docker-push"); e != nil {
				errColor.Printf("Docker push failed: %v\n", e)
				return e
			}

			success.Println("✅ Docker images pushed")
			return nil
		},
	}
	cmd.AddCommand(pushCmd)

	return cmd
}

// NewGenerateCommand creates the generate command
func NewGenerateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate code",
		Long:  `Generate code from various sources (proto, swagger, go generate).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, errColor, _, _, _ := ctx.GetColors()

			success.Println("⚙️  Generating code...")
			if e := ctx.RunMake("generate"); e != nil {
				errColor.Printf("Code generation failed: %v\n", e)
				return e
			}

			success.Println("✅ Code generation complete")
			return nil
		},
	}

	// Swagger subcommand
	swaggerCmd := &cobra.Command{
		Use:   "swagger",
		Short: "Generate Swagger documentation",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, errColor, _, _, _ := ctx.GetColors()

			success.Println("📚 Generating Swagger documentation...")
			if e := ctx.RunMake("swagger"); e != nil {
				errColor.Printf("Swagger generation failed: %v\n", e)
				return e
			}

			success.Println("✅ Swagger documentation generated")
			return nil
		},
	}
	cmd.AddCommand(swaggerCmd)

	return cmd
}

// NewLintCommand creates the lint command
func NewLintCommand() *cobra.Command {
	var fix, web bool

	cmd := &cobra.Command{
		Use:   "lint",
		Short: "Run linters",
		Long: `Run linters to check code quality and style.

Supports Go (golangci-lint) and frontend (ESLint/Prettier) linting.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, errColor, _, _, _ := ctx.GetColors()

			if web {
				success.Println("🔍 Linting web applications...")
				if e := ctx.RunMake("lint-web"); e != nil {
					errColor.Printf("Web lint failed: %v\n", e)
					return e
				}
				success.Println("✅ Web linting complete")
				return nil
			}

			if fix {
				success.Println("🔧 Fixing lint issues...")
				if e := ctx.RunMake("lint-fix"); e != nil {
					errColor.Printf("Lint fix failed: %v\n", e)
					return e
				}
				success.Println("✅ Lint fixes applied")
				return nil
			}

			success.Println("🔍 Running linters...")
			if e := ctx.RunMake("lint"); e != nil {
				errColor.Printf("Lint failed: %v\n", e)
				return e
			}

			success.Println("✅ Linting complete")
			return nil
		},
	}

	cmd.Flags().BoolVar(&fix, "fix", false, "Automatically fix lint issues")
	cmd.Flags().BoolVar(&web, "web", false, "Lint web applications")

	return cmd
}

// NewServicesCommand creates the services command to list available services
func NewServicesCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "services",
		Short: "List available services",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			_, _, _, _, header := ctx.GetColors()

			header.Println("\nAvailable Services:")

			rows := make([][]string, len(availableServices))
			for i, svc := range availableServices {
				port := getServicePort(svc)
				description := getServiceDescription(svc)
				rows[i] = []string{svc, port, description}
			}

			fmt.Print(FormatTable([]string{"Service", "Port", "Description"}, rows))
			return nil
		},
	}

	return cmd
}

func getServicePort(service string) string {
	ports := map[string]string{
		"identity-service":     "8001",
		"governance-service":   "8002",
		"provisioning-service": "8003",
		"audit-service":        "8004",
		"admin-api":            "8005",
		"oauth-service":        "8006",
		"gateway-service":      "8007",
		"access-service":       "8010",
	}
	if p, ok := ports[service]; ok {
		return p
	}
	return "-"
}

func getServiceDescription(service string) string {
	descriptions := map[string]string{
		"identity-service":     "Authentication, users, sessions, SSO",
		"governance-service":   "Access reviews, policies, compliance",
		"provisioning-service": "SCIM 2.0, user lifecycle management",
		"audit-service":        "Audit logging, compliance reports",
		"admin-api":            "Admin console backend API",
		"oauth-service":        "OAuth/OIDC authorization server",
		"gateway-service":      "API gateway service",
		"access-service":       "Zero Trust access proxy",
	}
	if d, ok := descriptions[service]; ok {
		return d
	}
	return ""
}

// NewDevStopCommand creates the dev-stop command
func NewDevStopCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dev-stop",
		Short: "Stop development environment",
		Long:  `Stop all running development services.`,
		Aliases: []string{"stop", "down"},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, errColor, _, _, _ := ctx.GetColors()

			success.Println("🛑 Stopping development environment...")
			if e := ctx.RunMake("dev-stop"); e != nil {
				errColor.Printf("Failed to stop services: %v\n", e)
				return e
			}

			success.Println("✅ Services stopped")
			return nil
		},
	}

	return cmd
}

// Add completion for services
func completeServices(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	var matches []string
	for _, svc := range availableServices {
		if strings.HasPrefix(svc, toComplete) {
			matches = append(matches, svc)
		}
	}
	return matches, cobra.ShellCompDirectiveNoFileComp
}
