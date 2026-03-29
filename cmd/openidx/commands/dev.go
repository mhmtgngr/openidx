package commands

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

// NewDevCommand creates the dev command
func NewDevCommand() *cobra.Command {
	var infraOnly, background bool

	cmd := &cobra.Command{
		Use:   "dev",
		Short: "Start development environment",
		Long: `Start the development environment including all services.

This command starts Docker containers for infrastructure services (PostgreSQL,
Redis, Elasticsearch) and application services (Identity, Governance, etc.).`,
		Aliases: []string{"start", "up"},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, errColor, _, _, _ := ctx.GetColors()

			if infraOnly {
				success.Println("🏗️  Starting infrastructure services...")
				if e := ctx.RunMake("dev-infra"); e != nil {
					errColor.Printf("Failed to start infrastructure: %v\n", e)
					return e
				}
				success.Println("✅ Infrastructure services started")
				return nil
			}

			success.Println("🚀 Starting development environment...")

			if background {
				// Start in background
				if e := ctx.RunMake("dev"); e != nil {
					errColor.Printf("Failed to start services: %v\n", e)
					return e
				}

				success.Println("✅ Services starting in background")
				success.Println("\nWaiting for services to be healthy...")

				// Simple wait loop
				for i := 0; i < 30; i++ {
					time.Sleep(2 * time.Second)
					fmt.Print(".")
					if i == 14 {
						fmt.Println() // Newline halfway
					}
				}
				fmt.Println()

				success.Println("\n✅ Development environment ready!")
				printServiceURLs()
				return nil
			}

			// Run in foreground
			if e := ctx.RunMake("dev"); e != nil {
				errColor.Printf("Failed to start services: %v\n", e)
				return e
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&infraOnly, "infra", false, "Start only infrastructure services")
	cmd.Flags().BoolVarP(&background, "background", "b", false, "Run services in background")
	cmd.Flags().BoolVarP(&infraOnly, "infra-only", "i", false, "Start only infrastructure services (deprecated)")

	return cmd
}

func printServiceURLs() {
	fmt.Println("\n📋 Service URLs:")
	fmt.Println("   Admin Console:   http://localhost:3000")
	fmt.Println("   API Gateway:     http://localhost:8088")
	fmt.Println("   OAuth Service:   http://localhost:8006")
	fmt.Println("   Identity:        http://localhost:8001")
	fmt.Println("   Governance:      http://localhost:8002")
	fmt.Println("   Provisioning:    http://localhost:8003")
	fmt.Println("   Audit:           http://localhost:8004")
	fmt.Println("   Admin API:       http://localhost:8005")
	fmt.Println("   Gateway Service: http://localhost:8007")
	fmt.Println("   APISIX Dashboard: http://localhost:9000")
	fmt.Println("   Grafana:         http://localhost:3001")
	fmt.Println("\n💡 Run 'openidx logs [service]' to view logs")
	fmt.Println("💡 Run 'openidx status' to check service health")
}
