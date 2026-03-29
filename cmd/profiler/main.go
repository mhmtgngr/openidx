// Package main provides a performance profiling CLI tool for OpenIDX services
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/openidx/openidx/internal/profiling"
)

const (
	defaultTimeout       = 30 * time.Second
	defaultCPUDuration   = 30 * time.Second
	defaultTraceDuration = 5 * time.Second
)

var (
	version   = "dev"
	buildTime = "unknown"
)

type command struct {
	name        string
	description string
	run         func(ctx context.Context, args []string) error
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmdName := os.Args[1]
	cmd, ok := commands()[cmdName]
	if !ok {
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmdName)
		printUsage()
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := cmd.run(ctx, os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func commands() map[string]command {
	return map[string]command{
		"cpu": {
			name:        "cpu",
			description: "Capture CPU profile from a service",
			run:         runCPUProfile,
		},
		"mem": {
			name:        "mem",
			description: "Capture heap profile from a service",
			run:         runMemProfile,
		},
		"block": {
			name:        "block",
			description: "Capture block profile from a service",
			run:         runBlockProfile,
		},
		"mutex": {
			name:        "mutex",
			description: "Capture mutex profile from a service",
			run:         runMutexProfile,
		},
		"trace": {
			name:        "trace",
			description: "Capture execution trace from a service",
			run:         runTrace,
		},
		"flame": {
			name:        "flame",
			description: "Generate flame graph from CPU profile",
			run:         runFlameGraph,
		},
		"http": {
			name:        "http",
			description: "Start pprof HTTP server for live profiling",
			run:         runHTTPServer,
		},
		"compare": {
			name:        "compare",
			description: "Compare two profiling files",
			run:         runCompare,
		},
		"list": {
			name:        "list",
			description: "List available profiling endpoints on a service",
			run:         runList,
		},
		"help": {
			name:        "help",
			description: "Show usage information",
			run: func(_ context.Context, _ []string) error {
				printUsage()
				return nil
			},
		},
		"version": {
			name:        "version",
			description: "Show version information",
			run: func(_ context.Context, _ []string) error {
				fmt.Printf("profiler version %s (built %s)\n", version, buildTime)
				return nil
			},
		},
	}
}

func printUsage() {
	fmt.Printf(`OpenIDX Profiler v%s

A performance profiling CLI tool for OpenIDX services.

USAGE:
    profiler [command] [arguments]

COMMANDS:
`, version)

	for _, cmd := range commands() {
		if cmd.name == "help" {
			continue
		}
		fmt.Printf("    %-12s %s\n", cmd.name, cmd.description)
	}

	fmt.Println(`EXAMPLES:
    # Capture 30-second CPU profile from identity-service
    profiler cpu identity-service 30s

    # Capture memory heap profile
    profiler mem identity-service

    # Capture 5-second execution trace
    profiler trace governance-service 5s

    # Generate flame graph from existing CPU profile
    profiler flame cpu-profile.prof

    # Start pprof HTTP server on port 6060
    profiler http 6060

    # Compare two CPU profiles
    profiler compare before.prof after.prof

    # List available profiling endpoints
    profiler list identity-service

SERVICES:
    Services are identified by name and use default ports:
    - identity-service     :8001
    - governance-service   :8002
    - provisioning-service :8003
    - audit-service        :8004
    - admin-api            :8005
    - gateway-service      :8006
    - access-service       :8007

    You can also specify custom address: profiler cpu localhost:9000 30s

ENVIRONMENT:
    APP_ENV=development    Required for profiling endpoints to be available`)
}

// getServiceAddress resolves a service name to its default address
func getServiceAddress(serviceOrAddr string) string {
	// If it looks like an address (contains :), return as-is
	if len(serviceOrAddr) > 0 && serviceOrAddr[0] == '/' ||
		(len(serviceOrAddr) >= 2 && serviceOrAddr[0] == '.' && serviceOrAddr[1] == '/') {
		return serviceOrAddr
	}

	// Check if it's already an address (host:port)
	for _, c := range serviceOrAddr {
		if c == ':' {
			return serviceOrAddr
		}
	}

	// Map service name to default port
	servicePorts := map[string]int{
		"identity-service":     8001,
		"governance-service":   8002,
		"provisioning-service": 8003,
		"audit-service":        8004,
		"admin-api":            8005,
		"gateway-service":      8006,
		"access-service":       8007,
		"oauth-service":        8008,
	}

	if port, ok := servicePorts[serviceOrAddr]; ok {
		return fmt.Sprintf("localhost:%d", port)
	}

	// Return as-is, assume it's a hostname
	return serviceOrAddr
}

// createHTTPClient creates an HTTP client for connecting to services
func createHTTPClient() *http.Client {
	return &http.Client{
		Timeout: defaultTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // For local development
			},
		},
	}
}

// runCPUProfile captures a CPU profile from a service
func runCPUProfile(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return errors.New("usage: profiler cpu [service] [duration]")
	}

	service := getServiceAddress(args[0])
	duration := defaultCPUDuration
	if len(args) >= 2 {
		d, err := time.ParseDuration(args[1])
		if err != nil {
			return fmt.Errorf("invalid duration: %w", err)
		}
		duration = d
	}

	output := "cpu.prof"
	if len(args) >= 3 {
		output = args[2]
	}

	fmt.Printf("Capturing %v CPU profile from %s...\n", duration, service)

	client := createHTTPClient()
	profiler, err := profiling.NewRemoteProfiler(service, client)
	if err != nil {
		return fmt.Errorf("failed to create profiler: %w", err)
	}

	if err := profiler.CPUProfile(ctx, duration, output); err != nil {
		return fmt.Errorf("failed to capture CPU profile: %w", err)
	}

	absPath, _ := filepath.Abs(output)
	fmt.Printf("CPU profile saved to %s\n", absPath)
	fmt.Printf("\nTo analyze:\n")
	fmt.Printf("  go tool pprof %s\n", output)
	fmt.Printf("  pprof -http=:8080 %s\n", output)

	return nil
}

// runMemProfile captures a memory heap profile from a service
func runMemProfile(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return errors.New("usage: profiler mem [service] [output-file]")
	}

	service := getServiceAddress(args[0])
	output := "heap.prof"
	if len(args) >= 2 {
		output = args[1]
	}

	fmt.Printf("Capturing heap profile from %s...\n", service)

	client := createHTTPClient()
	profiler, err := profiling.NewRemoteProfiler(service, client)
	if err != nil {
		return fmt.Errorf("failed to create profiler: %w", err)
	}

	if err := profiler.HeapProfile(ctx, output); err != nil {
		return fmt.Errorf("failed to capture heap profile: %w", err)
	}

	absPath, _ := filepath.Abs(output)
	fmt.Printf("Heap profile saved to %s\n", absPath)
	fmt.Printf("\nTo analyze:\n")
	fmt.Printf("  go tool pprof %s\n", output)

	return nil
}

// runBlockProfile captures a block profile from a service
func runBlockProfile(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return errors.New("usage: profiler block [service] [output-file]")
	}

	service := getServiceAddress(args[0])
	output := "block.prof"
	if len(args) >= 2 {
		output = args[1]
	}

	fmt.Printf("Capturing block profile from %s...\n", service)

	client := createHTTPClient()
	profiler, err := profiling.NewRemoteProfiler(service, client)
	if err != nil {
		return fmt.Errorf("failed to create profiler: %w", err)
	}

	if err := profiler.BlockProfile(ctx, output); err != nil {
		return fmt.Errorf("failed to capture block profile: %w", err)
	}

	absPath, _ := filepath.Abs(output)
	fmt.Printf("Block profile saved to %s\n", absPath)

	return nil
}

// runMutexProfile captures a mutex profile from a service
func runMutexProfile(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return errors.New("usage: profiler mutex [service] [output-file]")
	}

	service := getServiceAddress(args[0])
	output := "mutex.prof"
	if len(args) >= 2 {
		output = args[1]
	}

	fmt.Printf("Capturing mutex profile from %s...\n", service)

	client := createHTTPClient()
	profiler, err := profiling.NewRemoteProfiler(service, client)
	if err != nil {
		return fmt.Errorf("failed to create profiler: %w", err)
	}

	if err := profiler.MutexProfile(ctx, output); err != nil {
		return fmt.Errorf("failed to capture mutex profile: %w", err)
	}

	absPath, _ := filepath.Abs(output)
	fmt.Printf("Mutex profile saved to %s\n", absPath)

	return nil
}

// runTrace captures an execution trace from a service
func runTrace(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return errors.New("usage: profiler trace [service] [duration]")
	}

	service := getServiceAddress(args[0])
	duration := defaultTraceDuration
	if len(args) >= 2 {
		d, err := time.ParseDuration(args[1])
		if err != nil {
			return fmt.Errorf("invalid duration: %w", err)
		}
		duration = d
	}

	output := "trace.out"
	if len(args) >= 3 {
		output = args[2]
	}

	fmt.Printf("Capturing %v execution trace from %s...\n", duration, service)

	client := createHTTPClient()
	profiler, err := profiling.NewRemoteProfiler(service, client)
	if err != nil {
		return fmt.Errorf("failed to create profiler: %w", err)
	}

	if err := profiler.Trace(ctx, duration, output); err != nil {
		return fmt.Errorf("failed to capture trace: %w", err)
	}

	absPath, _ := filepath.Abs(output)
	fmt.Printf("Trace saved to %s\n", absPath)
	fmt.Printf("\nTo analyze:\n")
	fmt.Printf("  go tool trace %s\n", output)

	return nil
}

// runFlameGraph generates a flame graph from a CPU profile
func runFlameGraph(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return errors.New("usage: profiler flame [cpu-profile] [output-svg]")
	}

	inputFile := args[0]
	outputFile := "flamegraph.svg"
	if len(args) >= 2 {
		outputFile = args[1]
	}

	fmt.Printf("Generating flame graph from %s...\n", inputFile)

	if err := profiling.GenerateFlameGraph(inputFile, outputFile); err != nil {
		return fmt.Errorf("failed to generate flame graph: %w", err)
	}

	absPath, _ := filepath.Abs(outputFile)
	fmt.Printf("Flame graph saved to %s\n", absPath)
	fmt.Printf("\nOpen in a web browser to view.\n")

	return nil
}

// runHTTPServer starts a pprof HTTP server for live profiling
func runHTTPServer(ctx context.Context, args []string) error {
	port := 6060
	if len(args) >= 1 {
		p, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid port: %w", err)
		}
		port = p
	}

	fmt.Printf("Starting pprof HTTP server on :%d\n", port)
	fmt.Printf("Profiling endpoints:\n")
	fmt.Printf("  http://localhost:%d/debug/pprof/\n", port)
	fmt.Printf("  http://localhost:%d/debug/pprof/heap\n", port)
	fmt.Printf("  http://localhost:%d/debug/pprof/goroutine\n", port)
	fmt.Printf("  http://localhost:%d/debug/pprof/block\n", port)
	fmt.Printf("  http://localhost:%d/debug/pprof/mutex\n", port)
	fmt.Printf("  http://localhost:%d/debug/pprof/profile?seconds=30\n", port)
	fmt.Printf("  http://localhost:%d/debug/pprof/trace?seconds=5\n", port)
	fmt.Printf("\nPress Ctrl+C to stop\n")

	return profiling.StartHTTPServer(ctx, port)
}

// runCompare compares two profiling files
func runCompare(ctx context.Context, args []string) error {
	if len(args) < 2 {
		return errors.New("usage: profiler compare [before.prof] [after.prof]")
	}

	beforeFile := args[0]
	afterFile := args[1]

	fmt.Printf("Comparing profiles:\n")
	fmt.Printf("  Before: %s\n", beforeFile)
	fmt.Printf("  After:  %s\n", afterFile)
	fmt.Println()

	result, err := profiling.CompareProfiles(beforeFile, afterFile)
	if err != nil {
		return fmt.Errorf("failed to compare profiles: %w", err)
	}

	fmt.Println(result)
	return nil
}

// runList lists available profiling endpoints on a service
func runList(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return errors.New("usage: profiler list [service]")
	}

	service := getServiceAddress(args[0])
	client := createHTTPClient()

	fmt.Printf("Checking profiling endpoints on %s...\n\n", service)

	endpoints := []struct {
		name string
		path string
	}{
		{"Index", "/debug/pprof/"},
		{"Cmdline", "/debug/pprof/cmdline"},
		{"Profile", "/debug/pprof/profile"},
		{"Trace", "/debug/pprof/trace"},
		{"Symbol", "/debug/pprof/symbol"},
		{"Heap", "/debug/pprof/heap"},
		{"Goroutine", "/debug/pprof/goroutine"},
		{"Block", "/debug/pprof/block"},
		{"Mutex", "/debug/pprof/mutex"},
		{"Allocs", "/debug/pprof/allocs"},
		{"ThreadCreate", "/debug/pprof/threadcreate"},
	}

	baseURL := "http://" + service
	available := 0

	for _, ep := range endpoints {
		url := baseURL + ep.path
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("  %-15s [unavailable]\n", ep.name)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			fmt.Printf("  %-15s [available] %s\n", ep.name, url)
			available++
		} else {
			fmt.Printf("  %-15s [error: %d]\n", ep.name, resp.StatusCode)
		}
	}

	if available == 0 {
		fmt.Println("\nNo profiling endpoints available.")
		fmt.Println("Make sure the service is running with APP_ENV=development")
		return nil
	}

	fmt.Printf("\nFound %d available endpoint(s).\n", available)
	return nil
}

// downloadFile downloads a file from a URL
func downloadFile(client *http.Client, url string, w io.Writer) error {
	req, err := http.NewRequestWithContext(context.Background(), "GET", url, nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	_, err = io.Copy(w, resp.Body)
	return err
}
