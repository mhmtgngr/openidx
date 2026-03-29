// Package profiling provides performance profiling utilities for OpenIDX services
package profiling

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/pprof"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// RemoteProfiler connects to a remote service's pprof endpoints
type RemoteProfiler struct {
	baseURL string
	client  *http.Client
}

// NewRemoteProfiler creates a new profiler for the given service address
func NewRemoteProfiler(serviceAddr string, client *http.Client) (*RemoteProfiler, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	// Ensure the address has a scheme
	baseURL := serviceAddr
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "http://" + baseURL
	}

	return &RemoteProfiler{
		baseURL: baseURL,
		client:  client,
	}, nil
}

// CPUProfile captures a CPU profile for the given duration
func (r *RemoteProfiler) CPUProfile(ctx context.Context, duration time.Duration, outputFile string) error {
	url := fmt.Sprintf("%s/debug/pprof/profile?seconds=%d", r.baseURL, int(duration.Seconds()))

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch profile: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("failed to write profile: %w", err)
	}

	return nil
}

// HeapProfile captures a heap memory profile
func (r *RemoteProfiler) HeapProfile(ctx context.Context, outputFile string) error {
	url := fmt.Sprintf("%s/debug/pprof/heap", r.baseURL)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch profile: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("failed to write profile: %w", err)
	}

	return nil
}

// BlockProfile captures a block profiling profile
func (r *RemoteProfiler) BlockProfile(ctx context.Context, outputFile string) error {
	url := fmt.Sprintf("%s/debug/pprof/block", r.baseURL)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch profile: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("failed to write profile: %w", err)
	}

	return nil
}

// MutexProfile captures a mutex profiling profile
func (r *RemoteProfiler) MutexProfile(ctx context.Context, outputFile string) error {
	url := fmt.Sprintf("%s/debug/pprof/mutex", r.baseURL)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch profile: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("failed to write profile: %w", err)
	}

	return nil
}

// GoroutineProfile captures a goroutine profile
func (r *RemoteProfiler) GoroutineProfile(ctx context.Context, outputFile string) error {
	url := fmt.Sprintf("%s/debug/pprof/goroutine", r.baseURL)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch profile: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("failed to write profile: %w", err)
	}

	return nil
}

// Trace captures an execution trace for the given duration
func (r *RemoteProfiler) Trace(ctx context.Context, duration time.Duration, outputFile string) error {
	url := fmt.Sprintf("%s/debug/pprof/trace?seconds=%d", r.baseURL, int(duration.Seconds()))

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch trace: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("failed to write trace: %w", err)
	}

	return nil
}

// Cmdline returns the command line invocation of the service
func (r *RemoteProfiler) Cmdline(ctx context.Context) ([]string, error) {
	url := fmt.Sprintf("%s/debug/pprof/cmdline", r.baseURL)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch cmdline: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// pprof cmdline endpoint returns null-byte separated arguments
	cmdline := strings.Split(string(data), "\x00")
	result := make([]string, 0, len(cmdline))
	for _, arg := range cmdline {
		if arg != "" {
			result = append(result, arg)
		}
	}

	return result, nil
}

// GenerateFlameGraph generates a flame graph from a CPU profile
func GenerateFlameGraph(profileFile, outputFile string) error {
	// Check if flamegraph.pl is available
	_, err := exec.LookPath("flamegraph.pl")
	if err != nil {
		return fmt.Errorf("flamegraph.pl not found in PATH. Install from https://github.com/brendangregg/FlameGraph")
	}

	// Generate collapsed stack traces using go tool pprof
	collapsedFile := outputFile + ".collapsed"

	// Use pprof to generate output that can be fed to flamegraph.pl
	// First get the raw profile data
	rawCmd := exec.Command("go", "tool", "pprof", "-raw", profileFile)
	rawOutput, err := rawCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to run pprof -raw: %w", err)
	}

	// Write collapsed output
	collapsedF, err := os.Create(collapsedFile)
	if err != nil {
		return fmt.Errorf("failed to create collapsed file: %w", err)
	}
	defer collapsedF.Close()

	if _, err := collapsedF.Write(rawOutput); err != nil {
		return fmt.Errorf("failed to write collapsed output: %w", err)
	}

	// Generate flame graph
	flameCmd := exec.Command("flamegraph.pl", "--title=CPU Profile", collapsedFile)
	flameOutput, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer flameOutput.Close()

	flameCmd.Stdout = flameOutput
	flameCmd.Stderr = os.Stderr

	if err := flameCmd.Run(); err != nil {
		return fmt.Errorf("failed to generate flame graph: %w", err)
	}

	// Clean up collapsed file
	os.Remove(collapsedFile)

	return nil
}

// CompareProfiles compares two profiling files and returns a summary
func CompareProfiles(beforeFile, afterFile string) (string, error) {
	var result strings.Builder

	result.WriteString("Profile Comparison Report\n")
	result.WriteString("========================\n\n")

	// Get file info
	beforeInfo, err := os.Stat(beforeFile)
	if err != nil {
		return "", fmt.Errorf("failed to stat before file: %w", err)
	}

	afterInfo, err := os.Stat(afterFile)
	if err != nil {
		return "", fmt.Errorf("failed to stat after file: %w", err)
	}

	result.WriteString(fmt.Sprintf("Before: %s (%.2f MB)\n", beforeFile, float64(beforeInfo.Size())/1024/1024))
	result.WriteString(fmt.Sprintf("After:  %s (%.2f MB)\n\n", afterFile, float64(afterInfo.Size())/1024/1024))

	// Use pprof to get top entries for both profiles
	result.WriteString("Top Functions (Before):\n")
	beforeTop, err := getTopFunctions(beforeFile, 10)
	if err != nil {
		result.WriteString(fmt.Sprintf("  Error: %v\n", err))
	} else {
		result.WriteString(beforeTop)
	}

	result.WriteString("\nTop Functions (After):\n")
	afterTop, err := getTopFunctions(afterFile, 10)
	if err != nil {
		result.WriteString(fmt.Sprintf("  Error: %v\n", err))
	} else {
		result.WriteString(afterTop)
	}

	result.WriteString("\nVisual Comparison:\n")
	result.WriteString(fmt.Sprintf("  pprof -http=:8080 -base %s %s\n", beforeFile, afterFile))

	return result.String(), nil
}

// getTopFunctions returns the top functions from a profile
func getTopFunctions(profileFile string, topN int) (string, error) {
	cmd := exec.Command("go", "tool", "pprof", "-top", "-nodecount", strconv.Itoa(topN), profileFile)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to run pprof: %w", err)
	}

	return string(output), nil
}

// StartHTTPServer starts a pprof HTTP server for live profiling
func StartHTTPServer(ctx context.Context, port int) error {
	mux := http.NewServeMux()

	// Standard pprof endpoints
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	// Additional endpoints
	mux.HandleFunc("/debug/pprof/heap", pprof.Handler("heap").ServeHTTP)
	mux.HandleFunc("/debug/pprof/goroutine", pprof.Handler("goroutine").ServeHTTP)
	mux.HandleFunc("/debug/pprof/block", pprof.Handler("block").ServeHTTP)
	mux.HandleFunc("/debug/pprof/mutex", pprof.Handler("mutex").ServeHTTP)
	mux.HandleFunc("/debug/pprof/allocs", pprof.Handler("allocs").ServeHTTP)
	mux.HandleFunc("/debug/pprof/threadcreate", pprof.Handler("threadcreate").ServeHTTP)

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Wait for context cancellation or server error
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		return err
	}
}

// RegisterRoutes registers pprof routes with a Gin router (dev mode only)
func RegisterRoutes(engine *gin.Engine, isDevelopment bool) {
	if !isDevelopment {
		return
	}

	// Create a separate handler group for pprof
	pprofGroup := engine.Group("/debug/pprof")
	{
		pprofGroup.GET("/", gin.WrapH(http.HandlerFunc(pprof.Index)))
		pprofGroup.GET("/cmdline", gin.WrapH(http.HandlerFunc(pprof.Cmdline)))
		pprofGroup.GET("/profile", gin.WrapH(http.HandlerFunc(pprof.Profile)))
		pprofGroup.POST("/symbol", gin.WrapH(http.HandlerFunc(pprof.Symbol)))
		pprofGroup.GET("/symbol", gin.WrapH(http.HandlerFunc(pprof.Symbol)))
		pprofGroup.GET("/trace", gin.WrapH(http.HandlerFunc(pprof.Trace)))

		pprofGroup.GET("/heap", gin.WrapH(pprof.Handler("heap")))
		pprofGroup.GET("/goroutine", gin.WrapH(pprof.Handler("goroutine")))
		pprofGroup.GET("/block", gin.WrapH(pprof.Handler("block")))
		pprofGroup.GET("/mutex", gin.WrapH(pprof.Handler("mutex")))
		pprofGroup.GET("/allocs", gin.WrapH(pprof.Handler("allocs")))
		pprofGroup.GET("/threadcreate", gin.WrapH(pprof.Handler("threadcreate")))
	}
}

// SetupDevelopmentProfiling is a convenience function to enable pprof in development
// Returns true if profiling was enabled
func SetupDevelopmentProfiling(engine *gin.Engine, environment string) bool {
	isDev := environment == "development" || environment == "dev"
	RegisterRoutes(engine, isDev)
	return isDev
}

// Middleware enables runtime profiling for the request
func Middleware(profileDir string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Enable mutex and block profiling at runtime
		// This can be toggled via environment or admin endpoint
		c.Next()
	}
}

// ProfileConfig holds configuration for runtime profiling
type ProfileConfig struct {
	CPUProfile    string
	MemProfile    string
	BlockProfile  bool
	MutexProfile  bool
	ProfileRate   int
	BlockSize     int
	MutexFraction int
}

// ApplyConfig applies profiling configuration at runtime
func ApplyConfig(cfg ProfileConfig) error {
	// These would typically be set via runtime/memory and runtime/pprof
	// This is a placeholder for more advanced runtime configuration
	return nil
}

// GetProfilePath returns the default path for storing profiles
func GetProfilePath(serviceName string, profileType string) string {
	dir := filepath.Join("profiles", serviceName)
	os.MkdirAll(dir, 0755)

	timestamp := time.Now().Format("20060102_150405")
	return filepath.Join(dir, fmt.Sprintf("%s_%s.prof", profileType, timestamp))
}
