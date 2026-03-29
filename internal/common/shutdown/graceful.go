// Package shutdown provides graceful shutdown functionality for OpenIDX services.
// This file implements the GracefulShutdown function with signal handling,
// health check support, and pre-stop hooks for Kubernetes.
package shutdown

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
)

// CleanupFunc represents a cleanup function that can be run during shutdown.
// It receives a context that may be cancelled if the shutdown timeout is exceeded.
type CleanupFunc func(ctx context.Context) error

// HealthChecker is an interface for components that can report their health status.
type HealthChecker interface {
	// IsHealthy returns true if the component is healthy.
	IsHealthy(ctx context.Context) bool
}

// ShutdownState represents the current state of the shutdown process.
type ShutdownState int

const (
	// StateRunning indicates the service is running normally.
	StateRunning ShutdownState = iota
	// StateDraining indicates the service is draining active requests.
	StateDraining
	// StateStopping indicates the service is stopping internal components.
	StateStopping
	// StateTerminated indicates the service has terminated.
	StateTerminated
)

func (s ShutdownState) String() string {
	switch s {
	case StateRunning:
		return "running"
	case StateDraining:
		return "draining"
	case StateStopping:
		return "stopping"
	case StateTerminated:
		return "terminated"
	default:
		return "unknown"
	}
}

// ShutdownConfig holds configuration for the graceful shutdown process.
type ShutdownConfig struct {
	// Server is the HTTP server to shut down.
	Server *http.Server
	// Logger is the logger to use for shutdown messages.
	Logger *zap.Logger
	// Timeout is the maximum time to wait for shutdown to complete.
	Timeout time.Duration
	// HealthCheck is an optional health checker that will be polled during shutdown.
	HealthCheck HealthChecker
	// HealthCheckInterval is how often to check health during shutdown.
	HealthCheckInterval time.Duration
	// PreStopHook is an optional function to run before stopping the server.
	// This is useful for Kubernetes pre-stop hooks.
	PreStopHook CleanupFunc
	// DrainTimeout is how long to wait for active requests to complete.
	DrainTimeout time.Duration
}

// GracefulShutdown handles signal-driven graceful shutdown of services.
// It listens for SIGTERM and SIGINT signals, then executes the shutdown sequence:
//   1. Run pre-stop hook if configured
//   2. Stop accepting new requests
//   3. Wait for active requests to complete (with timeout)
//   4. Run cleanup functions in order
//   5. Flush logs and terminate
//
// The function blocks until shutdown is complete. It should typically be called
// as the last statement in main(), after starting the server in a goroutine.
//
// Example usage:
//
//	server := &http.Server{Addr: ":8080", Handler: handler}
//	go server.ListenAndServe()
//
//	ctx := context.Background()
//	err := GracefulShutdown(ctx, 30*time.Second,
//	    CloseDB(db),
//	    CloseRedis(redisClient),
//	)
//	if err != nil {
//	    log.Error("Shutdown error", zap.Error(err))
//	}
func GracefulShutdown(ctx context.Context, timeout time.Duration, cleaners ...CleanupFunc) error {
	cfg := ShutdownConfig{
		Timeout:     timeout,
		DrainTimeout: timeout / 2, // Use half the timeout for draining
	}
	return GracefulShutdownWithConfig(ctx, cfg, cleaners...)
}

// GracefulShutdownWithConfig performs graceful shutdown with the given configuration.
func GracefulShutdownWithConfig(ctx context.Context, cfg ShutdownConfig, cleaners ...CleanupFunc) error {
	// Apply defaults
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.DrainTimeout == 0 {
		cfg.DrainTimeout = cfg.Timeout / 2
	}
	if cfg.HealthCheckInterval == 0 {
		cfg.HealthCheckInterval = 500 * time.Millisecond
	}

	// Create logger if not provided
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	logger.Info("Graceful shutdown handler initialized",
		zap.Duration("timeout", cfg.Timeout),
		zap.Duration("drain_timeout", cfg.DrainTimeout),
		zap.Int("cleanup_functions", len(cleaners)),
	)

	// Set up signal channel
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Create a channel for manual shutdown triggering
	shutdownChan := make(chan struct{})

	// Start health check monitor if configured
	var healthWg sync.WaitGroup
	stopHealthCheck := make(chan struct{})
	if cfg.HealthCheck != nil {
		healthWg.Add(1)
		go func() {
			defer healthWg.Done()
			monitorHealth(ctx, cfg, stopHealthCheck, shutdownChan)
		}()
	}

	// Wait for signal
	select {
	case sig := <-sigChan:
		logger.Info("Received shutdown signal", zap.String("signal", sig.String()))
	case <-shutdownChan:
		logger.Info("Shutdown triggered by health check failure")
	case <-ctx.Done():
		logger.Info("Context cancelled, initiating shutdown")
	}

	// Stop health monitor
	close(stopHealthCheck)
	healthWg.Wait()

	// Execute shutdown sequence
	return executeShutdown(ctx, cfg, cleaners)
}

// monitorHealth periodically checks health and triggers shutdown if unhealthy.
func monitorHealth(ctx context.Context, cfg ShutdownConfig, stop <-chan struct{}, shutdownChan chan<- struct{}) {
	ticker := time.NewTicker(cfg.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !cfg.HealthCheck.IsHealthy(ctx) {
				cfg.Logger.Warn("Health check failed, triggering shutdown")
				select {
				case shutdownChan <- struct{}{}:
				default:
					// Shutdown already triggered
				}
				return
			}
		}
	}
}

// executeShutdown runs the shutdown sequence in phases.
func executeShutdown(ctx context.Context, cfg ShutdownConfig, cleaners []CleanupFunc) error {
	logger := cfg.Logger
	setState := func(s ShutdownState) {
		logger.Info("Shutdown state changed", zap.String("state", s.String()))
	}

	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	setState(StateDraining)

	// Phase 1: Run pre-stop hook if configured
	if cfg.PreStopHook != nil {
		logger.Info("Running pre-stop hook")
		start := time.Now()
		if err := cfg.PreStopHook(shutdownCtx); err != nil {
			logger.Error("Pre-stop hook failed",
				zap.Error(err),
				zap.Duration("duration", time.Since(start)),
			)
			// Continue with shutdown despite pre-stop hook failure
		} else {
			logger.Info("Pre-stop hook completed",
				zap.Duration("duration", time.Since(start)),
			)
		}
	}

	// Phase 2: Stop accepting new requests
	if cfg.Server != nil {
		logger.Info("Stopping HTTP server, draining active connections",
			zap.Duration("drain_timeout", cfg.DrainTimeout),
		)

		// Create a context for the drain phase
		drainCtx, drainCancel := context.WithTimeout(shutdownCtx, cfg.DrainTimeout)
		defer drainCancel()

		if err := cfg.Server.Shutdown(drainCtx); err != nil {
			if err == context.DeadlineExceeded {
				logger.Warn("Server drain timed out, forcing connections closed")
				// Force close any remaining connections
				cfg.Server.Close()
			} else {
				logger.Error("Error during server shutdown", zap.Error(err))
			}
		} else {
			logger.Info("HTTP server stopped gracefully")
		}
	}

	setState(StateStopping)

	// Phase 3: Run cleanup functions
	if len(cleaners) > 0 {
		logger.Info("Running cleanup functions", zap.Int("count", len(cleaners)))

		// Run cleanup functions with individual timeouts
		cleanupCtx, cleanupCancel := context.WithTimeout(shutdownCtx, cfg.Timeout-cfg.DrainTimeout)
		defer cleanupCancel()

		// Track which functions completed
		var wg sync.WaitGroup
		completed := make(map[int]bool)
		var mu sync.Mutex

		for i, cleaner := range cleaners {
			wg.Add(1)
			go func(idx int, fn CleanupFunc) {
				defer wg.Done()

				logger.Debug("Starting cleanup function", zap.Int("index", idx))

				// Each cleanup gets a portion of the remaining time
				fnCtx, fnCancel := context.WithTimeout(cleanupCtx, 5*time.Second)
				defer fnCancel()

				start := time.Now()
				if err := fn(fnCtx); err != nil {
					logger.Error("Cleanup function failed",
						zap.Int("index", idx),
						zap.Error(err),
						zap.Duration("duration", time.Since(start)),
					)
				} else {
					logger.Debug("Cleanup function completed",
						zap.Int("index", idx),
						zap.Duration("duration", time.Since(start)),
					)
				}

				mu.Lock()
				completed[idx] = true
				mu.Unlock()
			}(i, cleaner)
		}

		// Wait for all cleanup functions or timeout
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			logger.Info("All cleanup functions completed")
		case <-cleanupCtx.Done():
			logger.Warn("Cleanup timed out, some functions may not have completed")
			mu.Lock()
			for i := range cleaners {
				if !completed[i] {
					logger.Warn("Cleanup function did not complete", zap.Int("index", i))
				}
			}
			mu.Unlock()
		}
	}

	setState(StateTerminated)

	// Phase 4: Final logging
	logger.Info("Graceful shutdown complete")

	// Sync any buffered logs
	if logger != nil {
		_ = logger.Sync()
	}

	return nil
}

// Helper functions for common cleanup tasks

// CloseDB returns a CleanupFunc that closes a database connection.
func CloseDB(db interface{ Close() error }) CleanupFunc {
	return func(ctx context.Context) error {
		return db.Close()
	}
}

// CloseRedis returns a CleanupFunc that closes a Redis connection.
func CloseRedis(redis interface{ Close() error }) CleanupFunc {
	return func(ctx context.Context) error {
		return redis.Close()
	}
}

// CloseHTTPClient returns a CleanupFunc that closes an HTTP client.
func CloseHTTPClient(client interface{ CloseIdleConnections() }) CleanupFunc {
	return func(ctx context.Context) error {
		client.CloseIdleConnections()
		return nil
	}
}

// FlushLogger returns a CleanupFunc that syncs a logger.
func FlushLogger(logger interface{ Sync() error }) CleanupFunc {
	return func(ctx context.Context) error {
		return logger.Sync()
	}
}

// CancelContext returns a CleanupFunc that cancels a context.
func CancelContext(cancel context.CancelFunc) CleanupFunc {
	return func(ctx context.Context) error {
		cancel()
		return nil
	}
}

// Combined returns a CleanupFunc that runs multiple cleanup functions in sequence.
func Combined(cleaners ...CleanupFunc) CleanupFunc {
	return func(ctx context.Context) error {
		for i, cleaner := range cleaners {
			if err := cleaner(ctx); err != nil {
				return fmt.Errorf("cleanup function %d failed: %w", i, err)
			}
		}
		return nil
	}
}

// PreStopHook is a convenience function for creating a pre-stop hook that runs
// a command or function before shutdown begins. This is useful for Kubernetes
// pre-stop lifecycle hooks.
func PreStopHook(fn func() error) CleanupFunc {
	return func(ctx context.Context) error {
		return fn()
	}
}
