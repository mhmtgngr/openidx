// Package server provides graceful shutdown functionality for OpenIDX services
package server

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

// Shutdownable represents a component that can be gracefully shut down
type Shutdownable interface {
	Shutdown(ctx context.Context) error
	Name() string
}

// ShutdownFunc wraps a function to implement Shutdownable
type ShutdownFunc struct {
	name string
	fn   func(context.Context) error
}

// NewShutdownFunc creates a Shutdownable from a function
func NewShutdownFunc(name string, fn func(context.Context) error) *ShutdownFunc {
	return &ShutdownFunc{name: name, fn: fn}
}

// Name returns the component name
func (s *ShutdownFunc) Name() string {
	return s.name
}

// Shutdown calls the wrapped function
func (s *ShutdownFunc) Shutdown(ctx context.Context) error {
	return s.fn(ctx)
}

// GracefulShutdown manages graceful shutdown of HTTP servers and dependencies
type GracefulShutdown struct {
	server         *http.Server
	logger         *zap.Logger
	shutdownables  []Shutdownable
	shutdownTimeout time.Duration
	signalChan     chan os.Signal
	mu             sync.Mutex
}

// Config holds configuration for graceful shutdown
type Config struct {
	Server         *http.Server
	Logger         *zap.Logger
	Shutdownables  []Shutdownable
	ShutdownTimeout time.Duration
}

// New creates a new GracefulShutdown manager
func New(cfg Config) *GracefulShutdown {
	if cfg.ShutdownTimeout == 0 {
		cfg.ShutdownTimeout = 30 * time.Second
	}

	return &GracefulShutdown{
		server:         cfg.Server,
		logger:         cfg.Logger,
		shutdownables:  cfg.Shutdownables,
		shutdownTimeout: cfg.ShutdownTimeout,
		signalChan:     make(chan os.Signal, 1),
	}
}

// AddShutdownable adds a component to the shutdown list
func (g *GracefulShutdown) AddShutdownable(s Shutdownable) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.shutdownables = append(g.shutdownables, s)
}

// AddShutdownFunc adds a shutdown function as a component
func (g *GracefulShutdown) AddShutdownFunc(name string, fn func(context.Context) error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.shutdownables = append(g.shutdownables, NewShutdownFunc(name, fn))
}

// Start begins listening for shutdown signals
// This method blocks until a shutdown signal is received and shutdown is complete
func (g *GracefulShutdown) Start() {
	// Register signal handlers
	signal.Notify(g.signalChan,
		syscall.SIGINT,  // Ctrl+C
		syscall.SIGTERM, // termination signal
		syscall.SIGQUIT, // quit signal
	)

	// Wait for signal
	sig := <-g.signalChan
	g.logger.Info("Received shutdown signal",
		zap.String("signal", sig.String()),
	)

	// Perform graceful shutdown
	g.shutdown()
}

// StartWithContext is similar to Start but allows external cancellation
func (g *GracefulShutdown) StartWithContext(ctx context.Context) {
	select {
	case sig := <-g.signalChan:
		g.logger.Info("Received shutdown signal",
			zap.String("signal", sig.String()),
		)
		g.shutdown()
	case <-ctx.Done():
		g.logger.Info("Context cancelled, initiating shutdown")
		g.shutdown()
	}
}

// shutdown performs the actual shutdown sequence
func (g *GracefulShutdown) shutdown() {
	g.logger.Info("Starting graceful shutdown")

	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), g.shutdownTimeout)
	defer cancel()

	// First, shutdown the HTTP server to stop accepting new requests
	if g.server != nil {
		g.logger.Info("Shutting down HTTP server")
		if err := g.server.Shutdown(shutdownCtx); err != nil {
			if err == context.DeadlineExceeded {
				g.logger.Warn("Server shutdown timed out, forcing close")
				g.server.Close()
			} else {
				g.logger.Error("Error during server shutdown", zap.Error(err))
			}
		} else {
			g.logger.Info("HTTP server shutdown complete")
		}
	}

	// Then shutdown all registered components
	g.mu.Lock()
	shutdownables := make([]Shutdownable, len(g.shutdownables))
	copy(shutdownables, g.shutdownables)
	g.mu.Unlock()

	var wg sync.WaitGroup
	for _, component := range shutdownables {
		wg.Add(1)
		go func(s Shutdownable) {
			defer wg.Done()

			g.logger.Info("Shutting down component", zap.String("component", s.Name()))

			// Use a separate timeout for each component
			componentCtx, componentCancel := context.WithTimeout(shutdownCtx, 10*time.Second)
			defer componentCancel()

			if err := s.Shutdown(componentCtx); err != nil {
				if err == context.DeadlineExceeded {
					g.logger.Warn("Component shutdown timed out",
						zap.String("component", s.Name()))
				} else {
					g.logger.Error("Error shutting down component",
						zap.String("component", s.Name()),
						zap.Error(err))
				}
			} else {
				g.logger.Info("Component shutdown complete",
					zap.String("component", s.Name()))
			}
		}(component)
	}

	// Wait for all components to finish shutting down
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		g.logger.Info("All components shutdown complete")
	case <-shutdownCtx.Done():
		g.logger.Warn("Shutdown timed out waiting for components")
	}

	g.logger.Info("Graceful shutdown complete")
}

// ListenAndServe starts the HTTP server and then waits for shutdown signals
// This is a convenience method that combines server startup with graceful shutdown
func (g *GracefulShutdown) ListenAndServe() error {
	go func() {
		g.logger.Info(fmt.Sprintf("Server listening on %s", g.server.Addr))
		if err := g.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			g.logger.Error("Server error", zap.Error(err))
		}
	}()

	g.Start()
	return nil
}

// ListenAndServeTLS starts the HTTPS server and then waits for shutdown signals
func (g *GracefulShutdown) ListenAndServeTLS(certFile, keyFile string) error {
	go func() {
		g.logger.Info(fmt.Sprintf("Server listening on %s (TLS)", g.server.Addr))
		if err := g.server.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
			g.logger.Error("Server error", zap.Error(err))
		}
	}()

	g.Start()
	return nil
}

// Shutdown triggers a manual shutdown (e.g., from health check failure)
func (g *GracefulShutdown) Shutdown() {
	select {
	case g.signalChan <- syscall.SIGTERM:
		g.logger.Info("Manual shutdown triggered")
	default:
		g.logger.Info("Shutdown already in progress")
	}
}

// CloseDB is a helper that returns a ShutdownFunc for closing a database connection
func CloseDB(db interface{ Close() error }) Shutdownable {
	return NewShutdownFunc("database", func(ctx context.Context) error {
		return db.Close()
	})
}

// CloseRedis is a helper that returns a ShutdownFunc for closing a Redis connection
func CloseRedis(redis interface{ Close() error }) Shutdownable {
	return NewShutdownFunc("redis", func(ctx context.Context) error {
		return redis.Close()
	})
}

// CancelContext is a helper that returns a ShutdownFunc for cancelling a context
func CancelContext(cancel context.CancelFunc) Shutdownable {
	return NewShutdownFunc("context", func(ctx context.Context) error {
		cancel()
		return nil
	})
}

// CloseTracer is a helper that returns a ShutdownFunc for closing an OpenTelemetry tracer
func CloseTracer(shutdownFunc func(context.Context) error) Shutdownable {
	return NewShutdownFunc("tracer", shutdownFunc)
}
