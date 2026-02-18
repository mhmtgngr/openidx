// Package shutdown provides graceful shutdown coordination for OpenIDX services,
// managing HTTP server draining and cleanup hook execution with configurable timeouts.
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

// shutdownHook is a named cleanup function run during shutdown
type shutdownHook struct {
	Name string
	Fn   func(ctx context.Context) error
}

// serverEntry is a named HTTP server managed during shutdown
type serverEntry struct {
	Name   string
	Server *http.Server
}

// ShutdownManager coordinates graceful shutdown of servers and cleanup hooks
type ShutdownManager struct {
	logger  *zap.Logger
	timeout time.Duration
	hooks   []shutdownHook
	servers []*serverEntry
	mu      sync.Mutex
}

// NewShutdownManager creates a new ShutdownManager with the given logger and
// overall timeout for the shutdown sequence
func NewShutdownManager(logger *zap.Logger, timeout time.Duration) *ShutdownManager {
	return &ShutdownManager{
		logger:  logger.With(zap.String("component", "shutdown")),
		timeout: timeout,
		hooks:   make([]shutdownHook, 0),
		servers: make([]*serverEntry, 0),
	}
}

// RegisterHook adds a cleanup hook that will be called during shutdown.
// Hooks are executed in reverse registration order (LIFO).
func (sm *ShutdownManager) RegisterHook(name string, fn func(ctx context.Context) error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.hooks = append(sm.hooks, shutdownHook{Name: name, Fn: fn})
	sm.logger.Info("Registered shutdown hook", zap.String("hook", name))
}

// RegisterServer adds an HTTP server to be gracefully shut down.
// Servers are shut down concurrently before hooks are executed.
func (sm *ShutdownManager) RegisterServer(name string, server *http.Server) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.servers = append(sm.servers, &serverEntry{Name: name, Server: server})
	sm.logger.Info("Registered server for shutdown", zap.String("server", name))
}

// WaitForShutdown blocks until SIGINT or SIGTERM is received, then performs
// a graceful shutdown sequence:
//  1. Stop accepting new connections on all registered servers
//  2. Drain existing connections (within timeout)
//  3. Run cleanup hooks in reverse order
//  4. Log completion or timeout
func (sm *ShutdownManager) WaitForShutdown() {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	sig := <-quit
	sm.logger.Info("Shutdown signal received", zap.String("signal", sig.String()))

	ctx, cancel := context.WithTimeout(context.Background(), sm.timeout)
	defer cancel()

	sm.mu.Lock()
	servers := make([]*serverEntry, len(sm.servers))
	copy(servers, sm.servers)
	hooks := make([]shutdownHook, len(sm.hooks))
	copy(hooks, sm.hooks)
	sm.mu.Unlock()

	// Phase 1: Shut down all HTTP servers concurrently
	sm.logger.Info("Phase 1: Stopping HTTP servers", zap.Int("count", len(servers)))
	sm.shutdownServers(ctx, servers)

	// Phase 2: Execute cleanup hooks in reverse order (LIFO)
	sm.logger.Info("Phase 2: Running cleanup hooks", zap.Int("count", len(hooks)))
	sm.executeHooks(ctx, hooks)

	sm.logger.Info("Graceful shutdown complete")
}

// shutdownServers gracefully shuts down all registered servers concurrently
func (sm *ShutdownManager) shutdownServers(ctx context.Context, servers []*serverEntry) {
	if len(servers) == 0 {
		return
	}

	var wg sync.WaitGroup
	for _, entry := range servers {
		wg.Add(1)
		go func(e *serverEntry) {
			defer wg.Done()
			sm.logger.Info("Shutting down server", zap.String("server", e.Name))

			if err := e.Server.Shutdown(ctx); err != nil {
				sm.logger.Error("Server shutdown error",
					zap.String("server", e.Name),
					zap.Error(err),
				)
			} else {
				sm.logger.Info("Server shut down successfully", zap.String("server", e.Name))
			}
		}(entry)
	}

	// Wait for all servers or context deadline
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		sm.logger.Info("All servers shut down")
	case <-ctx.Done():
		sm.logger.Warn("Server shutdown timed out, some connections may be dropped")
	}
}

// executeHooks runs cleanup hooks in reverse registration order
func (sm *ShutdownManager) executeHooks(ctx context.Context, hooks []shutdownHook) {
	// Execute in reverse order (LIFO)
	for i := len(hooks) - 1; i >= 0; i-- {
		hook := hooks[i]

		// Check if context is already expired
		select {
		case <-ctx.Done():
			sm.logger.Warn("Shutdown timeout reached, skipping remaining hooks",
				zap.String("skipped_hook", hook.Name),
				zap.Int("remaining", i+1),
			)
			return
		default:
		}

		sm.logger.Info("Executing shutdown hook", zap.String("hook", hook.Name))
		start := time.Now()

		if err := hook.Fn(ctx); err != nil {
			sm.logger.Error("Shutdown hook failed",
				zap.String("hook", hook.Name),
				zap.Duration("duration", time.Since(start)),
				zap.Error(err),
			)
		} else {
			sm.logger.Info("Shutdown hook completed",
				zap.String("hook", hook.Name),
				zap.Duration("duration", time.Since(start)),
			)
		}
	}
}

// GracefulServe starts the HTTP server and registers it for graceful shutdown.
// It starts serving in a goroutine and returns immediately. The server will be
// shut down when WaitForShutdown is called.
func (sm *ShutdownManager) GracefulServe(name string, server *http.Server) error {
	sm.RegisterServer(name, server)

	errCh := make(chan error, 1)
	go func() {
		sm.logger.Info("Starting server",
			zap.String("server", name),
			zap.String("addr", server.Addr),
		)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("server %s failed: %w", name, err)
		}
	}()

	// Give the server a moment to fail on startup (e.g., port already in use)
	select {
	case err := <-errCh:
		return err
	case <-time.After(100 * time.Millisecond):
		return nil
	}
}
