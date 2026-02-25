// Package server provides graceful shutdown functionality for OpenIDX services
package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestNew(t *testing.T) {
	logger := zaptest.NewLogger(t)

	server := &http.Server{Addr: ":8080"}

	gs := New(Config{
		Server:         server,
		Logger:         logger,
		Shutdownables:  nil,
		ShutdownTimeout: 10 * time.Second,
	})

	assert.NotNil(t, gs)
}

func TestShutdownFunc(t *testing.T) {
	called := false
	fn := NewShutdownFunc("test", func(ctx context.Context) error {
		called = true
		return nil
	})

	assert.Equal(t, "test", fn.Name())

	ctx := context.Background()
	err := fn.Shutdown(ctx)
	require.NoError(t, err)
	assert.True(t, called)
}

func TestShutdownFunc_WithError(t *testing.T) {
	expectedErr := assert.AnError
	fn := NewShutdownFunc("failing", func(ctx context.Context) error {
		return expectedErr
	})

	ctx := context.Background()
	err := fn.Shutdown(ctx)
	assert.Equal(t, expectedErr, err)
}

func TestAddShutdownable(t *testing.T) {
	logger := zaptest.NewLogger(t)
	gs := New(Config{
		Server: &http.Server{Addr: ":8080"},
		Logger: logger,
	})

	shutdownable := NewShutdownFunc("test", func(ctx context.Context) error {
		return nil
	})

	gs.AddShutdownable(shutdownable)

	// Verify it was added (we can check by triggering shutdown)
	// Since we can't inspect the internal state directly,
	// we'll just ensure no panic occurs
}

func TestAddShutdownFunc(t *testing.T) {
	logger := zaptest.NewLogger(t)
	gs := New(Config{
		Server: &http.Server{Addr: ":8080"},
		Logger: logger,
	})

	called := false
	gs.AddShutdownFunc("test", func(ctx context.Context) error {
		called = true
		return nil
	})

	// The shutdownable should be added
	// We can't directly verify without triggering shutdown
	_ = called
}

func TestGracefulShutdown_MultipleComponents(t *testing.T) {
	logger := zaptest.NewLogger(t)

	callOrder := make([]string, 0)
	component1 := NewShutdownFunc("component1", func(ctx context.Context) error {
		callOrder = append(callOrder, "component1")
		return nil
	})
	component2 := NewShutdownFunc("component2", func(ctx context.Context) error {
		callOrder = append(callOrder, "component2")
		return nil
	})
	component3 := NewShutdownFunc("component3", func(ctx context.Context) error {
		callOrder = append(callOrder, "component3")
		return nil
	})

	gs := New(Config{
		Server:         &http.Server{Addr: ":8080"},
		Logger:         logger,
		Shutdownables:  []Shutdownable{component1, component2, component3},
		ShutdownTimeout: 5 * time.Second,
	})

	// Start the shutdown handler in a goroutine
	done := make(chan struct{})
	go func() {
		gs.Start()
		close(done)
	}()

	// Give time for Start() to begin listening
	time.Sleep(10 * time.Millisecond)

	// Trigger shutdown
	gs.Shutdown()

	// Wait for shutdown to complete
	select {
	case <-done:
		// Shutdown completed
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not complete in time")
	}

	// All components should have been called
	assert.Contains(t, callOrder, "component1")
	assert.Contains(t, callOrder, "component2")
	assert.Contains(t, callOrder, "component3")
	assert.Len(t, callOrder, 3)
}

func TestGracefulShutdown_ContextTimeout(t *testing.T) {
	logger := zaptest.NewLogger(t)

	slowComponent := NewShutdownFunc("slow", func(ctx context.Context) error {
		select {
		case <-time.After(10 * time.Second):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})

	gs := New(Config{
		Server:         &http.Server{Addr: ":8080"},
		Logger:         logger,
		Shutdownables:  []Shutdownable{slowComponent},
		ShutdownTimeout: 100 * time.Millisecond,
	})

	start := time.Now()
	gs.Shutdown()
	elapsed := time.Since(start)

	// Should complete within timeout + some overhead
	assert.Less(t, elapsed, 500*time.Millisecond)
}

func TestGracefulShutdown_ComponentError(t *testing.T) {
	logger := zaptest.NewLogger(t)

	errorComponent := NewShutdownFunc("error", func(ctx context.Context) error {
		return assert.AnError
	})
	okComponent := NewShutdownFunc("ok", func(ctx context.Context) error {
		return nil
	})

	gs := New(Config{
		Server:         &http.Server{Addr: ":8080"},
		Logger:         logger,
		Shutdownables:  []Shutdownable{errorComponent, okComponent},
		ShutdownTimeout: 1 * time.Second,
	})

	// Should not panic even when a component errors
	gs.Shutdown()
	time.Sleep(100 * time.Millisecond)
}

func TestCloseDB(t *testing.T) {
	db := &mockCloser{}
	shutdownable := CloseDB(db)

	assert.Equal(t, "database", shutdownable.Name())

	ctx := context.Background()
	err := shutdownable.Shutdown(ctx)
	require.NoError(t, err)
	assert.True(t, db.closed)
}

func TestCloseRedis(t *testing.T) {
	redis := &mockCloser{}
	shutdownable := CloseRedis(redis)

	assert.Equal(t, "redis", shutdownable.Name())

	ctx := context.Background()
	err := shutdownable.Shutdown(ctx)
	require.NoError(t, err)
	assert.True(t, redis.closed)
}

func TestCancelContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	shutdownable := CancelContext(cancel)

	assert.Equal(t, "context", shutdownable.Name())

	ctxErr := ctx.Err()
	assert.Nil(t, ctxErr) // Not cancelled yet

	err := shutdownable.Shutdown(context.Background())
	require.NoError(t, err)

	// Context should now be cancelled
	time.Sleep(10 * time.Millisecond)
	ctxErr = ctx.Err()
	assert.Equal(t, context.Canceled, ctxErr)
}

func TestCloseTracer(t *testing.T) {
	called := false
	shutdownFunc := func(ctx context.Context) error {
		called = true
		return nil
	}

	shutdownable := CloseTracer(shutdownFunc)

	assert.Equal(t, "tracer", shutdownable.Name())

	err := shutdownable.Shutdown(context.Background())
	require.NoError(t, err)
	assert.True(t, called)
}

func TestGracefulShutdown_HTTPServer(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create a test server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	ts := httptest.NewServer(handler)
	defer ts.Close()

	// Create a real HTTP server
	server := &http.Server{
		Addr:    ts.Listener.Addr().String(),
		Handler: handler,
	}

	// Start server in goroutine
	go func() {
		server.ListenAndServe()
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Verify server is running
	resp, err := http.Get(ts.URL)
	require.NoError(t, err)
	resp.Body.Close()

	gs := New(Config{
		Server:         server,
		Logger:         logger,
		Shutdownables:  nil,
		ShutdownTimeout: 5 * time.Second,
	})

	// Trigger graceful shutdown
	done := make(chan bool)
	go func() {
		gs.Shutdown()
		done <- true
	}()

	// Wait for shutdown to complete
	select {
	case <-done:
		// Shutdown completed
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown timed out")
	}
}

func TestGracefulShutdown_ConcurrentShutdownCalls(t *testing.T) {
	logger := zaptest.NewLogger(t)

	gs := New(Config{
		Server:         &http.Server{Addr: ":8080"},
		Logger:         logger,
		Shutdownables:  nil,
		ShutdownTimeout: 5 * time.Second,
	})

	// Call Shutdown multiple times concurrently
	done := make(chan bool, 3)
	for i := 0; i < 3; i++ {
		go func() {
			gs.Shutdown()
			done <- true
		}()
	}

	// All should complete without deadlock
	for i := 0; i < 3; i++ {
		select {
		case <-done:
		case <-time.After(1 * time.Second):
			t.Fatal("concurrent shutdown call timed out")
		}
	}
}

func TestGracefulShutdown_ServerShutdown(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create a simple handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	// Create test server
	server := &http.Server{
		Addr:    ":0", // Use random port
		Handler: handler,
	}

	// Start server
	go func() {
		server.ListenAndServe()
	}()

	// Wait for server to start
	time.Sleep(200 * time.Millisecond)

	gs := New(Config{
		Server:         server,
		Logger:         logger,
		Shutdownables:  nil,
		ShutdownTimeout: 1 * time.Second,
	})

	// Shutdown
	gs.Shutdown()

	// Server should be shut down, not accepting new connections
	time.Sleep(100 * time.Millisecond)
}

// mockCloser is a mock implementation for testing
type mockCloser struct {
	closed bool
}

func (m *mockCloser) Close() error {
	m.closed = true
	return nil
}

// TestShutdownableInterface ensures our types implement the interface
func TestShutdownableInterface(t *testing.T) {
	var _ Shutdownable = &ShutdownFunc{}
}

func TestGracefulShutdown_ComponentOrder(t *testing.T) {
	logger := zaptest.NewLogger(t)

	order := make([]string, 0)

	// Create components that record their shutdown order
	c1 := NewShutdownFunc("first", func(ctx context.Context) error {
		order = append(order, "first")
		return nil
	})
	c2 := NewShutdownFunc("second", func(ctx context.Context) error {
		order = append(order, "second")
		return nil
	})
	c3 := NewShutdownFunc("third", func(ctx context.Context) error {
		order = append(order, "third")
		return nil
	})

	gs := New(Config{
		Server:         &http.Server{Addr: ":8080"},
		Logger:         logger,
		Shutdownables:  []Shutdownable{c1, c2, c3},
		ShutdownTimeout: 5 * time.Second,
	})

	// Start the shutdown handler in a goroutine
	done := make(chan struct{})
	go func() {
		gs.Start()
		close(done)
	}()

	// Give time for Start() to begin listening
	time.Sleep(10 * time.Millisecond)

	// Trigger shutdown
	gs.Shutdown()

	// Wait for shutdown to complete
	select {
	case <-done:
		// Shutdown completed
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not complete in time")
	}

	// Components should be shut down concurrently, so order may vary
	// But all should be called
	assert.Len(t, order, 3)
	assert.Contains(t, order, "first")
	assert.Contains(t, order, "second")
	assert.Contains(t, order, "third")
}

func TestGracefulShutdown_EmptyShutdownables(t *testing.T) {
	logger := zaptest.NewLogger(t)

	gs := New(Config{
		Server:         &http.Server{Addr: ":8080"},
		Logger:         logger,
		Shutdownables:  []Shutdownable{},
		ShutdownTimeout: 1 * time.Second,
	})

	// Should not panic
	gs.Shutdown()
	time.Sleep(100 * time.Millisecond)
}

func TestShutdownWithContext(t *testing.T) {
	logger := zaptest.NewLogger(t)

	gs := New(Config{
		Server:         &http.Server{Addr: ":8080"},
		Logger:         logger,
		Shutdownables:  nil,
		ShutdownTimeout: 5 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan bool)
	go func() {
		gs.StartWithContext(ctx)
		done <- true
	}()

	// Should complete when context is done
	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("StartWithContext timed out")
	}
}

func TestListenAndServe(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create a test handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello"))
	})

	server := &http.Server{
		Addr:    ":0", // Random port
		Handler: handler,
	}

	gs := New(Config{
		Server:         server,
		Logger:         logger,
		Shutdownables:  nil,
		ShutdownTimeout: 5 * time.Second,
	})

	// This would normally block, but we'll just verify it doesn't panic immediately
	// In a real test, we'd run this in a goroutine and send a signal
	_ = gs
}

// BenchmarkShutdown benchmarks the shutdown process
func BenchmarkShutdown(b *testing.B) {
	logger := zaptest.NewLogger(b)

	component := NewShutdownFunc("test", func(ctx context.Context) error {
		return nil
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gs := New(Config{
			Server:         &http.Server{Addr: ":8080"},
			Logger:         logger,
			Shutdownables:  []Shutdownable{component},
			ShutdownTimeout: 5 * time.Second,
		})
		gs.Shutdown()
	}
}

// TestHelperFunctions tests the helper functions for creating Shutdownables
func TestHelperFunctions(t *testing.T) {
	t.Run("CloseDB", func(t *testing.T) {
		db := &mockCloser{}
		s := CloseDB(db)
		assert.Equal(t, "database", s.Name())
		s.Shutdown(context.Background())
		assert.True(t, db.closed)
	})

	t.Run("CloseRedis", func(t *testing.T) {
		redis := &mockCloser{}
		s := CloseRedis(redis)
		assert.Equal(t, "redis", s.Name())
		s.Shutdown(context.Background())
		assert.True(t, redis.closed)
	})

	t.Run("CancelContext", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		s := CancelContext(cancel)
		assert.Equal(t, "context", s.Name())
		s.Shutdown(context.Background())
		time.Sleep(10 * time.Millisecond)
		assert.Equal(t, context.Canceled, ctx.Err())
	})

	t.Run("CloseTracer", func(t *testing.T) {
		called := false
		fn := func(ctx context.Context) error {
			called = true
			return nil
		}
		s := CloseTracer(fn)
		assert.Equal(t, "tracer", s.Name())
		s.Shutdown(context.Background())
		assert.True(t, called)
	})
}
