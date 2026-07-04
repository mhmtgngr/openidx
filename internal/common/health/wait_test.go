package health

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestWaitForDependency_SucceedsAfterRetries(t *testing.T) {
	calls := 0
	probe := func(ctx context.Context) error {
		calls++
		if calls < 3 {
			return errors.New("not ready")
		}
		return nil
	}

	err := WaitForDependency(context.Background(), zap.NewNop(), "dep", 5, time.Millisecond, probe)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected probe to be called 3 times, got %d", calls)
	}
}

func TestWaitForDependency_FailsAfterAllAttempts(t *testing.T) {
	calls := 0
	probe := func(ctx context.Context) error {
		calls++
		return errors.New("always fails")
	}

	err := WaitForDependency(context.Background(), zap.NewNop(), "dep", 4, time.Millisecond, probe)
	if err == nil {
		t.Fatal("expected an error after all attempts fail")
	}
	if calls != 4 {
		t.Fatalf("expected probe to be called 4 times, got %d", calls)
	}
}

func TestWaitForDependency_ContextAlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	calls := 0
	probe := func(ctx context.Context) error {
		calls++
		return nil
	}

	err := WaitForDependency(ctx, zap.NewNop(), "dep", 3, time.Millisecond, probe)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if calls != 0 {
		t.Fatalf("expected probe not to be called, got %d calls", calls)
	}
}

func TestProbeHTTP_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	probe := ProbeHTTP(srv.URL, time.Second)
	if err := probe(context.Background()); err != nil {
		t.Fatalf("expected nil error for 200 response, got %v", err)
	}
}

func TestProbeHTTP_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	probe := ProbeHTTP(srv.URL, time.Second)
	if err := probe(context.Background()); err == nil {
		t.Fatal("expected an error for 503 response")
	}
}

func TestProbeHTTP_Unreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	url := srv.URL
	srv.Close() // close so the server is unreachable

	probe := ProbeHTTP(url, 200*time.Millisecond)
	if err := probe(context.Background()); err == nil {
		t.Fatal("expected an error for an unreachable server")
	}
}

func TestProbeOPA_HitsHealthEndpoint(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Trailing slash should be trimmed before appending /health.
	probe := ProbeOPA(srv.URL+"/", time.Second)
	if err := probe(context.Background()); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if gotPath != "/health" {
		t.Fatalf("expected OPA probe to hit /health, got %q", gotPath)
	}
}
