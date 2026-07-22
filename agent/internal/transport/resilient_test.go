package transport

import (
	"errors"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
)

// fakeTransport is a programmable Transport for testing ResilientTransport.
type fakeTransport struct {
	name        string
	getConfig   func() ([]byte, error)
	report      func([]byte) error
	dialErr     error
	callsConfig int
}

func (f *fakeTransport) Enroll(string) (*EnrollResponse, error) { return &EnrollResponse{}, nil }
func (f *fakeTransport) ReportResults(d []byte) error {
	if f.report != nil {
		return f.report(d)
	}
	return nil
}
func (f *fakeTransport) GetConfig() ([]byte, error) {
	f.callsConfig++
	if f.getConfig != nil {
		return f.getConfig()
	}
	return []byte(f.name), nil
}
func (f *fakeTransport) SendConsent(string, string) error { return nil }
func (f *fakeTransport) DialServiceConn(string) (net.Conn, error) {
	return nil, f.dialErr
}

func TestResilient_PrefersZitiWhenHealthy(t *testing.T) {
	ziti := &fakeTransport{name: "ziti"}
	https := &fakeTransport{name: "https"}
	r := NewResilientTransport(ziti, https, zap.NewNop())

	got, err := r.GetConfig()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if string(got) != "ziti" {
		t.Fatalf("expected ziti path, got %q", got)
	}
	if https.callsConfig != 0 {
		t.Fatalf("https should not have been called")
	}
}

func TestResilient_FallsBackOnOverlayFailure(t *testing.T) {
	ziti := &fakeTransport{name: "ziti", getConfig: func() ([]byte, error) {
		return nil, errors.New("unable to dial service 'openidx-access' (NO_EDGE_ROUTERS_AVAILABLE)")
	}}
	https := &fakeTransport{name: "https"}
	r := NewResilientTransport(ziti, https, zap.NewNop())

	got, err := r.GetConfig()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if string(got) != "https" {
		t.Fatalf("expected https fallback, got %q", got)
	}

	// Cooldown must now keep us on HTTPS without re-hitting Ziti.
	zitiCallsBefore := ziti.callsConfig
	if _, err := r.GetConfig(); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if ziti.callsConfig != zitiCallsBefore {
		t.Fatalf("ziti should be in cooldown, but was retried")
	}
}

func TestResilient_DoesNotMaskApplicationErrors(t *testing.T) {
	appErr := errors.New("401 unauthorized")
	ziti := &fakeTransport{name: "ziti", getConfig: func() ([]byte, error) {
		return nil, appErr
	}}
	https := &fakeTransport{name: "https"}
	r := NewResilientTransport(ziti, https, zap.NewNop())

	// A genuine application error must surface, NOT silently retry over HTTPS
	// (which could have different auth semantics).
	_, err := r.GetConfig()
	if err == nil {
		t.Fatalf("expected application error to surface")
	}
	if https.callsConfig != 0 {
		t.Fatalf("https must not be called on application error")
	}
}

func TestResilient_RecoversAfterCooldown(t *testing.T) {
	failing := true
	ziti := &fakeTransport{name: "ziti", getConfig: func() ([]byte, error) {
		if failing {
			return nil, errors.New("NO_EDGE_ROUTERS_AVAILABLE")
		}
		return []byte("ziti"), nil
	}}
	https := &fakeTransport{name: "https"}
	r := NewResilientTransport(ziti, https, zap.NewNop())

	if _, err := r.GetConfig(); err != nil { // trips cooldown
		t.Fatal(err)
	}
	// Simulate overlay recovery + cooldown expiry.
	failing = false
	r.mu.Lock()
	r.zitiCooldown = time.Now().Add(-time.Second)
	r.mu.Unlock()

	got, err := r.GetConfig()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ziti" {
		t.Fatalf("expected recovery to ziti, got %q", got)
	}
}

func TestResilient_NilZitiActsAsHTTPS(t *testing.T) {
	https := &fakeTransport{name: "https"}
	r := NewResilientTransport(nil, https, zap.NewNop())
	got, err := r.GetConfig()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "https" {
		t.Fatalf("expected https, got %q", got)
	}
	if _, err := r.DialServiceConn("x"); err == nil {
		t.Fatalf("expected DialServiceConn error with no ziti")
	}
}
