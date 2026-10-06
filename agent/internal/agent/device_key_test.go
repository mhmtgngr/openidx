//go:build !windows

package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/devicekey"
)

// keyServer is an access service that takes device keys and checks report
// signatures against the key it holds.
type keyServer struct {
	mu          sync.Mutex
	held        *ecdsa.PublicKey
	support     bool
	registers   int
	reports     int
	signedOK    int
	unsignedRep int
}

func (s *keyServer) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		defer s.mu.Unlock()
		switch r.URL.Path {
		case "/api/v1/access/agent/config":
			_, _ = w.Write([]byte(`{"checks":[{"type":"mock_pass","severity":"low"}],"report_interval":"1h"}`))
		case "/api/v1/access/agent/device-key":
			if !s.support {
				http.NotFound(w, r)
				return
			}
			s.registers++
			var req struct {
				PublicKey string `json:"public_key"`
			}
			_ = json.Unmarshal(body, &req)
			der, _ := base64.StdEncoding.DecodeString(req.PublicKey)
			pub, err := x509.ParsePKIXPublicKey(der)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			s.held = pub.(*ecdsa.PublicKey)
			w.WriteHeader(http.StatusCreated)
		case "/api/v1/access/agent/report":
			s.reports++
			ts := r.Header.Get(devicekey.HeaderTimestamp)
			sig, _ := base64.StdEncoding.DecodeString(r.Header.Get(devicekey.HeaderSignature))
			if ts == "" || len(sig) == 0 {
				s.unsignedRep++
				w.WriteHeader(http.StatusAccepted)
				return
			}
			unix, _ := strconv.ParseInt(ts, 10, 64)
			in, err := devicekey.RequestSigningInput(r.Method, r.URL.Path, r.Header.Get("X-Agent-ID"), unix, body)
			d := sha256.Sum256(in)
			if err == nil && s.held != nil && ecdsa.VerifyASN1(s.held, d[:], sig) {
				s.signedOK++
			}
			w.WriteHeader(http.StatusAccepted)
		default:
			http.NotFound(w, r)
		}
	}
}

func newKeyAgent(t *testing.T, srv *httptest.Server) (*Agent, string) {
	t.Helper()
	dir := t.TempDir()
	saveTestConfig(t, dir, &AgentConfig{ServerURL: srv.URL, AgentID: "agent-key-1", DeviceID: "d", AuthToken: "tok"})
	a, err := NewAgent(zap.NewNop(), dir)
	if err != nil {
		t.Fatal(err)
	}
	a.registry.Register("mock_pass", &mockPassCheck{name: "mock_pass"})
	return a, dir
}

// A device offers its key once, the server holds it, and every report from
// then on carries a signature that verifies against it.
func TestTheDeviceKeyIsOfferedOnceAndSignsEveryReport(t *testing.T) {
	ks := &keyServer{support: true}
	srv := httptest.NewServer(ks.handler(t))
	defer srv.Close()
	a, dir := newKeyAgent(t, srv)

	for i := 0; i < 3; i++ {
		if err := a.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if ks.registers != 1 {
		t.Fatalf("the key was offered %d times, want once", ks.registers)
	}
	if ks.signedOK != 3 || ks.unsignedRep != 0 {
		t.Fatalf("signed and verified %d of %d reports (%d unsigned)", ks.signedOK, ks.reports, ks.unsignedRep)
	}
	cfg, err := LoadConfig(dir)
	if err != nil || !cfg.DeviceKeyBound {
		t.Fatalf("agent.json records that the server holds the key: %+v, %v", cfg, err)
	}
}

// An older server has no device-key endpoint: the agent signs anyway (the
// server ignores the headers), does not mark the key bound, and does not
// offer it again on every cycle.
func TestAnOlderServerIsAskedAgainOnlyLater(t *testing.T) {
	ks := &keyServer{support: false}
	srv := httptest.NewServer(ks.handler(t))
	defer srv.Close()
	a, dir := newKeyAgent(t, srv)

	for i := 0; i < 2; i++ {
		if err := a.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if ks.reports != 2 || ks.unsignedRep != 0 {
		t.Fatalf("reports %d, unsigned %d: reports are signed whether or not the server holds the key",
			ks.reports, ks.unsignedRep)
	}
	cfg, _ := LoadConfig(dir)
	if cfg.DeviceKeyBound {
		t.Fatal("an unsupported registration must not be recorded as bound")
	}
}

// A device that cannot make a key reports unsigned, as before.
func TestNoKeyMeansUnsignedReportsNotAFailure(t *testing.T) {
	ks := &keyServer{support: true}
	srv := httptest.NewServer(ks.handler(t))
	defer srv.Close()
	old := openDeviceKey
	openDeviceKey = func(string) (devicekey.Key, error) { return nil, errors.New("no key store") }
	t.Cleanup(func() { openDeviceKey = old })
	a, _ := newKeyAgent(t, srv)

	if err := a.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ks.unsignedRep != 2 || ks.registers != 0 {
		t.Fatalf("unsigned %d, registrations %d", ks.unsignedRep, ks.registers)
	}
}

// The tray's remote-support loop never loads or offers the machine key.
func TestTheTraysLoopHasNoDeviceKey(t *testing.T) {
	ks := &keyServer{support: true}
	srv := httptest.NewServer(ks.handler(t))
	defer srv.Close()
	a, _ := newKeyAgent(t, srv)
	a.RemoteSupportOnly = true
	if err := a.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.deviceKey != nil || ks.registers != 0 {
		t.Fatal("the tray's loop must not touch the device key")
	}
}
