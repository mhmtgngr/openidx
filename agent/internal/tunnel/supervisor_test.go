package tunnel

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const healthyStatus = `{
  "Success": true,
  "Code": 0,
  "Data": {
    "Active": true,
    "ServiceVersion": {"Version": "v1.18.7", "Revision": "abc"},
    "Identities": [{
      "Name": "dev-agent-1", "Identifier": "dev-agent-1.json",
      "Active": true, "Loaded": true,
      "Services": [
        {"Name": "rdp-finance", "Permissions": {"Bind": false, "Dial": true}},
        {"Name": "erp-web", "Permissions": {"Bind": false, "Dial": true}},
        {"Name": "hosted-here", "Permissions": {"Bind": true, "Dial": false}},
        {"Name": "erp-web", "Permissions": {"Bind": false, "Dial": true}}
      ]
    }]
  }
}`

// env is one fake tunneler setup.
type env struct {
	dir, identitySrc, identityDir, statusFile, startsFile string
}

func newEnv(t *testing.T, run string) env {
	t.Helper()
	dir := t.TempDir()
	e := env{
		dir:         dir,
		identitySrc: filepath.Join(dir, "ziti-identity.json"),
		identityDir: filepath.Join(dir, "tunnel", "identities"),
		statusFile:  filepath.Join(dir, "status.json"),
		startsFile:  filepath.Join(dir, "starts.txt"),
	}
	writeFile(t, e.identitySrc, `{"ztAPI":"https://ctrl.example:1280","id":{"cert":"pem:C","key":"pem:K","ca":"pem:A"}}`)
	t.Setenv(fakeEnv, "1")
	t.Setenv(fakeStatusEnv, e.statusFile)
	t.Setenv(fakeStartsEnv, e.startsFile)
	t.Setenv(fakeRunEnv, run)
	return e
}

func (e env) config() Config {
	exe, _ := os.Executable()
	return Config{
		AgentID:        "agent-1",
		IdentitySource: e.identitySrc,
		IdentityDir:    e.identityDir,
		BinaryPath:     exe,
		Mode:           ModeChild,
		LogFile:        filepath.Join(e.dir, "tunnel.log"),
		MinBackoff:     20 * time.Millisecond,
		MaxBackoff:     80 * time.Millisecond,
		StableAfter:    time.Hour,
		PollInterval:   20 * time.Millisecond,
		CommandTimeout: 5 * time.Second,
		StopGrace:      2 * time.Second,
	}
}

func (e env) starts(t *testing.T) []string {
	data, err := os.ReadFile(e.startsFile)
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

func writeFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func runSupervisor(t *testing.T, s *Supervisor) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Run(ctx); close(done) }()
	return func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("supervisor did not stop")
		}
	}
}

func TestDisabledSupervisorIsOffAndStartsNothing(t *testing.T) {
	e := newEnv(t, "stay")
	s := New(e.config())
	stop := runSupervisor(t, s)
	time.Sleep(100 * time.Millisecond)
	stop()
	if got := s.Status(); got.State != StateOff || got.Services == nil {
		t.Fatalf("status = %+v, want off with non-nil services", got)
	}
	if n := len(e.starts(t)); n != 0 {
		t.Fatalf("a disabled supervisor started the tunneler %d times", n)
	}
}

func TestStartsTunnelerWithIdentityDirAndReportsConnected(t *testing.T) {
	e := newEnv(t, "stay")
	writeFile(t, e.statusFile, healthyStatus)
	s := New(e.config())
	s.SetEnabled(true)
	stop := runSupervisor(t, s)
	defer stop()

	eventually(t, "connected", func() bool { return s.Status().State == StateConnected })
	st := s.Status()
	if st.Version != "v1.18.7" {
		t.Errorf("version = %q, want the IPC's v1.18.7", st.Version)
	}
	if want := []string{"erp-web", "rdp-finance"}; strings.Join(st.Services, ",") != strings.Join(want, ",") {
		t.Errorf("services = %v, want %v (dialled, deduplicated, sorted)", st.Services, want)
	}
	if st.LastSeen == nil || time.Since(*st.LastSeen) > time.Minute {
		t.Errorf("last_seen = %v, want recent", st.LastSeen)
	}

	starts := e.starts(t)
	if len(starts) != 1 {
		t.Fatalf("starts = %v, want exactly one", starts)
	}
	want := "run --identity-dir " + e.identityDir + " -P " + IPCDiscriminator
	if starts[0] != want {
		t.Errorf("tunneler args = %q, want %q", starts[0], want)
	}
	copied, err := os.ReadFile(filepath.Join(e.identityDir, "dev-agent-1.json"))
	src, _ := os.ReadFile(e.identitySrc)
	if err != nil || string(copied) != string(src) {
		t.Fatalf("identity copy = %q (%v), want the agent's identity", copied, err)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(filepath.Join(e.identityDir, "dev-agent-1.json")); fi.Mode().Perm() != 0o600 {
			t.Errorf("identity copy mode = %v, want 0600", fi.Mode().Perm())
		}
	}
}

func TestCrashingTunnelerIsRestartedWithBackoff(t *testing.T) {
	e := newEnv(t, "crash")
	cfg := e.config()
	cfg.MinBackoff = 50 * time.Millisecond
	cfg.MaxBackoff = 200 * time.Millisecond
	s := New(cfg)
	s.SetEnabled(true)
	began := time.Now()
	stop := runSupervisor(t, s)

	sawExit := false
	eventually(t, "four starts", func() bool {
		sawExit = sawExit || strings.Contains(s.Detail(), "exited")
		return len(e.starts(t)) >= 4
	})
	elapsed := time.Since(began)
	eventually(t, "an exit reported", func() bool {
		sawExit = sawExit || strings.Contains(s.Detail(), "exited")
		return sawExit
	})
	stop()

	// Three restarts waited 50 + 100 + 200 ms at least.
	if elapsed < 350*time.Millisecond {
		t.Errorf("four starts took %v; the backoff (50, 100, 200 ms) was not applied", elapsed)
	}
	if st := s.Status(); st.State != StateDegraded {
		t.Errorf("a crash-looping tunneler is %q, want degraded", st.State)
	}
}

func TestBackoffDoublesAndCaps(t *testing.T) {
	min, max := time.Second, 10*time.Second
	for n, want := range map[int]time.Duration{1: 1 * time.Second, 2: 2 * time.Second, 3: 4 * time.Second,
		4: 8 * time.Second, 5: 10 * time.Second, 50: 10 * time.Second} {
		if got := backoff(n, min, max); got != want {
			t.Errorf("backoff(%d) = %v, want %v", n, got, want)
		}
	}
}

func TestDisablingStopsTheTunnelerAndRemovesTheIdentityCopy(t *testing.T) {
	e := newEnv(t, "stay")
	writeFile(t, e.statusFile, healthyStatus)
	s := New(e.config())
	s.SetEnabled(true)
	stop := runSupervisor(t, s)
	defer stop()
	eventually(t, "connected", func() bool { return s.Status().State == StateConnected })

	s.SetEnabled(false)
	eventually(t, "off", func() bool { return s.Status().State == StateOff })
	if _, err := os.Stat(filepath.Join(e.identityDir, "dev-agent-1.json")); !os.IsNotExist(err) {
		t.Errorf("the identity copy is still there after the tunnel was turned off (%v)", err)
	}
	if n := len(e.starts(t)); n != 1 {
		t.Errorf("starts = %d, want 1 (no restart after a deliberate stop)", n)
	}

	s.SetEnabled(true)
	eventually(t, "connected again", func() bool { return s.Status().State == StateConnected })
	if n := len(e.starts(t)); n != 2 {
		t.Errorf("starts = %d, want 2 after turning it back on", n)
	}
}

func TestIPCSilenceIsDegradedUnlessTheProbeConnects(t *testing.T) {
	e := newEnv(t, "stay") // no status file: tunnel_status fails
	s := New(e.config())
	s.SetEnabled(true)
	stop := runSupervisor(t, s)
	eventually(t, "a started tunneler", func() bool { return len(e.starts(t)) == 1 })
	eventually(t, "degraded with an IPC reason", func() bool {
		return s.Status().State == StateDegraded && strings.Contains(s.Detail(), "IPC")
	})
	stop()
	if s.Status().LastSeen != nil {
		t.Errorf("last_seen set although nothing answered")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	cfg := e.config()
	cfg.ProbeAddress = ln.Addr().String()
	s2 := New(cfg)
	s2.SetEnabled(true)
	stop2 := runSupervisor(t, s2)
	defer stop2()
	eventually(t, "connected by probe", func() bool { return s2.Status().State == StateConnected })
	if s2.Status().Version != fakeVersion {
		t.Errorf("version = %q, want the `version` command's %q", s2.Status().Version, fakeVersion)
	}
}

func TestMissingBinaryIsNotInstalled(t *testing.T) {
	e := newEnv(t, "stay")
	cfg := e.config()
	cfg.BinaryPath = filepath.Join(e.dir, "nope", BinaryName())
	s := New(cfg)
	s.SetEnabled(true)
	stop := runSupervisor(t, s)
	defer stop()
	eventually(t, "not_installed", func() bool { return s.Status().State == StateNotInstalled })
}

func TestNoDeviceIdentityIsDegradedAndStartsNothing(t *testing.T) {
	e := newEnv(t, "stay")
	cfg := e.config()
	cfg.IdentitySource = filepath.Join(e.dir, "missing.json")
	s := New(cfg)
	s.SetEnabled(true)
	stop := runSupervisor(t, s)
	eventually(t, "degraded", func() bool {
		return s.Status().State == StateDegraded && strings.Contains(s.Detail(), "no enrolled Ziti identity")
	})
	stop()
	if n := len(e.starts(t)); n != 0 {
		t.Errorf("started the tunneler %d times without an identity", n)
	}
}

func TestExternalModeReadsStatusWithoutStartingAnything(t *testing.T) {
	e := newEnv(t, "stay")
	writeFile(t, e.statusFile, healthyStatus)
	cfg := e.config()
	cfg.Mode = ModeExternal
	s := New(cfg)
	s.SetEnabled(true)
	stop := runSupervisor(t, s)
	eventually(t, "connected", func() bool { return s.Status().State == StateConnected })
	stop()
	if n := len(e.starts(t)); n != 0 {
		t.Errorf("external mode started the tunneler %d times", n)
	}
	if _, err := os.Stat(filepath.Join(e.identityDir, "dev-agent-1.json")); err != nil {
		t.Errorf("external mode did not provision the identity: %v", err)
	}
}

func TestStatusMarshalsToTheReportShape(t *testing.T) {
	ts := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	b, err := json.Marshal(Status{State: StateConnected, Version: "v1", LastSeen: &ts, Services: []string{"a"}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"state":"connected","version":"v1","last_seen":"2026-10-10T12:00:00Z","services":["a"]}`
	if string(b) != want {
		t.Errorf("got %s, want %s", b, want)
	}
	b, _ = json.Marshal(New(Config{}).Status())
	if string(b) != `{"state":"off","version":"","last_seen":null,"services":[]}` {
		t.Errorf("initial status = %s", b)
	}
}
