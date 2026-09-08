package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/agent"
)

// A device that is waiting for an administrator looked, to its user, exactly
// like one that was broken: Status() reports what is on disk and nothing about
// what the server allows. These cases pin the four answers the UI has to be
// able to tell apart — waiting, working, revoked, and "I could not ask" — and
// the one thing that must never happen, which is any of them being reported as
// an error the caller swallows.

// stateServer answers GET /agent/config with the given status and trust, or a
// 403 when revoked is set.
func stateServer(t *testing.T, status string, trusted, revoked bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/access/agent/config" {
			http.NotFound(w, r)
			return
		}
		if revoked {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"agent has been revoked"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"checks":            []any{},
			"report_interval":   "5m",
			"enrollment_status": status,
			"device_trusted":    trusted,
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// enrolledEngine writes an agent config pointing at serverURL and returns an
// engine over it.
func enrolledEngine(t *testing.T, serverURL string) *Engine {
	t.Helper()
	e := newTestEngine(t, &fakeBackend{})
	cfg := &agent.AgentConfig{
		ServerURL: serverURL,
		AgentID:   "agent-1",
		DeviceID:  "device-1",
		AuthToken: "agent-secret",
	}
	if err := cfg.Save(e.configDir); err != nil {
		t.Fatalf("save agent config: %v", err)
	}
	e.serverURL = serverURL
	return e
}

func decodeState(t *testing.T, out string, err error) deviceStatePayload {
	t.Helper()
	if err != nil {
		t.Fatalf("DeviceState returned an error instead of a state: %v", err)
	}
	var st deviceStatePayload
	if uerr := json.Unmarshal([]byte(out), &st); uerr != nil {
		t.Fatalf("DeviceState did not return JSON (%q): %v", out, uerr)
	}
	return st
}

func TestDeviceStateReportsWhatTheServerAllows(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      string
		trusted     bool
		wantState   string
		wantTrusted bool
	}{
		{"waiting for an administrator", "pending", false, "pending", false},
		{"enrolled and working", "active", false, "active", false},
		{"trusted", "active", true, "active", true},
		{"held", "suspended", false, "suspended", false},
		// Trust without an active status is not trust. The server should not
		// send that pair; if it does, the client must not render Tier 2.
		{"trusted but not active", "pending", true, "pending", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := stateServer(t, tc.status, tc.trusted, false)
			e := enrolledEngine(t, srv.URL)

			out, derr := e.DeviceState()
			st := decodeState(t, out, derr)
			if !st.Enrolled {
				t.Error("enrolled = false for a device with an agent config")
			}
			if !st.ServerReachable {
				t.Error("server_reachable = false against a live server")
			}
			if st.State != tc.wantState {
				t.Errorf("state = %q, want %q", st.State, tc.wantState)
			}
			if st.DeviceTrusted != tc.wantTrusted {
				t.Errorf("device_trusted = %v, want %v", st.DeviceTrusted, tc.wantTrusted)
			}
		})
	}
}

// TestDeviceStateReportsRevoked: the 403 that means "an administrator took this
// device off the fleet" is a state, not a failure. Reported as an error it
// would reach the user as "something went wrong, try again", which is the one
// thing that will never help.
func TestDeviceStateReportsRevoked(t *testing.T) {
	srv := stateServer(t, "", false, true)
	e := enrolledEngine(t, srv.URL)

	out, derr := e.DeviceState()
	st := decodeState(t, out, derr)
	if st.State != "revoked" {
		t.Errorf("state = %q, want revoked", st.State)
	}
	if !st.ServerReachable {
		t.Error("server_reachable = false; the server answered, it just said no")
	}
	if st.DeviceTrusted {
		t.Error("a revoked device is reported as trusted")
	}
}

func TestDeviceStateWhenNotEnrolled(t *testing.T) {
	e := newTestEngine(t, &fakeBackend{})

	out, derr := e.DeviceState()
	st := decodeState(t, out, derr)
	if st.State != "not_enrolled" {
		t.Errorf("state = %q, want not_enrolled", st.State)
	}
	if st.Enrolled {
		t.Error("enrolled = true on a machine with no agent config")
	}
}

// TestDeviceStateWhenTheServerIsUnreachable keeps "I could not ask" distinct
// from "the answer is no". A phone in a lift must not be told it has been
// revoked.
func TestDeviceStateWhenTheServerIsUnreachable(t *testing.T) {
	// A port nothing is listening on.
	e := enrolledEngine(t, "http://127.0.0.1:1")
	e.logger = zap.NewNop()

	out, derr := e.DeviceState()
	st := decodeState(t, out, derr)
	if st.State != "unknown" {
		t.Errorf("state = %q, want unknown", st.State)
	}
	if st.ServerReachable {
		t.Error("server_reachable = true against a closed port")
	}
	if !st.Enrolled {
		t.Error("enrolled = false; the local config still says it is")
	}
	if st.Error == "" {
		t.Error("no reason given for the unknown state")
	}
}

// TestDeviceStateAgainstAnOlderServer: a server that does not send the field
// yet must produce "unknown", never a confident "active". The client would
// otherwise promise a tier the server never granted.
func TestDeviceStateAgainstAnOlderServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"checks":[],"report_interval":"5m"}`))
	}))
	t.Cleanup(srv.Close)
	e := enrolledEngine(t, srv.URL)

	out, derr := e.DeviceState()
	st := decodeState(t, out, derr)
	if st.State != "unknown" {
		t.Errorf("state = %q, want unknown from a server that does not report it", st.State)
	}
	if st.DeviceTrusted {
		t.Error("device_trusted = true from a server that said nothing about trust")
	}
}
