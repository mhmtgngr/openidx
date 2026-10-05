package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/checks"
)

// mockPassCheck is a minimal Check implementation that always returns StatusPass.
type mockPassCheck struct {
	name string
}

func (m *mockPassCheck) Name() string { return m.name }
func (m *mockPassCheck) Run(_ context.Context, _ map[string]interface{}) *checks.CheckResult {
	return &checks.CheckResult{
		Status:  checks.StatusPass,
		Score:   1.0,
		Message: "mock check passed",
	}
}

// saveConfig writes an AgentConfig to dir so NewAgent can load it.
func saveTestConfig(t *testing.T, dir string, cfg *AgentConfig) {
	t.Helper()
	require.NoError(t, cfg.Save(dir))
}

func TestAgent_NewAgent(t *testing.T) {
	dir := t.TempDir()

	cfg := &AgentConfig{
		ServerURL:  "http://localhost:9999",
		AgentID:    "agent-test-001",
		DeviceID:   "device-test-001",
		EnrolledAt: "2026-01-01T00:00:00Z",
		AuthToken:  "tok-abc",
	}
	saveTestConfig(t, dir, cfg)

	logger := zap.NewNop()
	a, err := NewAgent(logger, dir)

	require.NoError(t, err)
	require.NotNil(t, a)

	assert.Equal(t, logger, a.logger)
	assert.Equal(t, dir, a.configDir)
	assert.Equal(t, cfg.AgentID, a.config.AgentID)
	assert.Equal(t, cfg.DeviceID, a.config.DeviceID)
	assert.Equal(t, cfg.ServerURL, a.config.ServerURL)
	assert.NotNil(t, a.client)
	assert.NotNil(t, a.registry)
	assert.NotNil(t, a.engine)
	assert.NotNil(t, a.serverCfg)
}

func TestAgent_NewAgent_MissingConfig(t *testing.T) {
	dir := t.TempDir() // no agent.json written

	_, err := NewAgent(zap.NewNop(), dir)
	require.Error(t, err)
}

func TestAgent_RunOnce(t *testing.T) {
	var reportReceived atomic.Bool
	var reportBody []byte

	// Mock server that handles /config and /report.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/access/agent/config":
			serverCfg := ServerConfig{
				Checks: []CheckConfig{
					{Type: "mock_pass", Severity: "low", Interval: "5m"},
				},
				ReportInterval: "5m",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(serverCfg)

		case "/api/v1/access/agent/report":
			var err error
			reportBody, err = func() ([]byte, error) {
				buf := make([]byte, r.ContentLength)
				_, e := r.Body.Read(buf)
				return buf, e
			}()
			_ = err
			reportReceived.Store(true)
			w.WriteHeader(http.StatusOK)

		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfg := &AgentConfig{
		ServerURL:  srv.URL,
		AgentID:    "agent-runonce-001",
		DeviceID:   "device-runonce-001",
		EnrolledAt: "2026-01-01T00:00:00Z",
		AuthToken:  "tok-runonce",
	}
	saveTestConfig(t, dir, cfg)

	a, err := NewAgent(zap.NewNop(), dir)
	require.NoError(t, err)

	// Register the mock check that the server config will request.
	a.registry.Register("mock_pass", &mockPassCheck{name: "mock_pass"})

	ctx := context.Background()
	require.NoError(t, a.RunOnce(ctx))

	assert.True(t, reportReceived.Load(), "expected report to be sent to server")

	// Validate that the report body contains expected fields.
	var payload map[string]interface{}
	require.NoError(t, json.Unmarshal(reportBody, &payload))
	assert.Equal(t, "agent-runonce-001", payload["agent_id"])
	assert.Equal(t, "device-runonce-001", payload["device_id"])

	results, ok := payload["results"].([]interface{})
	require.True(t, ok, "expected results array in payload")
	require.Len(t, results, 1)

	first := results[0].(map[string]interface{})
	assert.Equal(t, "mock_pass", first["check_type"])
	// The outcome is nested under "result", where the server reads it; a flat
	// status is what made every Windows report count as unknown.
	result, ok := first["result"].(map[string]interface{})
	require.True(t, ok, "expected the outcome nested under result")
	assert.Equal(t, string(checks.StatusPass), result["status"])
	assert.NotContains(t, first, "status", "the outcome must not also be sent flat")
}

func TestAgent_SyncConfig_FallbackOnError(t *testing.T) {
	// Server always returns 500 for /config.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	dir := t.TempDir()
	saveTestConfig(t, dir, &AgentConfig{
		ServerURL: srv.URL,
		AgentID:   "agent-fallback",
		DeviceID:  "device-fallback",
		AuthToken: "tok",
	})

	a, err := NewAgent(zap.NewNop(), dir)
	require.NoError(t, err)

	// SyncConfig should return an error but leave serverCfg as the default.
	syncErr := a.SyncConfig(context.Background())
	require.Error(t, syncErr)

	def := DefaultServerConfig()
	assert.Equal(t, def.ReportInterval, a.serverCfg.ReportInterval)
	assert.Len(t, a.serverCfg.Checks, len(def.Checks))
}

// TestAgent_RunOnce_ServerWireShape drives one cycle against the config the
// access service actually sends (agentCheck: name, enabled, check_type,
// severity). Before the agent read check_type, the check below ran as
// "unknown check type" and the report said so.
func TestAgent_RunOnce_ServerWireShape(t *testing.T) {
	var reportBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/access/agent/config":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"checks":[
				{"name":"mock_pass","enabled":true,"check_type":"mock_pass","severity":"high"},
				{"name":"mock_off","enabled":false,"check_type":"mock_off","severity":"low"}],
				"report_interval":"1h","enforcement_policy":"enforce"}`))
		case "/api/v1/access/agent/report":
			reportBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	saveTestConfig(t, dir, &AgentConfig{
		ServerURL: srv.URL,
		AgentID:   "agent-wire-001",
		DeviceID:  "device-wire-001",
		AuthToken: "tok-wire",
	})
	a, err := NewAgent(zap.NewNop(), dir)
	require.NoError(t, err)
	a.registry.Register("mock_pass", &mockPassCheck{name: "mock_pass"})
	a.registry.Register("mock_off", &mockPassCheck{name: "mock_off"})

	require.NoError(t, a.RunOnce(context.Background()))

	var payload struct {
		Results []struct {
			CheckType string `json:"check_type"`
			Severity  string `json:"severity"`
			Result    struct {
				Status  string  `json:"status"`
				Score   float64 `json:"score"`
				Message string  `json:"message"`
			} `json:"result"`
		} `json:"results"`
	}
	require.NoError(t, json.Unmarshal(reportBody, &payload))
	require.Len(t, payload.Results, 1, "the disabled check is not run or reported")
	got := payload.Results[0]
	assert.Equal(t, "mock_pass", got.CheckType)
	assert.Equal(t, "high", got.Severity)
	assert.Equal(t, string(checks.StatusPass), got.Result.Status)
	assert.NotContains(t, got.Result.Message, "unknown check type")
}
