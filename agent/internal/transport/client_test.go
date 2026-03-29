package transport

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_Enroll(t *testing.T) {
	expected := EnrollResponse{
		AgentID:   "agent-abc123",
		DeviceID:  "device-xyz789",
		AuthToken: "tok-supersecret",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/access/agent/enroll", r.URL.Path)
		assert.Equal(t, "Bearer enroll-token", r.Header.Get("Authorization"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(expected)
	}))
	defer server.Close()

	client := NewClient(server.URL, "", "")
	got, err := client.Enroll("enroll-token")

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, expected.AgentID, got.AgentID)
	assert.Equal(t, expected.DeviceID, got.DeviceID)
	assert.Equal(t, expected.AuthToken, got.AuthToken)
}

func TestClient_Enroll_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewClient(server.URL, "", "")
	got, err := client.Enroll("bad-token")

	assert.Error(t, err)
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "401")
}

func TestClient_ReportResults(t *testing.T) {
	payload := []byte(`{"checks":[{"id":"disk","status":"pass"}]}`)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/access/agent/report", r.URL.Path)
		assert.Equal(t, "Bearer auth-token", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	client := NewClient(server.URL, "auth-token", "")
	err := client.ReportResults(payload)

	assert.NoError(t, err)
}

func TestClient_ReportResults_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(server.URL, "auth-token", "")
	err := client.ReportResults([]byte(`{}`))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestClient_GetConfig(t *testing.T) {
	configJSON := []byte(`{"poll_interval":60,"checks":["disk","memory","process"]}`)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/access/agent/config", r.URL.Path)
		assert.Equal(t, "Bearer auth-token", r.Header.Get("Authorization"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(configJSON)
	}))
	defer server.Close()

	client := NewClient(server.URL, "auth-token", "")
	body, err := client.GetConfig()

	require.NoError(t, err)
	assert.Equal(t, configJSON, body)
}

func TestClient_GetConfig_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewClient(server.URL, "auth-token", "")
	body, err := client.GetConfig()

	assert.Error(t, err)
	assert.Nil(t, body)
	assert.Contains(t, err.Error(), "404")
}

func TestClient_ReportResults_SendsAgentIDHeader(t *testing.T) {
	var gotAgentID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAgentID = r.Header.Get("X-Agent-ID")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	client := NewClient(server.URL, "auth-token", "agent-test-001")
	err := client.ReportResults([]byte(`{}`))

	require.NoError(t, err)
	assert.Equal(t, "agent-test-001", gotAgentID)
}

func TestClient_GetConfig_SendsAgentIDHeader(t *testing.T) {
	var gotAgentID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAgentID = r.Header.Get("X-Agent-ID")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "auth-token", "agent-test-002")
	_, err := client.GetConfig()

	require.NoError(t, err)
	assert.Equal(t, "agent-test-002", gotAgentID)
}
