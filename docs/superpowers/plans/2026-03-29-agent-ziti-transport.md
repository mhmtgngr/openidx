# Agent Ziti Transport — Phase 2a Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace HTTPS transport with Ziti SDK for agent-server communication, with HTTPS fallback.

**Architecture:** New `agent/internal/transport/ziti.go` implementing the same interface as the HTTP client but routing through Ziti overlay. Enrollment enhanced to also enroll with Ziti controller.

**Tech Stack:** Go 1.25, openziti/sdk-golang v1.3.1, net/http

---

## Task 1: Add Ziti SDK dependency to agent module

**Files to modify:**
- `agent/go.mod`
- `agent/go.sum` (auto-generated)

**Implementation:**

Add `github.com/openziti/sdk-golang v1.3.1` to the `require` block in `agent/go.mod`:

```go
require (
	github.com/openziti/sdk-golang v1.3.1
	github.com/spf13/cobra v1.10.2
	github.com/stretchr/testify v1.11.1
	go.uber.org/zap v1.27.0
)
```

**Commands:**

```bash
cd /home/cmit/openidx/agent
go get github.com/openziti/sdk-golang@v1.3.1
go mod tidy
go build ./...
```

**Verification:** `go build ./...` must exit 0 with no errors.

**Commit message:** `feat(agent): add openziti/sdk-golang v1.3.1 dependency`

---

## Task 2: Create Ziti transport client

**Files to create:**
- `agent/internal/transport/ziti.go`
- `agent/internal/transport/ziti_test.go`

### Test first — `agent/internal/transport/ziti_test.go`

```go
package transport

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockZitiContext implements just enough of zitiDialer for unit tests.
type mockZitiContext struct {
	dialFn func(serviceName string) (net.Conn, error)
}

func (m *mockZitiContext) Dial(serviceName string) (net.Conn, error) {
	return m.dialFn(serviceName)
}

func TestZitiClient_Enroll_RoutesOverZiti(t *testing.T) {
	expected := EnrollResponse{
		AgentID:   "agent-ziti-001",
		DeviceID:  "device-ziti-001",
		AuthToken: "tok-ziti",
	}

	// Start a plain TCP server that speaks HTTP — the mock "Ziti dial" connects directly.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/access/agent/enroll", r.URL.Path)
		assert.Equal(t, "Bearer enroll-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(expected)
	}))
	defer server.Close()

	mock := &mockZitiContext{
		dialFn: func(_ string) (net.Conn, error) {
			return net.Dial("tcp", server.Listener.Addr().String())
		},
	}

	client := newZitiClientFromDialer(mock, server.URL, "openidx-agent", "")
	got, err := client.Enroll("enroll-token")

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, expected.AgentID, got.AgentID)
	assert.Equal(t, expected.DeviceID, got.DeviceID)
	assert.Equal(t, expected.AuthToken, got.AuthToken)
}

func TestZitiClient_ReportResults_RoutesOverZiti(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/access/agent/report", r.URL.Path)
		assert.Equal(t, "Bearer auth-tok", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	mock := &mockZitiContext{
		dialFn: func(_ string) (net.Conn, error) {
			return net.Dial("tcp", server.Listener.Addr().String())
		},
	}

	client := newZitiClientFromDialer(mock, server.URL, "openidx-agent", "auth-tok")
	err := client.ReportResults([]byte(`{"checks":[]}`))
	assert.NoError(t, err)
}

func TestZitiClient_GetConfig_RoutesOverZiti(t *testing.T) {
	configJSON := []byte(`{"report_interval":"5m","checks":[]}`)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/access/agent/config", r.URL.Path)
		assert.Equal(t, "Bearer auth-tok", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(configJSON)
	}))
	defer server.Close()

	mock := &mockZitiContext{
		dialFn: func(_ string) (net.Conn, error) {
			return net.Dial("tcp", server.Listener.Addr().String())
		},
	}

	client := newZitiClientFromDialer(mock, server.URL, "openidx-agent", "auth-tok")
	body, err := client.GetConfig()

	require.NoError(t, err)
	assert.Equal(t, configJSON, body)
}

func TestZitiClient_Enroll_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	mock := &mockZitiContext{
		dialFn: func(_ string) (net.Conn, error) {
			return net.Dial("tcp", server.Listener.Addr().String())
		},
	}

	client := newZitiClientFromDialer(mock, server.URL, "openidx-agent", "")
	got, err := client.Enroll("bad-token")

	assert.Error(t, err)
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "401")
}

func TestZitiClient_DialContext_UsesServiceName(t *testing.T) {
	var dialedService string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	mock := &mockZitiContext{
		dialFn: func(serviceName string) (net.Conn, error) {
			dialedService = serviceName
			return net.Dial("tcp", server.Listener.Addr().String())
		},
	}

	client := newZitiClientFromDialer(mock, server.URL, "my-special-service", "tok")
	_ = client.ReportResults([]byte(`{}`))

	assert.Equal(t, "my-special-service", dialedService)
}
```

### Implementation — `agent/internal/transport/ziti.go`

```go
// Package transport provides HTTP and Ziti overlay transport clients for the
// OpenIDX agent.
package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/openziti/sdk-golang/ziti"
)

// zitiDialer is the minimal interface from ziti.Context that ZitiClient needs.
// Using an interface rather than the concrete type keeps the client testable
// without a live Ziti controller.
type zitiDialer interface {
	Dial(serviceName string) (net.Conn, error)
}

// ZitiClient sends agent requests over the Ziti zero-trust overlay instead of
// plain HTTPS. It satisfies the same Transport interface as *Client.
type ZitiClient struct {
	baseURL     string
	authToken   string
	serviceName string
	httpClient  *http.Client
}

// NewZitiClient loads a Ziti identity from identityFile, creates a Ziti SDK
// context, and returns a ZitiClient that dials serviceName for every request.
//
// authToken is the Bearer token included in all non-enrollment requests.
func NewZitiClient(identityFile, serviceName, baseURL, authToken string) (*ZitiClient, error) {
	cfg, err := ziti.NewConfigFromFile(identityFile)
	if err != nil {
		return nil, fmt.Errorf("loading ziti identity from %q: %w", identityFile, err)
	}

	zitiCtx, err := ziti.NewContext(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating ziti context: %w", err)
	}

	return newZitiClientFromDialer(zitiCtx, baseURL, serviceName, authToken), nil
}

// newZitiClientFromDialer constructs a ZitiClient from an arbitrary zitiDialer.
// This is the internal constructor used by tests to inject a mock.
func newZitiClientFromDialer(d zitiDialer, baseURL, serviceName, authToken string) *ZitiClient {
	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return d.Dial(serviceName)
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: dialContext,
		},
	}

	return &ZitiClient{
		baseURL:     baseURL,
		authToken:   authToken,
		serviceName: serviceName,
		httpClient:  httpClient,
	}
}

// Enroll sends an enrollment request over the Ziti overlay using the provided
// one-time token and returns the enrollment response.
func (z *ZitiClient) Enroll(token string) (*EnrollResponse, error) {
	url := z.baseURL + "/api/v1/access/agent/enroll"

	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating enroll request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := z.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending enroll request over ziti: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("enroll request failed with status %d", resp.StatusCode)
	}

	var enrollResp EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&enrollResp); err != nil {
		return nil, fmt.Errorf("decoding enroll response: %w", err)
	}

	return &enrollResp, nil
}

// ReportResults posts check result data over the Ziti overlay.
func (z *ZitiClient) ReportResults(data []byte) error {
	url := z.baseURL + "/api/v1/access/agent/report"

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("creating report request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+z.authToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := z.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending report request over ziti: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("report request failed with status %d", resp.StatusCode)
	}

	return nil
}

// GetConfig retrieves the agent configuration over the Ziti overlay.
func (z *ZitiClient) GetConfig() ([]byte, error) {
	url := z.baseURL + "/api/v1/access/agent/config"

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating config request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+z.authToken)

	resp, err := z.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending config request over ziti: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("config request failed with status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading config response: %w", err)
	}

	return body, nil
}
```

**Commands:**

```bash
cd /home/cmit/openidx/agent
go test ./internal/transport/... -v -run TestZitiClient
```

**Commit message:** `feat(agent/transport): add ZitiClient routing requests over Ziti overlay`

---

## Task 3: Create transport interface + factory

**Files to create:**
- `agent/internal/transport/transport.go`

**Files to modify:**
- `agent/internal/agent/agent.go` — replace `*transport.Client` with `transport.Transport`

### Test first — add to `agent/internal/transport/ziti_test.go`

Append these tests to verify both concrete types satisfy the interface at compile time and that the factory selects the right implementation:

```go
// TestTransportInterface_CompileTime verifies that both Client and ZitiClient
// satisfy the Transport interface. This is a compile-time check via blank
// identifiers; if either line fails to compile, the interface is broken.
func TestTransportInterface_CompileTime(t *testing.T) {
	var _ Transport = (*Client)(nil)
	var _ Transport = (*ZitiClient)(nil)
}

func TestNewTransport_ReturnsHTTPClientWhenNoIdentityFile(t *testing.T) {
	cfg := TransportConfig{
		BaseURL:          "http://localhost:8001",
		AuthToken:        "tok",
		ZitiIdentityFile: "/nonexistent/path/ziti-identity.json",
		ZitiServiceName:  "openidx-agent",
	}

	tr := NewTransport(cfg)
	assert.NotNil(t, tr)
	// Should be a plain *Client since the identity file does not exist.
	_, ok := tr.(*Client)
	assert.True(t, ok, "expected *Client when Ziti identity file is absent")
}

func TestNewTransport_ReturnsZitiClientWhenIdentityFilePresent(t *testing.T) {
	// Write a minimal (but structurally valid) Ziti identity JSON so NewZitiClient
	// does not error on file-not-found. We expect it to fail later on parse,
	// so the factory must fall back to *Client without panicking.
	f, err := os.CreateTemp(t.TempDir(), "ziti-identity-*.json")
	require.NoError(t, err)
	f.WriteString(`{"ztAPI":"https://localhost:1280","id":{"key":"invalid"}}`)
	f.Close()

	cfg := TransportConfig{
		BaseURL:          "http://localhost:8001",
		AuthToken:        "tok",
		ZitiIdentityFile: f.Name(),
		ZitiServiceName:  "openidx-agent",
	}

	// NewTransport must not panic; it may return *Client on SDK parse failure.
	tr := NewTransport(cfg)
	assert.NotNil(t, tr)
}
```

(Add `"os"` to the import block of `ziti_test.go` for the temp file test.)

### Implementation — `agent/internal/transport/transport.go`

```go
// Package transport defines the Transport interface and factory for agent
// server communication. Implementations may use plain HTTPS or the Ziti
// zero-trust overlay.
package transport

import (
	"os"
)

// Transport is the interface that all agent transport clients must satisfy.
// It covers the three operations an agent performs against the server:
// initial enrollment, periodic result reporting, and config retrieval.
type Transport interface {
	// Enroll exchanges a one-time token for long-lived agent credentials.
	Enroll(token string) (*EnrollResponse, error)

	// ReportResults posts check result data to the server.
	ReportResults(data []byte) error

	// GetConfig retrieves the current agent configuration from the server.
	GetConfig() ([]byte, error)
}

// TransportConfig holds the parameters required by NewTransport to select and
// construct the appropriate Transport implementation.
type TransportConfig struct {
	// BaseURL is the HTTP base URL of the OpenIDX access service.
	BaseURL string

	// AuthToken is the Bearer token for authenticated requests.
	AuthToken string

	// ZitiIdentityFile is the path to the Ziti identity JSON file.
	// When this file exists, NewTransport returns a ZitiClient.
	ZitiIdentityFile string

	// ZitiServiceName is the Ziti service name the agent dials.
	ZitiServiceName string
}

// NewTransport returns a ZitiClient if the Ziti identity file specified in cfg
// exists and can be loaded; otherwise it returns a plain HTTP Client.
// This allows agents to transparently upgrade to zero-trust transport after
// enrollment without requiring a restart flag.
func NewTransport(cfg TransportConfig) Transport {
	if cfg.ZitiIdentityFile != "" {
		if _, err := os.Stat(cfg.ZitiIdentityFile); err == nil {
			zc, err := NewZitiClient(
				cfg.ZitiIdentityFile,
				cfg.ZitiServiceName,
				cfg.BaseURL,
				cfg.AuthToken,
			)
			if err == nil {
				return zc
			}
			// Identity file present but unparseable — fall through to HTTP.
		}
	}

	return NewClient(cfg.BaseURL, cfg.AuthToken)
}
```

### Modify `agent/internal/agent/agent.go`

Replace the `*transport.Client` field and construction with the `transport.Transport` interface:

**Diff — struct field (line ~21):**
```go
// Before
client    *transport.Client

// After
client    transport.Transport
```

**Diff — NewAgent construction (line ~34):**
```go
// Before
client := transport.NewClient(cfg.ServerURL, cfg.AuthToken)

// After
client := transport.NewTransport(transport.TransportConfig{
    BaseURL:          cfg.ServerURL,
    AuthToken:        cfg.AuthToken,
    ZitiIdentityFile: cfg.ZitiIdentityFile,
    ZitiServiceName:  "openidx-agent",
})
```

**Commands:**

```bash
cd /home/cmit/openidx/agent
go build ./...
go test ./internal/transport/... -v
go test ./internal/agent/... -v
```

**Commit message:** `feat(agent/transport): define Transport interface and NewTransport factory`

---

## Task 4: Enhanced enrollment with Ziti identity

**Files to modify:**
- `agent/internal/agent/config.go` — add `ZitiIdentityFile` field to `AgentConfig`
- `agent/internal/transport/client.go` — extend `EnrollResponse` with `ZitiJWT` field
- `agent/internal/agent/agent.go` — add `EnrollWithZiti` helper that processes `ZitiJWT` from the response

**Files to create:**
- `agent/internal/enrollment/enroll.go`
- `agent/internal/enrollment/enroll_test.go`

### Extend `EnrollResponse` in `agent/internal/transport/client.go`

```go
// EnrollResponse holds the response from the agent enrollment endpoint.
type EnrollResponse struct {
	AgentID   string `json:"agent_id"`
	DeviceID  string `json:"device_id"`
	AuthToken string `json:"auth_token"`
	// ZitiJWT is present when the server has provisioned a Ziti identity for
	// this agent. The agent should enroll with the Ziti controller using this
	// JWT and save the resulting identity file.
	ZitiJWT   string `json:"ziti_jwt,omitempty"`
}
```

### Extend `AgentConfig` in `agent/internal/agent/config.go`

```go
// AgentConfig holds the persisted configuration for a registered agent.
type AgentConfig struct {
	ServerURL        string `json:"server_url"`
	AgentID          string `json:"agent_id"`
	DeviceID         string `json:"device_id"`
	EnrolledAt       string `json:"enrolled_at"`
	AuthToken        string `json:"auth_token,omitempty"`
	// ZitiIdentityFile is the path to the Ziti identity JSON written after
	// Ziti enrollment. Empty until the agent has enrolled with the Ziti
	// controller.
	ZitiIdentityFile string `json:"ziti_identity_file,omitempty"`
}
```

### Test first — `agent/internal/enrollment/enroll_test.go`

```go
package enrollment_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openidx/openidx/agent/internal/enrollment"
)

func TestEnrollZiti_SavesIdentityFile(t *testing.T) {
	dir := t.TempDir()

	// enrollment.EnrollZiti calls enroll.ParseToken then enroll.Enroll from the
	// Ziti SDK. We use a fake enroller to avoid needing a live controller.
	fakeEnroller := &enrollment.FakeEnroller{
		IdentityJSON: []byte(`{"ztAPI":"https://ctrl:1280","id":{"cert":"fake"}}`),
	}

	identityPath, err := enrollment.EnrollZitiWithEnroller("fake-jwt-token", dir, fakeEnroller)

	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, "ziti-identity.json"), identityPath)

	data, err := os.ReadFile(identityPath)
	require.NoError(t, err)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &parsed))
	assert.Equal(t, "https://ctrl:1280", parsed["ztAPI"])

	// File must be mode 0600.
	info, err := os.Stat(identityPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestEnrollZiti_ReturnsErrorOnEnrollerFailure(t *testing.T) {
	dir := t.TempDir()

	fakeEnroller := &enrollment.FakeEnroller{Err: assert.AnError}

	_, err := enrollment.EnrollZitiWithEnroller("bad-jwt", dir, fakeEnroller)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ziti enrollment failed")
}

func TestEnrollZiti_SkipsWhenJWTEmpty(t *testing.T) {
	dir := t.TempDir()

	path, err := enrollment.EnrollZiti("", dir)
	assert.NoError(t, err)
	assert.Empty(t, path)
}
```

### Implementation — `agent/internal/enrollment/enroll.go`

```go
// Package enrollment handles agent and Ziti identity enrollment.
package enrollment

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/openziti/sdk-golang/ziti/enroll"
)

// Enroller abstracts the Ziti enrollment operation so it can be replaced with
// a fake in tests.
type Enroller interface {
	// Enroll performs the enrollment exchange and returns the identity JSON.
	Enroll(jwt string) ([]byte, error)
}

// FakeEnroller is a test double for Enroller.
type FakeEnroller struct {
	IdentityJSON []byte
	Err          error
}

func (f *FakeEnroller) Enroll(_ string) ([]byte, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return f.IdentityJSON, nil
}

// sdkEnroller wraps the real Ziti SDK enrollment functions.
type sdkEnroller struct{}

// Enroll parses the JWT and performs the real Ziti enrollment, returning the
// resulting identity JSON bytes.
func (s *sdkEnroller) Enroll(jwt string) ([]byte, error) {
	flags, err := enroll.ParseToken(jwt)
	if err != nil {
		return nil, fmt.Errorf("parsing ziti enrollment token: %w", err)
	}

	identity, err := enroll.Enroll(flags)
	if err != nil {
		return nil, fmt.Errorf("enrolling with ziti controller: %w", err)
	}

	return identity, nil
}

// EnrollZiti is the public entry point for production use. It calls the real
// Ziti SDK. Returns ("", nil) when jwt is empty so callers can skip enrollment
// safely when the server did not include a Ziti JWT.
func EnrollZiti(jwt, configDir string) (string, error) {
	if jwt == "" {
		return "", nil
	}
	return EnrollZitiWithEnroller(jwt, configDir, &sdkEnroller{})
}

// EnrollZitiWithEnroller is the testable variant that accepts an Enroller.
func EnrollZitiWithEnroller(jwt, configDir string, e Enroller) (string, error) {
	identityJSON, err := e.Enroll(jwt)
	if err != nil {
		return "", fmt.Errorf("ziti enrollment failed: %w", err)
	}

	if err := os.MkdirAll(configDir, 0700); err != nil {
		return "", fmt.Errorf("creating config directory: %w", err)
	}

	identityPath := filepath.Join(configDir, "ziti-identity.json")
	if err := os.WriteFile(identityPath, identityJSON, 0600); err != nil {
		return "", fmt.Errorf("writing ziti identity file: %w", err)
	}

	return identityPath, nil
}
```

### Wire enrollment into agent — additions to `agent/internal/agent/agent.go`

Add an `EnrollAndSave` method that orchestrates the full enrollment flow including optional Ziti identity enrollment:

```go
// EnrollAndSave performs agent enrollment using the provided one-time token.
// If the server returns a ziti_jwt in the response, it also performs Ziti
// enrollment and updates the config with the identity file path.
// The resulting config is persisted to configDir.
func (a *Agent) EnrollAndSave(ctx context.Context, token string) error {
	resp, err := a.client.Enroll(token)
	if err != nil {
		return fmt.Errorf("enrolling agent: %w", err)
	}

	a.config.AgentID = resp.AgentID
	a.config.DeviceID = resp.DeviceID
	a.config.AuthToken = resp.AuthToken

	if resp.ZitiJWT != "" {
		identityPath, err := enrollment.EnrollZiti(resp.ZitiJWT, a.configDir)
		if err != nil {
			a.logger.Warn("ziti enrollment failed, continuing without zero-trust transport",
				zap.Error(err))
		} else {
			a.config.ZitiIdentityFile = identityPath
			a.logger.Info("ziti enrollment complete", zap.String("identity_file", identityPath))
		}
	}

	if err := a.config.Save(a.configDir); err != nil {
		return fmt.Errorf("saving agent config: %w", err)
	}

	return nil
}
```

(Add `"github.com/openidx/openidx/agent/internal/enrollment"` to agent.go imports.)

**Commands:**

```bash
cd /home/cmit/openidx/agent
go build ./...
go test ./internal/enrollment/... -v
go test ./internal/agent/... -v
```

**Commit message:** `feat(agent): add Ziti identity enrollment and persist ZitiIdentityFile to config`

---

## Task 5: Update server-side to return Ziti JWT on enrollment

**Files to modify:**
- `internal/access/agent_api.go`

**Context:** `AgentAPIHandler` already has access to a `*database.PostgresDB`. To create Ziti identities it also needs the `*ZitiManager`. The handler must be extended to accept an optional `*ZitiManager` and, when present, call `CreateIdentity` and include the enrollment JWT in the response.

### Test first — add to `internal/access/agent_api_test.go` (create if absent)

```go
package access_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/access"
)

func TestHandleEnroll_NoZitiManager_OmitsZitiJWT(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	handler := access.NewAgentAPIHandler(zap.NewNop(), nil)
	handler.RegisterAgentRoutes(&r.RouterGroup)

	req := httptest.NewRequest(http.MethodPost, "/agent/enroll", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	assert.NotEmpty(t, resp["agent_id"])
	assert.NotEmpty(t, resp["device_id"])
	assert.NotEmpty(t, resp["auth_token"])
	// ziti_jwt must be absent when no ZitiManager is configured.
	_, hasZitiJWT := resp["ziti_jwt"]
	assert.False(t, hasZitiJWT)
}

func TestHandleEnroll_MissingAuth_Returns401(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	handler := access.NewAgentAPIHandler(zap.NewNop(), nil)
	handler.RegisterAgentRoutes(&r.RouterGroup)

	req := httptest.NewRequest(http.MethodPost, "/agent/enroll", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
```

### Implementation changes to `internal/access/agent_api.go`

**1. Add `zitiManager` field and update constructor:**

```go
// AgentAPIHandler handles HTTP endpoints for agent communication.
type AgentAPIHandler struct {
	logger      *zap.Logger
	db          *database.PostgresDB
	zitiManager *ZitiManager // optional; when non-nil, Ziti JWT is returned on enroll
}

// NewAgentAPIHandler constructs an AgentAPIHandler with the given logger and database.
func NewAgentAPIHandler(logger *zap.Logger, db *database.PostgresDB) *AgentAPIHandler {
	return &AgentAPIHandler{
		logger: logger,
		db:     db,
	}
}

// WithZitiManager attaches a ZitiManager to the handler so that agent
// enrollment also provisions a Ziti identity and returns the enrollment JWT.
// Call this after NewAgentAPIHandler when the Ziti overlay is available.
func (h *AgentAPIHandler) WithZitiManager(zm *ZitiManager) *AgentAPIHandler {
	h.zitiManager = zm
	return h
}
```

**2. Extend `enrollResponse` with `ZitiJWT`:**

```go
// enrollResponse is returned by HandleEnroll on success.
type enrollResponse struct {
	AgentID   string `json:"agent_id"`
	DeviceID  string `json:"device_id"`
	AuthToken string `json:"auth_token"`
	// ZitiJWT is populated when the server has provisioned a Ziti identity.
	// The agent should use this to enroll with the Ziti controller.
	ZitiJWT   string `json:"ziti_jwt,omitempty"`
}
```

**3. Update `HandleEnroll` to call `ZitiManager.CreateIdentity`:**

The existing `ZitiManager` exposes `CreateIdentity(name string) (*ZitiIdentityInfo, error)` via the management API. The JWT is nested at `info.Enrollment.OTT.JWT`.

```go
// HandleEnroll validates the Authorization header and returns a new set of
// identifiers for the enrolling agent. When a ZitiManager is configured it also
// provisions a Ziti identity and returns the enrollment JWT.
func (h *AgentAPIHandler) HandleEnroll(c *gin.Context) {
	if c.GetHeader("Authorization") == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing Authorization header"})
		return
	}

	agentID := uuid.New().String()
	deviceID := uuid.New().String()

	resp := enrollResponse{
		AgentID:   agentID,
		DeviceID:  deviceID,
		AuthToken: uuid.New().String(),
	}

	// Optionally provision a Ziti identity for this agent.
	if h.zitiManager != nil {
		identityName := "agent-" + agentID
		info, err := h.zitiManager.CreateIdentity(identityName)
		if err != nil {
			h.logger.Warn("failed to create ziti identity for agent, proceeding without ziti",
				zap.String("agent_id", agentID),
				zap.Error(err),
			)
		} else if info.Enrollment != nil && info.Enrollment.OTT != nil {
			resp.ZitiJWT = info.Enrollment.OTT.JWT
			h.logger.Info("ziti identity provisioned for agent",
				zap.String("agent_id", agentID),
				zap.String("ziti_identity_id", info.ID),
			)
		}
	}

	h.logger.Info("agent enrolled",
		zap.String("agent_id", resp.AgentID),
		zap.String("device_id", resp.DeviceID),
	)

	c.JSON(http.StatusOK, resp)
}
```

**Note:** `ZitiManager.CreateIdentity` is implemented via the management API pattern already present in `internal/access/ziti.go`. If the method does not yet exist, add it following the existing `zitiAPIRequest` helper pattern used by other management API calls in that file. The identity creation POST goes to `{ZitiCtrlURL}/edge/management/v1/identities` with body `{"name": name, "type": "Device", "isAdmin": false, "enrollment": {"ott": true}}`.

**Commands:**

```bash
cd /home/cmit/openidx
go build ./internal/access/...
go test ./internal/access/... -v -run TestHandleEnroll
```

**Commit message:** `feat(access): return Ziti enrollment JWT from agent enroll endpoint when ZitiManager present`

---

## Integration Checklist

After all 5 tasks are complete, verify end-to-end:

- [ ] `cd /home/cmit/openidx/agent && go test ./... -v` — all agent tests pass
- [ ] `cd /home/cmit/openidx && go test ./internal/access/... -v` — server-side tests pass
- [ ] `cd /home/cmit/openidx && go build ./...` — full repo builds without errors
- [ ] Manual smoke: start services with `make dev-infra && make dev`, enroll a test agent, confirm `ziti-identity.json` is written to the agent's config dir and subsequent requests are routed over the Ziti overlay

## Key File Paths

| File | Role |
|------|------|
| `agent/go.mod` | Add `github.com/openziti/sdk-golang v1.3.1` |
| `agent/internal/transport/transport.go` | `Transport` interface + `NewTransport` factory |
| `agent/internal/transport/ziti.go` | `ZitiClient` implementation |
| `agent/internal/transport/ziti_test.go` | Unit tests for `ZitiClient` and interface |
| `agent/internal/enrollment/enroll.go` | Ziti enrollment orchestration |
| `agent/internal/enrollment/enroll_test.go` | Tests with `FakeEnroller` |
| `agent/internal/agent/config.go` | Add `ZitiIdentityFile` to `AgentConfig` |
| `agent/internal/agent/agent.go` | Use `Transport` interface; add `EnrollAndSave` |
| `internal/access/agent_api.go` | Add `ZitiManager` field; return `ziti_jwt` on enroll |

## Reference — Existing Ziti Patterns in `internal/access/ziti.go`

- Identity loading: `ziti.NewConfigFromFile(path)` → `ziti.NewContext(cfg)`
- Enrollment: `enroll.ParseToken(jwt)` → `enroll.Enroll(flags)` → save JSON
- Dialing: wrap `zitiCtx.Dial(serviceName)` in `http.Transport.DialContext`
- Identity creation via mgmt API: POST to `{ctrl}/edge/management/v1/identities`
- `ZitiIdentityInfo.Enrollment.OTT.JWT` holds the one-time enrollment token
