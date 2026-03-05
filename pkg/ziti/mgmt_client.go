package ziti

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
)

// MgmtClientConfig holds configuration for the management API client.
type MgmtClientConfig struct {
	// ControllerURL is the base URL of the Ziti controller (e.g. https://ziti-controller:1280).
	ControllerURL string

	// AdminUser is the admin username for the Ziti management API.
	AdminUser string

	// AdminPassword is the admin password for the Ziti management API.
	AdminPassword string

	// CAFile is the optional path to the CA certificate for verifying the controller's TLS cert.
	// When provided (and the file exists), TLS verification uses this CA.
	// When empty or the file doesn't exist, falls back to InsecureSkipVerify if AllowInsecure is true.
	CAFile string

	// AllowInsecure skips TLS verification when no CA file is available.
	// This should only be true in development or when using container-internal communication
	// with self-signed certificates.
	AllowInsecure bool

	// Timeout is the HTTP client timeout for management API requests.
	// Defaults to 30 seconds if zero.
	Timeout time.Duration

	// Logger is the structured logger to use.
	Logger *zap.Logger
}

// MgmtClient is a clean, reusable client for the Ziti management API.
// It handles authentication, token refresh, TLS configuration, and
// provides context-aware request methods.
type MgmtClient struct {
	cfg    MgmtClientConfig
	client *http.Client
	logger *zap.Logger

	mu    sync.RWMutex
	token string
}

// apiResponse represents the generic Ziti management API envelope.
type apiResponse struct {
	Data  json.RawMessage `json:"data"`
	Error *apiError       `json:"error,omitempty"`
	Meta  json.RawMessage `json:"meta,omitempty"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// NewMgmtClient creates a new management API client with proper TLS configuration.
func NewMgmtClient(cfg MgmtClientConfig) (*MgmtClient, error) {
	if cfg.ControllerURL == "" {
		return nil, fmt.Errorf("controller URL is required")
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}

	if cfg.Logger == nil {
		cfg.Logger = zap.NewNop()
	}

	tlsConfig := buildTLSConfig(cfg.CAFile, cfg.AllowInsecure, cfg.Logger)

	mc := &MgmtClient{
		cfg:    cfg,
		logger: cfg.Logger.With(zap.String("component", "ziti-mgmt-client")),
		client: &http.Client{
			Timeout: cfg.Timeout,
			Transport: &http.Transport{
				TLSClientConfig:     tlsConfig,
				MaxIdleConns:        20,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}

	if err := mc.Authenticate(context.Background()); err != nil {
		return nil, fmt.Errorf("initial authentication failed: %w", err)
	}

	mc.logger.Info("Management API client initialized",
		zap.String("controller", cfg.ControllerURL),
		zap.Bool("tls_verified", !tlsConfig.InsecureSkipVerify))

	return mc, nil
}

// buildTLSConfig creates a TLS configuration that prefers proper CA verification
// and only falls back to InsecureSkipVerify when explicitly allowed and no CA is available.
func buildTLSConfig(caFile string, allowInsecure bool, logger *zap.Logger) *tls.Config {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(caPEM) {
				tlsConfig.RootCAs = pool
				logger.Info("Loaded Ziti CA certificate for TLS verification", zap.String("file", caFile))
				return tlsConfig
			}
			logger.Warn("CA file found but contains no valid certificates", zap.String("file", caFile))
		} else {
			logger.Debug("CA file not found, will use system CAs or insecure mode", zap.String("file", caFile))
		}
	}

	if allowInsecure {
		tlsConfig.InsecureSkipVerify = true
		logger.Warn("TLS verification disabled for Ziti controller (AllowInsecure=true)")
	}

	return tlsConfig
}

// Authenticate obtains a session token from the Ziti management API.
func (mc *MgmtClient) Authenticate(ctx context.Context) error {
	body, _ := json.Marshal(map[string]string{
		"username": mc.cfg.AdminUser,
		"password": mc.cfg.AdminPassword,
	})

	req, err := http.NewRequestWithContext(ctx, "POST",
		mc.cfg.ControllerURL+"/edge/management/v1/authenticate?method=password",
		bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := mc.client.Do(req)
	if err != nil {
		return fmt.Errorf("auth request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("auth failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode auth response: %w", err)
	}

	mc.mu.Lock()
	mc.token = result.Data.Token
	mc.mu.Unlock()

	return nil
}

// Request performs an authenticated request to the Ziti management API.
// It automatically re-authenticates on 401 and retries once.
func (mc *MgmtClient) Request(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	respData, statusCode, err := mc.doRequest(ctx, method, path, body)
	if err != nil {
		return respData, statusCode, err
	}

	// Re-authenticate on 401 and retry once
	if statusCode == http.StatusUnauthorized {
		mc.logger.Debug("Received 401, re-authenticating")
		if authErr := mc.Authenticate(ctx); authErr != nil {
			return respData, statusCode, fmt.Errorf("re-authentication failed: %w", authErr)
		}
		return mc.doRequest(ctx, method, path, body)
	}

	return respData, statusCode, nil
}

// doRequest performs a single authenticated HTTP request.
func (mc *MgmtClient) doRequest(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	mc.mu.RLock()
	token := mc.token
	mc.mu.RUnlock()

	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, mc.cfg.ControllerURL+path, reqBody)
	if err != nil {
		return nil, 0, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("zt-session", token)
	}

	resp, err := mc.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read response: %w", err)
	}

	return respBody, resp.StatusCode, nil
}

// Token returns the current session token (useful for SDK bootstrapping).
func (mc *MgmtClient) Token() string {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return mc.token
}

// ControllerURL returns the controller base URL.
func (mc *MgmtClient) ControllerURL() string {
	return mc.cfg.ControllerURL
}
