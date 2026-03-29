package transport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// EnrollResponse holds the response from the agent enrollment endpoint.
type EnrollResponse struct {
	AgentID   string `json:"agent_id"`
	DeviceID  string `json:"device_id"`
	AuthToken string `json:"auth_token"`
}

// Client is an HTTP client for communicating with the OpenIDX access API.
type Client struct {
	baseURL    string
	authToken  string
	httpClient *http.Client
}

// NewClient creates a new Client with a 30-second timeout.
func NewClient(baseURL, authToken string) *Client {
	return &Client{
		baseURL:   baseURL,
		authToken: authToken,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Enroll sends an enrollment request using the provided one-time token and
// returns the enrollment response containing the agent credentials.
func (c *Client) Enroll(token string) (*EnrollResponse, error) {
	url := c.baseURL + "/api/v1/access/agent/enroll"

	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating enroll request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending enroll request: %w", err)
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

// ReportResults posts check result data to the agent report endpoint.
func (c *Client) ReportResults(data []byte) error {
	url := c.baseURL + "/api/v1/access/agent/report"

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("creating report request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.authToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending report request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("report request failed with status %d", resp.StatusCode)
	}

	return nil
}

// GetConfig retrieves the agent configuration from the server and returns the
// raw response body.
func (c *Client) GetConfig() ([]byte, error) {
	url := c.baseURL + "/api/v1/access/agent/config"

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating config request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.authToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending config request: %w", err)
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
