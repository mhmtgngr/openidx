package transport

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/openziti/sdk-golang/ziti"
)

// ZitiClient communicates with OpenIDX server through the Ziti overlay network.
type ZitiClient struct {
	baseURL     string
	authToken   string
	agentID     string
	httpClient  *http.Client
	zitiCtx     ziti.Context
	serviceName string
}

// NewZitiClient creates a transport client that routes through Ziti.
func NewZitiClient(identityFile, serviceName, baseURL, authToken, agentID string) (*ZitiClient, error) {
	cfg, err := ziti.NewConfigFromFile(identityFile)
	if err != nil {
		return nil, fmt.Errorf("load ziti identity: %w", err)
	}

	zitiCtx, err := ziti.NewContext(cfg)
	if err != nil {
		return nil, fmt.Errorf("create ziti context: %w", err)
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return zitiCtx.Dial(serviceName)
		},
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}

	return &ZitiClient{
		baseURL:     baseURL,
		authToken:   authToken,
		agentID:     agentID,
		httpClient:  &http.Client{Transport: transport, Timeout: 30 * time.Second},
		zitiCtx:     zitiCtx,
		serviceName: serviceName,
	}, nil
}

// Close cleans up the Ziti context.
func (c *ZitiClient) Close() {
	if c.zitiCtx != nil {
		c.zitiCtx.Close()
	}
}

// Enroll delegates to a Client using the Ziti-backed HTTP client.
func (c *ZitiClient) Enroll(token string) (*EnrollResponse, error) {
	inner := &Client{baseURL: c.baseURL, authToken: c.authToken, agentID: c.agentID, httpClient: c.httpClient}
	return inner.Enroll(token)
}

// ReportResults delegates to a Client using the Ziti-backed HTTP client.
func (c *ZitiClient) ReportResults(data []byte) error {
	inner := &Client{baseURL: c.baseURL, authToken: c.authToken, agentID: c.agentID, httpClient: c.httpClient}
	return inner.ReportResults(data)
}

// GetConfig delegates to a Client using the Ziti-backed HTTP client.
func (c *ZitiClient) GetConfig() ([]byte, error) {
	inner := &Client{baseURL: c.baseURL, authToken: c.authToken, agentID: c.agentID, httpClient: c.httpClient}
	return inner.GetConfig()
}
