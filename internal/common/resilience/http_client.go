package resilience

import (
	"fmt"
	"net/http"
)

// ResilientHTTPClient wraps an http.Client with circuit breaker protection
type ResilientHTTPClient struct {
	client *http.Client
	cb     *CircuitBreaker
}

// NewResilientHTTPClient creates a new HTTP client with circuit breaker protection
func NewResilientHTTPClient(client *http.Client, cb *CircuitBreaker) *ResilientHTTPClient {
	return &ResilientHTTPClient{
		client: client,
		cb:     cb,
	}
}

// Do executes an HTTP request through the circuit breaker.
// HTTP 5xx responses are treated as failures for circuit breaker purposes.
func (rc *ResilientHTTPClient) Do(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	err := rc.cb.Execute(func() error {
		var e error
		resp, e = rc.client.Do(req)
		if e != nil {
			return e
		}
		if resp.StatusCode >= 500 {
			return fmt.Errorf("server error: HTTP %d", resp.StatusCode)
		}
		return nil
	})
	return resp, err
}
