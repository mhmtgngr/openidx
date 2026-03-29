package resilience

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

// ResilientHTTPClient wraps an http.Client with circuit breaker protection
type ResilientHTTPClient struct {
	client *http.Client
	cb     *CircuitBreaker
}

// NewResilientHTTPClient creates a new HTTP client with circuit breaker protection.
// If the provided client has no timeout configured, a default 10-second timeout is applied.
func NewResilientHTTPClient(client *http.Client, cb *CircuitBreaker) *ResilientHTTPClient {
	// Ensure the HTTP client has a timeout for external operations
	if client.Timeout == 0 {
		client.Timeout = 10 * time.Second
	}
	return &ResilientHTTPClient{
		client: client,
		cb:     cb,
	}
}

// Do executes an HTTP request through the circuit breaker.
// HTTP 5xx responses are treated as failures for circuit breaker purposes.
func (rc *ResilientHTTPClient) Do(req *http.Request) (*http.Response, error) {
	result, err := rc.cb.Execute(func() (interface{}, error) {
		resp, err := rc.client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode >= 500 {
			return resp, fmt.Errorf("server error: HTTP %d", resp.StatusCode)
		}
		return resp, nil
	})
	if err != nil {
		// Return response if we have one (even with error)
		if resp, ok := result.(*http.Response); ok {
			return resp, err
		}
		return nil, err
	}
	return result.(*http.Response), nil
}

// Get executes a GET request through the circuit breaker
func (rc *ResilientHTTPClient) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return rc.Do(req)
}

// Post executes a POST request through the circuit breaker
func (rc *ResilientHTTPClient) Post(url, contentType string, body interface{}) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, err
	}
	if body != nil {
		switch v := body.(type) {
		case []byte:
			req.Body = &bytesReader{bytes: v}
		case string:
			req.Body = &stringReader{s: v}
		default:
			// For other types, let caller create the request
			return rc.client.Do(req)
		}
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return rc.Do(req)
}

// bytesReader implements io.Reader for []byte
type bytesReader struct {
	bytes []byte
	index int
}

func (r *bytesReader) Read(p []byte) (n int, err error) {
	if r.index >= len(r.bytes) {
		return 0, io.EOF
	}
	n = copy(p, r.bytes[r.index:])
	r.index += n
	return n, nil
}

func (r *bytesReader) Close() error { return nil }

// stringReader implements io.Reader for string
type stringReader struct {
	s     string
	index int
}

func (r *stringReader) Read(p []byte) (n int, err error) {
	if r.index >= len(r.s) {
		return 0, io.EOF
	}
	n = copy(p, r.s[r.index:])
	r.index += n
	return n, nil
}

func (r *stringReader) Close() error { return nil }
