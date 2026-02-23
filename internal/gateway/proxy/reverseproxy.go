// Package proxy provides reverse proxy functionality for the gateway
package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openidx/openidx/internal/gateway"
)

// ReverseProxy is a custom reverse proxy handler for the gateway
type ReverseProxy struct {
	targetURL      *url.URL
	proxy          *httputil.ReverseProxy
	serviceName    string
	logger         gateway.Logger
	requestTimeout time.Duration
}

// Config holds configuration for the reverse proxy
type Config struct {
	TargetURL      string
	ServiceName    string
	RequestTimeout time.Duration
	Logger         gateway.Logger
	ModifyRequest  func(*http.Request) error
	ModifyResponse func(*http.Response) error
	ErrorHandler   func(http.ResponseWriter, *http.Request, error)
}

// NewReverseProxy creates a new reverse proxy for the given target URL
func NewReverseProxy(config Config) (*ReverseProxy, error) {
	targetURL, err := url.Parse(config.TargetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target URL: %w", err)
	}

	proxy := &ReverseProxy{
		targetURL:      targetURL,
		serviceName:    config.ServiceName,
		requestTimeout: config.RequestTimeout,
		logger:         config.Logger,
	}

	// Create the HTTP reverse proxy
	proxy.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			// Rewrite the request to target the upstream service
			pr.Out.URL.Scheme = targetURL.Scheme
			pr.Out.URL.Host = targetURL.Host
			pr.Out.URL.Path = targetURL.Path + pr.In.URL.Path

			// Preserve query string
			if pr.In.URL.RawQuery != "" {
				pr.Out.URL.RawQuery = pr.In.URL.RawQuery
			}

			// Set the host header to the target host
			pr.Out.Host = targetURL.Host

			// Call custom modifier if provided
			if config.ModifyRequest != nil {
				config.ModifyRequest(pr.Out)
			}
		},
		ModifyResponse: proxy.modifyResponse,
		ErrorHandler:   proxy.errorHandler,
	}

	return proxy, nil
}

// ServeHTTP implements the http.Handler interface
func (p *ReverseProxy) ServeHTTP(c *gin.Context) {
	// Add timeout context if configured
	if p.requestTimeout > 0 {
		ctx, cancel := context.WithTimeout(c.Request.Context(), p.requestTimeout)
		defer cancel()
		c.Request = c.Request.WithContext(ctx)
	}

	// Store Gin context in request for use in modifiers
	c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), "gin_context", c))

	// Serve the proxy request
	p.proxy.ServeHTTP(c.Writer, c.Request)
}

// ServeHTTPDirect serves an HTTP request directly (for non-Gin usage)
func (p *ReverseProxy) ServeHTTPDirect(w http.ResponseWriter, r *http.Request) {
	p.proxy.ServeHTTP(w, r)
}

// modifyRequest is called before forwarding the request to the target
func (p *ReverseProxy) modifyRequest(req *http.Request) error {
	// Get Gin context if available
	var c *gin.Context
	if ctxVal := req.Context().Value("gin_context"); ctxVal != nil {
		if ginCtx, ok := ctxVal.(*gin.Context); ok {
			c = ginCtx
		}
	}

	// Remove hop-by-hop headers
	removeHopByHopHeaders(req.Header)

	// Add gateway-specific headers
	if c != nil {
		// Add correlation ID
		if correlationID := GetCorrelationID(c); correlationID != "" {
			req.Header.Set("X-Correlation-ID", correlationID)
		}

		// Add request ID
		if requestID := c.GetHeader("X-Request-ID"); requestID != "" {
			req.Header.Set("X-Request-ID", requestID)
		}

		// Add gateway identification
		req.Header.Set("X-Gateway", "openidx-gateway/v1")

		// Add original request info
		req.Header.Set("X-Original-Host", req.Host)
		req.Header.Set("X-Forwarded-By", "openidx-gateway")
		req.Header.Set("X-Forwarded-For", getClientIP(c, req))
		req.Header.Set("X-Forwarded-Proto", getProto(c, req))
		req.Header.Set("X-Forwarded-Host", req.Host)

		// Add user context if authenticated
		if userID, exists := c.Get("user_id"); exists {
			req.Header.Set("X-User-ID", fmt.Sprint(userID))
		}

		if orgID, exists := c.Get("org_id"); exists {
			req.Header.Set("X-Org-ID", fmt.Sprint(orgID))
		}

		// Add session ID if present
		if sessionID, exists := c.Get("session_id"); exists {
			req.Header.Set("X-Session-ID", fmt.Sprint(sessionID))
		}
	}

	// Add service identification
	if p.serviceName != "" {
		req.Header.Set("X-Target-Service", p.serviceName)
	}

	return nil
}

// modifyResponse is called after receiving the response from the target
func (p *ReverseProxy) modifyResponse(resp *http.Response) error {
	// Remove hop-by-hop headers from response
	removeHopByHopHeaders(resp.Header)

	// Add gateway identification to response
	resp.Header.Set("X-Served-By", "openidx-gateway")

	if p.serviceName != "" {
		resp.Header.Set("X-Upstream-Service", p.serviceName)
	}

	return nil
}

// errorHandler handles errors from the proxy
func (p *ReverseProxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	// Log the error
	if p.logger != nil {
		p.logger.Error("Proxy error",
			"service", p.serviceName,
			"path", r.URL.Path,
			"error", err.Error(),
		)
	}

	// Check for specific error types
	if isTimeoutError(err) {
		w.WriteHeader(http.StatusGatewayTimeout)
		writeJSONError(w, "request timeout", "GATEWAY_TIMEOUT")
		return
	}

	if isConnectionError(err) {
		w.WriteHeader(http.StatusBadGateway)
		writeJSONError(w, "upstream service unavailable", "SERVICE_UNAVAILABLE")
		return
	}

	// Generic error response
	w.WriteHeader(http.StatusBadGateway)
	writeJSONError(w, "failed to reach upstream service", "PROXY_ERROR")
}

// GetCorrelationID gets the correlation ID from the Gin context
func GetCorrelationID(c *gin.Context) string {
	if correlationID, exists := c.Get("correlation_id"); exists {
		if id, ok := correlationID.(string); ok {
			return id
		}
	}
	return c.GetHeader("X-Correlation-ID")
}

// getClientIP gets the client IP address from the Gin context or request
func getClientIP(c *gin.Context, r *http.Request) string {
	if c != nil {
		return c.ClientIP()
	}

	// Try X-Forwarded-For header
	if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		// Get the first IP in the chain
		if idx := strings.Index(forwardedFor, ","); idx != -1 {
			return strings.TrimSpace(forwardedFor[:idx])
		}
		return forwardedFor
	}

	// Try X-Real-IP header
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}

// getProto gets the request protocol
func getProto(c *gin.Context, r *http.Request) string {
	// Try X-Forwarded-Proto header
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}

	// Try X-Forwarded-Scheme header
	if scheme := r.Header.Get("X-Forwarded-Scheme"); scheme != "" {
		return scheme
	}

	// Use TLS state from request
	if r.TLS != nil {
		return "https"
	}

	return "http"
}

// removeHopByHopHeaders removes hop-by-hop headers from the headers map
func removeHopByHopHeaders(headers http.Header) {
	// Headers to remove
	hopByHopHeaders := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}

	// Remove connection-specific headers
	if connectionHeaders := headers.Get("Connection"); connectionHeaders != "" {
		for _, header := range strings.Split(connectionHeaders, ",") {
			header = strings.TrimSpace(header)
			if header != "" {
				headers.Del(header)
			}
		}
	}

	// Remove standard hop-by-hop headers
	for _, header := range hopByHopHeaders {
		headers.Del(header)
	}
}

// writeJSONError writes a JSON error response
func writeJSONError(w http.ResponseWriter, message, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(fmt.Sprintf(`{"error":"%s","code":"%s"}`, message, code)))
}

// isTimeoutError checks if an error is a timeout error
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "timeout") ||
		strings.Contains(err.Error(), "context deadline exceeded")
}

// isConnectionError checks if an error is a connection error
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "connection refused") ||
		strings.Contains(err.Error(), "no such host") ||
		strings.Contains(err.Error(), "connection reset")
}

// ProxyDirector directs the proxy request
type ProxyDirector func(*http.Request)

// ResponseModifier modifies the response from the upstream service
type ResponseModifier func(*http.Response) error

// RequestModifier modifies the request before sending to upstream
type RequestModifier func(*http.Request) error

// BufferPool implements io.WriterTo for efficient buffering
type BufferPool struct {
	buffers chan *bytes.Buffer
}

// NewBufferPool creates a new buffer pool
func NewBufferPool(size int) *BufferPool {
	return &BufferPool{
		buffers: make(chan *bytes.Buffer, size),
	}
}

// Get gets a buffer from the pool
func (p *BufferPool) Get() *bytes.Buffer {
	select {
	case buf := <-p.buffers:
		return buf
	default:
		return &bytes.Buffer{}
	}
}

// Put returns a buffer to the pool
func (p *BufferPool) Put(buf *bytes.Buffer) {
	buf.Reset()
	select {
	case p.buffers <- buf:
	default:
		// Pool is full, discard
	}
}

// CopyResponse copies the response body
func CopyResponse(dst io.Writer, src io.Reader) error {
	buf := make([]byte, 32*1024)
	_, err := io.CopyBuffer(dst, src, buf)
	return err
}

// ProxyStats holds statistics for proxy requests
type ProxyStats struct {
	TotalRequests    int64
	SuccessfulRequests int64
	FailedRequests   int64
	TotalLatency     time.Duration
	AvgLatency       time.Duration
}

// StatsTracker tracks proxy statistics
type StatsTracker struct {
	stats map[string]*ProxyStats
	mu    sync.RWMutex
}

// NewStatsTracker creates a new statistics tracker
func NewStatsTracker() *StatsTracker {
	return &StatsTracker{
		stats: make(map[string]*ProxyStats),
	}
}

// RecordRequest records a proxy request
func (t *StatsTracker) RecordRequest(serviceName string, latency time.Duration, success bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.stats[serviceName] == nil {
		t.stats[serviceName] = &ProxyStats{}
	}

	stats := t.stats[serviceName]
	stats.TotalRequests++
	if success {
		stats.SuccessfulRequests++
	} else {
		stats.FailedRequests++
	}
	stats.TotalLatency += latency
	stats.AvgLatency = time.Duration(int64(stats.TotalLatency) / stats.TotalRequests)
}

// GetStats returns the statistics for a service
func (t *StatsTracker) GetStats(serviceName string) ProxyStats {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if stats, ok := t.stats[serviceName]; ok {
		return *stats
	}
	return ProxyStats{}
}

// GetAllStats returns all statistics
func (t *StatsTracker) GetAllStats() map[string]ProxyStats {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make(map[string]ProxyStats, len(t.stats))
	for k, v := range t.stats {
		result[k] = *v
	}
	return result
}

