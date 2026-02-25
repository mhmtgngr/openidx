// ============================================================================
// OpenIDX Production Health Monitor
// Monitors service health and sends alerts on failures
// ============================================================================

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

// Config holds the health monitor configuration
type Config struct {
	Services        []ServiceConfig `json:"services"`
	CheckInterval   time.Duration   `json:"check_interval"`
	Timeout         time.Duration   `json:"timeout"`
	AlertThreshold  int             `json:"alert_threshold"`
	SlackWebhookURL string          `json:"slack_webhook_url"`
	EmailSMTP       string          `json:"email_smtp"`
	EmailFrom       string          `json:"email_from"`
	EmailTo         string          `json:"email_to"`
}

// ServiceConfig defines a service to monitor
type ServiceConfig struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Type string `json:"type"` // "http", "tcp", "command"
}

// HealthStatus represents the health of a service
type HealthStatus struct {
	ServiceName  string
	Healthy      bool
	Status       string
	ResponseTime time.Duration
	LastError    error
	FailCount    int
	LastCheck    time.Time
}

// HealthMonitor manages health checking for all services
type HealthMonitor struct {
	config      Config
	statuses    map[string]*HealthStatus
	statusMutex sync.RWMutex
	httpClient  *http.Client
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewHealthMonitor creates a new health monitor
func NewHealthMonitor(config Config) *HealthMonitor {
	ctx, cancel := context.WithCancel(context.Background())

	// Create HTTP client with timeout and TLS config
	httpClient := &http.Client{
		Timeout: config.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
			MaxIdleConns:        10,
			IdleConnTimeout:     30 * time.Second,
			DisableCompression:  true,
			DisableKeepAlives:    false,
			MaxIdleConnsPerHost: 10,
		},
	}

	if config.CheckInterval == 0 {
		config.CheckInterval = 30 * time.Second
	}

	if config.Timeout == 0 {
		config.Timeout = 5 * time.Second
	}

	if config.AlertThreshold == 0 {
		config.AlertThreshold = 3
	}

	return &HealthMonitor{
		config:     config,
		statuses:   make(map[string]*HealthStatus),
		httpClient: httpClient,
		ctx:        ctx,
		cancel:     cancel,
	}
}

// checkHTTPHealth performs an HTTP health check
func (hm *HealthMonitor) checkHTTPHealth(service ServiceConfig) (bool, string, time.Duration, error) {
	start := time.Now()

	req, err := http.NewRequestWithContext(hm.ctx, http.MethodGet, service.URL, nil)
	if err != nil {
		return false, "", 0, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "OpenIDX-HealthMonitor/1.0")

	resp, err := hm.httpClient.Do(req)
	if err != nil {
		return false, "", 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	duration := time.Since(start)

	body, _ := io.ReadAll(resp.Body)

	// Consider 2xx and 3xx as healthy
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return true, fmt.Sprintf("HTTP %d", resp.StatusCode), duration, nil
	}

	return false, fmt.Sprintf("HTTP %d", resp.StatusCode), duration, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
}

// checkServiceHealth checks the health of a single service
func (hm *HealthMonitor) checkServiceHealth(service ServiceConfig) (*HealthStatus, error) {
	var healthy bool
	var status string
	var responseTime time.Duration
	var err error

	switch service.Type {
	case "http", "":
		healthy, status, responseTime, err = hm.checkHTTPHealth(service)
	default:
		err = fmt.Errorf("unsupported service type: %s", service.Type)
	}

	hs := &HealthStatus{
		ServiceName:  service.Name,
		Healthy:      healthy,
		Status:       status,
		ResponseTime: responseTime,
		LastError:    err,
		LastCheck:    time.Now(),
	}

	if !healthy && err != nil {
		hs.Status = fmt.Sprintf("Error: %v", err)
	}

	return hs, nil
}

// updateStatus updates the health status for a service
func (hm *HealthMonitor) updateStatus(service ServiceConfig, newStatus *HealthStatus) {
	hm.statusMutex.Lock()
	defer hm.statusMutex.Unlock()

	oldStatus, exists := hm.statuses[service.Name]
	if exists {
		if !newStatus.Healthy {
			newStatus.FailCount = oldStatus.FailCount + 1
		} else {
			newStatus.FailCount = 0
		}
	}

	hm.statuses[service.Name] = newStatus

	// Send alert if threshold exceeded
	if newStatus.FailCount == hm.config.AlertThreshold {
		hm.sendAlert(service, newStatus)
	}
}

// sendAlert sends an alert notification
func (hm *HealthMonitor) sendAlert(service ServiceConfig, status *HealthStatus) {
	alertMsg := fmt.Sprintf(
		"Alert: Service %s is unhealthy\n"+
			"Status: %s\n"+
			"Failed checks: %d\n"+
			"Last error: %v\n"+
			"Time: %s",
		service.Name, status.Status, status.FailCount, status.LastError, status.LastCheck.Format(time.RFC3339),
	)

	// Log alert
	fmt.Printf("[%s] ALERT: %s\n", time.Now().Format(time.RFC3339), alertMsg)

	// Send to Slack if configured
	if hm.config.SlackWebhookURL != "" {
		go hm.sendSlackAlert(service, status)
	}

	// Send email if configured
	if hm.config.EmailTo != "" {
		go hm.sendEmailAlert(service, status, alertMsg)
	}
}

// sendSlackAlert sends an alert to Slack
func (hm *HealthMonitor) sendSlackAlert(service ServiceConfig, status *HealthStatus) {
	payload := map[string]interface{}{
		"text": fmt.Sprintf("Service Health Alert: %s", service.Name),
		"attachments": []map[string]interface{}{
			{
				"color": "danger",
				"fields": []map[string]interface{}{
					{"title": "Service", "value": service.Name, "short": true},
					{"title": "Status", "value": status.Status, "short": true},
					{"title": "Failed Checks", "value": fmt.Sprintf("%d", status.FailCount), "short": true},
					{"title": "Time", "value": status.LastCheck.Format(time.RFC3339), "short": true},
					{"title": "Error", "value": fmt.Sprintf("%v", status.LastError), "short": false},
				},
			},
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Failed to marshal Slack payload: %v\n", err)
		return
	}

	resp, err := hm.httpClient.Post(hm.config.SlackWebhookURL, "application/json", bytes.NewReader(jsonData))
	if err != nil {
		fmt.Printf("Failed to send Slack alert: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Slack alert returned status %d\n", resp.StatusCode)
	}
}

// sendEmailAlert sends an alert via email
func (hm *HealthMonitor) sendEmailAlert(service ServiceConfig, status *HealthStatus, message string) {
	// TODO: Implement email sending
	// This would typically use net/smtp or a library like mailgun/sendgrid
	fmt.Printf("Email alert would be sent to %s: %s\n", hm.config.EmailTo, message)
}

// GetStatus returns the current health status of all services
func (hm *HealthMonitor) GetStatus() map[string]*HealthStatus {
	hm.statusMutex.RLock()
	defer hm.statusMutex.RUnlock()

	// Return a copy to avoid race conditions
	result := make(map[string]*HealthStatus, len(hm.statuses))
	for k, v := range hm.statuses {
		result[k] = v
	}
	return result
}

// Start begins the health monitoring loop
func (hm *HealthMonitor) Start() {
	fmt.Printf("Starting health monitor with %d services\n", len(hm.config.Services))
	fmt.Printf("Check interval: %v, Timeout: %v\n", hm.config.CheckInterval, hm.config.Timeout)

	ticker := time.NewTicker(hm.config.CheckInterval)
	defer ticker.Stop()

	// Run first check immediately
	hm.runChecks()

	// Main loop
	for {
		select {
		case <-hm.ctx.Done():
			fmt.Println("Health monitor stopped")
			return
		case <-ticker.C:
			hm.runChecks()
		}
	}
}

// runChecks executes health checks for all services
func (hm *HealthMonitor) runChecks() {
	var wg sync.WaitGroup

	for _, service := range hm.config.Services {
		wg.Add(1)
		go func(s ServiceConfig) {
			defer wg.Done()

			status, err := hm.checkServiceHealth(s)
			if err != nil {
				fmt.Printf("[%s] Error checking %s: %v\n", time.Now().Format(time.RFC3339), s.Name, err)
				return
			}

			hm.updateStatus(s, status)

			// Log status
			healthIcon := "OK"
			if !status.Healthy {
				healthIcon = "FAIL"
			}
			fmt.Printf("[%s] %s %s: %s (%v)\n",
				time.Now().Format(time.RFC3339),
				healthIcon,
				s.Name,
				status.Status,
				status.ResponseTime,
			)
		}(service)
	}

	wg.Wait()
}

// Stop gracefully stops the health monitor
func (hm *HealthMonitor) Stop() {
	hm.cancel()
}

// serveHTTP serves health status over HTTP
func (hm *HealthMonitor) serveHTTP(addr string) {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		statuses := hm.GetStatus()

		allHealthy := true
		for _, s := range statuses {
			if !s.Healthy {
				allHealthy = false
				break
			}
		}

		statusCode := http.StatusOK
		if !allHealthy {
			statusCode = http.StatusServiceUnavailable
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)

		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(map[string]interface{}{
			"healthy":   allHealthy,
			"timestamp": time.Now().Format(time.RFC3339),
			"services":  statuses,
		})
	})

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		// Prometheus-style metrics
		statuses := hm.GetStatus()

		w.Header().Set("Content-Type", "text/plain")

		for _, s := range statuses {
			healthy := 0
			if s.Healthy {
				healthy = 1
			}
			fmt.Fprintf(w, "health_service_status{name=%q} %d\n", s.ServiceName, healthy)
			fmt.Fprintf(w, "health_service_response_time_ms{name=%q} %d\n",
				s.ServiceName, s.ResponseTime.Milliseconds())
			fmt.Fprintf(w, "health_service_fail_count{name=%q} %d\n",
				s.ServiceName, s.FailCount)
		}
	})

	fmt.Printf("Starting HTTP server on %s\n", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Printf("HTTP server error: %v\n", err)
	}
}

// loadConfigFromFile loads configuration from a JSON file
func loadConfigFromFile(path string) (Config, error) {
	var config Config

	data, err := os.ReadFile(path)
	if err != nil {
		return config, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return config, fmt.Errorf("failed to parse config file: %w", err)
	}

	return config, nil
}

// defaultConfig returns the default production configuration
func defaultConfig() Config {
	domain := os.Getenv("DOMAIN")
	if domain == "" {
		domain = "openidx.tdv.org"
	}

	return Config{
		Services: []ServiceConfig{
			{Name: "Identity Service", URL: "http://identity-service:8001/health", Type: "http"},
			{Name: "Governance Service", URL: "http://governance-service:8002/health", Type: "http"},
			{Name: "Provisioning Service", URL: "http://provisioning-service:8003/health", Type: "http"},
			{Name: "Audit Service", URL: "http://audit-service:8004/health", Type: "http"},
			{Name: "Admin API", URL: "http://admin-api:8005/health", Type: "http"},
			{Name: "OAuth Service", URL: "http://oauth-service:8006/health", Type: "http"},
			{Name: "Access Service", URL: "http://access-service:8007/health", Type: "http"},
			{Name: "Public API", URL: fmt.Sprintf("https://%s/health", domain), Type: "http"},
			{Name: "OIDC Discovery", URL: fmt.Sprintf("https://%s/.well-known/openid-configuration", domain), Type: "http"},
		},
		CheckInterval:   30 * time.Second,
		Timeout:         10 * time.Second,
		AlertThreshold:  3,
		SlackWebhookURL: os.Getenv("SLACK_WEBHOOK_URL"),
		EmailTo:         os.Getenv("ALERT_EMAIL_TO"),
	}
}

func main() {
	// Parse command line flags
	configPath := os.Getenv("HEALTH_MONITOR_CONFIG")
	httpAddr := os.Getenv("HEALTH_MONITOR_ADDR")
	if httpAddr == "" {
		httpAddr = ":9000"
	}

	var config Config
	var err error

	if configPath != "" {
		config, err = loadConfigFromFile(configPath)
		if err != nil {
			fmt.Printf("Failed to load config from %s: %v\n", configPath, err)
			fmt.Println("Using default configuration")
			config = defaultConfig()
		}
	} else {
		config = defaultConfig()
	}

	// Create health monitor
	monitor := NewHealthMonitor(config)

	// Start HTTP server in background
	go monitor.serveHTTP(httpAddr)

	// Start monitoring (blocks until Stop is called)
	monitor.Start()
}
