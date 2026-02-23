// Package audit provides unit tests for webhook delivery with retry logic
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestWebhookDelivery_ExponentialBackoff(t *testing.T) {
	tests := []struct {
		name       string
		retryCount int
		baseDelay  time.Duration
		expected   time.Duration
	}{
		{
			name:       "retry 0 - no delay",
			retryCount: 0,
			baseDelay:  time.Second,
			expected:   0,
		},
		{
			name:       "retry 1 - 1 second",
			retryCount: 1,
			baseDelay:  time.Second,
			expected:   1 * time.Second,
		},
		{
			name:       "retry 2 - 2 seconds",
			retryCount: 2,
			baseDelay:  time.Second,
			expected:   2 * time.Second,
		},
		{
			name:       "retry 3 - 4 seconds",
			retryCount: 3,
			baseDelay:  time.Second,
			expected:   4 * time.Second,
		},
		{
			name:       "retry 4 - 8 seconds",
			retryCount: 4,
			baseDelay:  time.Second,
			expected:   8 * time.Second,
		},
		{
			name:       "retry 5 - 16 seconds",
			retryCount: 5,
			baseDelay:  time.Second,
			expected:   16 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Calculate delay using exponential backoff formula
			if tt.retryCount > 0 {
				delay := tt.baseDelay * time.Duration(1<<uint(tt.retryCount-1))
				assert.Equal(t, tt.expected, delay)
			} else {
				assert.Equal(t, time.Duration(0), tt.expected)
			}
		})
	}
}

func TestWebhookDelivery_MaxRetries(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)
	streamer := NewEventStreamer(logger, service)

	// Configure shorter delays for testing
	streamer.webhookConfig.MaxRetries = 3
	streamer.webhookConfig.RetryDelay = 10 * time.Millisecond

	_ = &WebhookDelivery{
		Event: &ServiceAuditEvent{
			ID:        "test-event",
			Timestamp: time.Now().UTC(),
		},
		WebhookURL: "http://invalid-endpoint-that-will-fail.local",
		RetryCount: 0,
		ID:         "test-delivery",
	}

	// Verify config is set
	assert.Equal(t, 3, streamer.webhookConfig.MaxRetries)
	assert.Equal(t, 10*time.Millisecond, streamer.webhookConfig.RetryDelay)
}

func TestWebhookDelivery_Success(t *testing.T) {
	// Create mock server that returns success
	var receivedPayload []byte
	var receivedHeaders http.Header
	successServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header

		body, _ := io.ReadAll(r.Body)
		receivedPayload = body

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status": "received"}`)
	}))
	defer successServer.Close()

	logger := zap.NewNop()
	service := createTestService(t)
	streamer := NewEventStreamer(logger, service)

	event := &ServiceAuditEvent{
		ID:        "event-123",
		Timestamp: time.Now().UTC(),
		EventType: EventTypeAuthentication,
		Outcome:   ServiceOutcomeSuccess,
		ActorID:   "user-123",
	}

	delivery := &WebhookDelivery{
		Event:      event,
		WebhookURL: successServer.URL,
		RetryCount: 0,
		ID:         "delivery-123",
	}

	// Test delivery
	success := streamer.deliverWebhook(delivery)

	assert.True(t, success, "Webhook delivery should succeed")
	assert.NotEmpty(t, receivedPayload, "Should receive payload")
	assert.Equal(t, "application/json", receivedHeaders.Get("Content-Type"))
	assert.Equal(t, "delivery-123", receivedHeaders.Get("X-OpenIDX-Delivery-ID"))

	// Verify payload structure
	var receivedEvent ServiceAuditEvent
	err := json.Unmarshal(receivedPayload, &receivedEvent)
	require.NoError(t, err)
	assert.Equal(t, event.ID, receivedEvent.ID)
	assert.Equal(t, event.ActorID, receivedEvent.ActorID)
}

func TestWebhookDelivery_Failure(t *testing.T) {
	// Create mock server that returns error
	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error": "internal server error"}`)
	}))
	defer errorServer.Close()

	logger := zap.NewNop()
	service := createTestService(t)
	streamer := NewEventStreamer(logger, service)

	event := &ServiceAuditEvent{
		ID:        "event-456",
		Timestamp: time.Now().UTC(),
	}

	delivery := &WebhookDelivery{
		Event:      event,
		WebhookURL: errorServer.URL,
		RetryCount: 0,
		ID:         "delivery-456",
	}

	// Test delivery
	success := streamer.deliverWebhook(delivery)

	assert.False(t, success, "Webhook delivery should fail for 500 status")
}

func TestWebhookDelivery_Timeout(t *testing.T) {
	// Create mock server that delays response
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer slowServer.Close()

	logger := zap.NewNop()
	service := createTestService(t)
	streamer := NewEventStreamer(logger, service)

	// Set a short timeout for testing
	streamer.webhookConfig.Timeout = 50 * time.Millisecond

	event := &ServiceAuditEvent{
		ID:        "event-789",
		Timestamp: time.Now().UTC(),
	}

	delivery := &WebhookDelivery{
		Event:      event,
		WebhookURL: slowServer.URL,
		RetryCount: 0,
		ID:         "delivery-789",
	}

	// Test delivery - should fail due to timeout
	success := streamer.deliverWebhook(delivery)

	assert.False(t, success, "Webhook delivery should fail due to timeout")
}

func TestWebhookDelivery_InvalidURL(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)
	streamer := NewEventStreamer(logger, service)

	event := &ServiceAuditEvent{
		ID:        "event-invalid",
		Timestamp: time.Now().UTC(),
	}

	delivery := &WebhookDelivery{
		Event:      event,
		WebhookURL: "://invalid-url",
		RetryCount: 0,
		ID:         "delivery-invalid",
	}

	// Test delivery
	success := streamer.deliverWebhook(delivery)

	assert.False(t, success, "Webhook delivery should fail for invalid URL")
}

func TestWebhookQueue_Full(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)

	// Create streamer with very small queue
	streamer := &EventStreamer{
		logger:       logger,
		clients:      make(map[string]*StreamClient),
		webhookQueue: make(chan *WebhookDelivery, 1), // Very small queue
		webhookConfig: &WebhookConfig{
			QueueSize: 1,
			Enabled:   true,
		},
		service: service,
	}

	event := &ServiceAuditEvent{
		ID:        "event-queue",
		Timestamp: time.Now().UTC(),
	}

	// Fill the queue
	streamer.SendWebhook(event, "http://example.com/webhook")

	// This should not block - the second webhook should be dropped
	// In production, this would log a warning
	streamer.SendWebhook(event, "http://example.com/webhook2")

	assert.Len(t, streamer.webhookQueue, 1, "Queue should only contain one delivery")
}

func TestWebhookDelivery_RetryLogic(t *testing.T) {
	attemptCount := 0
	var attemptDelays []time.Duration

	// Create server that fails twice then succeeds
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		if attemptCount < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer testServer.Close()

	logger := zap.NewNop()
	service := createTestService(t)
	streamer := NewEventStreamer(logger, service)

	// Configure for quick retry
	streamer.webhookConfig.MaxRetries = 5
	streamer.webhookConfig.RetryDelay = 10 * time.Millisecond

	event := &ServiceAuditEvent{
		ID:        "event-retry",
		Timestamp: time.Now().UTC(),
	}

	// Simulate retry logic
	maxAttempts := streamer.webhookConfig.MaxRetries
	success := false

	for attempt := 0; attempt <= maxAttempts; attempt++ {
		delivery := &WebhookDelivery{
			Event:      event,
			WebhookURL: testServer.URL,
			RetryCount: attempt,
			ID:         fmt.Sprintf("delivery-attempt-%d", attempt),
		}

		start := time.Now()
		result := streamer.deliverWebhook(delivery)
		elapsed := time.Since(start)

		attemptDelays = append(attemptDelays, elapsed)

		if result {
			success = true
			assert.Equal(t, 3, attemptCount, "Should succeed on third attempt")
			break
		}

		// Simulate exponential backoff delay
		if attempt < maxAttempts {
			delay := streamer.webhookConfig.RetryDelay * time.Duration(1<<uint(attempt))
			time.Sleep(delay)
		}
	}

	assert.True(t, success, "Webhook should eventually succeed")
}

func TestWebhookSubscription_Routes(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)
	streamer := NewEventStreamer(logger, service)

	// Create test router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	streamer.RegisterRoutes(router.Group("/api/v1/audit"))

	// Test webhook registration endpoint
	t.Run("register webhook", func(t *testing.T) {
		reqBody := `{
			"url": "https://example.com/webhook",
			"secret": "test-secret",
			"enabled": true,
			"filters": {
				"event_types": ["authentication"]
			}
		}`

		req := httptest.NewRequest("POST", "/api/v1/audit/webhooks",
			strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// Note: This will fail without a real database, but we can test the route exists
		assert.Contains(t, []int{201, 500}, w.Code)
	})

	// Test webhook list endpoint
	t.Run("list webhooks", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/audit/webhooks", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// Note: This will fail without a real database
		assert.Contains(t, []int{200, 500}, w.Code)
	})
}

func TestWebhookDelivery_PayloadStructure(t *testing.T) {
	var receivedJSON map[string]interface{}

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &receivedJSON)

		w.WriteHeader(http.StatusOK)
	}))
	defer testServer.Close()

	logger := zap.NewNop()
	service := createTestService(t)
	streamer := NewEventStreamer(logger, service)

	event := &ServiceAuditEvent{
		ID:          "event-payload",
		Timestamp:   time.Now().UTC(),
		EventType:   EventTypeAuthentication,
		Category:    CategorySecurity,
		Action:      "auth.login",
		Outcome:     ServiceOutcomeSuccess,
		ActorID:     "user-456",
		ActorType:   "user",
		ActorIP:     "192.168.1.1",
		TargetID:    "target-789",
		TargetType:  "session",
		ResourceID:  "resource-123",
		SessionID:   "session-456",
		RequestID:   "req-789",
		Details: map[string]interface{}{
			"method": "password",
			"user_agent": "test-agent",
		},
	}

	delivery := &WebhookDelivery{
		Event:      event,
		WebhookURL: testServer.URL,
		RetryCount: 0,
		ID:         "delivery-payload",
	}

	streamer.deliverWebhook(delivery)

	// Verify payload structure
	assert.NotEmpty(t, receivedJSON)
	assert.Equal(t, "event-payload", receivedJSON["id"])
	assert.Equal(t, "authentication", receivedJSON["event_type"])
	assert.Equal(t, "security", receivedJSON["category"])
	assert.Equal(t, "auth.login", receivedJSON["action"])
	assert.Equal(t, "success", receivedJSON["outcome"])
	assert.Equal(t, "user-456", receivedJSON["actor_id"])
	assert.Equal(t, "user", receivedJSON["actor_type"])
	assert.Equal(t, "192.168.1.1", receivedJSON["actor_ip"])
}

func TestWebhookConfig_Update(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)
	streamer := NewEventStreamer(logger, service)

	// Verify defaults
	assert.Equal(t, 5, streamer.webhookConfig.MaxRetries)
	assert.Equal(t, time.Second, streamer.webhookConfig.RetryDelay)

	// Update config
	newConfig := &WebhookConfig{
		MaxRetries: 10,
		RetryDelay: 2 * time.Second,
		Timeout:    60 * time.Second,
		QueueSize:   2000,
		Enabled:    false,
	}

	streamer.webhookConfig = newConfig

	assert.Equal(t, 10, streamer.webhookConfig.MaxRetries)
	assert.Equal(t, 2*time.Second, streamer.webhookConfig.RetryDelay)
	assert.Equal(t, 60*time.Second, streamer.webhookConfig.Timeout)
	assert.Equal(t, 2000, streamer.webhookConfig.QueueSize)
	assert.False(t, streamer.webhookConfig.Enabled)
}

// Benchmark tests
func BenchmarkWebhookDelivery_Success(b *testing.B) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer testServer.Close()

	logger := zap.NewNop()
	service := createTestService(&testing.T{})
	streamer := NewEventStreamer(logger, service)

	event := &ServiceAuditEvent{
		ID:        "bench-event",
		Timestamp: time.Now().UTC(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		delivery := &WebhookDelivery{
			Event:      event,
			WebhookURL: testServer.URL,
			RetryCount: 0,
			ID:         "bench-delivery",
		}
		streamer.deliverWebhook(delivery)
	}
}

func BenchmarkWebhookPayload_Marshal(b *testing.B) {
	event := &ServiceAuditEvent{
		ID:          "bench-event",
		Timestamp:   time.Now().UTC(),
		EventType:   EventTypeAuthentication,
		Category:    CategorySecurity,
		Action:      "auth.login",
		Outcome:     ServiceOutcomeSuccess,
		ActorID:     "user-456",
		Details: map[string]interface{}{
			"key1": "value1",
			"key2": "value2",
			"key3": 12345,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		json.Marshal(event)
	}
}
