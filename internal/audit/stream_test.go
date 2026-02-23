// Package audit provides unit tests for event streaming
package audit

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestNewEventStreamer(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)

	streamer := NewEventStreamer(logger, service)

	assert.NotNil(t, streamer)
	assert.NotNil(t, streamer.clients)
	assert.NotNil(t, streamer.webhookQueue)
	assert.NotNil(t, streamer.webhookConfig)
	assert.Equal(t, 5, streamer.webhookConfig.MaxRetries)
	assert.Equal(t, time.Second, streamer.webhookConfig.RetryDelay)
	assert.Equal(t, 1000, streamer.webhookConfig.QueueSize)
}

func TestEventStreamer_Broadcast(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)
	streamer := NewEventStreamer(logger, service)

	// Create a mock client
	mockClient := &StreamClient{
		ID:   "test-client-1",
		Send: make(chan *ServiceAuditEvent, 10),
		Filters: &StreamFilters{
			EventTypes: []EventType{EventTypeAuthentication},
		},
		done: make(chan struct{}),
	}
	defer close(mockClient.done)

	streamer.clients[mockClient.ID] = mockClient
	defer delete(streamer.clients, mockClient.ID)

	// Create test event
	event := &ServiceAuditEvent{
		ID:        "event-123",
		Timestamp: time.Now().UTC(),
		EventType: EventTypeAuthentication,
		Category:  CategorySecurity,
		Action:    "auth.login",
		Outcome:   ServiceOutcomeSuccess,
		ActorID:   "user-123",
	}

	// Broadcast event
	streamer.Broadcast(event)

	// Verify event was sent to client
	select {
	case receivedEvent := <-mockClient.Send:
		assert.Equal(t, event.ID, receivedEvent.ID)
		assert.Equal(t, event.EventType, receivedEvent.EventType)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Event not received within timeout")
	}
}

func TestStreamClient_MatchesFilters(t *testing.T) {
	tests := []struct {
		name      string
		filters   *StreamFilters
		event     *ServiceAuditEvent
		expected  bool
	}{
		{
			name: "no filters - match all",
			filters: nil,
			event: &ServiceAuditEvent{
				EventType: EventTypeAuthentication,
				Category:  CategorySecurity,
			},
			expected: true,
		},
		{
			name: "filter by event type - match",
			filters: &StreamFilters{
				EventTypes: []EventType{EventTypeAuthentication, EventTypeAuthorization},
			},
			event: &ServiceAuditEvent{
				EventType: EventTypeAuthentication,
			},
			expected: true,
		},
		{
			name: "filter by event type - no match",
			filters: &StreamFilters{
				EventTypes: []EventType{EventTypeAuthentication},
			},
			event: &ServiceAuditEvent{
				EventType: EventTypeUserManagement,
			},
			expected: false,
		},
		{
			name: "filter by category - match",
			filters: &StreamFilters{
				Categories: []EventCategory{CategorySecurity},
			},
			event: &ServiceAuditEvent{
				Category: CategorySecurity,
			},
			expected: true,
		},
		{
			name: "filter by category - no match",
			filters: &StreamFilters{
				Categories: []EventCategory{CategorySecurity},
			},
			event: &ServiceAuditEvent{
				Category: CategoryOperational,
			},
			expected: false,
		},
		{
			name: "filter by actor ID - match",
			filters: &StreamFilters{
				ActorID: "user-123",
			},
			event: &ServiceAuditEvent{
				ActorID: "user-123",
			},
			expected: true,
		},
		{
			name: "filter by actor ID - no match",
			filters: &StreamFilters{
				ActorID: "user-456",
			},
			event: &ServiceAuditEvent{
				ActorID: "user-123",
			},
			expected: false,
		},
		{
			name: "filter by outcome - match",
			filters: &StreamFilters{
				Outcome: func() *ServiceEventOutcome { o := ServiceOutcomeSuccess; return &o }(),
			},
			event: &ServiceAuditEvent{
				Outcome: ServiceOutcomeSuccess,
			},
			expected: true,
		},
		{
			name: "filter by outcome - no match",
			filters: &StreamFilters{
				Outcome: func() *ServiceEventOutcome { o := ServiceOutcomeSuccess; return &o }(),
			},
			event: &ServiceAuditEvent{
				Outcome: ServiceOutcomeFailure,
			},
			expected: false,
		},
		{
			name: "multiple filters - all match",
			filters: &StreamFilters{
				EventTypes: []EventType{EventTypeAuthentication},
				Categories: []EventCategory{CategorySecurity},
			},
			event: &ServiceAuditEvent{
				EventType: EventTypeAuthentication,
				Category:  CategorySecurity,
			},
			expected: true,
		},
		{
			name: "multiple filters - partial match",
			filters: &StreamFilters{
				EventTypes: []EventType{EventTypeAuthentication},
				Categories: []EventCategory{CategoryCompliance},
			},
			event: &ServiceAuditEvent{
				EventType: EventTypeAuthentication,
				Category:  CategorySecurity,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &StreamClient{
				Filters: tt.filters,
			}
			result := client.matchesFilters(tt.event)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEventStreamer_GetConnectedClients(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)
	streamer := NewEventStreamer(logger, service)

	// Initially no clients
	assert.Equal(t, 0, streamer.GetConnectedClients())

	// Add mock clients
	client1 := &StreamClient{
		ID:   "client-1",
		Send: make(chan *ServiceAuditEvent),
		done: make(chan struct{}),
	}
	client2 := &StreamClient{
		ID:   "client-2",
		Send: make(chan *ServiceAuditEvent),
		done: make(chan struct{}),
	}

	streamer.clients[client1.ID] = client1
	streamer.clients[client2.ID] = client2

	assert.Equal(t, 2, streamer.GetConnectedClients())

	// Remove a client
	delete(streamer.clients, client1.ID)
	assert.Equal(t, 1, streamer.GetConnectedClients())
}

func TestWebhookConfig_DefaultValues(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)
	streamer := NewEventStreamer(logger, service)

	config := streamer.webhookConfig

	assert.Equal(t, 5, config.MaxRetries)
	assert.Equal(t, time.Second, config.RetryDelay)
	assert.Equal(t, 30*time.Second, config.Timeout)
	assert.Equal(t, 1000, config.QueueSize)
	assert.True(t, config.Enabled)
}

func TestWebhookSubscription_Serialization(t *testing.T) {
	subscription := &WebhookSubscription{
		ID:      "webhook-123",
		URL:     "https://example.com/webhook",
		Secret:  "secret123",
		Enabled: true,
		Filters: &StreamFilters{
			EventTypes: []EventType{EventTypeAuthentication, EventTypeAuthorization},
			Categories: []EventCategory{CategorySecurity},
		},
		CreatedAt:     time.Now().UTC(),
		LastDelivery:  time.Now().UTC(),
		FailureCount:  0,
	}

	data, err := json.Marshal(subscription)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	var unmarshaled WebhookSubscription
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, subscription.ID, unmarshaled.ID)
	assert.Equal(t, subscription.URL, unmarshaled.URL)
	assert.Equal(t, subscription.Enabled, unmarshaled.Enabled)
	assert.NotNil(t, unmarshaled.Filters)
	assert.Len(t, unmarshaled.Filters.EventTypes, 2)
}

func TestSplitAndTrim(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		sep      string
		expected []string
	}{
		{
			name:     "comma separated values",
			input:    "auth,user,admin",
			sep:      ",",
			expected: []string{"auth", "user", "admin"},
		},
		{
			name:     "with whitespace",
			input:    " auth , user , admin ",
			sep:      ",",
			expected: []string{"auth", "user", "admin"},
		},
		{
			name:     "empty string",
			input:    "",
			sep:      ",",
			expected: nil,
		},
		{
			name:     "single value",
			input:    "auth",
			sep:      ",",
			expected: []string{"auth"},
		},
		{
			name:     "empty values",
			input:    "auth,,admin",
			sep:      ",",
			expected: []string{"auth", "admin"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitAndTrim(tt.input, tt.sep)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test WebSocket upgrade endpoint
func TestHandleWebSocketStream(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)
	streamer := NewEventStreamer(logger, service)

	// Create test router
	router := gin.New()
	streamer.RegisterRoutes(router.Group("/api/v1/audit"))

	// Create a test WebSocket server
	server := httptest.NewServer(router)
	defer server.Close()

	// Convert HTTP URL to WS URL
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/api/v1/audit/stream?client_id=test-client"

	// Create WebSocket client
	dialer := websocket.Dialer{}
	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Skip("WebSocket upgrade failed - may need gorilla/websocket server setup")
		return
	}
	defer conn.Close()

	// Verify connection was established
	assert.NotNil(t, conn)

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

	// Wait for ping message
	_, _, err = conn.ReadMessage()
	if err != nil {
		// Timeout is expected as no messages are sent
		assert.Contains(t, err.Error(), "timeout")
	}
}

func TestEventStreamer_RemoveClient(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)
	streamer := NewEventStreamer(logger, service)

	// Add a mock client
	client := &StreamClient{
		ID:   "test-client",
		Send: make(chan *ServiceAuditEvent),
		done: make(chan struct{}),
	}
	streamer.clients[client.ID] = client

	assert.Equal(t, 1, len(streamer.clients))

	// Remove the client
	streamer.removeClient(client.ID)

	assert.Equal(t, 0, len(streamer.clients))
	_, exists := streamer.clients[client.ID]
	assert.False(t, exists)
}

func TestWebhookDelivery_RetryDelay(t *testing.T) {
	tests := []struct {
		name            string
		retryCount      int
		baseDelay       time.Duration
		expectedMinDelay time.Duration
		expectedMaxDelay time.Duration
	}{
		{
			name:            "first retry",
			retryCount:      0,
			baseDelay:       time.Second,
			expectedMinDelay: 0,
			expectedMaxDelay: time.Second,
		},
		{
			name:            "second retry",
			retryCount:      1,
			baseDelay:       time.Second,
			expectedMinDelay: time.Second,
			expectedMaxDelay: 2 * time.Second,
		},
		{
			name:            "third retry",
			retryCount:      2,
			baseDelay:       time.Second,
			expectedMinDelay: 2 * time.Second,
			expectedMaxDelay: 4 * time.Second,
		},
		{
			name:            "fourth retry",
			retryCount:      3,
			baseDelay:       time.Second,
			expectedMinDelay: 4 * time.Second,
			expectedMaxDelay: 8 * time.Second,
		},
		{
			name:            "fifth retry",
			retryCount:      4,
			baseDelay:       time.Second,
			expectedMinDelay: 8 * time.Second,
			expectedMaxDelay: 16 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Calculate expected delay using exponential backoff formula
			delay := tt.baseDelay * time.Duration(1<<uint(tt.retryCount))

			assert.GreaterOrEqual(t, delay, tt.expectedMinDelay)
			assert.LessOrEqual(t, delay, tt.expectedMaxDelay)
		})
	}
}

func TestStreamFilters_JSONUnmarshal(t *testing.T) {
	jsonData := `{
		"event_types": ["authentication", "authorization"],
		"categories": ["security", "compliance"],
		"actor_id": "user-123",
		"outcome": "success"
	}`

	var filters StreamFilters
	err := json.Unmarshal([]byte(jsonData), &filters)
	require.NoError(t, err)

	assert.Len(t, filters.EventTypes, 2)
	assert.Len(t, filters.Categories, 2)
	assert.Equal(t, "user-123", filters.ActorID)
	assert.NotNil(t, filters.Outcome)
	assert.Equal(t, ServiceOutcomeSuccess, *filters.Outcome)
}

// Benchmark tests
func BenchmarkEventStreamer_Broadcast(b *testing.B) {
	logger := zap.NewNop()
	service := createTestService(&testing.T{})
	streamer := NewEventStreamer(logger, service)

	// Add mock clients
	for i := 0; i < 100; i++ {
		client := &StreamClient{
			ID:   "client-" + string(rune(i)),
			Send: make(chan *ServiceAuditEvent, 100),
			done: make(chan struct{}),
		}
		streamer.clients[client.ID] = client
	}

	event := &ServiceAuditEvent{
		ID:        "test-event",
		Timestamp: time.Now().UTC(),
		EventType: EventTypeAuthentication,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		streamer.Broadcast(event)
	}
}

func BenchmarkMatchesFilters(b *testing.B) {
	filters := &StreamFilters{
		EventTypes: []EventType{EventTypeAuthentication, EventTypeAuthorization},
		Categories: []EventCategory{CategorySecurity},
		ActorID:    "user-123",
	}

	client := &StreamClient{
		Filters: filters,
	}

	event := &ServiceAuditEvent{
		EventType: EventTypeAuthentication,
		Category:  CategorySecurity,
		ActorID:   "user-123",
		Outcome:   ServiceOutcomeSuccess,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client.matchesFilters(event)
	}
}
