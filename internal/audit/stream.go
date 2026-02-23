// Package audit provides real-time event streaming via WebSocket and webhook delivery
package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

// EventStreamer manages real-time streaming of audit events
type EventStreamer struct {
	logger        *zap.Logger
	clients       map[string]*StreamClient
	clientsMutex  sync.RWMutex
	webhookQueue  chan *WebhookDelivery
	webhookConfig *WebhookConfig
	service       *Service
}

// StreamClient represents a connected WebSocket client
type StreamClient struct {
	ID         string
	Conn       *websocket.Conn
	Send       chan *ServiceAuditEvent
	Filters    *StreamFilters
	done       chan struct{}
	mu         sync.Mutex
}

// StreamFilters defines event filters for a stream client
type StreamFilters struct {
	EventTypes []EventType           `json:"event_types"`
	Categories []EventCategory       `json:"categories"`
	ActorID    string                `json:"actor_id,omitempty"`
	Outcome    *ServiceEventOutcome  `json:"outcome,omitempty"`
}

// WebhookConfig holds webhook delivery configuration
type WebhookConfig struct {
	MaxRetries      int           `json:"max_retries"`
	RetryDelay      time.Duration `json:"retry_delay"`
	Timeout         time.Duration `json:"timeout"`
	QueueSize       int           `json:"queue_size"`
	Enabled         bool          `json:"enabled"`
}

// WebhookDelivery represents a webhook delivery attempt
type WebhookDelivery struct {
	Event      *ServiceAuditEvent `json:"event"`
	WebhookURL string             `json:"webhook_url"`
	RetryCount int                `json:"retry_count"`
	ID         string             `json:"id"`
}

// WebhookSubscription represents a registered webhook endpoint
type WebhookSubscription struct {
	ID            string         `json:"id"`
	URL           string         `json:"url"`
	Secret        string         `json:"secret,omitempty"`
	Enabled       bool           `json:"enabled"`
	Filters       *StreamFilters `json:"filters,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	LastDelivery  time.Time      `json:"last_delivery,omitempty"`
	FailureCount  int            `json:"failure_count"`
}

// WebSocket upgrader configuration
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // TODO: Configure proper origin checking
	},
}

// NewEventStreamer creates a new event streamer
func NewEventStreamer(logger *zap.Logger, service *Service) *EventStreamer {
	config := &WebhookConfig{
		MaxRetries: 5,
		RetryDelay: time.Second,
		Timeout:    30 * time.Second,
		QueueSize:  1000,
		Enabled:    true,
	}

	return &EventStreamer{
		logger:       logger,
		clients:      make(map[string]*StreamClient),
		webhookQueue: make(chan *WebhookDelivery, config.QueueSize),
		webhookConfig: config,
		service:      service,
	}
}

// RegisterRoutes registers streaming routes
func (es *EventStreamer) RegisterRoutes(r *gin.RouterGroup) {
	stream := r.Group("/stream")
	{
		stream.GET("", es.handleWebSocketStream)
		stream.POST("/subscribe", es.handleSubscribe)
	}

	webhooks := r.Group("/webhooks")
	{
		webhooks.POST("", es.handleRegisterWebhook)
		webhooks.GET("", es.handleListWebhooks)
		webhooks.DELETE("/:id", es.handleDeleteWebhook)
		webhooks.POST("/:id/test", es.handleTestWebhook)
	}

	// Start webhook delivery worker
	go es.webhookWorker()
}

// handleWebSocketStream upgrades HTTP to WebSocket and streams events
func (es *EventStreamer) handleWebSocketStream(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		es.logger.Error("Failed to upgrade to WebSocket", zap.Error(err))
		return
	}

	clientID := c.Query("client_id")
	if clientID == "" {
		clientID = fmt.Sprintf("client_%d", time.Now().UnixNano())
	}

	// Parse filters from query params
	filters := &StreamFilters{}
	if eventTypes := c.Query("event_types"); eventTypes != "" {
		var types []EventType
		for _, t := range splitAndTrim(eventTypes, ",") {
			types = append(types, EventType(t))
		}
		filters.EventTypes = types
	}
	if categories := c.Query("categories"); categories != "" {
		var cats []EventCategory
		for _, c := range splitAndTrim(categories, ",") {
			cats = append(cats, EventCategory(c))
		}
		filters.Categories = cats
	}
	filters.ActorID = c.Query("actor_id")
	if outcome := c.Query("outcome"); outcome != "" {
		o := ServiceEventOutcome(outcome)
		filters.Outcome = &o
	}

	client := &StreamClient{
		ID:      clientID,
		Conn:    conn,
		Send:    make(chan *ServiceAuditEvent, 256),
		Filters: filters,
		done:    make(chan struct{}),
	}

	es.clientsMutex.Lock()
	es.clients[clientID] = client
	es.clientsMutex.Unlock()

	es.logger.Info("WebSocket client connected",
		zap.String("client_id", clientID),
		zap.String("remote_addr", c.Request.RemoteAddr))

	// Start reader and writer goroutines
	go client.readPump(es)
	go client.writePump(es)
}

// readPump reads messages from the WebSocket connection
func (sc *StreamClient) readPump(es *EventStreamer) {
	defer func() {
		sc.Conn.Close()
		close(sc.done)
		es.removeClient(sc.ID)
	}()

	sc.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	sc.Conn.SetPongHandler(func(string) error {
		sc.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, _, err := sc.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				es.logger.Error("WebSocket read error",
					zap.String("client_id", sc.ID),
					zap.Error(err))
			}
			break
		}
	}
}

// writePump writes events to the WebSocket connection
func (sc *StreamClient) writePump(es *EventStreamer) {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		sc.Conn.Close()
	}()

	for {
		select {
		case event, ok := <-sc.Send:
			sc.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				sc.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if sc.matchesFilters(event) {
				data, err := json.Marshal(event)
				if err != nil {
					es.logger.Error("Failed to marshal event",
						zap.String("client_id", sc.ID),
						zap.Error(err))
					continue
				}

				if err := sc.Conn.WriteMessage(websocket.TextMessage, data); err != nil {
					es.logger.Error("WebSocket write error",
						zap.String("client_id", sc.ID),
						zap.Error(err))
					return
				}
			}

		case <-ticker.C:
			sc.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := sc.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}

		case <-sc.done:
			return
		}
	}
}

// matchesFilters checks if an event matches the client's filters
func (sc *StreamClient) matchesFilters(event *ServiceAuditEvent) bool {
	if sc.Filters == nil {
		return true
	}

	// Filter by event type
	if len(sc.Filters.EventTypes) > 0 {
		found := false
		for _, et := range sc.Filters.EventTypes {
			if event.EventType == et {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Filter by category
	if len(sc.Filters.Categories) > 0 {
		found := false
		for _, cat := range sc.Filters.Categories {
			if event.Category == cat {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Filter by actor ID
	if sc.Filters.ActorID != "" && event.ActorID != sc.Filters.ActorID {
		return false
	}

	// Filter by outcome
	if sc.Filters.Outcome != nil && event.Outcome != *sc.Filters.Outcome {
		return false
	}

	return true
}

// Broadcast sends an event to all connected WebSocket clients
func (es *EventStreamer) Broadcast(event *ServiceAuditEvent) {
	es.clientsMutex.RLock()
	defer es.clientsMutex.RUnlock()

	for _, client := range es.clients {
		select {
		case client.Send <- event:
		default:
			es.logger.Warn("Client send buffer full, dropping event",
				zap.String("client_id", client.ID))
		}
	}
}

// removeClient removes a client from the clients map
func (es *EventStreamer) removeClient(clientID string) {
	es.clientsMutex.Lock()
	defer es.clientsMutex.Unlock()
	delete(es.clients, clientID)
	es.logger.Info("WebSocket client disconnected", zap.String("client_id", clientID))
}

// handleSubscribe handles a subscription request (alternative to WebSocket)
func (es *EventStreamer) handleSubscribe(c *gin.Context) {
	var req struct {
		ClientID string         `json:"client_id"`
		Filters  *StreamFilters `json:"filters"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request body"})
		return
	}

	c.JSON(200, gin.H{
		"message":   "Use WebSocket endpoint at /api/v1/audit/stream for real-time events",
		"client_id": req.ClientID,
		"ws_url":    fmt.Sprintf("/api/v1/audit/stream?client_id=%s", req.ClientID),
	})
}

// handleRegisterWebhook registers a new webhook subscription
func (es *EventStreamer) handleRegisterWebhook(c *gin.Context) {
	var req struct {
		URL     string         `json:"url" binding:"required"`
		Secret  string         `json:"secret"`
		Enabled bool           `json:"enabled"`
		Filters *StreamFilters `json:"filters"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request body"})
		return
	}

	subscription := &WebhookSubscription{
		ID:        generateUUID(),
		URL:       req.URL,
		Secret:    req.Secret,
		Enabled:   req.Enabled,
		Filters:   req.Filters,
		CreatedAt: time.Now().UTC(),
	}

	// Store subscription in database
	ctx := c.Request.Context()
	_, err := es.service.db.Pool.Exec(ctx, `
		INSERT INTO webhook_subscriptions (id, url, secret, enabled, filters, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, subscription.ID, subscription.URL, subscription.Secret, subscription.Enabled,
		subscription.Filters, subscription.CreatedAt)

	if err != nil {
		es.logger.Error("Failed to store webhook subscription", zap.Error(err))
		c.JSON(500, gin.H{"error": "failed to register webhook"})
		return
	}

	c.JSON(201, subscription)
}

// handleListWebhooks lists all webhook subscriptions
func (es *EventStreamer) handleListWebhooks(c *gin.Context) {
	ctx := c.Request.Context()
	rows, err := es.service.db.Pool.Query(ctx, `
		SELECT id, url, enabled, filters, created_at, last_delivery, failure_count
		FROM webhook_subscriptions
		ORDER BY created_at DESC
	`)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to query webhooks"})
		return
	}
	defer rows.Close()

	var webhooks []*WebhookSubscription
	for rows.Next() {
		var wh WebhookSubscription
		var filtersJSON []byte
		err := rows.Scan(&wh.ID, &wh.URL, &wh.Enabled, &filtersJSON,
			&wh.CreatedAt, &wh.LastDelivery, &wh.FailureCount)
		if err != nil {
			continue
		}
		if len(filtersJSON) > 0 {
			json.Unmarshal(filtersJSON, &wh.Filters)
		}
		webhooks = append(webhooks, &wh)
	}

	c.JSON(200, webhooks)
}

// handleDeleteWebhook deletes a webhook subscription
func (es *EventStreamer) handleDeleteWebhook(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()

	_, err := es.service.db.Pool.Exec(ctx,
		"DELETE FROM webhook_subscriptions WHERE id = $1", id)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to delete webhook"})
		return
	}

	c.JSON(204, nil)
}

// handleTestWebhook sends a test event to a webhook
func (es *EventStreamer) handleTestWebhook(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()

	var url string
	err := es.service.db.Pool.QueryRow(ctx,
		"SELECT url FROM webhook_subscriptions WHERE id = $1", id).Scan(&url)
	if err != nil {
		c.JSON(404, gin.H{"error": "webhook not found"})
		return
	}

	// Create test event
	testEvent := &ServiceAuditEvent{
		ID:        generateUUID(),
		Timestamp: time.Now().UTC(),
		EventType: EventTypeSystem,
		Category:  CategoryOperational,
		Action:    "webhook.test",
		Outcome:   ServiceOutcomeSuccess,
		Details: map[string]interface{}{
			"message": "Test webhook delivery",
			"test":    true,
		},
	}

	delivery := &WebhookDelivery{
		Event:      testEvent,
		WebhookURL: url,
		RetryCount: 0,
		ID:         generateUUID(),
	}

	// Send test delivery directly
	success := es.deliverWebhook(delivery)
	if success {
		c.JSON(200, gin.H{"status": "delivered", "event": testEvent})
	} else {
		c.JSON(500, gin.H{"status": "failed", "event": testEvent})
	}
}

// SendWebhook queues a webhook for delivery
func (es *EventStreamer) SendWebhook(event *ServiceAuditEvent, webhookURL string) {
	delivery := &WebhookDelivery{
		Event:      event,
		WebhookURL: webhookURL,
		RetryCount: 0,
		ID:         generateUUID(),
	}

	select {
	case es.webhookQueue <- delivery:
	default:
		es.logger.Warn("Webhook queue full, dropping delivery",
			zap.String("webhook_url", webhookURL),
			zap.String("event_id", event.ID))
	}
}

// webhookWorker processes webhook deliveries from the queue
func (es *EventStreamer) webhookWorker() {
	for delivery := range es.webhookQueue {
		if !es.webhookConfig.Enabled {
			continue
		}

		success := es.deliverWebhook(delivery)
		if !success && delivery.RetryCount < es.webhookConfig.MaxRetries {
			// Exponential backoff retry
			delay := es.webhookConfig.RetryDelay * time.Duration(1<<uint(delivery.RetryCount))
			time.Sleep(delay)
			delivery.RetryCount++
			es.webhookQueue <- delivery
		}
	}
}

// deliverWebhook delivers a single webhook with retry logic
func (es *EventStreamer) deliverWebhook(delivery *WebhookDelivery) bool {
	ctx, cancel := context.WithTimeout(context.Background(), es.webhookConfig.Timeout)
	defer cancel()

	data, err := json.Marshal(delivery.Event)
	if err != nil {
		es.logger.Error("Failed to marshal webhook payload",
			zap.String("delivery_id", delivery.ID),
			zap.Error(err))
		return false
	}

	req, err := http.NewRequestWithContext(ctx, "POST", delivery.WebhookURL, bytes.NewReader(data))
	if err != nil {
		es.logger.Error("Failed to create webhook request",
			zap.String("delivery_id", delivery.ID),
			zap.Error(err))
		return false
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "OpenIDX-Audit-Streamer/1.0")
	req.Header.Set("X-OpenIDX-Delivery-ID", delivery.ID)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		es.logger.Warn("Webhook delivery failed",
			zap.String("delivery_id", delivery.ID),
			zap.String("webhook_url", delivery.WebhookURL),
			zap.Int("retry_count", delivery.RetryCount),
			zap.Error(err))
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		es.logger.Debug("Webhook delivered successfully",
			zap.String("delivery_id", delivery.ID),
			zap.String("webhook_url", delivery.WebhookURL),
			zap.Int("status_code", resp.StatusCode))

		// Update last delivery time
		updateCtx := context.Background()
		_, _ = es.service.db.Pool.Exec(updateCtx, `
			UPDATE webhook_subscriptions
			SET last_delivery = NOW(), failure_count = 0
			WHERE url = $1
		`, delivery.WebhookURL)

		return true
	}

	es.logger.Warn("Webhook returned non-success status",
		zap.String("delivery_id", delivery.ID),
		zap.String("webhook_url", delivery.WebhookURL),
		zap.Int("status_code", resp.StatusCode))

	// Increment failure count
	updateCtx := context.Background()
	_, _ = es.service.db.Pool.Exec(updateCtx, `
		UPDATE webhook_subscriptions
		SET failure_count = failure_count + 1
		WHERE url = $1
	`, delivery.WebhookURL)

	return false
}

// GetConnectedClients returns the number of connected WebSocket clients
func (es *EventStreamer) GetConnectedClients() int {
	es.clientsMutex.RLock()
	defer es.clientsMutex.RUnlock()
	return len(es.clients)
}

// splitAndTrim splits a string and trims whitespace from each part
func splitAndTrim(s, sep string) []string {
	if s == "" {
		return nil
	}
	parts := make([]string, 0)
	for _, p := range splitString(s, sep) {
		if trimmed := trimString(p); trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}

// Helper functions for string manipulation
func splitString(s, sep string) []string {
	if s == "" {
		return []string{}
	}
	var result []string
	current := ""
	for _, c := range s {
		if string(c) == sep {
			result = append(result, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	result = append(result, current)
	return result
}

func trimString(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}
