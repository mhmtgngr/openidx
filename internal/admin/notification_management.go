package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	apperrors "github.com/openidx/openidx/internal/common/errors"
)

// NotificationRoutingRule represents a rule for routing notifications to channels
type NotificationRoutingRule struct {
	ID                string          `json:"id"`
	Name              string          `json:"name"`
	EventType         string          `json:"event_type"`
	Conditions        json.RawMessage `json:"conditions"`
	Channels          json.RawMessage `json:"channels"` // ["in_app", "email", "sms"]
	TemplateOverrides json.RawMessage `json:"template_overrides"`
	Priority          int             `json:"priority"`
	Enabled           bool            `json:"enabled"`
	CreatedBy         *string         `json:"created_by"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

// NotificationDigest represents a digest configuration for batching notifications
type NotificationDigest struct {
	ID                string          `json:"id"`
	UserID            string          `json:"user_id"`
	DigestType        string          `json:"digest_type"` // daily, weekly
	Channel           string          `json:"channel"`
	LastSentAt        *time.Time      `json:"last_sent_at"`
	NextScheduledAt   *time.Time      `json:"next_scheduled_at"`
	NotificationCount int             `json:"notification_count"`
	Enabled           bool            `json:"enabled"`
	Settings          json.RawMessage `json:"settings"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

// BroadcastMessage represents a broadcast notification sent to multiple users
type BroadcastMessage struct {
	ID              string          `json:"id"`
	Title           string          `json:"title"`
	Body            string          `json:"body"`
	Channel         string          `json:"channel"`
	TargetType      string          `json:"target_type"` // all, role, group
	TargetIDs       json.RawMessage `json:"target_ids"`
	Priority        string          `json:"priority"` // low, normal, high, urgent
	ScheduledAt     *time.Time      `json:"scheduled_at"`
	SentAt          *time.Time      `json:"sent_at"`
	Status          string          `json:"status"` // draft, scheduled, sent, cancelled
	TotalRecipients int             `json:"total_recipients"`
	DeliveredCount  int             `json:"delivered_count"`
	ReadCount       int             `json:"read_count"`
	CreatedBy       *string         `json:"created_by"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// --- Routing Rules Handlers ---

func (s *Service) handleListRoutingRules(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, name, event_type, conditions, channels, template_overrides, priority, enabled, created_by, created_at, updated_at
		 FROM notification_routing_rules ORDER BY priority, event_type`)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to list routing rules", err))
		return
	}
	defer rows.Close()

	var rules []NotificationRoutingRule
	for rows.Next() {
		var r NotificationRoutingRule
		if err := rows.Scan(&r.ID, &r.Name, &r.EventType, &r.Conditions, &r.Channels,
			&r.TemplateOverrides, &r.Priority, &r.Enabled, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt); err != nil {
			continue
		}
		rules = append(rules, r)
	}
	if rules == nil {
		rules = []NotificationRoutingRule{}
	}
	c.JSON(http.StatusOK, gin.H{"data": rules})
}

func (s *Service) handleCreateRoutingRule(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	var req struct {
		Name       string          `json:"name"`
		EventType  string          `json:"event_type"`
		Conditions json.RawMessage `json:"conditions"`
		Channels   json.RawMessage `json:"channels"`
		Priority   int             `json:"priority"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, nil, apperrors.BadRequest("Invalid request body"))
		return
	}

	if req.Name == "" || req.EventType == "" {
		respondError(c, nil, apperrors.BadRequest("name and event_type are required"))
		return
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	conditions := req.Conditions
	if conditions == nil {
		conditions = json.RawMessage("{}")
	}
	channels := req.Channels
	if channels == nil {
		channels = json.RawMessage(`["in_app"]`)
	}

	var rule NotificationRoutingRule
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`INSERT INTO notification_routing_rules (name, event_type, conditions, channels, priority, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, name, event_type, conditions, channels, template_overrides, priority, enabled, created_by, created_at, updated_at`,
		req.Name, req.EventType, conditions, channels, req.Priority, nilIfEmpty(userIDStr),
	).Scan(&rule.ID, &rule.Name, &rule.EventType, &rule.Conditions, &rule.Channels,
		&rule.TemplateOverrides, &rule.Priority, &rule.Enabled, &rule.CreatedBy, &rule.CreatedAt, &rule.UpdatedAt)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to create routing rule", err))
		return
	}

	c.JSON(http.StatusCreated, rule)
}

func (s *Service) handleGetRoutingRule(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	var r NotificationRoutingRule
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT id, name, event_type, conditions, channels, template_overrides, priority, enabled, created_by, created_at, updated_at
		 FROM notification_routing_rules WHERE id = $1`, id,
	).Scan(&r.ID, &r.Name, &r.EventType, &r.Conditions, &r.Channels,
		&r.TemplateOverrides, &r.Priority, &r.Enabled, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		respondError(c, nil, apperrors.NotFound("Routing rule"))
		return
	}
	c.JSON(http.StatusOK, r)
}

func (s *Service) handleUpdateRoutingRule(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	var req struct {
		Name              *string          `json:"name"`
		EventType         *string          `json:"event_type"`
		Conditions        *json.RawMessage `json:"conditions"`
		Channels          *json.RawMessage `json:"channels"`
		TemplateOverrides *json.RawMessage `json:"template_overrides"`
		Priority          *int             `json:"priority"`
		Enabled           *bool            `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, nil, apperrors.BadRequest("Invalid request body"))
		return
	}

	sets := []string{"updated_at = NOW()"}
	args := []interface{}{}
	argIdx := 1

	if req.Name != nil {
		sets = append(sets, fmt.Sprintf("name = $%d", argIdx))
		args = append(args, *req.Name)
		argIdx++
	}
	if req.EventType != nil {
		sets = append(sets, fmt.Sprintf("event_type = $%d", argIdx))
		args = append(args, *req.EventType)
		argIdx++
	}
	if req.Conditions != nil {
		sets = append(sets, fmt.Sprintf("conditions = $%d", argIdx))
		args = append(args, *req.Conditions)
		argIdx++
	}
	if req.Channels != nil {
		sets = append(sets, fmt.Sprintf("channels = $%d", argIdx))
		args = append(args, *req.Channels)
		argIdx++
	}
	if req.TemplateOverrides != nil {
		sets = append(sets, fmt.Sprintf("template_overrides = $%d", argIdx))
		args = append(args, *req.TemplateOverrides)
		argIdx++
	}
	if req.Priority != nil {
		sets = append(sets, fmt.Sprintf("priority = $%d", argIdx))
		args = append(args, *req.Priority)
		argIdx++
	}
	if req.Enabled != nil {
		sets = append(sets, fmt.Sprintf("enabled = $%d", argIdx))
		args = append(args, *req.Enabled)
		argIdx++
	}

	args = append(args, id)
	query := fmt.Sprintf("UPDATE notification_routing_rules SET %s WHERE id = $%d",
		joinStrings(sets, ", "), argIdx)

	tag, err := s.db.Pool.Exec(c.Request.Context(), query, args...)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to update routing rule", err))
		return
	}
	if tag.RowsAffected() == 0 {
		respondError(c, nil, apperrors.NotFound("Routing rule"))
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Routing rule updated"})
}

func (s *Service) handleDeleteRoutingRule(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	tag, err := s.db.Pool.Exec(c.Request.Context(),
		"DELETE FROM notification_routing_rules WHERE id = $1", id)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to delete routing rule", err))
		return
	}
	if tag.RowsAffected() == 0 {
		respondError(c, nil, apperrors.NotFound("Routing rule"))
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Routing rule deleted"})
}

// --- Broadcast Messages Handlers ---

func (s *Service) handleListBroadcasts(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	ctx := c.Request.Context()
	status := c.Query("status")

	query := `SELECT b.id, b.title, b.body, b.channel, b.target_type, b.target_ids, b.priority,
	                 b.scheduled_at, b.sent_at, b.status, b.total_recipients, b.delivered_count, b.read_count,
	                 b.created_by, b.created_at, b.updated_at,
	                 COALESCE(u.first_name || ' ' || u.last_name, '') AS created_by_name
	          FROM broadcast_messages b
	          LEFT JOIN users u ON b.created_by = u.id`

	args := []interface{}{}
	if status != "" {
		query += " WHERE b.status = $1"
		args = append(args, status)
	}
	query += " ORDER BY b.created_at DESC"

	rows, err := s.db.Pool.Query(ctx, query, args...)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to list broadcasts", err))
		return
	}
	defer rows.Close()

	type BroadcastWithCreator struct {
		BroadcastMessage
		CreatedByName string `json:"created_by_name"`
	}

	var broadcasts []BroadcastWithCreator
	for rows.Next() {
		var b BroadcastWithCreator
		if err := rows.Scan(&b.ID, &b.Title, &b.Body, &b.Channel, &b.TargetType, &b.TargetIDs,
			&b.Priority, &b.ScheduledAt, &b.SentAt, &b.Status, &b.TotalRecipients,
			&b.DeliveredCount, &b.ReadCount, &b.CreatedBy, &b.CreatedAt, &b.UpdatedAt,
			&b.CreatedByName); err != nil {
			continue
		}
		broadcasts = append(broadcasts, b)
	}
	if broadcasts == nil {
		broadcasts = []BroadcastWithCreator{}
	}
	c.JSON(http.StatusOK, gin.H{"data": broadcasts})
}

func (s *Service) handleCreateBroadcast(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	var req struct {
		Title       string          `json:"title"`
		Body        string          `json:"body"`
		Channel     string          `json:"channel"`
		TargetType  string          `json:"target_type"`
		TargetIDs   json.RawMessage `json:"target_ids"`
		Priority    string          `json:"priority"`
		ScheduledAt *time.Time      `json:"scheduled_at"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, nil, apperrors.BadRequest("Invalid request body"))
		return
	}

	if req.Title == "" || req.Body == "" {
		respondError(c, nil, apperrors.BadRequest("title and body are required"))
		return
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	if req.Channel == "" {
		req.Channel = "in_app"
	}
	if req.TargetType == "" {
		req.TargetType = "all"
	}
	if req.Priority == "" {
		req.Priority = "normal"
	}
	targetIDs := req.TargetIDs
	if targetIDs == nil {
		targetIDs = json.RawMessage("[]")
	}

	var b BroadcastMessage
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`INSERT INTO broadcast_messages (title, body, channel, target_type, target_ids, priority, scheduled_at, status, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, 'draft', $8)
		 RETURNING id, title, body, channel, target_type, target_ids, priority, scheduled_at, sent_at, status,
		           total_recipients, delivered_count, read_count, created_by, created_at, updated_at`,
		req.Title, req.Body, req.Channel, req.TargetType, targetIDs, req.Priority, req.ScheduledAt, nilIfEmpty(userIDStr),
	).Scan(&b.ID, &b.Title, &b.Body, &b.Channel, &b.TargetType, &b.TargetIDs, &b.Priority,
		&b.ScheduledAt, &b.SentAt, &b.Status, &b.TotalRecipients, &b.DeliveredCount, &b.ReadCount,
		&b.CreatedBy, &b.CreatedAt, &b.UpdatedAt)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to create broadcast", err))
		return
	}

	c.JSON(http.StatusCreated, b)
}

func (s *Service) handleGetBroadcast(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	var b BroadcastMessage
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT id, title, body, channel, target_type, target_ids, priority, scheduled_at, sent_at, status,
		        total_recipients, delivered_count, read_count, created_by, created_at, updated_at
		 FROM broadcast_messages WHERE id = $1`, id,
	).Scan(&b.ID, &b.Title, &b.Body, &b.Channel, &b.TargetType, &b.TargetIDs, &b.Priority,
		&b.ScheduledAt, &b.SentAt, &b.Status, &b.TotalRecipients, &b.DeliveredCount, &b.ReadCount,
		&b.CreatedBy, &b.CreatedAt, &b.UpdatedAt)
	if err != nil {
		respondError(c, nil, apperrors.NotFound("Broadcast"))
		return
	}
	c.JSON(http.StatusOK, b)
}

func (s *Service) handleSendBroadcast(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	ctx := c.Request.Context()

	// Fetch the broadcast
	var b BroadcastMessage
	err := s.db.Pool.QueryRow(ctx,
		`SELECT id, title, body, channel, target_type, target_ids, priority, status
		 FROM broadcast_messages WHERE id = $1`, id,
	).Scan(&b.ID, &b.Title, &b.Body, &b.Channel, &b.TargetType, &b.TargetIDs, &b.Priority, &b.Status)
	if err != nil {
		respondError(c, nil, apperrors.NotFound("Broadcast"))
		return
	}

	if b.Status == "sent" {
		respondError(c, nil, apperrors.BadRequest("Broadcast has already been sent"))
		return
	}
	if b.Status == "cancelled" {
		respondError(c, nil, apperrors.BadRequest("Broadcast has been cancelled"))
		return
	}

	// Count target users based on target_type
	var recipientCount int
	switch b.TargetType {
	case "all":
		err = s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&recipientCount)
	case "role":
		var roleIDs []string
		if err := json.Unmarshal(b.TargetIDs, &roleIDs); err != nil {
			respondError(c, nil, apperrors.BadRequest("Invalid target_ids for role target type"))
			return
		}
		if len(roleIDs) == 0 {
			respondError(c, nil, apperrors.BadRequest("target_ids must not be empty for role target type"))
			return
		}
		err = s.db.Pool.QueryRow(ctx,
			`SELECT COUNT(DISTINCT user_id) FROM user_roles WHERE role_id = ANY($1::uuid[])`, roleIDs,
		).Scan(&recipientCount)
	case "group":
		var groupIDs []string
		if err := json.Unmarshal(b.TargetIDs, &groupIDs); err != nil {
			respondError(c, nil, apperrors.BadRequest("Invalid target_ids for group target type"))
			return
		}
		if len(groupIDs) == 0 {
			respondError(c, nil, apperrors.BadRequest("target_ids must not be empty for group target type"))
			return
		}
		err = s.db.Pool.QueryRow(ctx,
			`SELECT COUNT(DISTINCT user_id) FROM group_memberships WHERE group_id = ANY($1::uuid[])`, groupIDs,
		).Scan(&recipientCount)
	default:
		respondError(c, nil, apperrors.BadRequest("Invalid target_type"))
		return
	}
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to count target recipients", err))
		return
	}

	// Insert notifications for each target user using INSERT...SELECT
	var insertQuery string
	var insertArgs []interface{}

	switch b.TargetType {
	case "all":
		insertQuery = `INSERT INTO notifications (user_id, channel, type, title, body, metadata)
			SELECT id, $1, 'broadcast', $2, $3, jsonb_build_object('broadcast_id', $4)
			FROM users`
		insertArgs = []interface{}{b.Channel, b.Title, b.Body, b.ID}
	case "role":
		var roleIDs []string
		_ = json.Unmarshal(b.TargetIDs, &roleIDs)
		insertQuery = `INSERT INTO notifications (user_id, channel, type, title, body, metadata)
			SELECT DISTINCT ur.user_id, $1, 'broadcast', $2, $3, jsonb_build_object('broadcast_id', $4)
			FROM user_roles ur WHERE ur.role_id = ANY($5::uuid[])`
		insertArgs = []interface{}{b.Channel, b.Title, b.Body, b.ID, roleIDs}
	case "group":
		var groupIDs []string
		_ = json.Unmarshal(b.TargetIDs, &groupIDs)
		insertQuery = `INSERT INTO notifications (user_id, channel, type, title, body, metadata)
			SELECT DISTINCT gm.user_id, $1, 'broadcast', $2, $3, jsonb_build_object('broadcast_id', $4)
			FROM group_memberships gm WHERE gm.group_id = ANY($5::uuid[])`
		insertArgs = []interface{}{b.Channel, b.Title, b.Body, b.ID, groupIDs}
	}

	_, err = s.db.Pool.Exec(ctx, insertQuery, insertArgs...)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to send broadcast notifications", err))
		return
	}

	// Update broadcast status
	_, err = s.db.Pool.Exec(ctx,
		`UPDATE broadcast_messages
		 SET status = 'sent', sent_at = NOW(), total_recipients = $1, delivered_count = $1, updated_at = NOW()
		 WHERE id = $2`,
		recipientCount, id)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to update broadcast status", err))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":          "Broadcast sent successfully",
		"total_recipients": recipientCount,
	})
}

func (s *Service) handleDeleteBroadcast(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	ctx := c.Request.Context()

	// Only allow deleting drafts
	var status string
	err := s.db.Pool.QueryRow(ctx,
		"SELECT status FROM broadcast_messages WHERE id = $1", id).Scan(&status)
	if err != nil {
		respondError(c, nil, apperrors.NotFound("Broadcast"))
		return
	}
	if status != "draft" {
		respondError(c, nil, apperrors.BadRequest("Only draft broadcasts can be deleted"))
		return
	}

	tag, err := s.db.Pool.Exec(ctx,
		"DELETE FROM broadcast_messages WHERE id = $1 AND status = 'draft'", id)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to delete broadcast", err))
		return
	}
	if tag.RowsAffected() == 0 {
		respondError(c, nil, apperrors.NotFound("Broadcast"))
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Broadcast deleted"})
}

// --- Notification Stats Handler ---

func (s *Service) handleNotificationStats(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	ctx := c.Request.Context()

	// Total counts
	var totalSent, totalRead, totalUnread int
	err := s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM notifications").Scan(&totalSent)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to get notification stats", err))
		return
	}
	err = s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM notifications WHERE read = true").Scan(&totalRead)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to get notification stats", err))
		return
	}
	err = s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM notifications WHERE read = false").Scan(&totalUnread)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to get notification stats", err))
		return
	}

	// Channel breakdown
	channelRows, err := s.db.Pool.Query(ctx,
		"SELECT channel, COUNT(*) FROM notifications GROUP BY channel")
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to get notification stats", err))
		return
	}
	defer channelRows.Close()

	channelBreakdown := map[string]int{}
	for channelRows.Next() {
		var channel string
		var count int
		if err := channelRows.Scan(&channel, &count); err != nil {
			continue
		}
		channelBreakdown[channel] = count
	}

	// Recent broadcasts (last 5)
	broadcastRows, err := s.db.Pool.Query(ctx,
		`SELECT id, title, body, channel, target_type, target_ids, priority, scheduled_at, sent_at, status,
		        total_recipients, delivered_count, read_count, created_by, created_at, updated_at
		 FROM broadcast_messages ORDER BY created_at DESC LIMIT 5`)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to get notification stats", err))
		return
	}
	defer broadcastRows.Close()

	var recentBroadcasts []BroadcastMessage
	for broadcastRows.Next() {
		var b BroadcastMessage
		if err := broadcastRows.Scan(&b.ID, &b.Title, &b.Body, &b.Channel, &b.TargetType, &b.TargetIDs,
			&b.Priority, &b.ScheduledAt, &b.SentAt, &b.Status, &b.TotalRecipients,
			&b.DeliveredCount, &b.ReadCount, &b.CreatedBy, &b.CreatedAt, &b.UpdatedAt); err != nil {
			continue
		}
		recentBroadcasts = append(recentBroadcasts, b)
	}
	if recentBroadcasts == nil {
		recentBroadcasts = []BroadcastMessage{}
	}

	// Routing rules count (enabled only)
	var routingRulesCount int
	err = s.db.Pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM notification_routing_rules WHERE enabled = true").Scan(&routingRulesCount)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to get notification stats", err))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"total_sent":          totalSent,
		"total_read":          totalRead,
		"total_unread":        totalUnread,
		"channel_breakdown":   channelBreakdown,
		"recent_broadcasts":   recentBroadcasts,
		"routing_rules_count": routingRulesCount,
	})
}

