// Package risk provides security alert generation and delivery
package risk

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// AlertSeverity represents the severity level of an alert
type AlertSeverity string

const (
	SeverityInfo     AlertSeverity = "info"
	SeverityWarning  AlertSeverity = "warning"
	SeverityHigh     AlertSeverity = "high"
	SeverityCritical AlertSeverity = "critical"
)

// AlertType represents the type of security alert
type AlertType string

const (
	AlertTypeImpossibleTravel     AlertType = "impossible_travel"
	AlertTypeBruteForce           AlertType = "brute_force"
	AlertTypeCredentialStuffing    AlertType = "credential_stuffing"
	AlertTypeNewDevice            AlertType = "new_device"
	AlertTypeAnomalousLocation    AlertType = "anomalous_location"
	AlertTypeHighRiskLoginBlocked AlertType = "high_risk_login_blocked"
	AlertTypeAccountLockout       AlertType = "account_lockout"
	AlertTypeMFARequired          AlertType = "mfa_required"
	AlertTypePolicyViolation      AlertType = "policy_violation"
)

// AlertStatus represents the status of an alert
type AlertStatus string

const (
	AlertStatusOpen       AlertStatus = "open"
	AlertStatusAcknowledged AlertStatus = "acknowledged"
	AlertStatusResolved    AlertStatus = "resolved"
	AlertStatusFalsePositive AlertStatus = "false_positive"
)

// Alert represents a security alert
type Alert struct {
	ID                 string                 `json:"id"`
	TenantID           string                 `json:"tenant_id"`
	UserID             *string                `json:"user_id,omitempty"`
	Type               AlertType              `json:"type"`
	Severity           AlertSeverity          `json:"severity"`
	Status             AlertStatus            `json:"status"`
	Title              string                 `json:"title"`
	Description        string                 `json:"description"`
	Details            map[string]interface{} `json:"details,omitempty"`
	SourceIP           string                 `json:"source_ip,omitempty"`
	IPAddress          string                 `json:"ip_address,omitempty"`
	UserAgent          string                 `json:"user_agent,omitempty"`
	RemediationActions []string               `json:"remediation_actions,omitempty"`
	AcknowledgedBy     *string                `json:"acknowledged_by,omitempty"`
	AcknowledgedAt     *time.Time             `json:"acknowledged_at,omitempty"`
	ResolvedBy         *string                `json:"resolved_by,omitempty"`
	ResolvedAt         *time.Time             `json:"resolved_at,omitempty"`
	Deliveries         []AlertDelivery        `json:"deliveries,omitempty"`
	CreatedAt          time.Time              `json:"created_at"`
	UpdatedAt          time.Time              `json:"updated_at"`
}

// AlertDelivery tracks the delivery status of an alert
type AlertDelivery struct {
	ID         string    `json:"id"`
	Channel    string    `json:"channel"` // "webhook", "email", "sms"
	Status     string    `json:"status"`  // "pending", "sent", "failed"
	SentAt     time.Time `json:"sent_at"`
	Error      string    `json:"error,omitempty"`
	RetryCount int       `json:"retry_count"`
}

// AlertConfig holds configuration for alert delivery
type AlertConfig struct {
	// Webhook configuration
	WebhookURL     string
	WebhookTimeout time.Duration
	WebhookHeaders map[string]string

	// Email configuration
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	SMTPUseTLS   bool
	EmailFrom    string
	SecurityTeamEmail []string

	// Retry configuration
	MaxRetries    int
	RetryInterval time.Duration

	// Alert retention
	RetentionDays int
}

// DefaultAlertConfig returns default alert configuration
func DefaultAlertConfig() AlertConfig {
	return AlertConfig{
		WebhookTimeout:  10 * time.Second,
		WebhookHeaders:  make(map[string]string),
		SMTPPort:        587,
		SMTPUseTLS:      true,
		MaxRetries:      3,
		RetryInterval:   5 * time.Minute,
		RetentionDays:   90,
		SecurityTeamEmail: []string{},
	}
}

// AlertManager handles security alert generation and delivery
type AlertManager struct {
	db     *database.PostgresDB
	redis  *database.RedisClient
	config AlertConfig
	logger *zap.Logger
}

// NewAlertManager creates a new alert manager
func NewAlertManager(db *database.PostgresDB, redis *database.RedisClient, config AlertConfig, logger *zap.Logger) *AlertManager {
	if logger == nil {
		logger = zap.NewNop()
	}
	if config.WebhookTimeout == 0 {
		config = DefaultAlertConfig()
	}

	return &AlertManager{
		db:     db,
		redis:  redis,
		config: config,
		logger: logger.With(zap.String("component", "alert_manager")),
	}
}

// GenerateAlert creates and delivers a security alert
func (a *AlertManager) GenerateAlert(ctx context.Context, alert *Alert) error {
	now := time.Now()

	// Set timestamps
	if alert.ID == "" {
		alert.ID = uuid.New().String()
	}
	if alert.CreatedAt.IsZero() {
		alert.CreatedAt = now
	}
	alert.UpdatedAt = now

	// Set default status if not provided
	if alert.Status == "" {
		alert.Status = AlertStatusOpen
	}

	// Validate required fields
	if alert.Type == "" {
		return fmt.Errorf("alert type is required")
	}
	if alert.Severity == "" {
		return fmt.Errorf("alert severity is required")
	}
	if alert.Title == "" {
		return fmt.Errorf("alert title is required")
	}

	// Store in database
	err := a.storeAlert(ctx, alert)
	if err != nil {
		return fmt.Errorf("failed to store alert: %w", err)
	}

	// Deliver alert based on severity
	go a.deliverAlert(context.Background(), alert)

	a.logger.Info("Security alert generated",
		zap.String("alert_id", alert.ID),
		zap.String("type", string(alert.Type)),
		zap.String("severity", string(alert.Severity)),
		zap.String("user_id", func() string { if alert.UserID != nil { return *alert.UserID } else return "" }()),
	)

	return nil
}

// storeAlert persists the alert to the database
func (a *AlertManager) storeAlert(ctx context.Context, alert *Alert) error {
	detailsJSON, _ := json.Marshal(alert.Details)
	actionsJSON, _ := json.Marshal(alert.RemediationActions)
	deliveriesJSON, _ := json.Marshal(alert.Deliveries)

	_, err := a.db.Pool.Exec(ctx,
		`INSERT INTO security_alerts
		 (id, tenant_id, user_id, alert_type, severity, status, title, description,
		  details, source_ip, ip_address, user_agent, remediation_actions, deliveries,
		  acknowledged_by, acknowledged_at, resolved_by, resolved_at, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
		 ON CONFLICT (id) DO UPDATE
		 SET status = EXCLUDED.status,
		     updated_at = EXCLUDED.updated_at,
		     acknowledged_by = EXCLUDED.acknowledged_by,
		     acknowledged_at = EXCLUDED.acknowledged_at,
		     resolved_by = EXCLUDED.resolved_by,
		     resolved_at = EXCLUDED.resolved_at,
		     deliveries = EXCLUDED.deliveries`,
		alert.ID, alert.TenantID, alert.UserID, string(alert.Type), string(alert.Severity),
		string(alert.Status), alert.Title, alert.Description, detailsJSON,
		alert.SourceIP, alert.IPAddress, alert.UserAgent, actionsJSON, deliveriesJSON,
		alert.AcknowledgedBy, alert.AcknowledgedAt, alert.ResolvedBy, alert.ResolvedAt,
		alert.CreatedAt, alert.UpdatedAt)

	return err
}

// deliverAlert sends the alert through configured channels
func (a *AlertManager) deliverAlert(ctx context.Context, alert *Alert) {
	var deliveries []AlertDelivery

	// Webhook delivery
	if a.config.WebhookURL != "" {
		delivery := a.sendWebhook(ctx, alert)
		deliveries = append(deliveries, delivery)
	}

	// Email delivery for high severity alerts
	if alert.Severity == SeverityHigh || alert.Severity == SeverityCritical {
		if len(a.config.SecurityTeamEmail) > 0 {
			delivery := a.sendEmail(ctx, alert)
			deliveries = append(deliveries, delivery)
		}
	}

	// Update alert with delivery status
	alert.Deliveries = deliveries
	a.storeAlert(ctx, alert)
}

// sendWebhook delivers alert via webhook
func (a *AlertManager) sendWebhook(ctx context.Context, alert *Alert) AlertDelivery {
	delivery := AlertDelivery{
		ID:      uuid.New().String(),
		Channel: "webhook",
		Status:  "pending",
		SentAt:  time.Now(),
	}

	// Prepare webhook payload
	payload := map[string]interface{}{
		"id":          alert.ID,
		"type":        string(alert.Type),
		"severity":    string(alert.Severity),
		"title":       alert.Title,
		"description": alert.Description,
		"details":     alert.Details,
		"user_id":     alert.UserID,
		"tenant_id":   alert.TenantID,
		"ip_address":  alert.IPAddress,
		"created_at":  alert.CreatedAt,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		delivery.Status = "failed"
		delivery.Error = err.Error()
		return delivery
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", a.config.WebhookURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		delivery.Status = "failed"
		delivery.Error = err.Error()
		return delivery
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "OpenIDX-AlertManager/1.0")
	for k, v := range a.config.WebhookHeaders {
		req.Header.Set(k, v)
	}

	// Send request with retries
	client := &http.Client{
		Timeout: a.config.WebhookTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
	}

	var lastErr error
	for i := 0; i <= a.config.MaxRetries; i++ {
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				delivery.Status = "sent"
				a.logger.Info("Webhook alert sent successfully",
					zap.String("alert_id", alert.ID),
					zap.Int("status_code", resp.StatusCode),
				)
				return delivery
			}
			lastErr = fmt.Errorf("webhook returned status %d", resp.StatusCode)
		} else {
			lastErr = err
		}

		delivery.RetryCount = i + 1
		if i < a.config.MaxRetries {
			time.Sleep(a.config.RetryInterval)
		}
	}

	delivery.Status = "failed"
	delivery.Error = lastErr.Error()
	a.logger.Error("Webhook alert delivery failed",
		zap.String("alert_id", alert.ID),
		zap.Error(lastErr),
		zap.Int("retry_count", delivery.RetryCount),
	)

	return delivery
}

// sendEmail delivers alert via email
func (a *AlertManager) sendEmail(ctx context.Context, alert *Alert) AlertDelivery {
	delivery := AlertDelivery{
		ID:      uuid.New().String(),
		Channel: "email",
		Status:  "pending",
		SentAt:  time.Now(),
	}

	if a.config.SMTPHost == "" {
		delivery.Status = "failed"
		delivery.Error = "SMTP not configured"
		return delivery
	}

	// Prepare email content
	subject := fmt.Sprintf("[%s] %s", alert.Severity, alert.Title)
	body := a.formatEmailBody(alert)

	// Build email addresses
	var toAddresses []string
	for _, email := range a.config.SecurityTeamEmail {
		toAddresses = append(toAddresses, fmt.Sprintf("To: %s\r\n", email))
	}

	// Compose message
	var msg string
	msg = fmt.Sprintf("From: %s\r\n", a.config.EmailFrom)
	for _, addr := range a.config.SecurityTeamEmail {
		msg += fmt.Sprintf("To: %s\r\n", addr)
	}
	msg += fmt.Sprintf("Subject: %s\r\n", subject)
	msg += "MIME-version: 1.0\r\n"
	msg += "Content-Type: text/html; charset=\"UTF-8\"\r\n\r\n"
	msg += body

	// Send email
	auth := smtp.PlainAuth("", a.config.SMTPUsername, a.config.SMTPPassword, a.config.SMTPHost)
	addr := fmt.Sprintf("%s:%d", a.config.SMTPHost, a.config.SMTPPort)

	err := smtp.SendMail(addr, auth, a.config.EmailFrom, a.config.SecurityTeamEmail, []byte(msg))
	if err != nil {
		delivery.Status = "failed"
		delivery.Error = err.Error()
		a.logger.Error("Email alert delivery failed",
			zap.String("alert_id", alert.ID),
			zap.Error(err),
		)
		return delivery
	}

	delivery.Status = "sent"
	a.logger.Info("Email alert sent successfully",
		zap.String("alert_id", alert.ID),
		zap.Strings("recipients", a.config.SecurityTeamEmail),
	)

	return delivery
}

// formatEmailBody creates an HTML email body for the alert
func (a *AlertManager) formatEmailBody(alert *Alert) string {
	var color string
	switch alert.Severity {
	case SeverityCritical:
		color = "#dc2626" // red
	case SeverityHigh:
		color = "#f59e0b" // orange
	case SeverityWarning:
		color = "#eab308" // yellow
	default:
		color = "#3b82f6" // blue
	}

	html := `<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: ` + color + `; color: white; padding: 15px; border-radius: 5px 5px 0 0; }
        .content { background-color: #f9fafb; padding: 20px; border: 1px solid #e5e7eb; border-radius: 0 0 5px 5px; }
        .detail { margin: 10px 0; padding: 10px; background: white; border-left: 3px solid ` + color + `; }
        .footer { margin-top: 20px; font-size: 12px; color: #6b7280; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>` + alert.Title + `</h2>
        </div>
        <div class="content">
            <p><strong>Severity:</strong> ` + string(alert.Severity) + `</p>
            <p><strong>Type:</strong> ` + string(alert.Type) + `</p>
            <p><strong>Time:</strong> ` + alert.CreatedAt.Format(time.RFC1123) + `</p>
            <p><strong>Description:</strong> ` + alert.Description + `</p>`

	if alert.UserID != nil {
		html += `
            <div class="detail">
                <strong>User ID:</strong> ` + *alert.UserID + `
            </div>`
	}

	if alert.IPAddress != "" {
		html += `
            <div class="detail">
                <strong>IP Address:</strong> ` + alert.IPAddress + `
            </div>`
	}

	if len(alert.RemediationActions) > 0 {
		html += `
            <div class="detail">
                <strong>Recommended Actions:</strong>
                <ul>`
		for _, action := range alert.RemediationActions {
			html += `<li>` + action + `</li>`
		}
		html += `</ul>
            </div>`
	}

	html += `
            <div class="footer">
                <p>This is an automated security alert from OpenIDX.</p>
                <p>Alert ID: ` + alert.ID + `</p>
            </div>
        </div>
    </div>
</body>
</html>`

	return html
}

// GetAlert retrieves an alert by ID
func (a *AlertManager) GetAlert(ctx context.Context, alertID string) (*Alert, error) {
	var alert Alert
	var detailsJSON, actionsJSON, deliveriesJSON []byte

	err := a.db.Pool.QueryRow(ctx,
		`SELECT id, tenant_id, user_id, alert_type, severity, status, title, description,
		         details, source_ip, ip_address, user_agent, remediation_actions, deliveries,
		         acknowledged_by, acknowledged_at, resolved_by, resolved_at, created_at, updated_at
		 FROM security_alerts WHERE id = $1`,
		alertID).Scan(&alert.ID, &alert.TenantID, &alert.UserID, &alert.Type, &alert.Severity,
		&alert.Status, &alert.Title, &alert.Description, &detailsJSON, &alert.SourceIP,
		&alert.IPAddress, &alert.UserAgent, &actionsJSON, &deliveriesJSON,
		&alert.AcknowledgedBy, &alert.AcknowledgedAt, &alert.ResolvedBy, &alert.ResolvedAt,
		&alert.CreatedAt, &alert.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("alert not found: %w", err)
	}

	if detailsJSON != nil {
		json.Unmarshal(detailsJSON, &alert.Details)
	}
	if actionsJSON != nil {
		json.Unmarshal(actionsJSON, &alert.RemediationActions)
	}
	if deliveriesJSON != nil {
		json.Unmarshal(deliveriesJSON, &alert.Deliveries)
	}

	return &alert, nil
}

// ListAlerts retrieves alerts with optional filters
func (a *AlertManager) ListAlerts(ctx context.Context, tenantID string, filter AlertFilter) ([]Alert, int, error) {
	query := `SELECT id, tenant_id, user_id, alert_type, severity, status, title, description,
		         details, source_ip, ip_address, user_agent, remediation_actions, deliveries,
		         acknowledged_by, acknowledged_at, resolved_by, resolved_at, created_at, updated_at
		 FROM security_alerts WHERE tenant_id = $1`

	args := []interface{}{tenantID}
	argIdx := 2

	if filter.Severity != "" {
		query += fmt.Sprintf(" AND severity = $%d", argIdx)
		args = append(args, filter.Severity)
		argIdx++
	}
	if filter.Status != "" {
		query += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, filter.Status)
		argIdx++
	}
	if filter.UserID != "" {
		query += fmt.Sprintf(" AND user_id = $%d", argIdx)
		args = append(args, filter.UserID)
		argIdx++
	}
	if filter.Type != "" {
		query += fmt.Sprintf(" AND alert_type = $%d", argIdx)
		args = append(args, filter.Type)
		argIdx++
	}

	// Get total count
	var total int
	countQuery := "SELECT COUNT(*) FROM security_alerts WHERE tenant_id = $1"
	countArgs := []interface{}{tenantID}
	countArgIdx := 2

	if filter.Severity != "" {
		countQuery += fmt.Sprintf(" AND severity = $%d", countArgIdx)
		countArgs = append(countArgs, filter.Severity)
		countArgIdx++
	}
	if filter.Status != "" {
		countQuery += fmt.Sprintf(" AND status = $%d", countArgIdx)
		countArgs = append(countArgs, filter.Status)
		countArgIdx++
	}
	if filter.UserID != "" {
		countQuery += fmt.Sprintf(" AND user_id = $%d", countArgIdx)
		countArgs = append(countArgs, filter.UserID)
		countArgIdx++
	}
	if filter.Type != "" {
		countQuery += fmt.Sprintf(" AND alert_type = $%d", countArgIdx)
		countArgs = append(countArgs, filter.Type)
		countArgIdx++
	}

	err := a.db.Pool.QueryRow(ctx, countQuery, countArgs...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	query += " ORDER BY created_at DESC"
	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
		args = append(args, filter.Limit, filter.Offset)
	}

	rows, err := a.db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var alerts []Alert
	for rows.Next() {
		var alert Alert
		var detailsJSON, actionsJSON, deliveriesJSON []byte

		err := rows.Scan(&alert.ID, &alert.TenantID, &alert.UserID, &alert.Type, &alert.Severity,
			&alert.Status, &alert.Title, &alert.Description, &detailsJSON, &alert.SourceIP,
			&alert.IPAddress, &alert.UserAgent, &actionsJSON, &deliveriesJSON,
			&alert.AcknowledgedBy, &alert.AcknowledgedAt, &alert.ResolvedBy, &alert.ResolvedAt,
			&alert.CreatedAt, &alert.UpdatedAt)
		if err != nil {
			continue
		}

		if detailsJSON != nil {
			json.Unmarshal(detailsJSON, &alert.Details)
		}
		if actionsJSON != nil {
			json.Unmarshal(actionsJSON, &alert.RemediationActions)
		}
		if deliveriesJSON != nil {
			json.Unmarshal(deliveriesJSON, &alert.Deliveries)
		}

		alerts = append(alerts, alert)
	}

	return alerts, total, nil
}

// AlertFilter represents filters for listing alerts
type AlertFilter struct {
	Severity string
	Status   string
	UserID   string
	Type     string
	Limit    int
	Offset   int
}

// AcknowledgeAlert marks an alert as acknowledged
func (a *AlertManager) AcknowledgeAlert(ctx context.Context, alertID, acknowledgedBy string) error {
	now := time.Now()
	_, err := a.db.Pool.Exec(ctx,
		`UPDATE security_alerts
		 SET status = 'acknowledged', acknowledged_by = $2, acknowledged_at = $3, updated_at = $3
		 WHERE id = $1`,
		alertID, acknowledgedBy, now)

	if err != nil {
		return fmt.Errorf("failed to acknowledge alert: %w", err)
	}

	a.logger.Info("Alert acknowledged",
		zap.String("alert_id", alertID),
		zap.String("acknowledged_by", acknowledgedBy),
	)

	return nil
}

// ResolveAlert marks an alert as resolved
func (a *AlertManager) ResolveAlert(ctx context.Context, alertID, resolvedBy string) error {
	now := time.Now()
	_, err := a.db.Pool.Exec(ctx,
		`UPDATE security_alerts
		 SET status = 'resolved', resolved_by = $2, resolved_at = $3, updated_at = $3
		 WHERE id = $1`,
		alertID, resolvedBy, now)

	if err != nil {
		return fmt.Errorf("failed to resolve alert: %w", err)
	}

	a.logger.Info("Alert resolved",
		zap.String("alert_id", alertID),
		zap.String("resolved_by", resolvedBy),
	)

	return nil
}

// MarkAsFalsePositive marks an alert as a false positive
func (a *AlertManager) MarkAsFalsePositive(ctx context.Context, alertID, resolvedBy string) error {
	now := time.Now()
	_, err := a.db.Pool.Exec(ctx,
		`UPDATE security_alerts
		 SET status = 'false_positive', resolved_by = $2, resolved_at = $3, updated_at = $3
		 WHERE id = $1`,
		alertID, resolvedBy, now)

	if err != nil {
		return fmt.Errorf("failed to mark alert as false positive: %w", err)
	}

	a.logger.Info("Alert marked as false positive",
		zap.String("alert_id", alertID),
		zap.String("resolved_by", resolvedBy),
	)

	return nil
}

// CleanupOldAlerts removes alerts older than the retention period
func (a *AlertManager) CleanupOldAlerts(ctx context.Context) error {
	retentionDate := time.Now().AddDate(0, 0, -a.config.RetentionDays)

	result, err := a.db.Pool.Exec(ctx,
		`DELETE FROM security_alerts WHERE created_at < $1 AND status IN ('resolved', 'false_positive')`,
		retentionDate)

	if err != nil {
		return fmt.Errorf("failed to cleanup old alerts: %w", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected > 0 {
		a.logger.Info("Cleaned up old alerts",
			zap.Int64("count", rowsAffected),
			zap.Time("before_date", retentionDate),
		)
	}

	return nil
}

// GetAlertStatistics returns alert statistics for a tenant
func (a *AlertManager) GetAlertStatistics(ctx context.Context, tenantID string, days int) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Get counts by severity
	rows, err := a.db.Pool.Query(ctx,
		`SELECT severity, COUNT(*) as count
		 FROM security_alerts
		 WHERE tenant_id = $1 AND created_at > NOW() - ($2::int || ' days')::interval
		 GROUP BY severity`,
		tenantID, days)
	if err == nil {
		severityCounts := make(map[string]int)
		for rows.Next() {
			var severity string
			var count int
			if rows.Scan(&severity, &count) == nil {
				severityCounts[severity] = count
			}
		}
		rows.Close()
		stats["by_severity"] = severityCounts
	}

	// Get counts by status
	rows, err = a.db.Pool.Query(ctx,
		`SELECT status, COUNT(*) as count
		 FROM security_alerts
		 WHERE tenant_id = $1 AND created_at > NOW() - ($2::int || ' days')::interval
		 GROUP BY status`,
		tenantID, days)
	if err == nil {
		statusCounts := make(map[string]int)
		for rows.Next() {
			var status string
			var count int
			if rows.Scan(&status, &count) == nil {
				statusCounts[status] = count
			}
		}
		rows.Close()
		stats["by_status"] = statusCounts
	}

	// Get total count
	var totalCount int
	a.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM security_alerts
		 WHERE tenant_id = $1 AND created_at > NOW() - ($2::int || ' days')::interval`,
		tenantID, days).Scan(&totalCount)
	stats["total_count"] = totalCount

	return stats, nil
}
