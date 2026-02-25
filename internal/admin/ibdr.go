// Package admin provides Identity Breach Detection & Response (IBDR) system
// This module detects identity-related breaches, triggers incident response,
// and provides remediation workflows.
package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// BreachType represents the type of identity breach detected
type BreachType string

const (
	// BreachCredentialStuffing indicates credential stuffing attack
	BreachCredentialStuffing BreachType = "credential_stuffing"
	// BreachPasswordSpraying indicates password spraying attack
	BreachPasswordSpraying BreachType = "password_spraying"
	// BreachImpossibleTravel indicates impossible travel anomaly
	BreachImpossibleTravel BreachType = "impossible_travel"
	// BreachAnomalousAccess indicates unusual access patterns
	BreachAnomalousAccess BreachType = "anomalous_access"
	// BreachDataExfiltration indicates potential data exfiltration
	BreachDataExfiltration BreachType = "data_exfiltration"
	// BreachPrivilegeEscalation indicates privilege escalation attempt
	BreachPrivilegeEscalation BreachType = "privilege_escalation"
	// BreachSessionHijacking indicates session hijacking
	BreachSessionHijacking BreachType = "session_hijacking"
	// BreachMaliciousInsider indicates insider threat
	BreachMaliciousInsider BreachType = "malicious_insider"
)

// BreachSeverity represents the severity level of a breach
type BreachSeverity string

const (
	BreachSeverityInfo     BreachSeverity = "info"
	BreachSeverityLow      BreachSeverity = "low"
	BreachSeverityMedium   BreachSeverity = "medium"
	BreachSeverityHigh     BreachSeverity = "high"
	BreachSeverityCritical BreachSeverity = "critical"
)

// BreachStatus represents the status of breach handling
type BreachStatus string

const (
	StatusDetected    BreachStatus = "detected"
	StatusInvestigating BreachStatus = "investigating"
	StatusConfirmed   BreachStatus = "confirmed"
	StatusContained   BreachStatus = "contained"
	StatusResolved    BreachStatus = "resolved"
	StatusFalsePositive BreachStatus = "false_positive"
)

// BreachIncident represents a detected identity breach
type BreachIncident struct {
	ID                string                 `json:"id"`
	Type              BreachType             `json:"type"`
	Severity          BreachSeverity         `json:"severity"`
	Status            BreachStatus           `json:"status"`
	Title             string                 `json:"title"`
	Description       string                 `json:"description"`
	AffectedUserIDs   []string               `json:"affected_user_ids"`
	AffectedSessions  []string               `json:"affected_sessions"`
	AffectedResources []string               `json:"affected_resources"`
	DetectionMethod   string                 `json:"detection_method"`
	FirstDetectedAt   time.Time              `json:"first_detected_at"`
	LastActivityAt    time.Time              `json:"last_activity_at"`
	Confidence        float64                `json:"confidence"` // 0-1
	Indicators        json.RawMessage        `json:"indicators"`
	Metadata          map[string]interface{} `json:"metadata"`
	AssignedTo        *string                `json:"assigned_to,omitempty"`
	QuarantineAction  string                 `json:"quarantine_action"` // none, partial, full
	ContainmentSteps  []string               `json:"containment_steps"`
	ResolutionNotes   string                 `json:"resolution_notes,omitempty"`
	ResolvedAt        *time.Time             `json:"resolved_at,omitempty"`
	CreatedAt         time.Time              `json:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at"`
}

// BreachAlert represents a real-time breach alert
type BreachAlert struct {
	ID          string        `json:"id"`
	IncidentID  string        `json:"incident_id"`
	Type        BreachType    `json:"type"`
	Severity    BreachSeverity `json:"severity"`
	Message     string        `json:"message"`
	UserID      string        `json:"user_id"`
	SessionID   string        `json:"session_id"`
	IPAddress   string        `json:"ip_address"`
	CreatedAt   time.Time     `json:"created_at"`
	Acknowledged bool         `json:"acknowledged"`
	AckedAt     *time.Time    `json:"acked_at,omitempty"`
	AckedBy     *string       `json:"acked_by,omitempty"`
}

// BreachIndicator represents a specific indicator of compromise
type BreachIndicator struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"` // ip, user_agent, session, pattern
	Value       string    `json:"value"`
	Confidence  float64   `json:"confidence"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Occurrences int       `json:"occurrences"`
}

// QuarantineAction represents actions taken during quarantine
type QuarantineAction struct {
	ID            string    `json:"id"`
	IncidentID    string    `json:"incident_id"`
	UserID        string    `json:"user_id"`
	ActionType    string    `json:"action_type"` // revoke_sessions, reset_password, disable_account, block_ip
	Description   string    `json:"description"`
	ExecutedAt    time.Time `json:"executed_at"`
	ExecutedBy    string    `json:"executed_by"`
	Reversible    bool      `json:"reversible"`
	ReversedAt    *time.Time `json:"reversed_at,omitempty"`
}

// IBDRConfig represents configuration for IBDR system
type IBDRConfig struct {
	Enabled                     bool               `json:"enabled"`
	AutoQuarantineThreshold     float64            `json:"auto_quarantine_threshold"`     // confidence threshold
	AutoContainment             bool               `json:"auto_containment"`
	NotificationChannels        []string           `json:"notification_channels"`
	RetentionDays               int                `json:"retention_days"`
	EscalationRules             map[BreachSeverity]EscalationRule `json:"escalation_rules"`
}

// EscalationRule defines how to escalate breaches by severity
type EscalationRule struct {
	NotifyChannels []string        `json:"notify_channels"`
	EscalateAfter  time.Duration   `json:"escalate_after"`
	RequireApproval bool           `json:"require_approval"`
}

// ibdrService handles Identity Breach Detection & Response
type ibdrService struct {
	db     *database.PostgresDB
	logger *zap.Logger
	config *IBDRConfig
}

// DetectBreachAttempt analyzes an authentication attempt for breach indicators
func (s *ibdrService) DetectBreachAttempt(ctx context.Context, userID, ipAddress, userAgent, sessionID string) (*BreachIncident, error) {
	indicators := s.collectIndicators(ctx, userID, ipAddress, userAgent)

	// Analyze for different breach types
	breachType, severity, confidence := s.analyzeIndicators(ctx, indicators)

	if confidence < s.config.AutoQuarantineThreshold {
		// Log but don't create incident
		s.logger.Debug("Breach indicators below threshold",
			zap.String("user_id", userID),
			zap.Float64("confidence", confidence))
		return nil, nil
	}

	// Create breach incident
	incident := &BreachIncident{
		ID:                uuid.New().String(),
		Type:              breachType,
		Severity:          severity,
		Status:            StatusDetected,
		Title:             fmt.Sprintf("Potential %s detected for user %s", breachType, userID),
		Description:       s.generateDescription(breachType, indicators),
		AffectedUserIDs:   []string{userID},
		AffectedSessions:  []string{sessionID},
		DetectionMethod:   "automated",
		FirstDetectedAt:   time.Now(),
		LastActivityAt:    time.Now(),
		Confidence:        confidence,
		QuarantineAction:  "none",
		ContainmentSteps:  []string{},
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	indicatorsJSON, _ := json.Marshal(indicators)
	incident.Indicators = indicatorsJSON

	// Store incident
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO breach_incidents (id, type, severity, status, title, description, affected_user_ids,
			affected_sessions, detection_method, first_detected_at, last_activity_at, confidence,
			indicators, quarantine_action, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW(), NOW())
	`, incident.ID, incident.Type, incident.Severity, incident.Status,
		incident.Title, incident.Description, incident.AffectedUserIDs,
		incident.AffectedSessions, incident.DetectionMethod, incident.FirstDetectedAt,
		incident.LastActivityAt, incident.Confidence, incident.Indicators, incident.QuarantineAction)
	if err != nil {
		return nil, fmt.Errorf("failed to store incident: %w", err)
	}

	// Create alert
	s.createAlert(ctx, incident)

	// Auto-contain if configured
	if s.config.AutoContainment {
		s.TriggerIncidentResponse(ctx, incident.ID, "auto", true)
	}

	return incident, nil
}

// TriggerIncidentResponse initiates incident response actions
func (s *ibdrService) TriggerIncidentResponse(ctx context.Context, incidentID, actorID string, autoContain bool) error {
	// Get incident
	var incident BreachIncident
	var indicators []byte
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, type, severity, status, affected_user_ids, affected_sessions, quarantine_action, indicators
		FROM breach_incidents WHERE id = $1
	`, incidentID).Scan(&incident.ID, &incident.Type, &incident.Severity,
		&incident.Status, &incident.AffectedUserIDs, &incident.AffectedSessions,
		&incident.QuarantineAction, &indicators)
	if err != nil {
		return fmt.Errorf("incident not found: %w", err)
	}

	// Update status
	incident.Status = StatusInvestigating
	_, _ = s.db.Pool.Exec(ctx, `UPDATE breach_incidents SET status = $1, updated_at = NOW() WHERE id = $2`,
		StatusInvestigating, incidentID)

	// Execute containment based on severity and type
	actions := []string{}

	switch incident.Severity {
	case BreachSeverityCritical:
		// Full quarantine
		actions = s.executeFullQuarantine(ctx, &incident, actorID)
	case BreachSeverityHigh:
		// Partial quarantine
		actions = s.executePartialQuarantine(ctx, &incident, actorID)
	case BreachSeverityMedium:
		// Monitoring and session revocation
		actions = []string{"revoke_sessions", "enable_monitoring"}
		s.revokeUserSessions(ctx, incident.AffectedUserIDs)
	}

	incident.ContainmentSteps = actions
	incident.QuarantineAction = determineQuarantineAction(actions)
	incident.UpdatedAt = time.Now()

	// Update incident
	stepsJSON, _ := json.Marshal(actions)
	_, _ = s.db.Pool.Exec(ctx, `
		UPDATE breach_incidents
		SET containment_steps = $1, quarantine_action = $2, updated_at = NOW()
		WHERE id = $3
	`, stepsJSON, incident.QuarantineAction, incidentID)

	return nil
}

// GetBreachAlerts retrieves active breach alerts
func (s *ibdrService) GetBreachAlerts(ctx context.Context, includeAcknowledged bool) ([]BreachAlert, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, incident_id, type, severity, message, user_id, session_id, ip_address,
			created_at, acknowledged, acked_at, acked_by
		FROM breach_alerts
		WHERE acknowledged = $1 OR $1 = true
		ORDER BY created_at DESC
		LIMIT 100
	`, includeAcknowledged)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	alerts := []BreachAlert{}
	for rows.Next() {
		var alert BreachAlert
		rows.Scan(&alert.ID, &alert.IncidentID, &alert.Type, &alert.Severity,
			&alert.Message, &alert.UserID, &alert.SessionID, &alert.IPAddress,
			&alert.CreatedAt, &alert.Acknowledged, &alert.AckedAt, &alert.AckedBy)
		alerts = append(alerts, alert)
	}

	return alerts, nil
}

// AnalyzeBreachPatterns analyzes historical breach patterns
func (s *ibdrService) AnalyzeBreachPatterns(ctx context.Context, timeWindow time.Duration) (map[string]interface{}, error) {
	// Get breach statistics
	rows, err := s.db.Pool.Query(ctx, `
		SELECT type, severity, COUNT(*) as count
		FROM breach_incidents
		WHERE created_at > NOW() - $1::interval
		GROUP BY type, severity
		ORDER BY count DESC
	`, fmt.Sprintf("%d seconds", int(timeWindow.Seconds())))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byType := make(map[BreachType]int)
	bySeverity := make(map[BreachSeverity]int)

	for rows.Next() {
		var breachType BreachType
		var severity BreachSeverity
		var count int
		rows.Scan(&breachType, &severity, &count)
		byType[breachType] += count
		bySeverity[severity] += count
	}

	return map[string]interface{}{
		"by_type":     byType,
		"by_severity": bySeverity,
		"time_window": timeWindow.String(),
		"generated_at": time.Now(),
	}, nil
}

// Helper methods

func (s *ibdrService) collectIndicators(ctx context.Context, userID, ipAddress, userAgent string) []BreachIndicator {
	indicators := []BreachIndicator{}

	// Check for multiple failed logins from this IP
	var failCount int
	s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_logs
		WHERE event_type = 'failed_login' AND ip_address = $1 AND created_at > NOW() - INTERVAL '1 hour'
	`, ipAddress).Scan(&failCount)
	if failCount > 10 {
		indicators = append(indicators, BreachIndicator{
			ID:          uuid.New().String(),
			Type:        "ip",
			Value:       ipAddress,
			Confidence:  float64(failCount) / 100,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			Occurrences: failCount,
		})
	}

	// Check for successful logins from different locations
	var locationCount int
	s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT country_code) FROM audit_logs
		WHERE user_id = $1 AND event_type = 'login' AND created_at > NOW() - INTERVAL '24 hours'
	`, userID).Scan(&locationCount)
	if locationCount > 3 {
		indicators = append(indicators, BreachIndicator{
			ID:          uuid.New().String(),
			Type:        "geo_anomaly",
			Value:       fmt.Sprintf("user_%s", userID),
			Confidence:  0.7,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			Occurrences: locationCount,
		})
	}

	return indicators
}

func (s *ibdrService) analyzeIndicators(ctx context.Context, indicators []BreachIndicator) (BreachType, BreachSeverity, float64) {
	if len(indicators) == 0 {
		return "", BreachSeverityInfo, 0
	}

	// Calculate aggregate confidence
	maxConfidence := 0.0
	hasIPIndicator := false
	hasGeoIndicator := false

	for _, ind := range indicators {
		if ind.Confidence > maxConfidence {
			maxConfidence = ind.Confidence
		}
		if ind.Type == "ip" {
			hasIPIndicator = true
		}
		if ind.Type == "geo_anomaly" {
			hasGeoIndicator = true
		}
	}

	// Determine breach type and severity
	var breachType BreachType
	var severity BreachSeverity

	if hasGeoIndicator {
		breachType = BreachImpossibleTravel
		severity = BreachSeverityHigh
	} else if hasIPIndicator {
		breachType = BreachCredentialStuffing
		severity = BreachSeverityMedium
	} else {
		breachType = BreachAnomalousAccess
		severity = BreachSeverityLow
	}

	// Adjust severity based on confidence
	if maxConfidence > 0.8 {
		switch severity {
		case BreachSeverityMedium:
			severity = BreachSeverityHigh
		case BreachSeverityLow:
			severity = BreachSeverityMedium
		}
	}

	return breachType, severity, maxConfidence
}

func (s *ibdrService) generateDescription(breachType BreachType, indicators []BreachIndicator) string {
	switch breachType {
	case BreachCredentialStuffing:
		return "Multiple failed authentication attempts from known malicious IP addresses or patterns consistent with credential stuffing."
	case BreachImpossibleTravel:
		return "Successful logins from geographically impossible locations within a short time period."
	case BreachAnomalousAccess:
		return "Access patterns that deviate significantly from established user baseline."
	case BreachDataExfiltration:
		return "Unusual data access volumes consistent with data exfiltration attempts."
	default:
		return "Potential security incident detected requiring investigation."
	}
}

func (s *ibdrService) createAlert(ctx context.Context, incident *BreachIncident) error {
	alert := &BreachAlert{
		ID:         uuid.New().String(),
		IncidentID: incident.ID,
		Type:       incident.Type,
		Severity:   incident.Severity,
		Message:    incident.Title,
		CreatedAt:  time.Now(),
	}

	if len(incident.AffectedUserIDs) > 0 {
		alert.UserID = incident.AffectedUserIDs[0]
	}
	if len(incident.AffectedSessions) > 0 {
		alert.SessionID = incident.AffectedSessions[0]
	}

	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO breach_alerts (id, incident_id, type, severity, message, user_id, session_id, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
	`, alert.ID, alert.IncidentID, alert.Type, alert.Severity,
		alert.Message, alert.UserID, alert.SessionID)

	return err
}

func (s *ibdrService) executeFullQuarantine(ctx context.Context, incident *BreachIncident, actorID string) []string {
	actions := []string{}

	// Disable affected user accounts
	for _, userID := range incident.AffectedUserIDs {
		_, _ = s.db.Pool.Exec(ctx, `
			UPDATE users SET status = 'quarantined', updated_at = NOW() WHERE id = $1
		`, userID)
		actions = append(actions, fmt.Sprintf("disabled_user_%s", userID))
	}

	// Revoke all sessions
	s.revokeUserSessions(ctx, incident.AffectedUserIDs)
	actions = append(actions, "revoked_all_sessions")

	// Block IPs if available
	for _, sessionID := range incident.AffectedSessions {
		var ipAddress string
		s.db.Pool.QueryRow(ctx, `
			SELECT ip_address FROM sessions WHERE id = $1
		`, sessionID).Scan(&ipAddress)
		if ipAddress != "" {
			s.blockIPAddress(ctx, ipAddress)
			actions = append(actions, fmt.Sprintf("blocked_ip_%s", ipAddress))
		}
	}

	return actions
}

func (s *ibdrService) executePartialQuarantine(ctx context.Context, incident *BreachIncident, actorID string) []string {
	actions := []string{}

	// Revoke affected sessions only
	s.revokeUserSessions(ctx, incident.AffectedUserIDs)
	actions = append(actions, "revoked_sessions")

	// Enable enhanced monitoring
	for _, userID := range incident.AffectedUserIDs {
		_, _ = s.db.Pool.Exec(ctx, `
			INSERT INTO user_monitoring (user_id, level, reason, created_at)
			VALUES ($1, 'enhanced', $2, NOW())
		`, userID, incident.ID)
		actions = append(actions, fmt.Sprintf("enhanced_monitoring_%s", userID))
	}

	return actions
}

func (s *ibdrService) revokeUserSessions(ctx context.Context, userIDs []string) {
	for _, userID := range userIDs {
		_, _ = s.db.Pool.Exec(ctx, `
			UPDATE sessions SET revoked = true, revoked_at = NOW() WHERE user_id = $1
		`, userID)
	}
}

func (s *ibdrService) blockIPAddress(ctx context.Context, ipAddress string) {
	_, _ = s.db.Pool.Exec(ctx, `
		INSERT INTO blocked_ips (ip_address, reason, created_at)
		VALUES ($1, $2, NOW())
	`, ipAddress, "breach_response")
}

func determineQuarantineAction(actions []string) string {
	for _, action := range actions {
		if action == "disabled_user" || strings.HasPrefix(action, "disabled_user_") {
			return "full"
		}
	}
	if len(actions) > 0 {
		return "partial"
	}
	return "none"
}

// validateBreachIncidentRequest validates a breach incident creation request
func validateBreachIncidentRequest(incidentType string, severity string, affectedUsers []string) error {
	// Validate breach type
	validTypes := map[BreachType]bool{
		BreachCredentialStuffing:  true,
		BreachPasswordSpraying:    true,
		BreachImpossibleTravel:    true,
		BreachAnomalousAccess:     true,
		BreachDataExfiltration:    true,
		BreachPrivilegeEscalation: true,
		BreachSessionHijacking:    true,
		BreachMaliciousInsider:    true,
	}
	if !validTypes[BreachType(incidentType)] {
		return fmt.Errorf("invalid breach_type: %s", incidentType)
	}

	// Validate severity
	validSeverities := map[BreachSeverity]bool{
		BreachSeverityInfo:     true,
		BreachSeverityLow:      true,
		BreachSeverityMedium:   true,
		BreachSeverityHigh:     true,
		BreachSeverityCritical: true,
	}
	if !validSeverities[BreachSeverity(severity)] {
		return fmt.Errorf("invalid severity: %s", severity)
	}

	// Validate affected users
	if len(affectedUsers) == 0 {
		return fmt.Errorf("at least one affected_user_id is required")
	}
	for _, userID := range affectedUsers {
		if len(userID) < 3 {
			return fmt.Errorf("invalid user_id format: %s", userID)
		}
	}

	return nil
}

// Handlers

func (s *Service) handleIBDRDetectBreach(c *gin.Context) {
	ctx := c.Request.Context()

	var req struct {
		UserID    string `json:"user_id" binding:"required"`
		IPAddress string `json:"ip_address"`
		UserAgent string `json:"user_agent"`
		SessionID string `json:"session_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate required fields
	if req.UserID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}

	// Validate user_id format (UUID or similar)
	if len(req.UserID) < 3 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id format"})
		return
	}

	// Validate IP address format if provided
	if req.IPAddress != "" {
		// Basic IP validation - should contain at least 3 dots for IPv4 or be IPv6 format
		// In production, use a proper IP validation library
		ipParts := 0
		for _, char := range req.IPAddress {
			if char == '.' {
				ipParts++
			}
		}
		// Allow IPv4 (dots), IPv6 (colons), or localhost
		if ipParts > 0 && ipParts != 3 && req.IPAddress != "localhost" && !strings.Contains(req.IPAddress, ":") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid ip_address format"})
			return
		}
	}

	config := &IBDRConfig{
		Enabled:                 true,
		AutoQuarantineThreshold: 0.7,
		AutoContainment:         true,
	}
	service := &ibdrService{db: s.db, logger: s.logger, config: config}

	incident, err := service.DetectBreachAttempt(ctx, req.UserID, req.IPAddress, req.UserAgent, req.SessionID)
	if err != nil {
		s.logger.Error("failed to detect breach", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "breach detection failed"})
		return
	}

	if incident == nil {
		c.JSON(http.StatusOK, gin.H{"message": "no breach detected"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"incident": incident})
}

func (s *Service) handleIBDRIncidents(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, type, severity, status, title, description, first_detected_at, confidence, quarantine_action
		FROM breach_incidents
		ORDER BY first_detected_at DESC
		LIMIT 100
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list incidents"})
		return
	}
	defer rows.Close()

	incidents := []BreachIncident{}
	for rows.Next() {
		var inc BreachIncident
		rows.Scan(&inc.ID, &inc.Type, &inc.Severity, &inc.Status,
			&inc.Title, &inc.Description, &inc.FirstDetectedAt,
			&inc.Confidence, &inc.QuarantineAction)
		incidents = append(incidents, inc)
	}

	c.JSON(http.StatusOK, gin.H{"data": incidents})
}

func (s *Service) handleIBDRAlerts(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()

	includeAcked := c.DefaultQuery("include_acknowledged", "false") == "true"

	service := &ibdrService{db: s.db, logger: s.logger, config: &IBDRConfig{}}
	alerts, err := service.GetBreachAlerts(ctx, includeAcked)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get alerts"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": alerts})
}

func (s *Service) handleIBDRTriggerResponse(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()
	incidentID := c.Param("id")

	service := &ibdrService{db: s.db, logger: s.logger, config: &IBDRConfig{}}
	err := service.TriggerIncidentResponse(ctx, incidentID, c.GetString("user_id"), false)
	if err != nil {
		s.logger.Error("failed to trigger incident response", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to trigger response"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "incident response triggered"})
}
