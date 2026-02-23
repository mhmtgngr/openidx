// Package audit provides anomaly detection for security events
package audit

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// AnomalyDetector analyzes audit events for suspicious patterns
type AnomalyDetector struct {
	logger          *zap.Logger
	service         *Service
	config          *DetectorConfig
	bruteForceState map[string]*FailedLoginTracker
	mu              sync.RWMutex
}

// DetectorConfig holds configuration for anomaly detection
type DetectorConfig struct {
	// Brute force detection
	BruteForceWindow    time.Duration `json:"brute_force_window"`
	BruteForceThreshold int           `json:"brute_force_threshold"`

	// Bulk access detection
	BulkAccessWindow    time.Duration `json:"bulk_access_window"`
	BulkAccessThreshold int           `json:"bulk_access_threshold"`

	// Off-hours detection
	BusinessHoursStart int `json:"business_hours_start"` // Hour (0-23)
	BusinessHoursEnd   int `json:"business_hours_end"`   // Hour (0-23)
	Timezone           string `json:"timezone"`

	// Privilege escalation window
	EscalationWindow time.Duration `json:"escalation_window"`

	// Alert settings
	AlertEnabled bool     `json:"alert_enabled"`
	AlertTags    []string `json:"alert_tags"`
}

// FailedLoginTracker tracks failed login attempts for brute force detection
type FailedLoginTracker struct {
	ActorID    string
	Attempts   []time.Time
	FirstSeen  time.Time
	AlertSent  bool
}

// AnomalyType represents the type of anomaly detected
type AnomalyType string

const (
	AnomalyBruteForce      AnomalyType = "brute_force"
	AnomalyPrivilegeEscalation AnomalyType = "privilege_escalation"
	AnomalyBulkAccess      AnomalyType = "bulk_access"
	AnomalyOffHoursAdmin   AnomalyType = "off_hours_admin"
	AnomalyImpossibleTravel AnomalyType = "impossible_travel"
	AnomalyDataExfiltration AnomalyType = "data_exfiltration"
)

// AnomalyAlert represents a detected anomaly
type AnomalyAlert struct {
	ID          string                 `json:"id"`
	Type        AnomalyType             `json:"type"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	EventID     string                 `json:"event_id"`
	ActorID     string                 `json:"actor_id"`
	Timestamp   time.Time              `json:"timestamp"`
	Details     map[string]interface{} `json:"details"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// NewAnomalyDetector creates a new anomaly detector
func NewAnomalyDetector(logger *zap.Logger, service *Service) *AnomalyDetector {
	config := &DetectorConfig{
		BruteForceWindow:    5 * time.Minute,
		BruteForceThreshold: 5,
		BulkAccessWindow:    1 * time.Minute,
		BulkAccessThreshold: 100,
		BusinessHoursStart:  9,
		BusinessHoursEnd:    17,
		Timezone:            "UTC",
		EscalationWindow:    5 * time.Minute,
		AlertEnabled:        true,
		AlertTags:           []string{"security", "anomaly"},
	}

	return &AnomalyDetector{
		logger:          logger,
		service:         service,
		config:          config,
		bruteForceState: make(map[string]*FailedLoginTracker),
	}
}

// AnalyzeEvent analyzes a single event for anomalies
func (ad *AnomalyDetector) AnalyzeEvent(ctx context.Context, event *ServiceAuditEvent) []*AnomalyAlert {
	var alerts []*AnomalyAlert

	// Only analyze events with outcomes
	if event.Outcome == "" {
		return alerts
	}

	// Brute force detection (failed authentication)
	if event.EventType == EventTypeAuthentication &&
		event.Outcome == ServiceOutcomeFailure &&
		event.Action == "auth.login.failed" {

		if alert := ad.detectBruteForce(event); alert != nil {
			alerts = append(alerts, alert)
		}
	}

	// Privilege escalation detection
	if event.EventType == EventTypeRoleManagement ||
		event.EventType == EventTypeUserManagement {

		if alert := ad.detectPrivilegeEscalation(ctx, event); alert != nil {
			alerts = append(alerts, alert)
		}
	}

	// Bulk access detection
	if event.EventType == EventTypeAuthorization ||
		event.Category == CategoryAccess {

		if alert := ad.detectBulkAccess(ctx, event); alert != nil {
			alerts = append(alerts, alert)
		}
	}

	// Off-hours admin activity detection
	if event.Category == CategorySecurity &&
		(event.ActorType == "admin" || event.ActorType == "system") {

		if alert := ad.detectOffHoursAdmin(event); alert != nil {
			alerts = append(alerts, alert)
		}
	}

	// Store alerts if enabled
	if ad.config.AlertEnabled && len(alerts) > 0 {
		ad.storeAlerts(ctx, alerts)
	}

	return alerts
}

// detectBruteForce detects brute force login attacks
// Rule: >5 failed logins in 5 minutes from the same actor
func (ad *AnomalyDetector) detectBruteForce(event *ServiceAuditEvent) *AnomalyAlert {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	actorID := event.ActorID
	if actorID == "" {
		actorID = event.ActorIP // Fall back to IP address
	}

	tracker, exists := ad.bruteForceState[actorID]
	if !exists {
		tracker = &FailedLoginTracker{
			ActorID:   actorID,
			Attempts:  []time.Time{},
			FirstSeen: time.Now().UTC(),
		}
		ad.bruteForceState[actorID] = tracker
	}

	// Add current attempt
	tracker.Attempts = append(tracker.Attempts, event.Timestamp)

	// Remove attempts outside the window
	cutoff := time.Now().UTC().Add(-ad.config.BruteForceWindow)
	var validAttempts []time.Time
	for _, attempt := range tracker.Attempts {
		if attempt.After(cutoff) {
			validAttempts = append(validAttempts, attempt)
		}
	}
	tracker.Attempts = validAttempts

	// Check threshold
	if len(tracker.Attempts) >= ad.config.BruteForceThreshold && !tracker.AlertSent {
		tracker.AlertSent = true

		return &AnomalyAlert{
			ID:          generateUUID(),
			Type:        AnomalyBruteForce,
			Severity:    "high",
			Title:       "Potential Brute Force Attack Detected",
			Description: fmt.Sprintf("More than %d failed login attempts from %s within %s",
				ad.config.BruteForceThreshold, actorID, ad.config.BruteForceWindow),
			EventID:   event.ID,
			ActorID:   actorID,
			Timestamp: time.Now().UTC(),
			Details: map[string]interface{}{
				"failed_attempts":     len(tracker.Attempts),
				"detection_window":    ad.config.BruteForceWindow.String(),
				"threshold":           ad.config.BruteForceThreshold,
				"first_failure":       tracker.FirstSeen,
				"source_ip":           event.ActorIP,
				"actor_type":          event.ActorType,
				"time_window_exceeded": true,
			},
		}
	}

	// Reset alert sent if attempts drop below half threshold
	if tracker.AlertSent && len(tracker.Attempts) < ad.config.BruteForceThreshold/2 {
		tracker.AlertSent = false
	}

	return nil
}

// detectPrivilegeEscalation detects suspicious privilege escalation
// Rule: Role change followed immediately by sensitive action
func (ad *AnomalyDetector) detectPrivilegeEscalation(ctx context.Context, event *ServiceAuditEvent) *AnomalyAlert {
	// Check if this is a role change event
	if event.Action == "role.assign" || event.Action == "role.create" {
		// Look for sensitive actions within the escalation window
		sensitiveActions := []string{
			"user.delete", "policy.change", "config.change",
			"permission.grant", "data.export", "data.delete",
		}

		// Query for events by the same actor within the window
		windowStart := event.Timestamp.Add(-ad.config.EscalationWindow)
		windowEnd := event.Timestamp.Add(ad.config.EscalationWindow)

		rows, err := ad.service.db.Pool.Query(ctx, `
			SELECT id, action, timestamp, outcome
			FROM audit_events
			WHERE actor_id = $1
			  AND timestamp BETWEEN $2 AND $3
			  AND id != $4
			ORDER BY timestamp ASC
			LIMIT 10
		`, event.ActorID, windowStart, windowEnd, event.ID)

		if err != nil {
			ad.logger.Warn("Failed to query for escalation events", zap.Error(err))
			return nil
		}
		defer rows.Close()

		var followedBySensitive []string
		for rows.Next() {
			var id, action string
			var ts time.Time
			var outcome ServiceEventOutcome
			if err := rows.Scan(&id, &action, &ts, &outcome); err != nil {
				continue
			}

			// Check if action is sensitive and occurred after role change
			for _, sensitive := range sensitiveActions {
				if action == sensitive && ts.After(event.Timestamp) && outcome == ServiceOutcomeSuccess {
					followedBySensitive = append(followedBySensitive, action)
				}
			}
		}

		if len(followedBySensitive) > 0 {
			return &AnomalyAlert{
				ID:          generateUUID(),
				Type:        AnomalyPrivilegeEscalation,
				Severity:    "critical",
				Title:       "Potential Privilege Escalation Detected",
				Description: fmt.Sprintf("Role assignment followed by sensitive action: %v",
					followedBySensitive),
				EventID:   event.ID,
				ActorID:   event.ActorID,
				Timestamp: time.Now().UTC(),
				Details: map[string]interface{}{
					"role_change_action":   event.Action,
					"sensitive_actions":    followedBySensitive,
					"escalation_window":    ad.config.EscalationWindow.String(),
					"target_id":            event.TargetID,
					"new_role":             event.Details,
				},
			}
		}
	}

	return nil
}

// detectBulkAccess detects bulk data access patterns
// Rule: >100 resource reads in 1 minute from the same actor
func (ad *AnomalyDetector) detectBulkAccess(ctx context.Context, event *ServiceAuditEvent) *AnomalyAlert {
	// Count resource access events by this actor in the window
	windowStart := event.Timestamp.Add(-ad.config.BulkAccessWindow)
	windowEnd := event.Timestamp.Add(ad.config.BulkAccessWindow)

	var accessCount int
	err := ad.service.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM audit_events
		WHERE actor_id = $1
		  AND event_type = 'authorization'
		  AND timestamp BETWEEN $2 AND $3
		  AND outcome = 'success'
	`, event.ActorID, windowStart, windowEnd).Scan(&accessCount)

	if err != nil {
		return nil
	}

	if accessCount > ad.config.BulkAccessThreshold {
		// Get breakdown by resource type
		rows, _ := ad.service.db.Pool.Query(ctx, `
			SELECT resource_type, COUNT(*) as count
			FROM audit_events
			WHERE actor_id = $1
			  AND event_type = 'authorization'
			  AND timestamp BETWEEN $2 AND $3
			  AND outcome = 'success'
			GROUP BY resource_type
			ORDER BY count DESC
		`, event.ActorID, windowStart, windowEnd)
		defer rows.Close()

		resourceBreakdown := make(map[string]int)
		for rows.Next() {
			var resourceType string
			var count int
			if rows.Scan(&resourceType, &count) == nil {
				resourceBreakdown[resourceType] = count
			}
		}

		return &AnomalyAlert{
			ID:          generateUUID(),
			Type:        AnomalyBulkAccess,
			Severity:    "medium",
			Title:       "Suspicious Bulk Access Pattern Detected",
			Description: fmt.Sprintf("More than %d resource accesses detected within %s",
				ad.config.BulkAccessThreshold, ad.config.BulkAccessWindow),
			EventID:   event.ID,
			ActorID:   event.ActorID,
			Timestamp: time.Now().UTC(),
			Details: map[string]interface{}{
				"total_accesses":      accessCount,
				"detection_window":    ad.config.BulkAccessWindow.String(),
				"threshold":           ad.config.BulkAccessThreshold,
				"resource_breakdown":  resourceBreakdown,
				"actor_ip":            event.ActorIP,
			},
		}
	}

	return nil
}

// detectOffHoursAdmin detects administrative actions outside business hours
// Rule: Admin action performed outside business hours (9AM-5PM by default)
func (ad *AnomalyDetector) detectOffHoursAdmin(event *ServiceAuditEvent) *AnomalyAlert {
	hour := event.Timestamp.Hour()
	start := ad.config.BusinessHoursStart
	end := ad.config.BusinessHoursEnd

	// Handle overnight schedules (e.g., 22:00 to 06:00)
	isBusinessHours := false
	if start < end {
		// Normal schedule (e.g., 9:00 to 17:00)
		isBusinessHours = hour >= start && hour < end
	} else {
		// Overnight schedule (e.g., 22:00 to 06:00)
		isBusinessHours = hour >= start || hour < end
	}

	if !isBusinessHours {
		// Check if this is a sensitive action
		sensitiveActions := map[string]bool{
			"user.delete":         true,
			"role.assign":         true,
			"role.revoke":         true,
			"policy.change":       true,
			"policy.delete":       true,
			"config.change":       true,
			"permission.grant":    true,
			"permission.revoke":   true,
			"group.delete":        true,
			"data.export":         true,
			"data.delete":         true,
		}

		if sensitiveActions[event.Action] {
			return &AnomalyAlert{
				ID:          generateUUID(),
				Type:        AnomalyOffHoursAdmin,
				Severity:    "medium",
				Title:       "Off-Hours Administrative Action Detected",
				Description: fmt.Sprintf("Administrative action '%s' performed outside business hours (%d:00 - %d:00)",
					event.Action, start, end),
				EventID:   event.ID,
				ActorID:   event.ActorID,
				Timestamp: time.Now().UTC(),
				Details: map[string]interface{}{
					"action":         event.Action,
					"hour":           hour,
					"business_hours": fmt.Sprintf("%d:00-%d:00", start, end),
					"actor_type":     event.ActorType,
					"target_id":      event.TargetID,
					"timezone":       ad.config.Timezone,
				},
			}
		}
	}

	return nil
}

// storeAlerts stores detected anomalies in the database
func (ad *AnomalyDetector) storeAlerts(ctx context.Context, alerts []*AnomalyAlert) {
	for _, alert := range alerts {
		_, err := ad.service.db.Pool.Exec(ctx, `
			INSERT INTO security_alerts (id, type, severity, title, description, event_id,
			                              actor_id, timestamp, details, metadata, status)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'open')
		`, alert.ID, string(alert.Type), alert.Severity, alert.Title,
			alert.Description, alert.EventID, alert.ActorID, alert.Timestamp,
			alert.Details, alert.Metadata)

		if err != nil {
			ad.logger.Error("Failed to store anomaly alert",
				zap.String("alert_id", alert.ID),
				zap.Error(err))
		} else {
			ad.logger.Info("Anomaly alert stored",
				zap.String("alert_id", alert.ID),
				zap.String("type", string(alert.Type)),
				zap.String("severity", alert.Severity))
		}
	}
}

// CleanupOldState removes stale tracking state
func (ad *AnomalyDetector) CleanupOldState() {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	cutoff := time.Now().UTC().Add(-ad.config.BruteForceWindow * 2)
	for actorID, tracker := range ad.bruteForceState {
		if tracker.FirstSeen.Before(cutoff) && len(tracker.Attempts) == 0 {
			delete(ad.bruteForceState, actorID)
		}
	}
}

// GetActiveTrackers returns the current number of active brute force trackers
func (ad *AnomalyDetector) GetActiveTrackers() int {
	ad.mu.RLock()
	defer ad.mu.RUnlock()
	return len(ad.bruteForceState)
}

// UpdateConfig updates the detector configuration
func (ad *AnomalyDetector) UpdateConfig(config *DetectorConfig) {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	ad.config = config
}

// GetConfig returns the current detector configuration
func (ad *AnomalyDetector) GetConfig() *DetectorConfig {
	ad.mu.RLock()
	defer ad.mu.RUnlock()
	return ad.config
}
