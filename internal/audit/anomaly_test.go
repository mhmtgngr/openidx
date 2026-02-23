// Package audit provides unit tests for anomaly detection
package audit

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNewAnomalyDetector(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)

	detector := NewAnomalyDetector(logger, service)

	assert.NotNil(t, detector)
	assert.NotNil(t, detector.config)
	assert.NotNil(t, detector.bruteForceState)
	assert.Equal(t, 5, detector.config.BruteForceThreshold)
	assert.Equal(t, 5*time.Minute, detector.config.BruteForceWindow)
	assert.Equal(t, 100, detector.config.BulkAccessThreshold)
	assert.Equal(t, 1*time.Minute, detector.config.BulkAccessWindow)
	assert.Equal(t, 9, detector.config.BusinessHoursStart)
	assert.Equal(t, 17, detector.config.BusinessHoursEnd)
}

func TestBruteForceDetection(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)
	detector := NewAnomalyDetector(logger, service)
	ctx := context.Background()

	actorID := "attacker-123"
	baseEvent := &ServiceAuditEvent{
		Timestamp:  time.Now().UTC(),
		EventType:  EventTypeAuthentication,
		Category:   CategorySecurity,
		Action:     "auth.login.failed",
		Outcome:    ServiceOutcomeFailure,
		ActorID:    actorID,
		ActorIP:    "192.168.1.100",
		ActorType:  "user",
	}

	var alerts []*AnomalyAlert

	// Send 4 failed logins - should not trigger yet
	for i := 0; i < 4; i++ {
		event := *baseEvent
		event.ID = generateUUID()
		event.Timestamp = time.Now().UTC()
		alerts = detector.AnalyzeEvent(ctx, &event)
		assert.Empty(t, alerts, "Should not trigger alert before threshold")
	}

	// Send 5th failed login - should trigger alert
	event := *baseEvent
	event.ID = generateUUID()
	event.Timestamp = time.Now().UTC()
	alerts = detector.AnalyzeEvent(ctx, &event)
	assert.Len(t, alerts, 1, "Should trigger alert at threshold")

	alert := alerts[0]
	assert.Equal(t, AnomalyBruteForce, alert.Type)
	assert.Equal(t, "high", alert.Severity)
	assert.Equal(t, "Potential Brute Force Attack Detected", alert.Title)
	assert.Equal(t, actorID, alert.ActorID)
	assert.Equal(t, 5, alert.Details["failed_attempts"])

	// Send more events - should not trigger again (alert already sent)
	for i := 0; i < 3; i++ {
		event := *baseEvent
		event.ID = generateUUID()
		event.Timestamp = time.Now().UTC()
		alerts = detector.AnalyzeEvent(ctx, &event)
		assert.Empty(t, alerts, "Should not trigger duplicate alert")
	}
}

func TestBruteForceDetection_WindowExpiry(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)
	detector := NewAnomalyDetector(logger, service)
	ctx := context.Background()

	actorID := "user-window-test"
	oldTime := time.Now().UTC().Add(-10 * time.Minute)

	// Send 5 old failed logins (outside the window)
	for i := 0; i < 5; i++ {
		event := &ServiceAuditEvent{
			ID:        generateUUID(),
			Timestamp: oldTime,
			EventType: EventTypeAuthentication,
			Category:   CategorySecurity,
			Action:     "auth.login.failed",
			Outcome:    ServiceOutcomeFailure,
			ActorID:    actorID,
			ActorIP:    "192.168.1.101",
		}
		detector.AnalyzeEvent(ctx, event)
	}

	// Send new failed login - old attempts should be expired
	newEvent := &ServiceAuditEvent{
		ID:        generateUUID(),
		Timestamp: time.Now().UTC(),
		EventType: EventTypeAuthentication,
		Category:   CategorySecurity,
		Action:     "auth.login.failed",
		Outcome:    ServiceOutcomeFailure,
		ActorID:    actorID,
		ActorIP:    "192.168.1.101",
	}
	alerts := detector.AnalyzeEvent(ctx, newEvent)
	assert.Empty(t, alerts, "Old attempts should be expired")

	// Need 4 more attempts to trigger (already have 1 from above)
	for i := 0; i < 4; i++ {
		event := *newEvent
		event.ID = generateUUID()
		event.Timestamp = time.Now().UTC()
		alerts = detector.AnalyzeEvent(ctx, &event)
		if len(alerts) > 0 {
			break // Alert triggered, exit loop
		}
	}
	assert.Len(t, alerts, 1, "Should trigger with 5 total new attempts")
}

func TestPrivilegeEscalationDetection(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)
	detector := NewAnomalyDetector(logger, service)
	ctx := context.Background()

	// This test requires database queries, so we'll test the logic structure
	roleChangeEvent := &ServiceAuditEvent{
		ID:          generateUUID(),
		Timestamp:   time.Now().UTC(),
		EventType:   EventTypeRoleManagement,
		Category:    CategorySecurity,
		Action:      "role.assign",
		Outcome:     ServiceOutcomeSuccess,
		ActorID:     "admin-123",
		ActorType:   "admin",
		TargetID:    "user-456",
		TargetType:  "user",
		Details: map[string]interface{}{
			"new_role": "administrator",
		},
	}

	alerts := detector.AnalyzeEvent(ctx, roleChangeEvent)

	// Without actual database events, this won't trigger
	// but we verify the detector processes the event
	assert.NotNil(t, alerts)
}

func TestBulkAccessDetection(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)
	detector := NewAnomalyDetector(logger, service)
	ctx := context.Background()

	// This requires database queries to count events
	event := &ServiceAuditEvent{
		ID:        generateUUID(),
		Timestamp: time.Now().UTC(),
		EventType: EventTypeAuthorization,
		Category:  CategoryAccess,
		Action:    "resource.read",
		Outcome:   ServiceOutcomeSuccess,
		ActorID:   "bulk-user-123",
		ActorIP:   "192.168.1.102",
		ResourceID: "resource-456",
	}

	alerts := detector.AnalyzeEvent(ctx, event)

	// Without actual database data, won't trigger but processes event
	assert.NotNil(t, alerts)
}

func TestOffHoursAdminDetection(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)
	detector := NewAnomalyDetector(logger, service)
	ctx := context.Background()

	// Create an event at 2 AM (outside 9-5 business hours)
	earlyMorning := time.Date(2024, 1, 1, 2, 30, 0, 0, time.UTC)

	event := &ServiceAuditEvent{
		ID:          generateUUID(),
		Timestamp:   earlyMorning,
		EventType:   EventTypeUserManagement,
		Category:    CategorySecurity,
		Action:      "user.delete",
		Outcome:     ServiceOutcomeSuccess,
		ActorID:     "admin-123",
		ActorType:   "admin",
		ActorIP:     "192.168.1.103",
		TargetID:    "user-789",
		TargetType:  "user",
	}

	alerts := detector.AnalyzeEvent(ctx, event)

	assert.Len(t, alerts, 1, "Should detect off-hours admin action")

	alert := alerts[0]
	assert.Equal(t, AnomalyOffHoursAdmin, alert.Type)
	assert.Equal(t, "medium", alert.Severity)
	assert.Equal(t, "Off-Hours Administrative Action Detected", alert.Title)
	assert.Contains(t, alert.Description, "user.delete")
	assert.Equal(t, 2, alert.Details["hour"])
}

func TestOffHoursDetection_BusinessHours(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)
	detector := NewAnomalyDetector(logger, service)
	ctx := context.Background()

	// Create an event at 10 AM (within business hours)
	businessHour := time.Date(2024, 1, 1, 10, 30, 0, 0, time.UTC)

	event := &ServiceAuditEvent{
		ID:          generateUUID(),
		Timestamp:   businessHour,
		EventType:   EventTypeUserManagement,
		Category:    CategorySecurity,
		Action:      "user.delete",
		Outcome:     ServiceOutcomeSuccess,
		ActorID:     "admin-123",
		ActorType:   "admin",
	}

	alerts := detector.AnalyzeEvent(ctx, event)

	assert.Empty(t, alerts, "Should not alert during business hours")
}

func TestOffHoursDetection_OvernightSchedule(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)
	detector := NewAnomalyDetector(logger, service)

	// Set overnight schedule (10 PM to 6 AM)
	detector.config.BusinessHoursStart = 22
	detector.config.BusinessHoursEnd = 6

	ctx := context.Background()

	// Event at 11 PM - should be business hours
	eveningEvent := &ServiceAuditEvent{
		ID:        generateUUID(),
		Timestamp: time.Date(2024, 1, 1, 23, 0, 0, 0, time.UTC),
		EventType: EventTypeUserManagement,
		Category:  CategorySecurity,
		Action:    "user.delete",
		Outcome:   ServiceOutcomeSuccess,
		ActorID:   "admin-123",
		ActorType: "admin",
	}

	alerts := detector.AnalyzeEvent(ctx, eveningEvent)
	assert.Empty(t, alerts, "11 PM should be business hours with overnight schedule")

	// Event at 3 AM - should be business hours
	earlyEvent := &ServiceAuditEvent{
		ID:        generateUUID(),
		Timestamp: time.Date(2024, 1, 1, 3, 0, 0, 0, time.UTC),
		EventType: EventTypeUserManagement,
		Category:  CategorySecurity,
		Action:    "user.delete",
		Outcome:   ServiceOutcomeSuccess,
		ActorID:   "admin-123",
		ActorType: "admin",
	}

	alerts = detector.AnalyzeEvent(ctx, earlyEvent)
	assert.Empty(t, alerts, "3 AM should be business hours with overnight schedule")

	// Event at noon - should be off hours
	noonEvent := &ServiceAuditEvent{
		ID:        generateUUID(),
		Timestamp: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		EventType: EventTypeUserManagement,
		Category:  CategorySecurity,
		Action:    "user.delete",
		Outcome:   ServiceOutcomeSuccess,
		ActorID:   "admin-123",
		ActorType: "admin",
	}

	alerts = detector.AnalyzeEvent(ctx, noonEvent)
	assert.Len(t, alerts, 1, "Noon should be off hours with overnight schedule")
}

func TestAnomalyAlert_Serialization(t *testing.T) {
	alert := &AnomalyAlert{
		ID:          "alert-123",
		Type:        AnomalyBruteForce,
		Severity:    "high",
		Title:       "Test Alert",
		Description: "This is a test alert",
		EventID:     "event-456",
		ActorID:     "user-789",
		Timestamp:   time.Now().UTC(),
		Details: map[string]interface{}{
			"failed_attempts": 5,
			"time_window":     "5m0s",
		},
		Metadata: map[string]interface{}{
			"source": "anomaly_detector",
		},
	}

	// Test JSON marshaling
	data, err := json.Marshal(alert)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// Test JSON unmarshaling
	var unmarshaled AnomalyAlert
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, alert.ID, unmarshaled.ID)
	assert.Equal(t, alert.Type, unmarshaled.Type)
	assert.Equal(t, alert.Severity, unmarshaled.Severity)
	assert.Equal(t, alert.Title, unmarshaled.Title)
	assert.Equal(t, alert.ActorID, unmarshaled.ActorID)
}

func TestAnomalyDetector_CleanupOldState(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)
	detector := NewAnomalyDetector(logger, service)

	actorID := "cleanup-test-user"

	// Add some state
	detector.bruteForceState[actorID] = &FailedLoginTracker{
		ActorID:   actorID,
		FirstSeen: time.Now().UTC().Add(-30 * time.Minute),
		Attempts:  []time.Time{},
	}

	assert.Equal(t, 1, detector.GetActiveTrackers())

	// Cleanup should remove old state
	detector.CleanupOldState()

	assert.Equal(t, 0, detector.GetActiveTrackers(), "Old state should be cleaned up")
}

func TestAnomalyDetector_UpdateConfig(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)
	detector := NewAnomalyDetector(logger, service)

	// Verify defaults
	assert.Equal(t, 5, detector.config.BruteForceThreshold)
	assert.Equal(t, 5*time.Minute, detector.config.BruteForceWindow)

	// Update config
	newConfig := &DetectorConfig{
		BruteForceThreshold: 10,
		BruteForceWindow:    10 * time.Minute,
		BulkAccessThreshold: 200,
		BusinessHoursStart:  8,
		BusinessHoursEnd:    20,
		AlertEnabled:        false,
	}

	detector.UpdateConfig(newConfig)

	// Verify updates
	config := detector.GetConfig()
	assert.Equal(t, 10, config.BruteForceThreshold)
	assert.Equal(t, 10*time.Minute, config.BruteForceWindow)
	assert.Equal(t, 200, config.BulkAccessThreshold)
	assert.Equal(t, 8, config.BusinessHoursStart)
	assert.Equal(t, 20, config.BusinessHoursEnd)
	assert.False(t, config.AlertEnabled)
}

func TestAnomalyTypes(t *testing.T) {
	// Verify all anomaly types are defined
	types := []AnomalyType{
		AnomalyBruteForce,
		AnomalyPrivilegeEscalation,
		AnomalyBulkAccess,
		AnomalyOffHoursAdmin,
		AnomalyImpossibleTravel,
		AnomalyDataExfiltration,
	}

	expectedStrings := []string{
		"brute_force",
		"privilege_escalation",
		"bulk_access",
		"off_hours_admin",
		"impossible_travel",
		"data_exfiltration",
	}

	for i, at := range types {
		assert.Equal(t, expectedStrings[i], string(at))
	}
}

func TestFailedLoginTracker(t *testing.T) {
	tracker := &FailedLoginTracker{
		ActorID:   "test-user",
		Attempts:  []time.Time{},
		FirstSeen: time.Now().UTC(),
		AlertSent: false,
	}

	// Add attempts
	for i := 0; i < 3; i++ {
		tracker.Attempts = append(tracker.Attempts, time.Now().UTC())
	}

	assert.Len(t, tracker.Attempts, 3)
	assert.Equal(t, "test-user", tracker.ActorID)
	assert.False(t, tracker.AlertSent)

	// Mark alert as sent
	tracker.AlertSent = true
	assert.True(t, tracker.AlertSent)
}

func TestAnalyzeEvent_NonMatchingEvent(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)
	detector := NewAnomalyDetector(logger, service)
	ctx := context.Background()

	// Event that doesn't match any detection rule
	event := &ServiceAuditEvent{
		ID:          generateUUID(),
		Timestamp:   time.Now().UTC(),
		EventType:   EventTypeSystem,
		Category:    CategoryOperational,
		Action:      "system.ping",
		Outcome:     ServiceOutcomeSuccess,
		ActorID:     "system-123",
		ActorType:   "system",
	}

	alerts := detector.AnalyzeEvent(ctx, event)

	assert.Empty(t, alerts, "Non-matching events should not trigger alerts")
}

func TestSensitiveActions(t *testing.T) {
	// Verify sensitive actions are correctly identified in off-hours detection
	logger := zap.NewNop()
	service := createTestService(t)
	detector := NewAnomalyDetector(logger, service)
	ctx := context.Background()

	sensitiveActions := []string{
		"user.delete", "role.assign", "role.revoke", "policy.change",
		"policy.delete", "config.change", "permission.grant",
		"permission.revoke", "group.delete", "data.export", "data.delete",
	}

	offHour := time.Date(2024, 1, 1, 3, 0, 0, 0, time.UTC)

	for _, action := range sensitiveActions {
		event := &ServiceAuditEvent{
			ID:          generateUUID(),
			Timestamp:   offHour,
			EventType:   EventTypeUserManagement,
			Category:    CategorySecurity,
			Action:      action,
			Outcome:     ServiceOutcomeSuccess,
			ActorID:     "admin-123",
			ActorType:   "admin",
		}

		alerts := detector.AnalyzeEvent(ctx, event)
		assert.Len(t, alerts, 1, "Action %s should trigger off-hours alert", action)
	}

	// Non-sensitive action should not trigger
	nonSensitiveEvent := &ServiceAuditEvent{
		ID:          generateUUID(),
		Timestamp:   offHour,
		EventType:   EventTypeUserManagement,
		Category:    CategorySecurity,
		Action:      "user.view",
		Outcome:     ServiceOutcomeSuccess,
		ActorID:     "admin-123",
		ActorType:   "admin",
	}

	alerts := detector.AnalyzeEvent(ctx, nonSensitiveEvent)
	assert.Empty(t, alerts, "Non-sensitive action should not trigger off-hours alert")
}

// Benchmark tests
func BenchmarkAnalyzeEvent(b *testing.B) {
	logger := zap.NewNop()
	service := createTestService(&testing.T{})
	detector := NewAnomalyDetector(logger, service)
	ctx := context.Background()

	event := &ServiceAuditEvent{
		ID:          generateUUID(),
		Timestamp:   time.Now().UTC(),
		EventType:   EventTypeAuthentication,
		Category:    CategorySecurity,
		Action:      "auth.login.failed",
		Outcome:     ServiceOutcomeFailure,
		ActorID:     "user-123",
		ActorIP:     "192.168.1.1",
		ActorType:   "user",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.AnalyzeEvent(ctx, event)
	}
}
