// Package metrics provides audit service specific metrics
package metrics

import (
	"context"
	"time"
)

// AuditMetricsCollector collects audit-specific business metrics
type AuditMetricsCollector struct {
	serviceName string
	db          AuditDBStats
}

// AuditDBStats interface for audit database stats
type AuditDBStats interface {
	EventCount(ctx context.Context, eventType string, since time.Time) (int64, error)
	TotalEventCount(ctx context.Context) (int64, error)
	RetentionStatus(ctx context.Context) (map[string]int64, error)
}

// NewAuditMetricsCollector creates a new audit metrics collector
func NewAuditMetricsCollector(serviceName string, db AuditDBStats) *AuditMetricsCollector {
	return &AuditMetricsCollector{
		serviceName: serviceName,
		db:          db,
	}
}

// Start starts the metrics collection loop
func (a *AuditMetricsCollector) Start(ctx context.Context) {
	// Initial collection
	a.collectMetrics(ctx)

	// Collect every 30 seconds
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				a.collectMetrics(ctx)
			case <-ctx.Done():
				return
			}
		}
	}()
}

// collectMetrics gathers all audit metrics
func (a *AuditMetricsCollector) collectMetrics(ctx context.Context) {
	if a.db == nil {
		return
	}

	// Total events in the last 24 hours
	since := time.Now().Add(-24 * time.Hour)
	eventTypes := []string{
		"user.login",
		"user.logout",
		"user.created",
		"user.deleted",
		"access.granted",
		"access.denied",
		"policy.created",
		"policy.updated",
		"policy.deleted",
		"review.created",
		"review.completed",
		"data.exported",
		"settings.changed",
	}

	for _, eventType := range eventTypes {
		if _, err := a.db.EventCount(ctx, eventType, since); err == nil {
			// Update counter with delta (simplified - in production use proper delta tracking)
		}
	}
}

// RecordAuditEvent records an audit event
func (a *AuditMetricsCollector) RecordAuditEvent(eventType string) {
	RecordAuditEvent(a.serviceName, eventType)
}

// RecordComplianceReportGenerated records a compliance report generation
func (a *AuditMetricsCollector) RecordComplianceReportGenerated(reportType string, success bool, duration time.Duration) {
	outcome := "success"
	if !success {
		outcome = "failure"
	}
	RecordTokenOperation("compliance_report_"+reportType, outcome)

	// Record duration if successful
	if success {
		// Could use a duration histogram here
	}
}

// RecordSIEMExport records a SIEM export event
func (a *AuditMetricsCollector) RecordSIEMExport(destination string, eventCount int, success bool) {
	outcome := "success"
	if !success {
		outcome = "failure"
	}
	RecordTokenOperation("siem_export_"+destination, outcome)
}

// RecordRetentionApplied records when retention policy is applied
func (a *AuditMetricsCollector) RecordRetentionApplied(policyName string, deletedCount int) {
	RecordTokenOperation("retention_applied", policyName)
}

// RecordSearchQuery records an audit log search query
func (a *AuditMetricsCollector) RecordSearchQuery(duration time.Duration, resultCount int) {
	RecordTokenOperation("audit_search", "success")
}

// RecordExport records an audit log export event
func (a *AuditMetricsCollector) RecordExport(format string, recordCount int, success bool) {
	outcome := "success"
	if !success {
		outcome = "failure"
	}
	RecordTokenOperation("audit_export_"+format, outcome)
}

// Common audit event types for consistency
const (
	EventTypeUserLogin       = "user.login"
	EventTypeUserLogout      = "user.logout"
	EventTypeUserCreated     = "user.created"
	EventTypeUserDeleted     = "user.deleted"
	EventTypeUserUpdated     = "user.updated"
	EventTypeAccessGranted   = "access.granted"
	EventTypeAccessDenied    = "access.denied"
	EventTypePolicyCreated   = "policy.created"
	EventTypePolicyUpdated   = "policy.updated"
	EventTypePolicyDeleted   = "policy.deleted"
	EventTypeReviewCreated   = "review.created"
	EventTypeReviewCompleted = "review.completed"
	EventTypeDataExported    = "data.exported"
	EventTypeSettingsChanged = "settings.changed"
	EventTypeMFAEnabled      = "mfa.enabled"
	EventTypeMFADisabled     = "mfa.disabled"
	EventTypeRoleAssigned    = "role.assigned"
	EventTypeRoleRevoked     = "role.revoked"
)
