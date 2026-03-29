// Package metrics provides admin API specific metrics
package metrics

import (
	"context"
	"time"
)

// AdminMetricsCollector collects admin-specific business metrics
type AdminMetricsCollector struct {
	serviceName string
	db          AdminDBStats
}

// AdminDBStats interface for admin database stats
type AdminDBStats interface {
	OrganizationCount(ctx context.Context) (int64, error)
	ApplicationCount(ctx context.Context) (int64, error)
	DirectoryCount(ctx context.Context) (int64, error)
	WebhookCount(ctx context.Context) (int64, error)
	ActiveSessionCount(ctx context.Context) (int64, error)
}

// NewAdminMetricsCollector creates a new admin metrics collector
func NewAdminMetricsCollector(serviceName string, db AdminDBStats) *AdminMetricsCollector {
	return &AdminMetricsCollector{
		serviceName: serviceName,
		db:          db,
	}
}

// Start starts the metrics collection loop
func (g *AdminMetricsCollector) Start(ctx context.Context) {
	// Initial collection
	g.collectMetrics(ctx)

	// Collect every 30 seconds
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				g.collectMetrics(ctx)
			case <-ctx.Done():
				return
			}
		}
	}()
}

// collectMetrics gathers all admin metrics
func (g *AdminMetricsCollector) collectMetrics(ctx context.Context) {
	if g.db == nil {
		return
	}

	// These could be added as additional gauges if needed
	// For now, we rely on the identity service metrics for user counts
}

// RecordOrganizationCreated records a new organization
func (g *AdminMetricsCollector) RecordOrganizationCreated() {
	RecordTokenOperation("organization", "created")
}

// RecordOrganizationDeleted records an organization deletion
func (g *AdminMetricsCollector) RecordOrganizationDeleted() {
	RecordTokenOperation("organization", "deleted")
}

// RecordApplicationCreated records a new application
func (g *AdminMetricsCollector) RecordApplicationCreated(appType string) {
	RecordTokenOperation("application_"+appType, "created")
}

// RecordApplicationDeleted records an application deletion
func (g *AdminMetricsCollector) RecordApplicationDeleted() {
	RecordTokenOperation("application", "deleted")
}

// RecordDirectorySync records a directory sync event
func (g *AdminMetricsCollector) RecordDirectorySync(dirType string, success bool, userCount int) {
	outcome := "success"
	if !success {
		outcome = "failure"
	}
	RecordTokenOperation("directory_sync_"+dirType, outcome)
}

// RecordWebhookDelivery records a webhook delivery attempt
func (g *AdminMetricsCollector) RecordWebhookDelivery(eventType string, success bool, duration time.Duration) {
	outcome := "success"
	if !success {
		outcome = "failure"
	}
	RecordTokenOperation("webhook_delivery", outcome)
}

// RecordSettingsChange records a settings change event
func (g *AdminMetricsCollector) RecordSettingsChange(settingName string) {
	RecordAuditEvent(g.serviceName, "settings.changed")
}

// RecordAPIKeyCreated records an API key creation
func (g *AdminMetricsCollector) RecordAPIKeyCreated(keyType string) {
	RecordTokenOperation("api_key_"+keyType, "created")
}

// RecordAPIKeyRevoked records an API key revocation
func (g *AdminMetricsCollector) RecordAPIKeyRevoked() {
	RecordTokenOperation("api_key", "revoked")
}

// RecordExportStarted records an export operation start
func (g *AdminMetricsCollector) RecordExportStarted(exportType string) {
	RecordTokenOperation("export_"+exportType, "started")
}

// RecordExportCompleted records an export operation completion
func (g *AdminMetricsCollector) RecordExportCompleted(exportType string, success bool) {
	outcome := "success"
	if !success {
		outcome = "failure"
	}
	RecordTokenOperation("export_"+exportType, outcome)
}
