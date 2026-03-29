// Package metrics provides governance service specific metrics
package metrics

import (
	"context"
	"time"
)

// GovernanceMetricsCollector collects governance-specific business metrics
type GovernanceMetricsCollector struct {
	serviceName string
	db          GovernanceDBStats
}

// GovernanceDBStats interface for governance database stats
type GovernanceDBStats interface {
	AccessReviewCount(ctx context.Context, status string) (int64, error)
	PolicyViolationCount(ctx context.Context, policyType, severity string) (int64, error)
	PendingReviewCount(ctx context.Context) (int64, error)
}

// NewGovernanceMetricsCollector creates a new governance metrics collector
func NewGovernanceMetricsCollector(serviceName string, db GovernanceDBStats) *GovernanceMetricsCollector {
	return &GovernanceMetricsCollector{
		serviceName: serviceName,
		db:          db,
	}
}

// Start starts the metrics collection loop
func (g *GovernanceMetricsCollector) Start(ctx context.Context) {
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

// collectMetrics gathers all governance metrics
func (g *GovernanceMetricsCollector) collectMetrics(ctx context.Context) {
	if g.db == nil {
		return
	}

	// Access reviews by status
	statuses := []string{"pending", "completed", "expired", "in_progress"}
	for _, status := range statuses {
		if count, err := g.db.AccessReviewCount(ctx, status); err == nil {
			SetAccessReviews(g.serviceName, status, float64(count))
		}
	}

	// Pending reviews (for alerting)
	if count, err := g.db.PendingReviewCount(ctx); err == nil {
		// Could set an alert threshold here
		if count > 100 {
			// High pending reviews alert
		}
	}
}

// RecordAccessReviewCreated records a new access review
func (g *GovernanceMetricsCollector) RecordAccessReviewCreated(reviewType string) {
	IncAccessReviews(g.serviceName, "pending")
}

// RecordAccessReviewCompleted records an access review completion
func (g *GovernanceMetricsCollector) RecordAccessReviewCompleted(fromStatus string) {
	DecAccessReviews(g.serviceName, fromStatus)
	IncAccessReviews(g.serviceName, "completed")
}

// RecordAccessReviewExpired records an access review expiration
func (g *GovernanceMetricsCollector) RecordAccessReviewExpired(fromStatus string) {
	DecAccessReviews(g.serviceName, fromStatus)
	IncAccessReviews(g.serviceName, "expired")
}

// RecordPolicyViolation records a policy violation detection
func (g *GovernanceMetricsCollector) RecordPolicyViolation(policyType, severity string) {
	RecordPolicyViolation(g.serviceName, policyType, severity)
}

// RecordReviewDecision records a review decision
func (g *GovernanceMetricsCollector) RecordReviewDecision(decision string) {
	// decision: approve, deny, escalate
	RecordTokenOperation("review_decision", decision)
}

// RecordCampaignStarted records an access review campaign start
func (g *GovernanceMetricsCollector) RecordCampaignStarted(campaignType string) {
	RecordTokenOperation("campaign_start", campaignType)
}

// RecordCampaignCompleted records an access review campaign completion
func (g *GovernanceMetricsCollector) RecordCampaignCompleted(campaignType string, success bool) {
	outcome := "success"
	if !success {
		outcome = "failure"
	}
	RecordTokenOperation("campaign_complete", outcome)
}
