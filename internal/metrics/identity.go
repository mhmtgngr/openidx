// Package metrics provides identity service specific metrics
package metrics

import (
	"context"
	"time"
)

// IdentityMetricsCollector collects identity-specific business metrics
type IdentityMetricsCollector struct {
	serviceName string
	db          DBStatsCollector
	redis       CacheStatsCollector
}

// DBStatsCollector interface for database stats collection
type DBStatsCollector interface {
	UserCount(ctx context.Context) (int64, error)
	ActiveSessionCount(ctx context.Context) (int64, error)
	MFAEnrollmentCount(ctx context.Context, method string) (int64, error)
}

// CacheStatsCollector interface for cache-based metrics
type CacheStatsCollector interface {
	ActiveSessionCount(ctx context.Context) (int64, error)
}

// NewIdentityMetricsCollector creates a new identity metrics collector
func NewIdentityMetricsCollector(serviceName string, db DBStatsCollector, redis CacheStatsCollector) *IdentityMetricsCollector {
	return &IdentityMetricsCollector{
		serviceName: serviceName,
		db:          db,
		redis:       redis,
	}
}

// Start starts the metrics collection loop
func (i *IdentityMetricsCollector) Start(ctx context.Context) {
	// Initial collection
	i.collectMetrics(ctx)

	// Collect every 30 seconds
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				i.collectMetrics(ctx)
			case <-ctx.Done():
				return
			}
		}
	}()
}

// collectMetrics gathers all identity metrics
func (i *IdentityMetricsCollector) collectMetrics(ctx context.Context) {
	// Total users
	if i.db != nil {
		if count, err := i.db.UserCount(ctx); err == nil {
			SetTotalUsers(i.serviceName, float64(count))
		}

		// Active sessions (from cache or db)
		if count, err := i.db.ActiveSessionCount(ctx); err == nil {
			SetActiveSessions(i.serviceName, float64(count))
		}

		// MFA enrollments by method
		methods := []string{"totp", "sms", "email", "webauthn"}
		for _, method := range methods {
			if count, err := i.db.MFAEnrollmentCount(ctx, method); err == nil {
				SetMFAEnrollments(i.serviceName, method, float64(count))
			}
		}
	}
}

// RecordLoginAttempt records a login attempt (success or failure)
func (i *IdentityMetricsCollector) RecordLoginAttempt(success bool, method, failureReason string) {
	if success {
		RecordSuccessfulLogin(i.serviceName, method)
	} else {
		RecordFailedLogin(i.serviceName, failureReason)
		RecordAuthAttempt(method, "failure")
	}
}

// RecordMFALogin records MFA verification during login
func (i *IdentityMetricsCollector) RecordMFALogin(method string, success bool, duration time.Duration) {
	if success {
		RecordMFAVerification(method, "success")
	} else {
		RecordMFAVerification(method, "failure")
	}
	RecordMFADuration(method, duration)
}

// RecordSessionCreated records a new session being created
func (i *IdentityMetricsCollector) RecordSessionCreated() {
	IncActiveSessions(i.serviceName)
}

// RecordSessionDestroyed records a session being destroyed
func (i *IdentityMetricsCollector) RecordSessionDestroyed() {
	DecActiveSessions(i.serviceName)
}

// RecordUserCreated records a new user being created
func (i *IdentityMetricsCollector) RecordUserCreated() {
	// This would typically trigger a cache refresh of user count
}

// RecordUserDeleted records a user being deleted
func (i *IdentityMetricsCollector) RecordUserDeleted() {
	// This would typically trigger a cache refresh of user count
}
