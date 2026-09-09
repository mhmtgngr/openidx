// Package audit provides compliance report generators for SOC2, ISO27001, and GDPR
package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/syssettings"
)

// SOC2Report represents a SOC 2 Type II compliance report
type SOC2Report struct {
	ReportID       string                   `json:"report_id"`
	PeriodStart    time.Time                `json:"period_start"`
	PeriodEnd      time.Time                `json:"period_end"`
	GeneratedAt    time.Time                `json:"generated_at"`
	GeneratedBy    string                   `json:"generated_by"`
	AccessReviews  AccessReviewMetrics      `json:"access_reviews"`
	PasswordPolicy PasswordPolicyMetrics    `json:"password_policy"`
	MFAAdoption    MFAAdoptionMetrics       `json:"mfa_adoption"`
	SessionMgmt    SessionManagementMetrics `json:"session_management"`
}

// AccessReviewMetrics tracks access review compliance
type AccessReviewMetrics struct {
	TotalReviews     int       `json:"total_reviews"`
	PendingReviews   int       `json:"pending_reviews"`
	CompletedReviews int       `json:"completed_reviews"`
	OverdueReviews   int       `json:"overdue_reviews"`
	LastReviewDate   time.Time `json:"last_review_date"`
	CompletionRate   float64   `json:"completion_rate"`
	ComplianceStatus string    `json:"compliance_status"`
}

// PasswordPolicyMetrics tracks password policy compliance
type PasswordPolicyMetrics struct {
	MinLength              int    `json:"min_length"`
	RequireUppercase       bool   `json:"require_uppercase"`
	RequireLowercase       bool   `json:"require_lowercase"`
	RequireNumbers         bool   `json:"require_numbers"`
	RequireSpecialChars    bool   `json:"require_special_chars"`
	MaxAgeDays             int    `json:"max_age_days"`
	UsersWithWeakPasswords int    `json:"users_with_weak_passwords"`
	ComplianceStatus       string `json:"compliance_status"`
}

// MFAAdoptionMetrics tracks MFA adoption
type MFAAdoptionMetrics struct {
	TotalUsers        int       `json:"total_users"`
	UsersWithMFA      int       `json:"users_with_mfa"`
	UsersWithTOTP     int       `json:"users_with_totp"`
	UsersWithWebAuthn int       `json:"users_with_webauthn"`
	AdoptionRate      float64   `json:"adoption_rate"`
	LastUpdated       time.Time `json:"last_updated"`
	ComplianceStatus  string    `json:"compliance_status"`
}

// SessionManagementMetrics tracks session management
type SessionManagementMetrics struct {
	ActiveSessions      int       `json:"active_sessions"`
	AverageSessionHours float64   `json:"average_session_hours"`
	SessionTimeoutMins  int       `json:"session_timeout_minutes"`
	IdleTimeoutMins     int       `json:"idle_timeout_minutes"`
	LastActivityCheck   time.Time `json:"last_activity_check"`
	ComplianceStatus    string    `json:"compliance_status"`
}

// ISO27001Report represents an ISO 27001:2022 compliance report
type ISO27001Report struct {
	ReportID            string                     `json:"report_id"`
	PeriodStart         time.Time                  `json:"period_start"`
	PeriodEnd           time.Time                  `json:"period_end"`
	GeneratedAt         time.Time                  `json:"generated_at"`
	GeneratedBy         string                     `json:"generated_by"`
	AccessControl       AccessControlMetrics       `json:"access_control"`
	Cryptography        CryptographyMetrics        `json:"cryptography"`
	OperationalSecurity OperationalSecurityMetrics `json:"operational_security"`
}

// AccessControlMetrics for ISO 27001 A.9
type AccessControlMetrics struct {
	TotalUsers       int       `json:"total_users"`
	AdminUsers       int       `json:"admin_users"`
	AdminRatio       float64   `json:"admin_ratio"`
	RolesDefined     int       `json:"roles_defined"`
	GroupsDefined    int       `json:"groups_defined"`
	LastAccessReview time.Time `json:"last_access_review"`
	ComplianceStatus string    `json:"compliance_status"`
}

// CryptographyMetrics for ISO 27001 A.10
type CryptographyMetrics struct {
	TLSEnabled         bool      `json:"tls_enabled"`
	TLSMinVersion      string    `json:"tls_min_version"`
	EncryptionAtRest   bool      `json:"encryption_at_rest"`
	KeyRotationEnabled bool      `json:"key_rotation_enabled"`
	LastKeyRotation    time.Time `json:"last_key_rotation"`
	ComplianceStatus   string    `json:"compliance_status"`
}

// OperationalSecurityMetrics for ISO 27001 A.12
type OperationalSecurityMetrics struct {
	TotalEvents      int             `json:"total_events"`
	EventsByType     map[string]int  `json:"events_by_type"`
	EventsByDay      []DayEventCount `json:"events_by_day"`
	FailedEvents     int             `json:"failed_events"`
	ErrorRate        float64         `json:"error_rate"`
	LoggingCoverage  float64         `json:"logging_coverage"`
	ComplianceStatus string          `json:"compliance_status"`
}

// DayEventCount tracks events per day
type DayEventCount struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

// GDPRReport represents a GDPR compliance report
type GDPRReport struct {
	ReportID            string                    `json:"report_id"`
	PeriodStart         time.Time                 `json:"period_start"`
	PeriodEnd           time.Time                 `json:"period_end"`
	GeneratedAt         time.Time                 `json:"generated_at"`
	GeneratedBy         string                    `json:"generated_by"`
	DataAccessLogs      DataAccessMetrics         `json:"data_access_logs"`
	ConsentRecords      ConsentMetrics            `json:"consent_records"`
	DataSubjectRequests DataSubjectRequestMetrics `json:"data_subject_requests"`
	DataDeletionRecords DataDeletionMetrics       `json:"data_deletion_records"`
}

// DataAccessMetrics tracks data access for GDPR Art.30
type DataAccessMetrics struct {
	TotalAccessEvents int            `json:"total_access_events"`
	AccessByActor     map[string]int `json:"access_by_actor"`
	AccessByDataType  map[string]int `json:"access_by_data_type"`
	LastAccessLog     time.Time      `json:"last_access_log"`
	ComplianceStatus  string         `json:"compliance_status"`
}

// ConsentMetrics tracks consent records for GDPR Art.7
type ConsentMetrics struct {
	TotalConsentRecords int       `json:"total_consent_records"`
	ActiveConsents      int       `json:"active_consents"`
	WithdrawnConsents   int       `json:"withdrawn_consents"`
	PendingConsents     int       `json:"pending_consents"`
	LastConsentUpdate   time.Time `json:"last_consent_update"`
	ComplianceStatus    string    `json:"compliance_status"`
}

// DataSubjectRequestMetrics tracks GDPR Art.15-20 requests
type DataSubjectRequestMetrics struct {
	TotalRequests       int            `json:"total_requests"`
	RequestsByType      map[string]int `json:"requests_by_type"`
	PendingRequests     int            `json:"pending_requests"`
	CompletedRequests   int            `json:"completed_requests"`
	OverdueRequests     int            `json:"overdue_requests"`
	AverageResponseDays float64        `json:"average_response_days"`
	LastRequestDate     time.Time      `json:"last_request_date"`
	ComplianceStatus    string         `json:"compliance_status"`
}

// DataDeletionMetrics tracks right to be forgotten (Art.17)
type DataDeletionMetrics struct {
	TotalDeletionRequests int       `json:"total_deletion_requests"`
	CompletedDeletions    int       `json:"completed_deletions"`
	PendingDeletions      int       `json:"pending_deletions"`
	FailedDeletions       int       `json:"failed_deletions"`
	AverageDeletionDays   float64   `json:"average_deletion_days"`
	LastDeletionDate      time.Time `json:"last_deletion_date"`
	ComplianceStatus      string    `json:"compliance_status"`
}

// GenerateSOC2Report generates a SOC 2 compliance report
func (s *Service) GenerateSOC2Report(ctx context.Context, startDate, endDate time.Time, generatedBy string) (*SOC2Report, error) {
	s.logger.Info("Generating SOC 2 report",
		zap.String("start_date", startDate.Format(time.RFC3339)),
		zap.String("end_date", endDate.Format(time.RFC3339)))

	report := &SOC2Report{
		ReportID:    generateReportID(),
		PeriodStart: startDate,
		PeriodEnd:   endDate,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: generatedBy,
	}

	// Gather metrics. A section that cannot be measured fails the report:
	// see metricQuery for why a compliance document must not publish the zero
	// left behind by a query that did not run.
	var err error
	if report.AccessReviews, err = s.getAccessReviewMetrics(ctx, startDate, endDate); err != nil {
		return nil, fmt.Errorf("access review metrics: %w", err)
	}
	if report.PasswordPolicy, err = s.getPasswordPolicyMetrics(ctx); err != nil {
		return nil, fmt.Errorf("password policy metrics: %w", err)
	}
	if report.MFAAdoption, err = s.getMFAMetrics(ctx); err != nil {
		return nil, fmt.Errorf("MFA adoption metrics: %w", err)
	}
	if report.SessionMgmt, err = s.getSessionManagementMetrics(ctx); err != nil {
		return nil, fmt.Errorf("session management metrics: %w", err)
	}

	return report, nil
}

// GenerateISO27001Report generates an ISO 27001:2022 compliance report
func (s *Service) GenerateISO27001Report(ctx context.Context, startDate, endDate time.Time, generatedBy string) (*ISO27001Report, error) {
	s.logger.Info("Generating ISO 27001 report",
		zap.String("start_date", startDate.Format(time.RFC3339)),
		zap.String("end_date", endDate.Format(time.RFC3339)))

	report := &ISO27001Report{
		ReportID:    generateReportID(),
		PeriodStart: startDate,
		PeriodEnd:   endDate,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: generatedBy,
	}

	var err error
	if report.AccessControl, err = s.getISOAccessControlMetrics(ctx, startDate, endDate); err != nil {
		return nil, fmt.Errorf("access control metrics: %w", err)
	}
	if report.Cryptography, err = s.getCryptographyMetrics(ctx); err != nil {
		return nil, fmt.Errorf("cryptography metrics: %w", err)
	}
	if report.OperationalSecurity, err = s.getOperationalSecurityMetrics(ctx, startDate, endDate); err != nil {
		return nil, fmt.Errorf("operational security metrics: %w", err)
	}

	return report, nil
}

// GenerateGDPRReport generates a GDPR compliance report
func (s *Service) GenerateGDPRReport(ctx context.Context, startDate, endDate time.Time, generatedBy string) (*GDPRReport, error) {
	s.logger.Info("Generating GDPR report",
		zap.String("start_date", startDate.Format(time.RFC3339)),
		zap.String("end_date", endDate.Format(time.RFC3339)))

	report := &GDPRReport{
		ReportID:    generateReportID(),
		PeriodStart: startDate,
		PeriodEnd:   endDate,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: generatedBy,
	}

	var err error
	if report.DataAccessLogs, err = s.getDataAccessMetrics(ctx, startDate, endDate); err != nil {
		return nil, fmt.Errorf("data access metrics: %w", err)
	}
	if report.ConsentRecords, err = s.getConsentMetrics(ctx); err != nil {
		return nil, fmt.Errorf("consent metrics: %w", err)
	}
	if report.DataSubjectRequests, err = s.getDataSubjectRequestMetrics(ctx, startDate, endDate); err != nil {
		return nil, fmt.Errorf("data subject request metrics: %w", err)
	}
	if report.DataDeletionRecords, err = s.getDataDeletionMetrics(ctx, startDate, endDate); err != nil {
		return nil, fmt.Errorf("data deletion metrics: %w", err)
	}

	return report, nil
}

// Metric gathering methods

func (s *Service) getAccessReviewMetrics(ctx context.Context, startDate, endDate time.Time) (AccessReviewMetrics, error) {
	metrics := AccessReviewMetrics{}
	q := s.newMetricQuery(ctx)

	q.scan("total access reviews", &metrics.TotalReviews, `
		SELECT COALESCE(COUNT(*), 0)
		FROM access_reviews
		WHERE created_at BETWEEN $1 AND $2
		AND org_id = $3
	`, startDate, endDate, q.org())

	q.scan("pending access reviews", &metrics.PendingReviews, `
		SELECT COALESCE(COUNT(*), 0)
		FROM access_reviews
		WHERE status = 'pending'
		AND org_id = $1
	`, q.org())

	q.scan("completed access reviews", &metrics.CompletedReviews, `
		SELECT COALESCE(COUNT(*), 0)
		FROM access_reviews
		WHERE status = 'completed'
		AND completed_at BETWEEN $1 AND $2
		AND org_id = $3
	`, startDate, endDate, q.org())

	// access_reviews has no due_date; the campaign's deadline is end_date.
	// The overdue count therefore read 0 on every report ever generated --
	// a compliance dashboard stating that no access review is overdue,
	// which is the reading an auditor takes as evidence.
	q.scan("overdue access reviews", &metrics.OverdueReviews, `
		SELECT COALESCE(COUNT(*), 0)
		FROM access_reviews
		WHERE status = 'pending' AND end_date < NOW()
		AND org_id = $1
	`, q.org())

	var lastReview time.Time
	q.scan("last completed access review", &lastReview, `
		SELECT COALESCE(MAX(completed_at), '1970-01-01'::timestamp)
		FROM access_reviews
		WHERE status = 'completed'
		AND org_id = $1
	`, q.org())
	metrics.LastReviewDate = lastReview

	if err := q.failed(); err != nil {
		return AccessReviewMetrics{}, err
	}

	if metrics.TotalReviews > 0 {
		metrics.CompletionRate = float64(metrics.CompletedReviews) / float64(metrics.TotalReviews) * 100
	}

	metrics.ComplianceStatus = determineComplianceStatus(metrics.CompletionRate, 80, 50)

	return metrics, nil
}

func (s *Service) getPasswordPolicyMetrics(ctx context.Context) (PasswordPolicyMetrics, error) {
	metrics := PasswordPolicyMetrics{
		MinLength:           8,
		RequireUppercase:    true,
		RequireLowercase:    true,
		RequireNumbers:      true,
		RequireSpecialChars: true,
		MaxAgeDays:          90,
		ComplianceStatus:    "compliant",
	}
	q := s.newMetricQuery(ctx)

	// The settings row is the one read here that legitimately may not exist: a
	// deployment that has never opened the security settings page has no row,
	// and the defaults above are then the policy in force. So this one keeps
	// its own error handling and does not fail the report.
	//
	// It read `WHERE key = 'security'` until v1.34.0 and no such row has ever
	// been written -- security is an object inside the 'system' document -- so
	// the defaults above were the answer on every install regardless of what
	// the operator had configured. Two of the field names were wrong as well:
	// the console writes require_special and max_age, not require_special_chars
	// and max_age_days, so those two would have stayed default even against the
	// right row.
	if settings, err := syssettings.Load(ctx, s.db.Pool); err == nil && q.failed() == nil {
		pp := settings.Security.PasswordPolicy
		metrics.MinLength = pp.MinLength
		metrics.RequireUppercase = pp.RequireUppercase
		metrics.RequireLowercase = pp.RequireLowercase
		metrics.RequireNumbers = pp.RequireNumbers
		metrics.RequireSpecialChars = pp.RequireSpecial
		metrics.MaxAgeDays = pp.MaxAge
	}

	q.scan("users with weak passwords", &metrics.UsersWithWeakPasswords, `
		SELECT COALESCE(COUNT(*), 0)
		FROM users
		WHERE enabled = true
		AND CHAR_LENGTH(password_hash) < 50
		AND org_id = $1
	`, q.org())

	if err := q.failed(); err != nil {
		return PasswordPolicyMetrics{}, err
	}

	if metrics.MinLength < 8 || !metrics.RequireNumbers {
		metrics.ComplianceStatus = "non_compliant"
	} else if metrics.UsersWithWeakPasswords > 0 {
		metrics.ComplianceStatus = "partial"
	}

	return metrics, nil
}

func (s *Service) getMFAMetrics(ctx context.Context) (MFAAdoptionMetrics, error) {
	metrics := MFAAdoptionMetrics{
		ComplianceStatus: "non_compliant",
		LastUpdated:      time.Now().UTC(),
	}
	q := s.newMetricQuery(ctx)

	q.scan("enabled users", &metrics.TotalUsers, `
		SELECT COALESCE(COUNT(*), 0)
		FROM users
		WHERE enabled = true
		AND org_id = $1
	`, q.org())

	q.scan("users with TOTP", &metrics.UsersWithTOTP, `
		SELECT COALESCE(COUNT(DISTINCT user_id), 0)
		FROM mfa_totp
		WHERE enabled = true
		AND org_id = $1
	`, q.org())

	q.scan("users with WebAuthn", &metrics.UsersWithWebAuthn, `
		SELECT COALESCE(COUNT(DISTINCT user_id), 0)
		FROM mfa_webauthn
		WHERE org_id = $1
	`, q.org())

	q.scan("users with any MFA factor", &metrics.UsersWithMFA, `
		SELECT COALESCE(COUNT(DISTINCT user_id), 0) FROM (
			SELECT user_id FROM mfa_totp WHERE enabled = true AND org_id = $1
			UNION
			SELECT user_id FROM mfa_webauthn WHERE org_id = $1
		) mfa
	`, q.org())

	if err := q.failed(); err != nil {
		return MFAAdoptionMetrics{}, err
	}

	if metrics.TotalUsers > 0 {
		metrics.AdoptionRate = float64(metrics.UsersWithMFA) / float64(metrics.TotalUsers) * 100
	}

	metrics.ComplianceStatus = determineComplianceStatus(metrics.AdoptionRate, 80, 50)

	return metrics, nil
}

func (s *Service) getSessionManagementMetrics(ctx context.Context) (SessionManagementMetrics, error) {
	metrics := SessionManagementMetrics{
		ComplianceStatus:  "compliant",
		LastActivityCheck: time.Now().UTC(),
	}
	q := s.newMetricQuery(ctx)

	q.scan("active sessions", &metrics.ActiveSessions, `
		SELECT COALESCE(COUNT(*), 0)
		FROM sessions
		WHERE expires_at > NOW()
		AND org_id = $1
	`, q.org())

	// sessions records its start as started_at; there is no created_at, so
	// this statement could never plan and the average read 0 hours.
	q.scan("average session length", &metrics.AverageSessionHours, `
		SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (expires_at - started_at)) / 3600.0), 0)
		FROM sessions
		WHERE started_at > NOW() - INTERVAL '30 days'
		AND org_id = $1
	`, q.org())

	if err := q.failed(); err != nil {
		return SessionManagementMetrics{}, err
	}

	// As in the password section: a deployment that has never saved security
	// settings has no row, and the zero timeout below is then a real reading of
	// an unconfigured install, which the compliance status treats as
	// non-compliant. Before v1.34.0 the wrong key meant EVERY install read as
	// unconfigured, so this control reported non-compliant on installs with a
	// session timeout configured.
	//
	// idle_timeout is stored in seconds (the console's default is 1800) and
	// this metric is in minutes; the old code assigned the raw number, so a
	// 30-minute idle timeout would have been reported as 1800 minutes had the
	// read ever returned anything.
	if settings, err := syssettings.Load(ctx, s.db.Pool); err == nil {
		metrics.SessionTimeoutMins = settings.Security.SessionTimeout
		metrics.IdleTimeoutMins = settings.Security.IdleTimeout / 60
	}

	if metrics.SessionTimeoutMins == 0 {
		metrics.ComplianceStatus = "non_compliant"
	} else if metrics.SessionTimeoutMins > 480 || metrics.AverageSessionHours > 24 {
		metrics.ComplianceStatus = "partial"
	}

	return metrics, nil
}

func (s *Service) getISOAccessControlMetrics(ctx context.Context, startDate, endDate time.Time) (AccessControlMetrics, error) {
	metrics := AccessControlMetrics{
		ComplianceStatus: "compliant",
	}
	q := s.newMetricQuery(ctx)

	q.scan("enabled users", &metrics.TotalUsers, `
		SELECT COALESCE(COUNT(*), 0)
		FROM users
		WHERE enabled = true
		AND org_id = $1
	`, q.org())

	q.scan("administrator accounts", &metrics.AdminUsers, `
		SELECT COALESCE(COUNT(DISTINCT ur.user_id), 0)
		FROM user_roles ur
		JOIN roles r ON ur.role_id = r.id AND r.org_id = ur.org_id
		WHERE r.name IN ('admin', 'super_admin')
		AND ur.user_id IN (SELECT id FROM users WHERE enabled = true AND org_id = ur.org_id)
		AND ur.org_id = $1
	`, q.org())

	q.scan("roles defined", &metrics.RolesDefined, `
		SELECT COALESCE(COUNT(*), 0)
		FROM roles
		WHERE org_id = $1
	`, q.org())

	q.scan("groups defined", &metrics.GroupsDefined, `
		SELECT COALESCE(COUNT(*), 0)
		FROM groups
		WHERE org_id = $1
	`, q.org())

	var lastReview time.Time
	q.scan("last completed access review", &lastReview, `
		SELECT COALESCE(MAX(completed_at), '1970-01-01'::timestamp)
		FROM access_reviews
		WHERE status = 'completed'
		AND org_id = $1
	`, q.org())

	if err := q.failed(); err != nil {
		return AccessControlMetrics{}, err
	}

	if metrics.TotalUsers > 0 {
		metrics.AdminRatio = float64(metrics.AdminUsers) / float64(metrics.TotalUsers) * 100
	}
	metrics.LastAccessReview = lastReview

	if metrics.AdminRatio > 20 {
		metrics.ComplianceStatus = "partial"
	}
	if metrics.RolesDefined < 3 {
		metrics.ComplianceStatus = "non_compliant"
	}

	return metrics, nil
}

func (s *Service) getCryptographyMetrics(ctx context.Context) (CryptographyMetrics, error) {
	metrics := CryptographyMetrics{
		TLSEnabled:         true,
		TLSMinVersion:      "1.2",
		EncryptionAtRest:   true,
		KeyRotationEnabled: true,
		ComplianceStatus:   "compliant",
	}
	q := s.newMetricQuery(ctx)
	if err := q.failed(); err != nil {
		return CryptographyMetrics{}, err
	}

	// This read a system_settings row keyed 'security' for tls_enabled,
	// tls_min_version, encryption_at_rest and key_rotation_enabled. That row
	// has never existed, and none of those four fields exists anywhere in the
	// console's settings document either -- there is no screen that sets them.
	// The read could therefore never return anything, and the four values
	// above have always been the literals they are initialised to.
	//
	// The dead query is removed rather than pointed at the right row, because
	// the right row does not carry these fields. The literals remain, and they
	// remain what they were: an assumption this report states, not a
	// measurement it took. Sourcing them from the deployment's real TLS and
	// encryption configuration (config.Config carries both) is a separate
	// change; internal/audit holds no config today.

	// Key rotations are recorded as audit events — the old query hit a
	// phantom `key_rotation_events` table (no migration creates it) and
	// always yielded the zero time with the error discarded.
	var lastRotation time.Time
	q.scan("last key rotation", &lastRotation, `
		SELECT COALESCE(MAX(timestamp), '1970-01-01'::timestamptz)
		FROM audit_events
		WHERE event_type = 'key_rotation' AND org_id = $1
	`, q.org())
	if err := q.failed(); err != nil {
		return CryptographyMetrics{}, err
	}
	metrics.LastKeyRotation = lastRotation

	if !metrics.TLSEnabled || metrics.TLSMinVersion < "1.2" {
		metrics.ComplianceStatus = "non_compliant"
	} else if !metrics.EncryptionAtRest {
		metrics.ComplianceStatus = "partial"
	}

	return metrics, nil
}

func (s *Service) getOperationalSecurityMetrics(ctx context.Context, startDate, endDate time.Time) (OperationalSecurityMetrics, error) {
	metrics := OperationalSecurityMetrics{
		EventsByType:     make(map[string]int),
		EventsByDay:      []DayEventCount{},
		ComplianceStatus: "compliant",
	}
	q := s.newMetricQuery(ctx)

	q.scan("total audit events", &metrics.TotalEvents, `
		SELECT COALESCE(COUNT(*), 0)
		FROM audit_events
		WHERE timestamp BETWEEN $1 AND $2
		AND org_id = $3
	`, startDate, endDate, q.org())

	q.scan("failed audit events", &metrics.FailedEvents, `
		SELECT COALESCE(COUNT(*), 0)
		FROM audit_events
		WHERE outcome = 'failure'
		AND timestamp BETWEEN $1 AND $2
		AND org_id = $3
	`, startDate, endDate, q.org())

	if err := q.failed(); err != nil {
		return OperationalSecurityMetrics{}, err
	}

	// The two grouped reads are the same defect in the multi-row shape: `if err
	// == nil` around the loop meant a failed query left EventsByDay empty, and
	// an empty EventsByDay is a LOGGING COVERAGE OF 0% -- the section then
	// reports "non_compliant" on the strength of a query that never ran.
	rows, err := s.db.Pool.Query(ctx, `
		SELECT event_type, COUNT(*)
		FROM audit_events
		WHERE timestamp BETWEEN $1 AND $2
		AND org_id = $3
		GROUP BY event_type
	`, startDate, endDate, q.org())
	if err != nil {
		return OperationalSecurityMetrics{}, fmt.Errorf("events by type: %w", err)
	}
	for rows.Next() {
		var eventType string
		var count int
		if err := rows.Scan(&eventType, &count); err != nil {
			rows.Close()
			return OperationalSecurityMetrics{}, fmt.Errorf("events by type: %w", err)
		}
		metrics.EventsByType[eventType] = count
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return OperationalSecurityMetrics{}, fmt.Errorf("events by type: %w", err)
	}

	rows, err = s.db.Pool.Query(ctx, `
		SELECT DATE(timestamp) as day, COUNT(*) as count
		FROM audit_events
		WHERE timestamp BETWEEN $1 AND $2
		AND org_id = $3
		GROUP BY DATE(timestamp)
		ORDER BY day
	`, startDate, endDate, q.org())
	if err != nil {
		return OperationalSecurityMetrics{}, fmt.Errorf("events by day: %w", err)
	}
	for rows.Next() {
		var day time.Time
		var count int
		if err := rows.Scan(&day, &count); err != nil {
			rows.Close()
			return OperationalSecurityMetrics{}, fmt.Errorf("events by day: %w", err)
		}
		metrics.EventsByDay = append(metrics.EventsByDay, DayEventCount{
			Date:  day.Format("2006-01-02"),
			Count: count,
		})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return OperationalSecurityMetrics{}, fmt.Errorf("events by day: %w", err)
	}

	if metrics.TotalEvents > 0 {
		metrics.ErrorRate = float64(metrics.FailedEvents) / float64(metrics.TotalEvents) * 100
	}

	totalDays := int(endDate.Sub(startDate).Hours()/24) + 1
	if totalDays > 0 {
		metrics.LoggingCoverage = float64(len(metrics.EventsByDay)) / float64(totalDays) * 100
	}

	if metrics.ErrorRate > 20 || metrics.LoggingCoverage < 80 {
		metrics.ComplianceStatus = "non_compliant"
	} else if metrics.ErrorRate > 10 || metrics.LoggingCoverage < 95 {
		metrics.ComplianceStatus = "partial"
	}

	return metrics, nil
}

func (s *Service) getDataAccessMetrics(ctx context.Context, startDate, endDate time.Time) (DataAccessMetrics, error) {
	metrics := DataAccessMetrics{
		AccessByActor:    make(map[string]int),
		AccessByDataType: make(map[string]int),
		ComplianceStatus: "compliant",
	}
	q := s.newMetricQuery(ctx)

	// event_type = 'data_access' is declared in service.go and written by
	// nothing, so these four queries counted zero on every report ever
	// generated. What this trail actually records as a read is an action
	// under event_type 'authorization' -- see DataAccessActions, which says
	// which five and why, and whose own test fails on a name nothing
	// writes. The event_type term stays for the day a writer adopts it.
	q.scan("total data-access events", &metrics.TotalAccessEvents, `
		SELECT COALESCE(COUNT(*), 0)
		FROM audit_events
		WHERE (event_type = 'data_access' OR action = ANY($4))
		AND timestamp BETWEEN $1 AND $2
		AND org_id = $3
	`, startDate, endDate, q.org(), DataAccessActions)

	q.scan("last data-access event", &metrics.LastAccessLog, `
		SELECT COALESCE(MAX(timestamp), '1970-01-01'::timestamp)
		FROM audit_events
		WHERE (event_type = 'data_access' OR action = ANY($2))
		AND org_id = $1
	`, q.org(), DataAccessActions)

	if err := q.failed(); err != nil {
		return DataAccessMetrics{}, err
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT actor_id, COUNT(*)
		FROM audit_events
		WHERE (event_type = 'data_access' OR action = ANY($4))
		AND timestamp BETWEEN $1 AND $2
		AND org_id = $3
		GROUP BY actor_id
		ORDER BY COUNT(*) DESC
		LIMIT 10
	`, startDate, endDate, q.org(), DataAccessActions)
	if err != nil {
		return DataAccessMetrics{}, fmt.Errorf("data access by actor: %w", err)
	}
	for rows.Next() {
		var actorID string
		var count int
		if err := rows.Scan(&actorID, &count); err != nil {
			rows.Close()
			return DataAccessMetrics{}, fmt.Errorf("data access by actor: %w", err)
		}
		metrics.AccessByActor[actorID] = count
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return DataAccessMetrics{}, fmt.Errorf("data access by actor: %w", err)
	}

	// audit_events describes what was acted on as (target_id, target_type);
	// it has no resource_type, which an earlier commit corrected here. That
	// was one reason this section was empty in every report and not the
	// reason: the predicate below matched no row either.
	rows, err = s.db.Pool.Query(ctx, `
		SELECT target_type, COUNT(*)
		FROM audit_events
		WHERE (event_type = 'data_access' OR action = ANY($4))
		AND timestamp BETWEEN $1 AND $2
		AND org_id = $3
		GROUP BY target_type
	`, startDate, endDate, q.org(), DataAccessActions)
	if err != nil {
		return DataAccessMetrics{}, fmt.Errorf("data access by data type: %w", err)
	}
	for rows.Next() {
		var resourceType string
		var count int
		if err := rows.Scan(&resourceType, &count); err != nil {
			rows.Close()
			return DataAccessMetrics{}, fmt.Errorf("data access by data type: %w", err)
		}
		metrics.AccessByDataType[resourceType] = count
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return DataAccessMetrics{}, fmt.Errorf("data access by data type: %w", err)
	}

	if metrics.TotalAccessEvents == 0 {
		metrics.ComplianceStatus = "partial"
	}

	return metrics, nil
}

func (s *Service) getConsentMetrics(ctx context.Context) (ConsentMetrics, error) {
	metrics := ConsentMetrics{
		ComplianceStatus: "compliant",
	}
	// This section had already grown its own version of metricQuery -- a local
	// closure collecting the first error, and a "unknown" compliance status --
	// after the same defect was found here: the old queries hit a phantom
	// `consent_records` table, every Scan error was discarded, and the zero
	// value forced non_compliant on every install regardless of real consent
	// state. The status is gone with the closure. One section reporting
	// "unknown" while the rest reported numbers still produced a document an
	// auditor would read as a report; a failed measurement now fails the whole
	// report, which is the only reading that cannot mislead.
	q := s.newMetricQuery(ctx)

	q.scan("consent records", &metrics.TotalConsentRecords,
		`SELECT COUNT(*) FROM user_consents WHERE org_id = $1`, q.org())
	q.scan("active consents", &metrics.ActiveConsents,
		`SELECT COUNT(*) FROM user_consents WHERE granted = true AND revoked_at IS NULL AND org_id = $1`, q.org())
	q.scan("withdrawn consents", &metrics.WithdrawnConsents,
		`SELECT COUNT(*) FROM user_consents WHERE revoked_at IS NOT NULL AND org_id = $1`, q.org())
	// user_consents has no pending state: a consent either exists
	// (granted/revoked) or does not.
	metrics.PendingConsents = 0

	var lastUpdate time.Time
	q.scan("last consent change", &lastUpdate, `
		SELECT COALESCE(MAX(COALESCE(revoked_at, granted_at, created_at)), '1970-01-01'::timestamptz)
		FROM user_consents WHERE org_id = $1`, q.org())
	metrics.LastConsentUpdate = lastUpdate

	if err := q.failed(); err != nil {
		return ConsentMetrics{}, err
	}

	if metrics.TotalConsentRecords == 0 {
		metrics.ComplianceStatus = "non_compliant"
	}

	return metrics, nil
}

func (s *Service) getDataSubjectRequestMetrics(ctx context.Context, startDate, endDate time.Time) (DataSubjectRequestMetrics, error) {
	metrics := DataSubjectRequestMetrics{
		RequestsByType:   make(map[string]int),
		ComplianceStatus: "compliant",
	}
	q := s.newMetricQuery(ctx)

	q.scan("data-subject requests", &metrics.TotalRequests, `
		SELECT COALESCE(COUNT(*), 0)
		FROM data_subject_requests
		WHERE created_at BETWEEN $1 AND $2
		AND org_id = $3
	`, startDate, endDate, q.org())

	q.scan("pending data-subject requests", &metrics.PendingRequests, `
		SELECT COALESCE(COUNT(*), 0)
		FROM data_subject_requests
		WHERE status = 'pending'
		AND created_at BETWEEN $1 AND $2
		AND org_id = $3
	`, startDate, endDate, q.org())

	q.scan("completed data-subject requests", &metrics.CompletedRequests, `
		SELECT COALESCE(COUNT(*), 0)
		FROM data_subject_requests
		WHERE status = 'completed'
		AND created_at BETWEEN $1 AND $2
		AND org_id = $3
	`, startDate, endDate, q.org())

	q.scan("overdue data-subject requests", &metrics.OverdueRequests, `
		SELECT COALESCE(COUNT(*), 0)
		FROM data_subject_requests
		WHERE status != 'completed'
		AND created_at < NOW() - INTERVAL '30 days'
		AND org_id = $1
	`, q.org())

	q.scan("average data-subject response time", &metrics.AverageResponseDays, `
		SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (completed_at - created_at)) / 86400.0), 0)
		FROM data_subject_requests
		WHERE status = 'completed'
		AND created_at BETWEEN $1 AND $2
		AND org_id = $3
	`, startDate, endDate, q.org())

	var lastReq time.Time
	q.scan("last data-subject request", &lastReq, `
		SELECT COALESCE(MAX(created_at), '1970-01-01'::timestamp)
		FROM data_subject_requests
		WHERE org_id = $1
	`, q.org())
	metrics.LastRequestDate = lastReq

	if err := q.failed(); err != nil {
		return DataSubjectRequestMetrics{}, err
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT request_type, COUNT(*)
		FROM data_subject_requests
		WHERE created_at BETWEEN $1 AND $2
		AND org_id = $3
		GROUP BY request_type
	`, startDate, endDate, q.org())
	if err != nil {
		return DataSubjectRequestMetrics{}, fmt.Errorf("data-subject requests by type: %w", err)
	}
	for rows.Next() {
		var reqType string
		var count int
		if err := rows.Scan(&reqType, &count); err != nil {
			rows.Close()
			return DataSubjectRequestMetrics{}, fmt.Errorf("data-subject requests by type: %w", err)
		}
		metrics.RequestsByType[reqType] = count
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return DataSubjectRequestMetrics{}, fmt.Errorf("data-subject requests by type: %w", err)
	}

	if metrics.OverdueRequests > 0 || metrics.AverageResponseDays > 30 {
		metrics.ComplianceStatus = "non_compliant"
	} else if metrics.PendingRequests > 10 {
		metrics.ComplianceStatus = "partial"
	}

	return metrics, nil
}

func (s *Service) getDataDeletionMetrics(ctx context.Context, startDate, endDate time.Time) (DataDeletionMetrics, error) {
	metrics := DataDeletionMetrics{
		ComplianceStatus: "compliant",
	}
	q := s.newMetricQuery(ctx)

	q.scan("deletion requests", &metrics.TotalDeletionRequests, `
		SELECT COALESCE(COUNT(*), 0)
		FROM data_subject_requests
		WHERE request_type = 'deletion'
		AND created_at BETWEEN $1 AND $2
		AND org_id = $3
	`, startDate, endDate, q.org())

	q.scan("completed deletions", &metrics.CompletedDeletions, `
		SELECT COALESCE(COUNT(*), 0)
		FROM data_subject_requests
		WHERE request_type = 'deletion'
		AND status = 'completed'
		AND created_at BETWEEN $1 AND $2
		AND org_id = $3
	`, startDate, endDate, q.org())

	q.scan("pending deletions", &metrics.PendingDeletions, `
		SELECT COALESCE(COUNT(*), 0)
		FROM data_subject_requests
		WHERE request_type = 'deletion'
		AND status = 'pending'
		AND org_id = $1
	`, q.org())

	q.scan("failed deletions", &metrics.FailedDeletions, `
		SELECT COALESCE(COUNT(*), 0)
		FROM data_subject_requests
		WHERE request_type = 'deletion'
		AND status = 'failed'
		AND org_id = $1
	`, q.org())

	q.scan("average deletion time", &metrics.AverageDeletionDays, `
		SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (completed_at - created_at)) / 86400.0), 0)
		FROM data_subject_requests
		WHERE request_type = 'deletion'
		AND status = 'completed'
		AND created_at BETWEEN $1 AND $2
		AND org_id = $3
	`, startDate, endDate, q.org())

	var lastDel time.Time
	q.scan("last completed deletion", &lastDel, `
		SELECT COALESCE(MAX(completed_at), '1970-01-01'::timestamp)
		FROM data_subject_requests
		WHERE request_type = 'deletion'
		AND status = 'completed'
		AND org_id = $1
	`, q.org())
	metrics.LastDeletionDate = lastDel

	if err := q.failed(); err != nil {
		return DataDeletionMetrics{}, err
	}

	if metrics.FailedDeletions > 0 || metrics.AverageDeletionDays > 30 {
		metrics.ComplianceStatus = "non_compliant"
	} else if metrics.PendingDeletions > 5 {
		metrics.ComplianceStatus = "partial"
	}

	return metrics, nil
}

func generateReportID() string {
	return fmt.Sprintf("report_%d", time.Now().UnixNano())
}

func determineComplianceStatus(value, compliantThreshold, partialThreshold float64) string {
	if value >= compliantThreshold {
		return "compliant"
	}
	if value >= partialThreshold {
		return "partial"
	}
	return "non_compliant"
}

// HTTP Handlers for standard (non-detailed) compliance reports

// handleGenerateGDPRReport handles POST requests to generate a standard GDPR compliance report
func (s *Service) handleGenerateGDPRReport(c *gin.Context) {
	var req struct {
		StartDate string `json:"start_date"`
		EndDate   string `json:"end_date"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}

	startDate, err := time.Parse("2006-01-02", req.StartDate)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid start_date format, expected YYYY-MM-DD"})
		return
	}

	endDate, err := time.Parse("2006-01-02", req.EndDate)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid end_date format, expected YYYY-MM-DD"})
		return
	}
	endDate = endDate.Add(24*time.Hour - time.Second)

	report, err := s.GenerateGDPRReport(c.Request.Context(), startDate, endDate, "system")
	if err != nil {
		s.logger.Error("Failed to generate GDPR report", zap.Error(err))
		c.JSON(500, gin.H{"error": "failed to generate report"})
		return
	}

	c.JSON(201, report)
}
