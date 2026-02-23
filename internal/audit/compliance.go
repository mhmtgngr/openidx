// Package audit provides compliance report generators for SOC2, ISO27001, and GDPR
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// SOC2Report represents a SOC 2 Type II compliance report
type SOC2Report struct {
	ReportID      string                   `json:"report_id"`
	PeriodStart   time.Time                `json:"period_start"`
	PeriodEnd     time.Time                `json:"period_end"`
	GeneratedAt   time.Time                `json:"generated_at"`
	GeneratedBy   string                   `json:"generated_by"`
	AccessReviews AccessReviewMetrics      `json:"access_reviews"`
	PasswordPolicy PasswordPolicyMetrics   `json:"password_policy"`
	MFAAdoption   MFAAdoptionMetrics       `json:"mfa_adoption"`
	SessionMgmt   SessionManagementMetrics `json:"session_management"`
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
	MinLength            int     `json:"min_length"`
	RequireUppercase     bool    `json:"require_uppercase"`
	RequireLowercase     bool    `json:"require_lowercase"`
	RequireNumbers       bool    `json:"require_numbers"`
	RequireSpecialChars  bool    `json:"require_special_chars"`
	MaxAgeDays           int     `json:"max_age_days"`
	UsersWithWeakPasswords int    `json:"users_with_weak_passwords"`
	ComplianceStatus     string  `json:"compliance_status"`
}

// MFAAdoptionMetrics tracks MFA adoption
type MFAAdoptionMetrics struct {
	TotalUsers       int       `json:"total_users"`
	UsersWithMFA     int       `json:"users_with_mfa"`
	UsersWithTOTP    int       `json:"users_with_totp"`
	UsersWithWebAuthn int       `json:"users_with_webauthn"`
	AdoptionRate     float64   `json:"adoption_rate"`
	LastUpdated      time.Time `json:"last_updated"`
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
	ReportID            string                      `json:"report_id"`
	PeriodStart         time.Time                   `json:"period_start"`
	PeriodEnd           time.Time                   `json:"period_end"`
	GeneratedAt         time.Time                   `json:"generated_at"`
	GeneratedBy         string                      `json:"generated_by"`
	AccessControl       AccessControlMetrics        `json:"access_control"`
	Cryptography        CryptographyMetrics         `json:"cryptography"`
	OperationalSecurity OperationalSecurityMetrics `json:"operational_security"`
}

// AccessControlMetrics for ISO 27001 A.9
type AccessControlMetrics struct {
	TotalUsers      int       `json:"total_users"`
	AdminUsers      int       `json:"admin_users"`
	AdminRatio      float64   `json:"admin_ratio"`
	RolesDefined    int       `json:"roles_defined"`
	GroupsDefined   int       `json:"groups_defined"`
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
	TotalEvents      int               `json:"total_events"`
	EventsByType     map[string]int     `json:"events_by_type"`
	EventsByDay      []DayEventCount    `json:"events_by_day"`
	FailedEvents     int               `json:"failed_events"`
	ErrorRate        float64           `json:"error_rate"`
	LoggingCoverage  float64           `json:"logging_coverage"`
	ComplianceStatus string            `json:"compliance_status"`
}

// DayEventCount tracks events per day
type DayEventCount struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

// GDPRReport represents a GDPR compliance report
type GDPRReport struct {
	ReportID            string                     `json:"report_id"`
	PeriodStart         time.Time                  `json:"period_start"`
	PeriodEnd           time.Time                  `json:"period_end"`
	GeneratedAt         time.Time                  `json:"generated_at"`
	GeneratedBy         string                     `json:"generated_by"`
	DataAccessLogs      DataAccessMetrics          `json:"data_access_logs"`
	ConsentRecords      ConsentMetrics             `json:"consent_records"`
	DataSubjectRequests DataSubjectRequestMetrics  `json:"data_subject_requests"`
	DataDeletionRecords DataDeletionMetrics       `json:"data_deletion_records"`
}

// DataAccessMetrics tracks data access for GDPR Art.30
type DataAccessMetrics struct {
	TotalAccessEvents int               `json:"total_access_events"`
	AccessByActor    map[string]int     `json:"access_by_actor"`
	AccessByDataType map[string]int     `json:"access_by_data_type"`
	LastAccessLog    time.Time          `json:"last_access_log"`
	ComplianceStatus string            `json:"compliance_status"`
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
	TotalRequests       int               `json:"total_requests"`
	RequestsByType      map[string]int     `json:"requests_by_type"`
	PendingRequests     int               `json:"pending_requests"`
	CompletedRequests   int               `json:"completed_requests"`
	OverdueRequests     int               `json:"overdue_requests"`
	AverageResponseDays float64           `json:"average_response_days"`
	LastRequestDate     time.Time          `json:"last_request_date"`
	ComplianceStatus    string            `json:"compliance_status"`
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

	// Gather metrics
	report.AccessReviews = s.getAccessReviewMetrics(ctx, startDate, endDate)
	report.PasswordPolicy = s.getPasswordPolicyMetrics(ctx)
	report.MFAAdoption = s.getMFAMetrics(ctx)
	report.SessionMgmt = s.getSessionManagementMetrics(ctx)

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

	report.AccessControl = s.getISOAccessControlMetrics(ctx, startDate, endDate)
	report.Cryptography = s.getCryptographyMetrics(ctx)
	report.OperationalSecurity = s.getOperationalSecurityMetrics(ctx, startDate, endDate)

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

	report.DataAccessLogs = s.getDataAccessMetrics(ctx, startDate, endDate)
	report.ConsentRecords = s.getConsentMetrics(ctx)
	report.DataSubjectRequests = s.getDataSubjectRequestMetrics(ctx, startDate, endDate)
	report.DataDeletionRecords = s.getDataDeletionMetrics(ctx, startDate, endDate)

	return report, nil
}

// Metric gathering methods

func (s *Service) getAccessReviewMetrics(ctx context.Context, startDate, endDate time.Time) AccessReviewMetrics {
	metrics := AccessReviewMetrics{}

	if s.db != nil && s.db.Pool != nil {
		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(COUNT(*), 0)
			FROM access_reviews
			WHERE created_at BETWEEN $1 AND $2
		`, startDate, endDate).Scan(&metrics.TotalReviews)

		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(COUNT(*), 0)
			FROM access_reviews
			WHERE status = 'pending'
		`).Scan(&metrics.PendingReviews)

		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(COUNT(*), 0)
			FROM access_reviews
			WHERE status = 'completed'
			AND completed_at BETWEEN $1 AND $2
		`, startDate, endDate).Scan(&metrics.CompletedReviews)

		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(COUNT(*), 0)
			FROM access_reviews
			WHERE status = 'pending' AND due_date < NOW()
		`).Scan(&metrics.OverdueReviews)

		var lastReview time.Time
		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(MAX(completed_at), '1970-01-01'::timestamp)
			FROM access_reviews
			WHERE status = 'completed'
		`).Scan(&lastReview)
		metrics.LastReviewDate = lastReview
	}

	if metrics.TotalReviews > 0 {
		metrics.CompletionRate = float64(metrics.CompletedReviews) / float64(metrics.TotalReviews) * 100
	}

	metrics.ComplianceStatus = determineComplianceStatus(metrics.CompletionRate, 80, 50)

	return metrics
}

func (s *Service) getPasswordPolicyMetrics(ctx context.Context) PasswordPolicyMetrics {
	metrics := PasswordPolicyMetrics{
		MinLength:            8,
		RequireUppercase:     true,
		RequireLowercase:     true,
		RequireNumbers:       true,
		RequireSpecialChars:  true,
		MaxAgeDays:           90,
		ComplianceStatus:     "compliant",
	}

	if s.db != nil && s.db.Pool != nil {
		var settingsJSON []byte
		err := s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(value::text, '{}')
			FROM system_settings
			WHERE key = 'security'
		`).Scan(&settingsJSON)

		if err == nil && len(settingsJSON) > 0 {
			var secSettings map[string]interface{}
			if json.Unmarshal(settingsJSON, &secSettings) == nil {
				if pp, ok := secSettings["password_policy"].(map[string]interface{}); ok {
					if ml, ok := pp["min_length"].(float64); ok {
						metrics.MinLength = int(ml)
					}
					if uc, ok := pp["require_uppercase"].(bool); ok {
						metrics.RequireUppercase = uc
					}
					if lc, ok := pp["require_lowercase"].(bool); ok {
						metrics.RequireLowercase = lc
					}
					if num, ok := pp["require_numbers"].(bool); ok {
						metrics.RequireNumbers = num
					}
					if sc, ok := pp["require_special_chars"].(bool); ok {
						metrics.RequireSpecialChars = sc
					}
					if ma, ok := pp["max_age_days"].(float64); ok {
						metrics.MaxAgeDays = int(ma)
					}
				}
			}
		}

		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(COUNT(*), 0)
			FROM users
			WHERE enabled = true
			AND CHAR_LENGTH(password_hash) < 50
		`).Scan(&metrics.UsersWithWeakPasswords)
	}

	if metrics.MinLength < 8 || !metrics.RequireNumbers {
		metrics.ComplianceStatus = "non_compliant"
	} else if metrics.UsersWithWeakPasswords > 0 {
		metrics.ComplianceStatus = "partial"
	}

	return metrics
}

func (s *Service) getMFAMetrics(ctx context.Context) MFAAdoptionMetrics {
	metrics := MFAAdoptionMetrics{
		ComplianceStatus: "non_compliant",
		LastUpdated:      time.Now().UTC(),
	}

	if s.db != nil && s.db.Pool != nil {
		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(COUNT(*), 0)
			FROM users
			WHERE enabled = true
		`).Scan(&metrics.TotalUsers)

		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(COUNT(DISTINCT user_id), 0)
			FROM mfa_totp
			WHERE enabled = true
		`).Scan(&metrics.UsersWithTOTP)

		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(COUNT(DISTINCT user_id), 0)
			FROM webauthn_credentials
		`).Scan(&metrics.UsersWithWebAuthn)

		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(COUNT(DISTINCT user_id), 0) FROM (
				SELECT user_id FROM mfa_totp WHERE enabled = true
				UNION
				SELECT user_id FROM webauthn_credentials
			) mfa
		`).Scan(&metrics.UsersWithMFA)
	}

	if metrics.TotalUsers > 0 {
		metrics.AdoptionRate = float64(metrics.UsersWithMFA) / float64(metrics.TotalUsers) * 100
	}

	metrics.ComplianceStatus = determineComplianceStatus(metrics.AdoptionRate, 80, 50)

	return metrics
}

func (s *Service) getSessionManagementMetrics(ctx context.Context) SessionManagementMetrics {
	metrics := SessionManagementMetrics{
		ComplianceStatus:  "compliant",
		LastActivityCheck: time.Now().UTC(),
	}

	if s.db != nil && s.db.Pool != nil {
		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(COUNT(*), 0)
			FROM sessions
			WHERE expires_at > NOW()
		`).Scan(&metrics.ActiveSessions)

		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (expires_at - created_at)) / 3600.0), 0)
			FROM sessions
			WHERE created_at > NOW() - INTERVAL '30 days'
		`).Scan(&metrics.AverageSessionHours)

		var settingsJSON []byte
		err := s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(value::text, '{}')
			FROM system_settings
			WHERE key = 'security'
		`).Scan(&settingsJSON)

		if err == nil && len(settingsJSON) > 0 {
			var secSettings map[string]interface{}
			if json.Unmarshal(settingsJSON, &secSettings) == nil {
				if st, ok := secSettings["session_timeout"].(float64); ok {
					metrics.SessionTimeoutMins = int(st)
				}
				if it, ok := secSettings["idle_timeout"].(float64); ok {
					metrics.IdleTimeoutMins = int(it)
				}
			}
		}
	}

	if metrics.SessionTimeoutMins == 0 {
		metrics.ComplianceStatus = "non_compliant"
	} else if metrics.SessionTimeoutMins > 480 || metrics.AverageSessionHours > 24 {
		metrics.ComplianceStatus = "partial"
	}

	return metrics
}

func (s *Service) getISOAccessControlMetrics(ctx context.Context, startDate, endDate time.Time) AccessControlMetrics {
	metrics := AccessControlMetrics{
		ComplianceStatus: "compliant",
	}

	if s.db != nil && s.db.Pool != nil {
		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(COUNT(*), 0)
			FROM users
			WHERE enabled = true
		`).Scan(&metrics.TotalUsers)

		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(COUNT(DISTINCT ur.user_id), 0)
			FROM user_roles ur
			JOIN roles r ON ur.role_id = r.id
			WHERE r.name IN ('admin', 'super_admin')
			AND ur.user_id IN (SELECT id FROM users WHERE enabled = true)
		`).Scan(&metrics.AdminUsers)

		if metrics.TotalUsers > 0 {
			metrics.AdminRatio = float64(metrics.AdminUsers) / float64(metrics.TotalUsers) * 100
		}

		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(COUNT(*), 0)
			FROM roles
		`).Scan(&metrics.RolesDefined)

		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(COUNT(*), 0)
			FROM groups
		`).Scan(&metrics.GroupsDefined)

		var lastReview time.Time
		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(MAX(completed_at), '1970-01-01'::timestamp)
			FROM access_reviews
			WHERE status = 'completed'
		`).Scan(&lastReview)
		metrics.LastAccessReview = lastReview
	}

	if metrics.AdminRatio > 20 {
		metrics.ComplianceStatus = "partial"
	}
	if metrics.RolesDefined < 3 {
		metrics.ComplianceStatus = "non_compliant"
	}

	return metrics
}

func (s *Service) getCryptographyMetrics(ctx context.Context) CryptographyMetrics {
	metrics := CryptographyMetrics{
		TLSEnabled:         true,
		TLSMinVersion:      "1.2",
		EncryptionAtRest:   true,
		KeyRotationEnabled: true,
		ComplianceStatus:   "compliant",
	}

	if s.db != nil && s.db.Pool != nil {
		var settingsJSON []byte
		err := s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(value::text, '{}')
			FROM system_settings
			WHERE key = 'security'
		`).Scan(&settingsJSON)

		if err == nil && len(settingsJSON) > 0 {
			var secSettings map[string]interface{}
			if json.Unmarshal(settingsJSON, &secSettings) == nil {
				if tls, ok := secSettings["tls_enabled"].(bool); ok {
					metrics.TLSEnabled = tls
				}
				if mv, ok := secSettings["tls_min_version"].(string); ok {
					metrics.TLSMinVersion = mv
				}
				if enc, ok := secSettings["encryption_at_rest"].(bool); ok {
					metrics.EncryptionAtRest = enc
				}
				if kr, ok := secSettings["key_rotation_enabled"].(bool); ok {
					metrics.KeyRotationEnabled = kr
				}
			}
		}

		var lastRotation time.Time
		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(MAX(created_at), '1970-01-01'::timestamp)
			FROM key_rotation_events
			WHERE status = 'completed'
		`).Scan(&lastRotation)
		metrics.LastKeyRotation = lastRotation
	}

	if !metrics.TLSEnabled || metrics.TLSMinVersion < "1.2" {
		metrics.ComplianceStatus = "non_compliant"
	} else if !metrics.EncryptionAtRest {
		metrics.ComplianceStatus = "partial"
	}

	return metrics
}

func (s *Service) getOperationalSecurityMetrics(ctx context.Context, startDate, endDate time.Time) OperationalSecurityMetrics {
	metrics := OperationalSecurityMetrics{
		EventsByType:     make(map[string]int),
		EventsByDay:      []DayEventCount{},
		ComplianceStatus: "compliant",
	}

	if s.db != nil && s.db.Pool != nil {
		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(COUNT(*), 0)
			FROM audit_events
			WHERE timestamp BETWEEN $1 AND $2
		`, startDate, endDate).Scan(&metrics.TotalEvents)

		rows, err := s.db.Pool.Query(ctx, `
			SELECT event_type, COUNT(*)
			FROM audit_events
			WHERE timestamp BETWEEN $1 AND $2
			GROUP BY event_type
		`, startDate, endDate)
		if err == nil {
			for rows.Next() {
				var eventType string
				var count int
				if rows.Scan(&eventType, &count) == nil {
					metrics.EventsByType[eventType] = count
				}
			}
			rows.Close()
		}

		rows, err = s.db.Pool.Query(ctx, `
			SELECT DATE(timestamp) as day, COUNT(*) as count
			FROM audit_events
			WHERE timestamp BETWEEN $1 AND $2
			GROUP BY DATE(timestamp)
			ORDER BY day
		`, startDate, endDate)
		if err == nil {
			for rows.Next() {
				var day time.Time
				var count int
				if rows.Scan(&day, &count) == nil {
					metrics.EventsByDay = append(metrics.EventsByDay, DayEventCount{
						Date:  day.Format("2006-01-02"),
						Count: count,
					})
				}
			}
			rows.Close()
		}

		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(COUNT(*), 0)
			FROM audit_events
			WHERE outcome = 'failure'
			AND timestamp BETWEEN $1 AND $2
		`, startDate, endDate).Scan(&metrics.FailedEvents)
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

	return metrics
}

func (s *Service) getDataAccessMetrics(ctx context.Context, startDate, endDate time.Time) DataAccessMetrics {
	metrics := DataAccessMetrics{
		AccessByActor:    make(map[string]int),
		AccessByDataType: make(map[string]int),
		ComplianceStatus: "compliant",
	}

	if s.db != nil && s.db.Pool != nil {
		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(COUNT(*), 0)
			FROM audit_events
			WHERE event_type = 'data_access'
			AND timestamp BETWEEN $1 AND $2
		`, startDate, endDate).Scan(&metrics.TotalAccessEvents)

		rows, err := s.db.Pool.Query(ctx, `
			SELECT actor_id, COUNT(*)
			FROM audit_events
			WHERE event_type = 'data_access'
			AND timestamp BETWEEN $1 AND $2
			GROUP BY actor_id
			ORDER BY COUNT(*) DESC
			LIMIT 10
		`, startDate, endDate)
		if err == nil {
			for rows.Next() {
				var actorID string
				var count int
				if rows.Scan(&actorID, &count) == nil {
					metrics.AccessByActor[actorID] = count
				}
			}
			rows.Close()
		}

		rows, err = s.db.Pool.Query(ctx, `
			SELECT resource_type, COUNT(*)
			FROM audit_events
			WHERE event_type = 'data_access'
			AND timestamp BETWEEN $1 AND $2
			GROUP BY resource_type
		`, startDate, endDate)
		if err == nil {
			for rows.Next() {
				var resourceType string
				var count int
				if rows.Scan(&resourceType, &count) == nil {
					metrics.AccessByDataType[resourceType] = count
				}
			}
			rows.Close()
		}

		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(MAX(timestamp), '1970-01-01'::timestamp)
			FROM audit_events
			WHERE event_type = 'data_access'
		`).Scan(&metrics.LastAccessLog)
	}

	if metrics.TotalAccessEvents == 0 {
		metrics.ComplianceStatus = "partial"
	}

	return metrics
}

func (s *Service) getConsentMetrics(ctx context.Context) ConsentMetrics {
	metrics := ConsentMetrics{
		ComplianceStatus: "compliant",
	}

	if s.db != nil && s.db.Pool != nil {
		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(COUNT(*), 0)
			FROM consent_records
		`).Scan(&metrics.TotalConsentRecords)

		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(COUNT(*), 0)
			FROM consent_records
			WHERE status = 'active'
		`).Scan(&metrics.ActiveConsents)

		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(COUNT(*), 0)
			FROM consent_records
			WHERE status = 'withdrawn'
		`).Scan(&metrics.WithdrawnConsents)

		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(COUNT(*), 0)
			FROM consent_records
			WHERE status = 'pending'
		`).Scan(&metrics.PendingConsents)

		var lastUpdate time.Time
		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(MAX(updated_at), '1970-01-01'::timestamp)
			FROM consent_records
		`).Scan(&lastUpdate)
		metrics.LastConsentUpdate = lastUpdate
	}

	if metrics.TotalConsentRecords == 0 {
		metrics.ComplianceStatus = "non_compliant"
	} else if metrics.PendingConsents > 0 {
		metrics.ComplianceStatus = "partial"
	}

	return metrics
}

func (s *Service) getDataSubjectRequestMetrics(ctx context.Context, startDate, endDate time.Time) DataSubjectRequestMetrics {
	metrics := DataSubjectRequestMetrics{
		RequestsByType:    make(map[string]int),
		ComplianceStatus:  "compliant",
	}

	if s.db != nil && s.db.Pool != nil {
		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(COUNT(*), 0)
			FROM data_subject_requests
			WHERE created_at BETWEEN $1 AND $2
		`, startDate, endDate).Scan(&metrics.TotalRequests)

		rows, err := s.db.Pool.Query(ctx, `
			SELECT request_type, COUNT(*)
			FROM data_subject_requests
			WHERE created_at BETWEEN $1 AND $2
			GROUP BY request_type
		`, startDate, endDate)
		if err == nil {
			for rows.Next() {
				var reqType string
				var count int
				if rows.Scan(&reqType, &count) == nil {
					metrics.RequestsByType[reqType] = count
				}
			}
			rows.Close()
		}

		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(COUNT(*), 0)
			FROM data_subject_requests
			WHERE status = 'pending'
			AND created_at BETWEEN $1 AND $2
		`, startDate, endDate).Scan(&metrics.PendingRequests)

		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(COUNT(*), 0)
			FROM data_subject_requests
			WHERE status = 'completed'
			AND created_at BETWEEN $1 AND $2
		`, startDate, endDate).Scan(&metrics.CompletedRequests)

		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(COUNT(*), 0)
			FROM data_subject_requests
			WHERE status != 'completed'
			AND created_at < NOW() - INTERVAL '30 days'
		`).Scan(&metrics.OverdueRequests)

		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (completed_at - created_at)) / 86400.0), 0)
			FROM data_subject_requests
			WHERE status = 'completed'
			AND created_at BETWEEN $1 AND $2
		`, startDate, endDate).Scan(&metrics.AverageResponseDays)

		var lastReq time.Time
		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(MAX(created_at), '1970-01-01'::timestamp)
			FROM data_subject_requests
		`).Scan(&lastReq)
		metrics.LastRequestDate = lastReq
	}

	if metrics.OverdueRequests > 0 || metrics.AverageResponseDays > 30 {
		metrics.ComplianceStatus = "non_compliant"
	} else if metrics.PendingRequests > 10 {
		metrics.ComplianceStatus = "partial"
	}

	return metrics
}

func (s *Service) getDataDeletionMetrics(ctx context.Context, startDate, endDate time.Time) DataDeletionMetrics {
	metrics := DataDeletionMetrics{
		ComplianceStatus: "compliant",
	}

	if s.db != nil && s.db.Pool != nil {
		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(COUNT(*), 0)
			FROM data_subject_requests
			WHERE request_type = 'deletion'
			AND created_at BETWEEN $1 AND $2
		`, startDate, endDate).Scan(&metrics.TotalDeletionRequests)

		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(COUNT(*), 0)
			FROM data_subject_requests
			WHERE request_type = 'deletion'
			AND status = 'completed'
			AND created_at BETWEEN $1 AND $2
		`, startDate, endDate).Scan(&metrics.CompletedDeletions)

		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(COUNT(*), 0)
			FROM data_subject_requests
			WHERE request_type = 'deletion'
			AND status = 'pending'
		`).Scan(&metrics.PendingDeletions)

		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(COUNT(*), 0)
			FROM data_subject_requests
			WHERE request_type = 'deletion'
			AND status = 'failed'
		`).Scan(&metrics.FailedDeletions)

		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (completed_at - created_at)) / 86400.0), 0)
			FROM data_subject_requests
			WHERE request_type = 'deletion'
			AND status = 'completed'
			AND created_at BETWEEN $1 AND $2
		`, startDate, endDate).Scan(&metrics.AverageDeletionDays)

		var lastDel time.Time
		s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(MAX(completed_at), '1970-01-01'::timestamp)
			FROM data_subject_requests
			WHERE request_type = 'deletion'
			AND status = 'completed'
		`).Scan(&lastDel)
		metrics.LastDeletionDate = lastDel
	}

	if metrics.FailedDeletions > 0 || metrics.AverageDeletionDays > 30 {
		metrics.ComplianceStatus = "non_compliant"
	} else if metrics.PendingDeletions > 5 {
		metrics.ComplianceStatus = "partial"
	}

	return metrics
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

// handleGenerateSOC2Report handles POST requests to generate a standard SOC 2 compliance report
func (s *Service) handleGenerateSOC2Report(c *gin.Context) {
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

	report, err := s.GenerateSOC2Report(c.Request.Context(), startDate, endDate, "system")
	if err != nil {
		s.logger.Error("Failed to generate SOC 2 report", zap.Error(err))
		c.JSON(500, gin.H{"error": "failed to generate report"})
		return
	}

	c.JSON(201, report)
}

// handleGenerateISO27001Report handles POST requests to generate a standard ISO 27001 compliance report
func (s *Service) handleGenerateISO27001Report(c *gin.Context) {
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

	report, err := s.GenerateISO27001Report(c.Request.Context(), startDate, endDate, "system")
	if err != nil {
		s.logger.Error("Failed to generate ISO 27001 report", zap.Error(err))
		c.JSON(500, gin.H{"error": "failed to generate report"})
		return
	}

	c.JSON(201, report)
}

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
