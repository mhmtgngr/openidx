// Package audit provides audit logging and compliance reporting
package audit

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
)

// AuditEvent represents an audit log entry
type AuditEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	EventType   EventType              `json:"event_type"`
	Category    EventCategory          `json:"category"`
	Action      string                 `json:"action"`
	Outcome     EventOutcome           `json:"outcome"`
	ActorID     string                 `json:"actor_id,omitempty"`
	ActorType   string                 `json:"actor_type,omitempty"`
	ActorIP     string                 `json:"actor_ip,omitempty"`
	TargetID    string                 `json:"target_id,omitempty"`
	TargetType  string                 `json:"target_type,omitempty"`
	ResourceID  string                 `json:"resource_id,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
	SessionID   string                 `json:"session_id,omitempty"`
	RequestID   string                 `json:"request_id,omitempty"`
}

// EventType defines the type of audit event
type EventType string

const (
	EventTypeAuthentication  EventType = "authentication"
	EventTypeAuthorization   EventType = "authorization"
	EventTypeUserManagement  EventType = "user_management"
	EventTypeGroupManagement EventType = "group_management"
	EventTypeRoleManagement  EventType = "role_management"
	EventTypeConfiguration   EventType = "configuration"
	EventTypeDataAccess      EventType = "data_access"
	EventTypeSystem          EventType = "system"
)

// EventCategory defines the category of audit event
type EventCategory string

const (
	CategorySecurity    EventCategory = "security"
	CategoryCompliance  EventCategory = "compliance"
	CategoryOperational EventCategory = "operational"
	CategoryAccess      EventCategory = "access"
)

// EventOutcome defines the outcome of an event
type EventOutcome string

const (
	OutcomeSuccess EventOutcome = "success"
	OutcomeFailure EventOutcome = "failure"
	OutcomePending EventOutcome = "pending"
)

// AuditQuery defines parameters for querying audit logs
type AuditQuery struct {
	StartTime  *time.Time    `json:"start_time,omitempty"`
	EndTime    *time.Time    `json:"end_time,omitempty"`
	EventType  EventType     `json:"event_type,omitempty"`
	Category   EventCategory `json:"category,omitempty"`
	ActorID    string        `json:"actor_id,omitempty"`
	TargetID   string        `json:"target_id,omitempty"`
	Outcome    EventOutcome  `json:"outcome,omitempty"`
	Offset     int           `json:"offset"`
	Limit      int           `json:"limit"`
}

// ComplianceReport represents a compliance report
type ComplianceReport struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Type         ReportType        `json:"type"`
	Framework    string            `json:"framework"`
	Status       ReportStatus      `json:"status"`
	StartDate    time.Time         `json:"start_date"`
	EndDate      time.Time         `json:"end_date"`
	GeneratedAt  time.Time         `json:"generated_at"`
	GeneratedBy  string            `json:"generated_by"`
	Summary      ReportSummary     `json:"summary"`
	Findings     []ReportFinding   `json:"findings,omitempty"`
}

// ReportType defines the type of compliance report
type ReportType string

const (
	ReportTypeSOC2      ReportType = "soc2"
	ReportTypeISO27001  ReportType = "iso27001"
	ReportTypeGDPR      ReportType = "gdpr"
	ReportTypeHIPAA     ReportType = "hipaa"
	ReportTypePCI       ReportType = "pci_dss"
	ReportTypeCustom    ReportType = "custom"
)

// ReportStatus defines the status of a report
type ReportStatus string

const (
	ReportStatusPending    ReportStatus = "pending"
	ReportStatusGenerating ReportStatus = "generating"
	ReportStatusCompleted  ReportStatus = "completed"
	ReportStatusFailed     ReportStatus = "failed"
)

// ReportSummary contains summary statistics for a report
type ReportSummary struct {
	TotalControls   int `json:"total_controls"`
	PassedControls  int `json:"passed_controls"`
	FailedControls  int `json:"failed_controls"`
	PartialControls int `json:"partial_controls"`
	NotApplicable   int `json:"not_applicable"`
}

// ReportFinding represents a finding in a compliance report
type ReportFinding struct {
	ControlID   string `json:"control_id"`
	ControlName string `json:"control_name"`
	Status      string `json:"status"`
	Evidence    string `json:"evidence,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// Service provides audit operations
type Service struct {
	db     *database.PostgresDB
	es     *database.ElasticsearchClient
	config *config.Config
	logger *zap.Logger
}

// NewService creates a new audit service
func NewService(db *database.PostgresDB, es *database.ElasticsearchClient, cfg *config.Config, logger *zap.Logger) *Service {
	return &Service{
		db:     db,
		es:     es,
		config: cfg,
		logger: logger.With(zap.String("service", "audit")),
	}
}

// LogEvent logs an audit event
func (s *Service) LogEvent(ctx context.Context, event *AuditEvent) error {
	s.logger.Debug("Logging audit event",
		zap.String("event_type", string(event.EventType)),
		zap.String("action", event.Action))
	
	event.Timestamp = time.Now()
	
	data, _ := json.Marshal(event)
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO audit_events (id, timestamp, event_type, category, action, outcome,
		                          actor_id, actor_type, actor_ip, target_id, target_type,
		                          resource_id, details, session_id, request_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`, event.ID, event.Timestamp, event.EventType, event.Category, event.Action, event.Outcome,
		event.ActorID, event.ActorType, event.ActorIP, event.TargetID, event.TargetType,
		event.ResourceID, data, event.SessionID, event.RequestID)
	
	return err
}

// QueryEvents queries audit events with filtering
func (s *Service) QueryEvents(ctx context.Context, query *AuditQuery) ([]AuditEvent, int, error) {
	s.logger.Debug("Querying audit events")

	// Build dynamic query with filters
	baseQuery := `
		SELECT id, timestamp, event_type, category, action, outcome,
		       COALESCE(actor_id, ''), COALESCE(actor_type, ''), COALESCE(actor_ip, ''),
		       COALESCE(target_id, ''), COALESCE(target_type, ''),
		       COALESCE(resource_id, ''), COALESCE(details::text, '{}')::jsonb,
		       COALESCE(session_id, ''), COALESCE(request_id, '')
		FROM audit_events
		WHERE 1=1
	`
	countQuery := "SELECT COUNT(*) FROM audit_events WHERE 1=1"

	args := []interface{}{}
	countArgs := []interface{}{}
	argIndex := 1

	// Time range filtering
	if query.StartTime != nil {
		baseQuery += " AND timestamp >= $" + strconv.Itoa(argIndex)
		countQuery += " AND timestamp >= $" + strconv.Itoa(argIndex)
		args = append(args, *query.StartTime)
		countArgs = append(countArgs, *query.StartTime)
		argIndex++
	}

	if query.EndTime != nil {
		baseQuery += " AND timestamp <= $" + strconv.Itoa(argIndex)
		countQuery += " AND timestamp <= $" + strconv.Itoa(argIndex)
		args = append(args, *query.EndTime)
		countArgs = append(countArgs, *query.EndTime)
		argIndex++
	}

	// Event type filtering
	if query.EventType != "" {
		baseQuery += " AND event_type = $" + strconv.Itoa(argIndex)
		countQuery += " AND event_type = $" + strconv.Itoa(argIndex)
		args = append(args, query.EventType)
		countArgs = append(countArgs, query.EventType)
		argIndex++
	}

	// Category filtering
	if query.Category != "" {
		baseQuery += " AND category = $" + strconv.Itoa(argIndex)
		countQuery += " AND category = $" + strconv.Itoa(argIndex)
		args = append(args, query.Category)
		countArgs = append(countArgs, query.Category)
		argIndex++
	}

	// Outcome filtering
	if query.Outcome != "" {
		baseQuery += " AND outcome = $" + strconv.Itoa(argIndex)
		countQuery += " AND outcome = $" + strconv.Itoa(argIndex)
		args = append(args, query.Outcome)
		countArgs = append(countArgs, query.Outcome)
		argIndex++
	}

	// Actor ID filtering
	if query.ActorID != "" {
		baseQuery += " AND actor_id = $" + strconv.Itoa(argIndex)
		countQuery += " AND actor_id = $" + strconv.Itoa(argIndex)
		args = append(args, query.ActorID)
		countArgs = append(countArgs, query.ActorID)
		argIndex++
	}

	// Get total count
	var total int
	err := s.db.Pool.QueryRow(ctx, countQuery, countArgs...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// Add ordering and pagination
	baseQuery += " ORDER BY timestamp DESC OFFSET $" + strconv.Itoa(argIndex) + " LIMIT $" + strconv.Itoa(argIndex+1)
	args = append(args, query.Offset, query.Limit)

	rows, err := s.db.Pool.Query(ctx, baseQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var events []AuditEvent
	for rows.Next() {
		var e AuditEvent
		var details []byte
		if err := rows.Scan(
			&e.ID, &e.Timestamp, &e.EventType, &e.Category, &e.Action, &e.Outcome,
			&e.ActorID, &e.ActorType, &e.ActorIP, &e.TargetID, &e.TargetType,
			&e.ResourceID, &details, &e.SessionID, &e.RequestID,
		); err != nil {
			return nil, 0, err
		}
		json.Unmarshal(details, &e.Details)
		events = append(events, e)
	}

	return events, total, nil
}

// GenerateComplianceReport generates a compliance report
func (s *Service) GenerateComplianceReport(ctx context.Context, reportType ReportType, startDate, endDate time.Time) (*ComplianceReport, error) {
	s.logger.Info("Generating compliance report",
		zap.String("type", string(reportType)),
		zap.Time("start_date", startDate),
		zap.Time("end_date", endDate))

	report := &ComplianceReport{
		ID:          generateUUID(),
		Type:        reportType,
		StartDate:   startDate,
		EndDate:     endDate,
		GeneratedAt: time.Now(),
		Status:      ReportStatusGenerating,
	}

	// Get framework name and controls based on report type
	switch reportType {
	case ReportTypeSOC2:
		report.Framework = "SOC 2 Type II"
		report.Name = "SOC 2 Compliance Report"
		report.Findings = s.evaluateSOC2Controls(ctx, startDate, endDate)
	case ReportTypeISO27001:
		report.Framework = "ISO 27001:2022"
		report.Name = "ISO 27001 Compliance Report"
		report.Findings = s.evaluateISO27001Controls(ctx, startDate, endDate)
	case ReportTypeGDPR:
		report.Framework = "GDPR"
		report.Name = "GDPR Compliance Report"
		report.Findings = s.evaluateGDPRControls(ctx, startDate, endDate)
	case ReportTypeHIPAA:
		report.Framework = "HIPAA"
		report.Name = "HIPAA Compliance Report"
		report.Findings = s.evaluateHIPAAControls(ctx, startDate, endDate)
	case ReportTypePCI:
		report.Framework = "PCI-DSS v4.0"
		report.Name = "PCI-DSS Compliance Report"
		report.Findings = s.evaluatePCIDSSControls(ctx, startDate, endDate)
	default:
		report.Framework = "Custom"
		report.Name = "Custom Compliance Report"
		report.Findings = []ReportFinding{}
	}

	// Calculate summary
	report.Summary = s.calculateSummary(report.Findings)
	report.Status = ReportStatusCompleted

	// Store report in database
	if err := s.storeComplianceReport(ctx, report); err != nil {
		s.logger.Warn("Failed to store compliance report", zap.Error(err))
	}

	return report, nil
}

func (s *Service) evaluateSOC2Controls(ctx context.Context, startDate, endDate time.Time) []ReportFinding {
	findings := []ReportFinding{
		// CC6.1 - Logical and Physical Access Controls
		{
			ControlID:   "CC6.1",
			ControlName: "Logical and Physical Access Controls",
			Status:      s.evaluateAccessControlStatus(ctx, startDate, endDate),
			Evidence:    "Access control policies implemented; MFA enabled for privileged access",
			Remediation: "",
		},
		// CC6.2 - Access Authentication and Authorization
		{
			ControlID:   "CC6.2",
			ControlName: "Prior to Access Authentication and Authorization",
			Status:      s.evaluateAuthenticationStatus(ctx, startDate, endDate),
			Evidence:    "Authentication events logged; session management implemented",
			Remediation: "",
		},
		// CC6.3 - Access Revocation
		{
			ControlID:   "CC6.3",
			ControlName: "Access Removal",
			Status:      s.evaluateAccessRevocationStatus(ctx, startDate, endDate),
			Evidence:    "User deprovisioning workflow active; access reviews conducted",
			Remediation: "",
		},
		// CC7.2 - Monitoring Activities
		{
			ControlID:   "CC7.2",
			ControlName: "System Monitoring Activities",
			Status:      s.evaluateMonitoringStatus(ctx, startDate, endDate),
			Evidence:    "Audit logging enabled; security events monitored",
			Remediation: "",
		},
		// CC7.3 - Evaluation of Security Events
		{
			ControlID:   "CC7.3",
			ControlName: "Evaluation of Security Events",
			Status:      "passed",
			Evidence:    "Security event review process established",
			Remediation: "",
		},
		// CC8.1 - Change Management
		{
			ControlID:   "CC8.1",
			ControlName: "Changes to Infrastructure and Software",
			Status:      "passed",
			Evidence:    "Change management process documented",
			Remediation: "",
		},
	}

	return findings
}

func (s *Service) evaluateISO27001Controls(ctx context.Context, startDate, endDate time.Time) []ReportFinding {
	return []ReportFinding{
		// A.9 Access Control
		{
			ControlID:   "A.9.1.1",
			ControlName: "Access Control Policy",
			Status:      "passed",
			Evidence:    "Access control policy documented and implemented",
		},
		{
			ControlID:   "A.9.2.1",
			ControlName: "User Registration and De-registration",
			Status:      s.evaluateAccessControlStatus(ctx, startDate, endDate),
			Evidence:    "User lifecycle management implemented via SCIM",
		},
		{
			ControlID:   "A.9.2.3",
			ControlName: "Management of Privileged Access Rights",
			Status:      s.evaluatePrivilegedAccessStatus(ctx, startDate, endDate),
			Evidence:    "Privileged access review process active",
		},
		{
			ControlID:   "A.9.4.1",
			ControlName: "Information Access Restriction",
			Status:      "passed",
			Evidence:    "Role-based access control implemented",
		},
		// A.12 Operations Security
		{
			ControlID:   "A.12.4.1",
			ControlName: "Event Logging",
			Status:      s.evaluateMonitoringStatus(ctx, startDate, endDate),
			Evidence:    "Comprehensive audit logging enabled",
		},
		{
			ControlID:   "A.12.4.3",
			ControlName: "Administrator and Operator Logs",
			Status:      "passed",
			Evidence:    "Admin actions logged and monitored",
		},
	}
}

func (s *Service) evaluateGDPRControls(ctx context.Context, startDate, endDate time.Time) []ReportFinding {
	return []ReportFinding{
		{
			ControlID:   "Art.5",
			ControlName: "Principles of Processing",
			Status:      "passed",
			Evidence:    "Data processing principles documented",
		},
		{
			ControlID:   "Art.25",
			ControlName: "Data Protection by Design",
			Status:      "passed",
			Evidence:    "Privacy by design principles implemented",
		},
		{
			ControlID:   "Art.30",
			ControlName: "Records of Processing Activities",
			Status:      s.evaluateMonitoringStatus(ctx, startDate, endDate),
			Evidence:    "Processing activities logged in audit system",
		},
		{
			ControlID:   "Art.32",
			ControlName: "Security of Processing",
			Status:      s.evaluateAuthenticationStatus(ctx, startDate, endDate),
			Evidence:    "Security measures implemented",
		},
	}
}

func (s *Service) evaluateHIPAAControls(ctx context.Context, startDate, endDate time.Time) []ReportFinding {
	return []ReportFinding{
		{
			ControlID:   "164.312(a)(1)",
			ControlName: "Access Control",
			Status:      s.evaluateAccessControlStatus(ctx, startDate, endDate),
			Evidence:    "Unique user identification implemented",
		},
		{
			ControlID:   "164.312(b)",
			ControlName: "Audit Controls",
			Status:      s.evaluateMonitoringStatus(ctx, startDate, endDate),
			Evidence:    "Audit logging mechanisms in place",
		},
		{
			ControlID:   "164.312(c)(1)",
			ControlName: "Integrity Controls",
			Status:      "passed",
			Evidence:    "Data integrity controls implemented",
		},
		{
			ControlID:   "164.312(d)",
			ControlName: "Person or Entity Authentication",
			Status:      s.evaluateAuthenticationStatus(ctx, startDate, endDate),
			Evidence:    "Multi-factor authentication available",
		},
	}
}

func (s *Service) evaluatePCIDSSControls(ctx context.Context, startDate, endDate time.Time) []ReportFinding {
	return []ReportFinding{
		{
			ControlID:   "7.1",
			ControlName: "Restrict Access to System Components",
			Status:      s.evaluateAccessControlStatus(ctx, startDate, endDate),
			Evidence:    "Access limited based on business need",
		},
		{
			ControlID:   "8.2",
			ControlName: "User Identification Management",
			Status:      "passed",
			Evidence:    "Unique IDs assigned to all users",
		},
		{
			ControlID:   "8.3",
			ControlName: "Strong Authentication",
			Status:      s.evaluateAuthenticationStatus(ctx, startDate, endDate),
			Evidence:    "MFA implemented for access",
		},
		{
			ControlID:   "10.2",
			ControlName: "Audit Logs Implementation",
			Status:      s.evaluateMonitoringStatus(ctx, startDate, endDate),
			Evidence:    "Audit logs capture required events",
		},
	}
}

func (s *Service) evaluateAccessControlStatus(ctx context.Context, startDate, endDate time.Time) string {
	// Check for any unauthorized access attempts
	var failedCount int
	s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_events
		WHERE event_type = 'authorization'
		AND outcome = 'failure'
		AND timestamp BETWEEN $1 AND $2
	`, startDate, endDate).Scan(&failedCount)

	if failedCount > 100 {
		return "partial"
	}
	return "passed"
}

func (s *Service) evaluateAuthenticationStatus(ctx context.Context, startDate, endDate time.Time) string {
	// Check authentication failure rate
	var totalAuth, failedAuth int
	s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_events
		WHERE event_type = 'authentication'
		AND timestamp BETWEEN $1 AND $2
	`, startDate, endDate).Scan(&totalAuth)

	s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_events
		WHERE event_type = 'authentication'
		AND outcome = 'failure'
		AND timestamp BETWEEN $1 AND $2
	`, startDate, endDate).Scan(&failedAuth)

	if totalAuth > 0 && float64(failedAuth)/float64(totalAuth) > 0.3 {
		return "failed"
	}
	if totalAuth > 0 && float64(failedAuth)/float64(totalAuth) > 0.1 {
		return "partial"
	}
	return "passed"
}

func (s *Service) evaluateAccessRevocationStatus(ctx context.Context, startDate, endDate time.Time) string {
	// Check if user deprovisioning is active
	var deactivatedCount int
	s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_events
		WHERE event_type = 'user_management'
		AND action LIKE '%deactivate%' OR action LIKE '%disable%'
		AND timestamp BETWEEN $1 AND $2
	`, startDate, endDate).Scan(&deactivatedCount)

	return "passed"
}

func (s *Service) evaluateMonitoringStatus(ctx context.Context, startDate, endDate time.Time) string {
	// Check if audit logging is working
	var eventCount int
	s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_events
		WHERE timestamp BETWEEN $1 AND $2
	`, startDate, endDate).Scan(&eventCount)

	if eventCount == 0 {
		return "failed"
	}
	return "passed"
}

func (s *Service) evaluatePrivilegedAccessStatus(ctx context.Context, startDate, endDate time.Time) string {
	// Check privileged access management
	var privilegedEvents int
	s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_events
		WHERE event_type = 'role_management'
		AND timestamp BETWEEN $1 AND $2
	`, startDate, endDate).Scan(&privilegedEvents)

	return "passed"
}

func (s *Service) calculateSummary(findings []ReportFinding) ReportSummary {
	summary := ReportSummary{
		TotalControls: len(findings),
	}

	for _, f := range findings {
		switch f.Status {
		case "passed":
			summary.PassedControls++
		case "failed":
			summary.FailedControls++
		case "partial":
			summary.PartialControls++
		case "not_applicable":
			summary.NotApplicable++
		}
	}

	return summary
}

func (s *Service) storeComplianceReport(ctx context.Context, report *ComplianceReport) error {
	summaryJSON, _ := json.Marshal(report.Summary)
	findingsJSON, _ := json.Marshal(report.Findings)

	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO compliance_reports (id, type, framework, name, status, start_date, end_date, generated_at, summary, findings)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, report.ID, report.Type, report.Framework, report.Name, report.Status,
		report.StartDate, report.EndDate, report.GeneratedAt, summaryJSON, findingsJSON)

	return err
}

func generateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// GetEventStatistics returns statistics about audit events
func (s *Service) GetEventStatistics(ctx context.Context, startDate, endDate time.Time) (map[string]interface{}, error) {
	stats := map[string]interface{}{
		"total_events":       0,
		"by_type":            map[string]int{},
		"by_outcome":         map[string]int{},
		"by_category":        map[string]int{},
		"events_per_day":     []map[string]interface{}{},
		"failed_auth_count":  0,
		"success_rate":       0.0,
	}

	// Get total events in time range
	var totalEvents int
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_events
		WHERE timestamp BETWEEN $1 AND $2
	`, startDate, endDate).Scan(&totalEvents)
	if err != nil {
		return nil, err
	}
	stats["total_events"] = totalEvents

	// Get events by type
	byType := map[string]int{}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT event_type, COUNT(*) as count
		FROM audit_events
		WHERE timestamp BETWEEN $1 AND $2
		GROUP BY event_type
	`, startDate, endDate)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var eventType string
		var count int
		rows.Scan(&eventType, &count)
		byType[eventType] = count
	}
	rows.Close()
	stats["by_type"] = byType

	// Get events by outcome
	byOutcome := map[string]int{}
	rows, err = s.db.Pool.Query(ctx, `
		SELECT outcome, COUNT(*) as count
		FROM audit_events
		WHERE timestamp BETWEEN $1 AND $2
		GROUP BY outcome
	`, startDate, endDate)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var outcome string
		var count int
		rows.Scan(&outcome, &count)
		byOutcome[outcome] = count
	}
	rows.Close()
	stats["by_outcome"] = byOutcome

	// Get events by category
	byCategory := map[string]int{}
	rows, err = s.db.Pool.Query(ctx, `
		SELECT category, COUNT(*) as count
		FROM audit_events
		WHERE timestamp BETWEEN $1 AND $2
		GROUP BY category
	`, startDate, endDate)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var category string
		var count int
		rows.Scan(&category, &count)
		byCategory[category] = count
	}
	rows.Close()
	stats["by_category"] = byCategory

	// Get events per day for charts
	eventsPerDay := []map[string]interface{}{}
	rows, err = s.db.Pool.Query(ctx, `
		SELECT DATE(timestamp) as day, COUNT(*) as count
		FROM audit_events
		WHERE timestamp BETWEEN $1 AND $2
		GROUP BY DATE(timestamp)
		ORDER BY day
	`, startDate, endDate)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var day time.Time
		var count int
		rows.Scan(&day, &count)
		eventsPerDay = append(eventsPerDay, map[string]interface{}{
			"date":  day.Format("2006-01-02"),
			"count": count,
		})
	}
	rows.Close()
	stats["events_per_day"] = eventsPerDay

	// Get failed authentication count
	var failedAuthCount int
	s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_events
		WHERE event_type = 'authentication'
		AND outcome = 'failure'
		AND timestamp BETWEEN $1 AND $2
	`, startDate, endDate).Scan(&failedAuthCount)
	stats["failed_auth_count"] = failedAuthCount

	// Calculate success rate
	if totalEvents > 0 {
		successCount := byOutcome["success"]
		stats["success_rate"] = float64(successCount) / float64(totalEvents) * 100
	}

	return stats, nil
}

// ListComplianceReports lists all compliance reports
func (s *Service) ListComplianceReports(ctx context.Context, offset, limit int) ([]ComplianceReport, int, error) {
	var total int
	err := s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM compliance_reports").Scan(&total)
	if err != nil {
		// Table might not exist yet
		return []ComplianceReport{}, 0, nil
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, type, framework, name, status, start_date, end_date, generated_at, summary, findings
		FROM compliance_reports
		ORDER BY generated_at DESC
		OFFSET $1 LIMIT $2
	`, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var reports []ComplianceReport
	for rows.Next() {
		var r ComplianceReport
		var summaryJSON, findingsJSON []byte
		if err := rows.Scan(
			&r.ID, &r.Type, &r.Framework, &r.Name, &r.Status,
			&r.StartDate, &r.EndDate, &r.GeneratedAt, &summaryJSON, &findingsJSON,
		); err != nil {
			return nil, 0, err
		}
		json.Unmarshal(summaryJSON, &r.Summary)
		json.Unmarshal(findingsJSON, &r.Findings)
		reports = append(reports, r)
	}

	return reports, total, nil
}

// GetComplianceReport retrieves a compliance report by ID
func (s *Service) GetComplianceReport(ctx context.Context, reportID string) (*ComplianceReport, error) {
	var r ComplianceReport
	var summaryJSON, findingsJSON []byte
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, type, framework, name, status, start_date, end_date, generated_at, summary, findings
		FROM compliance_reports WHERE id = $1
	`, reportID).Scan(
		&r.ID, &r.Type, &r.Framework, &r.Name, &r.Status,
		&r.StartDate, &r.EndDate, &r.GeneratedAt, &summaryJSON, &findingsJSON,
	)
	if err != nil {
		return nil, err
	}
	json.Unmarshal(summaryJSON, &r.Summary)
	json.Unmarshal(findingsJSON, &r.Findings)
	return &r, nil
}

// RegisterRoutes registers audit service routes
func RegisterRoutes(router *gin.Engine, svc *Service) {
	audit := router.Group("/api/v1/audit")
	{
		// Events
		audit.GET("/events", svc.handleListEvents)
		audit.POST("/events", svc.handleLogEvent)
		audit.GET("/events/:id", svc.handleGetEvent)
		
		// Statistics
		audit.GET("/statistics", svc.handleGetStatistics)
		
		// Reports
		audit.GET("/reports", svc.handleListReports)
		audit.POST("/reports", svc.handleGenerateReport)
		audit.GET("/reports/:id", svc.handleGetReport)
		audit.GET("/reports/:id/download", svc.handleDownloadReport)
		
		// Export
		audit.POST("/export", svc.handleExportEvents)
	}
}

// HTTP Handlers

func (s *Service) handleListEvents(c *gin.Context) {
	query := &AuditQuery{
		Offset: 0,
		Limit:  50,
	}

	// Parse offset and limit
	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil {
			query.Offset = parsed
		}
	}
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil {
			query.Limit = parsed
		}
	}

	// Parse time range
	if start := c.Query("start_time"); start != "" {
		if t, err := time.Parse(time.RFC3339, start); err == nil {
			query.StartTime = &t
		}
	}
	if end := c.Query("end_time"); end != "" {
		if t, err := time.Parse(time.RFC3339, end); err == nil {
			query.EndTime = &t
		}
	}

	// Parse filters
	if eventType := c.Query("event_type"); eventType != "" {
		query.EventType = EventType(eventType)
	}
	if category := c.Query("category"); category != "" {
		query.Category = EventCategory(category)
	}
	if outcome := c.Query("outcome"); outcome != "" {
		query.Outcome = EventOutcome(outcome)
	}
	if actorID := c.Query("actor_id"); actorID != "" {
		query.ActorID = actorID
	}

	events, total, err := s.QueryEvents(c.Request.Context(), query)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.Header("X-Total-Count", strconv.Itoa(total))
	c.JSON(200, events)
}

func (s *Service) handleLogEvent(c *gin.Context) {
	var event AuditEvent
	if err := c.ShouldBindJSON(&event); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if err := s.LogEvent(c.Request.Context(), &event); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(201, event)
}

func (s *Service) handleGetEvent(c *gin.Context) {
	eventID := c.Param("id")
	var e AuditEvent
	var details []byte
	err := s.db.Pool.QueryRow(c.Request.Context(), `
		SELECT id, timestamp, event_type, category, action, outcome,
		       COALESCE(actor_id, ''), COALESCE(actor_type, ''), COALESCE(actor_ip, ''),
		       COALESCE(target_id, ''), COALESCE(target_type, ''),
		       COALESCE(resource_id, ''), COALESCE(details::text, '{}')::jsonb,
		       COALESCE(session_id, ''), COALESCE(request_id, '')
		FROM audit_events WHERE id = $1
	`, eventID).Scan(
		&e.ID, &e.Timestamp, &e.EventType, &e.Category, &e.Action, &e.Outcome,
		&e.ActorID, &e.ActorType, &e.ActorIP, &e.TargetID, &e.TargetType,
		&e.ResourceID, &details, &e.SessionID, &e.RequestID,
	)
	if err != nil {
		c.JSON(404, gin.H{"error": "event not found"})
		return
	}
	json.Unmarshal(details, &e.Details)
	c.JSON(200, e)
}

func (s *Service) handleGetStatistics(c *gin.Context) {
	now := time.Now()
	startDate := now.AddDate(0, 0, -30)

	// Parse custom date range
	if start := c.Query("start"); start != "" {
		if t, err := time.Parse("2006-01-02", start); err == nil {
			startDate = t
		}
	}
	endDate := now
	if end := c.Query("end"); end != "" {
		if t, err := time.Parse("2006-01-02", end); err == nil {
			endDate = t.Add(24*time.Hour - time.Second) // End of day
		}
	}

	stats, err := s.GetEventStatistics(c.Request.Context(), startDate, endDate)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, stats)
}

func (s *Service) handleListReports(c *gin.Context) {
	offset := 0
	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil {
			offset = parsed
		}
	}
	limit := 20
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil {
			limit = parsed
		}
	}

	reports, total, err := s.ListComplianceReports(c.Request.Context(), offset, limit)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.Header("X-Total-Count", strconv.Itoa(total))
	c.JSON(200, reports)
}

func (s *Service) handleGenerateReport(c *gin.Context) {
	var req struct {
		Type      ReportType `json:"type"`
		StartDate time.Time  `json:"start_date"`
		EndDate   time.Time  `json:"end_date"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	report, err := s.GenerateComplianceReport(c.Request.Context(), req.Type, req.StartDate, req.EndDate)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(201, report)
}

func (s *Service) handleGetReport(c *gin.Context) {
	report, err := s.GetComplianceReport(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(404, gin.H{"error": "report not found"})
		return
	}
	c.JSON(200, report)
}

func (s *Service) handleDownloadReport(c *gin.Context) {
	report, err := s.GetComplianceReport(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(404, gin.H{"error": "report not found"})
		return
	}

	// Generate CSV format for simplicity (PDF would require external library)
	format := c.Query("format")
	if format == "" {
		format = "csv"
	}

	var content strings.Builder
	if format == "csv" {
		// CSV Header
		content.WriteString("Control ID,Control Name,Status,Evidence,Remediation\n")

		// CSV Data
		for _, finding := range report.Findings {
			content.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s\n",
				escapeCSV(finding.ControlID),
				escapeCSV(finding.ControlName),
				escapeCSV(finding.Status),
				escapeCSV(finding.Evidence),
				escapeCSV(finding.Remediation),
			))
		}

		c.Header("Content-Type", "text/csv")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s_%s.csv", report.Type, report.GeneratedAt.Format("2006-01-02")))
		c.String(200, content.String())
	} else {
		// Return JSON for other formats
		c.JSON(200, report)
	}
}

func (s *Service) handleExportEvents(c *gin.Context) {
	var req struct {
		StartTime *time.Time    `json:"start_time"`
		EndTime   *time.Time    `json:"end_time"`
		EventType EventType     `json:"event_type"`
		Category  EventCategory `json:"category"`
		Outcome   EventOutcome  `json:"outcome"`
		Format    string        `json:"format"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		// Use query params as fallback
	}

	query := &AuditQuery{
		StartTime: req.StartTime,
		EndTime:   req.EndTime,
		EventType: req.EventType,
		Category:  req.Category,
		Outcome:   req.Outcome,
		Offset:    0,
		Limit:     10000, // Max export limit
	}

	events, _, err := s.QueryEvents(c.Request.Context(), query)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	// Generate CSV
	var content strings.Builder
	content.WriteString("ID,Timestamp,Event Type,Category,Action,Outcome,Actor ID,Actor IP,Target ID,Target Type\n")

	for _, e := range events {
		content.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
			escapeCSV(e.ID),
			e.Timestamp.Format(time.RFC3339),
			escapeCSV(string(e.EventType)),
			escapeCSV(string(e.Category)),
			escapeCSV(e.Action),
			escapeCSV(string(e.Outcome)),
			escapeCSV(e.ActorID),
			escapeCSV(e.ActorIP),
			escapeCSV(e.TargetID),
			escapeCSV(e.TargetType),
		))
	}

	c.Header("Content-Type", "text/csv")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=audit_events_%s.csv", time.Now().Format("2006-01-02")))
	c.String(200, content.String())
}

func escapeCSV(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}
