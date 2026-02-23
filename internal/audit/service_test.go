package audit

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// TestServiceAuditEventSerialization verifies ServiceAuditEvent JSON marshaling
func TestServiceAuditEventSerialization(t *testing.T) {
	event := &ServiceAuditEvent{
		ID:         "evt-001",
		Timestamp:  time.Now(),
		EventType:  EventTypeAuthentication,
		Category:   CategorySecurity,
		Action:     "login",
		Outcome:    ServiceOutcomeSuccess,
		ActorID:    "user-123",
		ActorType:  "user",
		ActorIP:    "192.168.1.1",
		TargetID:   "session-456",
		TargetType: "session",
		ResourceID: "res-789",
		Details:    map[string]interface{}{"method": "password", "mfa": true},
		SessionID:  "sess-001",
		RequestID:  "req-001",
	}

	data, err := json.Marshal(event)
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	var decoded ServiceAuditEvent
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, "evt-001", decoded.ID)
	assert.Equal(t, EventTypeAuthentication, decoded.EventType)
	assert.Equal(t, CategorySecurity, decoded.Category)
	assert.Equal(t, ServiceOutcomeSuccess, decoded.Outcome)
	assert.Equal(t, "user-123", decoded.ActorID)
	assert.Equal(t, "192.168.1.1", decoded.ActorIP)
	assert.Equal(t, "password", decoded.Details["method"])
}

// TestEventTypes verifies all event type constants
func TestEventTypes(t *testing.T) {
	types := []EventType{
		EventTypeAuthentication,
		EventTypeAuthorization,
		EventTypeUserManagement,
		EventTypeGroupManagement,
		EventTypeRoleManagement,
		EventTypeConfiguration,
		EventTypeDataAccess,
		EventTypeSystem,
	}

	assert.Len(t, types, 8)

	for _, et := range types {
		assert.NotEmpty(t, string(et))
	}

	// Verify specific values
	assert.Equal(t, EventType("authentication"), EventTypeAuthentication)
	assert.Equal(t, EventType("authorization"), EventTypeAuthorization)
	assert.Equal(t, EventType("user_management"), EventTypeUserManagement)
	assert.Equal(t, EventType("group_management"), EventTypeGroupManagement)
	assert.Equal(t, EventType("role_management"), EventTypeRoleManagement)
	assert.Equal(t, EventType("configuration"), EventTypeConfiguration)
	assert.Equal(t, EventType("data_access"), EventTypeDataAccess)
	assert.Equal(t, EventType("system"), EventTypeSystem)
}

// TestEventCategories verifies all event category constants
func TestEventCategories(t *testing.T) {
	categories := []EventCategory{
		CategorySecurity,
		CategoryCompliance,
		CategoryOperational,
		CategoryAccess,
	}

	assert.Len(t, categories, 4)
	assert.Equal(t, EventCategory("security"), CategorySecurity)
	assert.Equal(t, EventCategory("compliance"), CategoryCompliance)
	assert.Equal(t, EventCategory("operational"), CategoryOperational)
	assert.Equal(t, EventCategory("access"), CategoryAccess)
}

// TestEventOutcomes verifies all outcome constants
func TestEventOutcomes(t *testing.T) {
	outcomes := []ServiceEventOutcome{
		ServiceOutcomeSuccess,
		ServiceOutcomeFailure,
		ServiceOutcomePending,
	}

	assert.Len(t, outcomes, 3)
	assert.Equal(t, ServiceEventOutcome("success"), ServiceOutcomeSuccess)
	assert.Equal(t, ServiceEventOutcome("failure"), ServiceOutcomeFailure)
	assert.Equal(t, ServiceEventOutcome("pending"), ServiceOutcomePending)
}

// TestAuditQueryDefaults verifies default query values
func TestAuditQueryDefaults(t *testing.T) {
	query := &AuditQuery{}

	assert.Nil(t, query.StartTime)
	assert.Nil(t, query.EndTime)
	assert.Empty(t, query.EventType)
	assert.Empty(t, query.Category)
	assert.Empty(t, query.ActorID)
	assert.Empty(t, query.TargetID)
	assert.Empty(t, query.Outcome)
	assert.Equal(t, 0, query.Offset)
	assert.Equal(t, 0, query.Limit)
}

// TestAuditQuerySerialization verifies AuditQuery JSON round-trip
func TestAuditQuerySerialization(t *testing.T) {
	now := time.Now()
	query := &AuditQuery{
		StartTime: &now,
		EndTime:   &now,
		EventType: EventTypeAuthentication,
		Category:  CategorySecurity,
		ActorID:   "user-1",
		Outcome:   ServiceOutcomeFailure,
		Offset:    0,
		Limit:     50,
	}

	data, err := json.Marshal(query)
	assert.NoError(t, err)

	var decoded AuditQuery
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, EventTypeAuthentication, decoded.EventType)
	assert.Equal(t, CategorySecurity, decoded.Category)
	assert.Equal(t, ServiceOutcomeFailure, decoded.Outcome)
	assert.Equal(t, 50, decoded.Limit)
}

// TestComplianceReportModel verifies compliance report serialization
func TestComplianceReportModel(t *testing.T) {
	report := &ComplianceReport{
		ID:          "rpt-001",
		Name:        "Q1 SOC2 Report",
		Type:        ReportTypeSOC2,
		Framework:   "SOC 2 Type II",
		Status:      ReportStatusCompleted,
		StartDate:   time.Now().AddDate(0, -3, 0),
		EndDate:     time.Now(),
		GeneratedAt: time.Now(),
		GeneratedBy: "admin",
		Summary: ReportSummary{
			TotalControls:   100,
			PassedControls:  85,
			FailedControls:  10,
			PartialControls: 3,
			NotApplicable:   2,
		},
		Findings: []ReportFinding{
			{
				ControlID:   "CC1.1",
				ControlName: "Control Environment",
				Status:      "passed",
				Evidence:    "Documented policies",
			},
			{
				ControlID:   "CC6.1",
				ControlName: "Logical Access",
				Status:      "failed",
				Evidence:    "No MFA enforcement",
				Remediation: "Enable MFA for all admin accounts",
			},
		},
	}

	data, err := json.Marshal(report)
	assert.NoError(t, err)

	var decoded ComplianceReport
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, "rpt-001", decoded.ID)
	assert.Equal(t, ReportTypeSOC2, decoded.Type)
	assert.Equal(t, ReportStatusCompleted, decoded.Status)
	assert.Equal(t, 100, decoded.Summary.TotalControls)
	assert.Equal(t, 85, decoded.Summary.PassedControls)
	assert.Len(t, decoded.Findings, 2)
	assert.Equal(t, "CC6.1", decoded.Findings[1].ControlID)
	assert.NotEmpty(t, decoded.Findings[1].Remediation)
}

// TestReportTypes verifies all report type constants
func TestReportTypes(t *testing.T) {
	types := []ReportType{
		ReportTypeSOC2,
		ReportTypeISO27001,
		ReportTypeGDPR,
		ReportTypeHIPAA,
		ReportTypePCI,
		ReportTypeCustom,
	}

	assert.Len(t, types, 6)
	assert.Equal(t, ReportType("soc2"), ReportTypeSOC2)
	assert.Equal(t, ReportType("iso27001"), ReportTypeISO27001)
	assert.Equal(t, ReportType("gdpr"), ReportTypeGDPR)
	assert.Equal(t, ReportType("hipaa"), ReportTypeHIPAA)
	assert.Equal(t, ReportType("pci_dss"), ReportTypePCI)
	assert.Equal(t, ReportType("custom"), ReportTypeCustom)
}

// TestReportStatuses verifies all report status constants
func TestReportStatuses(t *testing.T) {
	statuses := []ReportStatus{
		ReportStatusPending,
		ReportStatusGenerating,
		ReportStatusCompleted,
		ReportStatusFailed,
	}

	assert.Len(t, statuses, 4)
	assert.Equal(t, ReportStatus("pending"), ReportStatusPending)
	assert.Equal(t, ReportStatus("generating"), ReportStatusGenerating)
	assert.Equal(t, ReportStatus("completed"), ReportStatusCompleted)
	assert.Equal(t, ReportStatus("failed"), ReportStatusFailed)
}

// TestReportSummaryCompleteness verifies that passed + failed + partial + na = total
func TestReportSummaryCompleteness(t *testing.T) {
	summary := ReportSummary{
		TotalControls:   100,
		PassedControls:  85,
		FailedControls:  10,
		PartialControls: 3,
		NotApplicable:   2,
	}

	sum := summary.PassedControls + summary.FailedControls + summary.PartialControls + summary.NotApplicable
	assert.Equal(t, summary.TotalControls, sum)
}

// TestAuditEventDetailsMap verifies details field handles arbitrary JSON
func TestAuditEventDetailsMap(t *testing.T) {
	event := &ServiceAuditEvent{
		ID:        "evt-100",
		EventType: EventTypeAuthentication,
		Details: map[string]interface{}{
			"browser":    "Chrome",
			"os":         "Linux",
			"mfa_used":   true,
			"attempt":    float64(1),
			"ip_list":    []interface{}{"10.0.0.1", "10.0.0.2"},
		},
	}

	data, err := json.Marshal(event)
	assert.NoError(t, err)

	var decoded ServiceAuditEvent
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, "Chrome", decoded.Details["browser"])
	assert.Equal(t, true, decoded.Details["mfa_used"])
	assert.Len(t, decoded.Details["ip_list"], 2)
}

// TestNewService verifies service construction
func TestNewService(t *testing.T) {
	// NewService with nil logger panics because it calls logger.With()
	assert.Panics(t, func() {
		NewService(nil, nil, nil, nil)
	})
}
