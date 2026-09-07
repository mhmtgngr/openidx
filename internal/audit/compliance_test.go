// Package audit provides unit tests for compliance report generation
package audit

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openidx/openidx/internal/common/orgctx"
)

func TestDetermineComplianceStatus(t *testing.T) {
	tests := []struct {
		name               string
		value              float64
		compliantThreshold float64
		partialThreshold   float64
		expectedStatus     string
	}{
		{
			name:               "fully compliant",
			value:              95.0,
			compliantThreshold: 80.0,
			partialThreshold:   50.0,
			expectedStatus:     "compliant",
		},
		{
			name:               "exactly compliant threshold",
			value:              80.0,
			compliantThreshold: 80.0,
			partialThreshold:   50.0,
			expectedStatus:     "compliant",
		},
		{
			name:               "partial compliance",
			value:              65.0,
			compliantThreshold: 80.0,
			partialThreshold:   50.0,
			expectedStatus:     "partial",
		},
		{
			name:               "exactly partial threshold",
			value:              50.0,
			compliantThreshold: 80.0,
			partialThreshold:   50.0,
			expectedStatus:     "partial",
		},
		{
			name:               "non compliant",
			value:              30.0,
			compliantThreshold: 80.0,
			partialThreshold:   50.0,
			expectedStatus:     "non_compliant",
		},
		{
			name:               "zero value",
			value:              0.0,
			compliantThreshold: 80.0,
			partialThreshold:   50.0,
			expectedStatus:     "non_compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := determineComplianceStatus(tt.value, tt.compliantThreshold, tt.partialThreshold)
			assert.Equal(t, tt.expectedStatus, result)
		})
	}
}

func TestGenerateReportID(t *testing.T) {
	id1 := generateReportID()
	id2 := generateReportID()

	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)
	assert.NotEqual(t, id1, id2) // IDs should be unique
	assert.Contains(t, id1, "report_")
	assert.Contains(t, id2, "report_")
}

func TestSOC2ReportSerialization(t *testing.T) {
	report := &SOC2Report{
		ReportID:    "test_report_123",
		PeriodStart: time.Now().UTC().Add(-24 * time.Hour),
		PeriodEnd:   time.Now().UTC(),
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "test-user",
		AccessReviews: AccessReviewMetrics{
			TotalReviews:     100,
			PendingReviews:   20,
			CompletedReviews: 75,
			OverdueReviews:   5,
			CompletionRate:   75.0,
			ComplianceStatus: "compliant",
		},
		PasswordPolicy: PasswordPolicyMetrics{
			MinLength:              8,
			RequireUppercase:       true,
			RequireLowercase:       true,
			RequireNumbers:         true,
			RequireSpecialChars:    true,
			MaxAgeDays:             90,
			UsersWithWeakPasswords: 2,
			ComplianceStatus:       "compliant",
		},
		MFAAdoption: MFAAdoptionMetrics{
			TotalUsers:        500,
			UsersWithMFA:      450,
			UsersWithTOTP:     300,
			UsersWithWebAuthn: 150,
			AdoptionRate:      90.0,
			LastUpdated:       time.Now().UTC(),
			ComplianceStatus:  "compliant",
		},
		SessionMgmt: SessionManagementMetrics{
			ActiveSessions:      125,
			AverageSessionHours: 2.5,
			SessionTimeoutMins:  30,
			IdleTimeoutMins:     15,
			ComplianceStatus:    "compliant",
		},
	}

	// Test JSON marshaling
	data, err := json.Marshal(report)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// Test JSON unmarshaling
	var unmarshaled SOC2Report
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, report.ReportID, unmarshaled.ReportID)
	assert.Equal(t, report.GeneratedBy, unmarshaled.GeneratedBy)
	assert.Equal(t, report.AccessReviews.TotalReviews, unmarshaled.AccessReviews.TotalReviews)
	assert.Equal(t, report.MFAAdoption.AdoptionRate, unmarshaled.MFAAdoption.AdoptionRate)
}

func TestISO27001ReportSerialization(t *testing.T) {
	report := &ISO27001Report{
		ReportID:    "iso_report_456",
		PeriodStart: time.Now().UTC().Add(-24 * time.Hour),
		PeriodEnd:   time.Now().UTC(),
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "test-user",
		AccessControl: AccessControlMetrics{
			TotalUsers:       1000,
			AdminUsers:       50,
			RolesDefined:     10,
			GroupsDefined:    25,
			AdminRatio:       5.0,
			ComplianceStatus: "compliant",
		},
		Cryptography: CryptographyMetrics{
			TLSEnabled:         true,
			TLSMinVersion:      "1.3",
			EncryptionAtRest:   true,
			KeyRotationEnabled: true,
			ComplianceStatus:   "compliant",
		},
		OperationalSecurity: OperationalSecurityMetrics{
			TotalEvents:      10000,
			EventsByType:     map[string]int{"authentication": 5000, "authorization": 3000},
			EventsByDay:      []DayEventCount{{Date: "2024-01-01", Count: 1000}},
			FailedEvents:     50,
			ErrorRate:        0.5,
			LoggingCoverage:  100.0,
			ComplianceStatus: "compliant",
		},
	}

	data, err := json.Marshal(report)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	var unmarshaled ISO27001Report
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, report.ReportID, unmarshaled.ReportID)
	assert.Equal(t, report.AccessControl.AdminRatio, unmarshaled.AccessControl.AdminRatio)
	assert.Len(t, unmarshaled.OperationalSecurity.EventsByType, 2)
}

func TestGDPRReportSerialization(t *testing.T) {
	report := &GDPRReport{
		ReportID:    "gdpr_report_789",
		PeriodStart: time.Now().UTC().Add(-24 * time.Hour),
		PeriodEnd:   time.Now().UTC(),
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "test-user",
		DataAccessLogs: DataAccessMetrics{
			TotalAccessEvents: 500,
			AccessByActor:     map[string]int{"user1": 100, "user2": 50},
			AccessByDataType:  map[string]int{"personal": 300, "sensitive": 200},
			ComplianceStatus:  "compliant",
		},
		ConsentRecords: ConsentMetrics{
			TotalConsentRecords: 1000,
			ActiveConsents:      950,
			WithdrawnConsents:   40,
			PendingConsents:     10,
			ComplianceStatus:    "compliant",
		},
		DataSubjectRequests: DataSubjectRequestMetrics{
			TotalRequests:       50,
			RequestsByType:      map[string]int{"access": 20, "deletion": 15, "portability": 15},
			PendingRequests:     5,
			CompletedRequests:   40,
			OverdueRequests:     5,
			AverageResponseDays: 7.5,
			ComplianceStatus:    "partial",
		},
		DataDeletionRecords: DataDeletionMetrics{
			TotalDeletionRequests: 15,
			CompletedDeletions:    12,
			PendingDeletions:      2,
			FailedDeletions:       1,
			AverageDeletionDays:   14.0,
			ComplianceStatus:      "compliant",
		},
	}

	data, err := json.Marshal(report)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	var unmarshaled GDPRReport
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, report.ReportID, unmarshaled.ReportID)
	assert.Equal(t, report.DataAccessLogs.TotalAccessEvents, unmarshaled.DataAccessLogs.TotalAccessEvents)
	assert.Equal(t, report.DataSubjectRequests.ComplianceStatus, unmarshaled.DataSubjectRequests.ComplianceStatus)
}

// A compliance report that cannot be measured is refused, not published.
//
// This replaces three tests that could not fail. They built a Service whose
// pool is nil, generated all three reports, and asserted things like
// `assert.GreaterOrEqual(t, report.MFAAdoption.TotalUsers, 0)` -- true of the
// zero value, and the zero value was all any of those fields ever held,
// because every query in the report had been skipped. The reports were
// complete documents made entirely of numbers nobody measured, and the suite
// certified their shape.
//
// The two ways a report can arrive unmeasured are the two cases here: no
// database, and no organization to scope the queries to. Both used to produce a
// full report of zeros; both now produce an error, and the handler answers 500.
func TestAnUnmeasurableComplianceReportIsRefused(t *testing.T) {
	start := time.Now().UTC().Add(-30 * 24 * time.Hour)
	end := time.Now().UTC()
	orgCtx := orgctx.With(context.Background(), orgctx.Org{ID: "00000000-0000-0000-0000-000000000010"})

	generators := map[string]func(*Service, context.Context) (interface{}, error){
		"SOC 2": func(s *Service, ctx context.Context) (interface{}, error) {
			return s.GenerateSOC2Report(ctx, start, end, "test-user")
		},
		"ISO 27001": func(s *Service, ctx context.Context) (interface{}, error) {
			return s.GenerateISO27001Report(ctx, start, end, "test-user")
		},
		"GDPR": func(s *Service, ctx context.Context) (interface{}, error) {
			return s.GenerateGDPRReport(ctx, start, end, "test-user")
		},
	}

	for name, generate := range generators {
		t.Run(name+" without a database", func(t *testing.T) {
			report, err := generate(createTestService(t), orgCtx)
			require.Error(t, err, "a report generated with no database is a document of "+
				"numbers nobody measured; it must not be produced")
			assert.ErrorIs(t, err, errNoComplianceDatabase)
			assert.Nil(t, report)
		})

		t.Run(name+" without an organization", func(t *testing.T) {
			report, err := generate(createTestService(t), context.Background())
			require.Error(t, err, "every metric filters on org_id: with no organization "+
				"in context each one comes back zero, and a report of zeros reads as a finding")
			assert.Contains(t, err.Error(), "organization context")
			assert.Nil(t, report)
		})
	}
}
