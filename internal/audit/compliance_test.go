// Package audit provides unit tests for compliance report generation
package audit

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSOC2Report(t *testing.T) {
	// Create test service
	service := createTestService(t)
	ctx := context.Background()

	startDate := time.Now().UTC().Add(-30 * 24 * time.Hour)
	endDate := time.Now().UTC()

	report, err := service.GenerateSOC2Report(ctx, startDate, endDate, "test-user")
	require.NoError(t, err)
	require.NotNil(t, report)

	// Verify report structure
	assert.NotEmpty(t, report.ReportID)
	assert.Equal(t, startDate, report.PeriodStart)
	assert.Equal(t, endDate, report.PeriodEnd)
	assert.Equal(t, "test-user", report.GeneratedBy)
	assert.False(t, report.GeneratedAt.IsZero())

	// Verify access review metrics
	assert.GreaterOrEqual(t, report.AccessReviews.TotalReviews, 0)
	assert.GreaterOrEqual(t, report.AccessReviews.PendingReviews, 0)
	assert.GreaterOrEqual(t, report.AccessReviews.CompletedReviews, 0)
	assert.GreaterOrEqual(t, report.AccessReviews.OverdueReviews, 0)
	assert.GreaterOrEqual(t, report.AccessReviews.CompletionRate, 0.0)
	assert.LessOrEqual(t, report.AccessReviews.CompletionRate, 100.0)
	assert.Contains(t, []string{"compliant", "partial", "non_compliant"},
		report.AccessReviews.ComplianceStatus)

	// Verify password policy metrics
	assert.Greater(t, report.PasswordPolicy.MinLength, 0)
	assert.IsType(t, false, report.PasswordPolicy.RequireUppercase)
	assert.IsType(t, false, report.PasswordPolicy.RequireLowercase)
	assert.IsType(t, false, report.PasswordPolicy.RequireNumbers)
	assert.IsType(t, false, report.PasswordPolicy.RequireSpecialChars)
	assert.Contains(t, []string{"compliant", "partial", "non_compliant"},
		report.PasswordPolicy.ComplianceStatus)

	// Verify MFA adoption metrics
	assert.GreaterOrEqual(t, report.MFAAdoption.TotalUsers, 0)
	assert.GreaterOrEqual(t, report.MFAAdoption.UsersWithMFA, 0)
	assert.GreaterOrEqual(t, report.MFAAdoption.UsersWithTOTP, 0)
	assert.GreaterOrEqual(t, report.MFAAdoption.UsersWithWebAuthn, 0)
	assert.GreaterOrEqual(t, report.MFAAdoption.AdoptionRate, 0.0)
	assert.LessOrEqual(t, report.MFAAdoption.AdoptionRate, 100.0)
	assert.Contains(t, []string{"compliant", "partial", "non_compliant"},
		report.MFAAdoption.ComplianceStatus)

	// Verify session management metrics
	assert.GreaterOrEqual(t, report.SessionMgmt.ActiveSessions, 0)
	assert.GreaterOrEqual(t, report.SessionMgmt.AverageSessionHours, 0.0)
	assert.GreaterOrEqual(t, report.SessionMgmt.SessionTimeoutMins, 0)
	assert.Contains(t, []string{"compliant", "partial", "non_compliant"},
		report.SessionMgmt.ComplianceStatus)
}

func TestGenerateISO27001Report(t *testing.T) {
	service := createTestService(t)
	ctx := context.Background()

	startDate := time.Now().UTC().Add(-30 * 24 * time.Hour)
	endDate := time.Now().UTC()

	report, err := service.GenerateISO27001Report(ctx, startDate, endDate, "test-user")
	require.NoError(t, err)
	require.NotNil(t, report)

	// Verify report structure
	assert.NotEmpty(t, report.ReportID)
	assert.Equal(t, startDate, report.PeriodStart)
	assert.Equal(t, endDate, report.PeriodEnd)
	assert.Equal(t, "test-user", report.GeneratedBy)
	assert.False(t, report.GeneratedAt.IsZero())

	// Verify access control metrics
	assert.GreaterOrEqual(t, report.AccessControl.TotalUsers, 0)
	assert.GreaterOrEqual(t, report.AccessControl.AdminUsers, 0)
	assert.GreaterOrEqual(t, report.AccessControl.RolesDefined, 0)
	assert.GreaterOrEqual(t, report.AccessControl.GroupsDefined, 0)
	assert.GreaterOrEqual(t, report.AccessControl.AdminRatio, 0.0)
	assert.LessOrEqual(t, report.AccessControl.AdminRatio, 100.0)
	assert.Contains(t, []string{"compliant", "partial", "non_compliant"},
		report.AccessControl.ComplianceStatus)

	// Verify cryptography metrics
	assert.IsType(t, false, report.Cryptography.TLSEnabled)
	assert.NotEmpty(t, report.Cryptography.TLSMinVersion)
	assert.IsType(t, false, report.Cryptography.EncryptionAtRest)
	assert.IsType(t, false, report.Cryptography.KeyRotationEnabled)
	assert.Contains(t, []string{"compliant", "partial", "non_compliant"},
		report.Cryptography.ComplianceStatus)

	// Verify operational security metrics
	assert.GreaterOrEqual(t, report.OperationalSecurity.TotalEvents, 0)
	assert.NotNil(t, report.OperationalSecurity.EventsByType)
	assert.NotNil(t, report.OperationalSecurity.EventsByDay)
	assert.GreaterOrEqual(t, report.OperationalSecurity.FailedEvents, 0)
	assert.GreaterOrEqual(t, report.OperationalSecurity.ErrorRate, 0.0)
	assert.GreaterOrEqual(t, report.OperationalSecurity.LoggingCoverage, 0.0)
	assert.LessOrEqual(t, report.OperationalSecurity.LoggingCoverage, 100.0)
	assert.Contains(t, []string{"compliant", "partial", "non_compliant"},
		report.OperationalSecurity.ComplianceStatus)
}

func TestGenerateGDPRReport(t *testing.T) {
	service := createTestService(t)
	ctx := context.Background()

	startDate := time.Now().UTC().Add(-30 * 24 * time.Hour)
	endDate := time.Now().UTC()

	report, err := service.GenerateGDPRReport(ctx, startDate, endDate, "test-user")
	require.NoError(t, err)
	require.NotNil(t, report)

	// Verify report structure
	assert.NotEmpty(t, report.ReportID)
	assert.Equal(t, startDate, report.PeriodStart)
	assert.Equal(t, endDate, report.PeriodEnd)
	assert.Equal(t, "test-user", report.GeneratedBy)
	assert.False(t, report.GeneratedAt.IsZero())

	// Verify data access metrics
	assert.GreaterOrEqual(t, report.DataAccessLogs.TotalAccessEvents, 0)
	assert.NotNil(t, report.DataAccessLogs.AccessByActor)
	assert.NotNil(t, report.DataAccessLogs.AccessByDataType)
	assert.Contains(t, []string{"compliant", "partial", "non_compliant"},
		report.DataAccessLogs.ComplianceStatus)

	// Verify consent metrics
	assert.GreaterOrEqual(t, report.ConsentRecords.TotalConsentRecords, 0)
	assert.GreaterOrEqual(t, report.ConsentRecords.ActiveConsents, 0)
	assert.GreaterOrEqual(t, report.ConsentRecords.WithdrawnConsents, 0)
	assert.GreaterOrEqual(t, report.ConsentRecords.PendingConsents, 0)
	assert.Contains(t, []string{"compliant", "partial", "non_compliant"},
		report.ConsentRecords.ComplianceStatus)

	// Verify data subject request metrics
	assert.GreaterOrEqual(t, report.DataSubjectRequests.TotalRequests, 0)
	assert.NotNil(t, report.DataSubjectRequests.RequestsByType)
	assert.GreaterOrEqual(t, report.DataSubjectRequests.PendingRequests, 0)
	assert.GreaterOrEqual(t, report.DataSubjectRequests.CompletedRequests, 0)
	assert.GreaterOrEqual(t, report.DataSubjectRequests.OverdueRequests, 0)
	assert.GreaterOrEqual(t, report.DataSubjectRequests.AverageResponseDays, 0.0)
	assert.Contains(t, []string{"compliant", "partial", "non_compliant"},
		report.DataSubjectRequests.ComplianceStatus)

	// Verify data deletion metrics
	assert.GreaterOrEqual(t, report.DataDeletionRecords.TotalDeletionRequests, 0)
	assert.GreaterOrEqual(t, report.DataDeletionRecords.CompletedDeletions, 0)
	assert.GreaterOrEqual(t, report.DataDeletionRecords.PendingDeletions, 0)
	assert.GreaterOrEqual(t, report.DataDeletionRecords.FailedDeletions, 0)
	assert.GreaterOrEqual(t, report.DataDeletionRecords.AverageDeletionDays, 0.0)
	assert.Contains(t, []string{"compliant", "partial", "non_compliant"},
		report.DataDeletionRecords.ComplianceStatus)
}

func TestDetermineComplianceStatus(t *testing.T) {
	tests := []struct {
		name                  string
		value                 float64
		compliantThreshold    float64
		partialThreshold      float64
		expectedStatus        string
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
			MinLength:            8,
			RequireUppercase:     true,
			RequireLowercase:     true,
			RequireNumbers:       true,
			RequireSpecialChars:  true,
			MaxAgeDays:           90,
			UsersWithWeakPasswords: 2,
			ComplianceStatus:     "compliant",
		},
		MFAAdoption: MFAAdoptionMetrics{
			TotalUsers:      500,
			UsersWithMFA:    450,
			UsersWithTOTP:   300,
			UsersWithWebAuthn: 150,
			AdoptionRate:    90.0,
			LastUpdated:     time.Now().UTC(),
			ComplianceStatus: "compliant",
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

// Helper function to create a test service
func createTestService(t *testing.T) *Service {
	// This would typically set up a test database connection
	// For now, return a minimal service struct
	return &Service{
		// Initialize with test configuration
	}
}

// Run benchmarks
func BenchmarkGenerateSOC2Report(b *testing.B) {
	service := createTestService(&testing.T{})
	ctx := context.Background()
	startDate := time.Now().UTC().Add(-30 * 24 * time.Hour)
	endDate := time.Now().UTC()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = service.GenerateSOC2Report(ctx, startDate, endDate, "benchmark")
	}
}

func BenchmarkGenerateISO27001Report(b *testing.B) {
	service := createTestService(&testing.T{})
	ctx := context.Background()
	startDate := time.Now().UTC().Add(-30 * 24 * time.Hour)
	endDate := time.Now().UTC()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = service.GenerateISO27001Report(ctx, startDate, endDate, "benchmark")
	}
}

func BenchmarkGenerateGDPRReport(b *testing.B) {
	service := createTestService(&testing.T{})
	ctx := context.Background()
	startDate := time.Now().UTC().Add(-30 * 24 * time.Hour)
	endDate := time.Now().UTC()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = service.GenerateGDPRReport(ctx, startDate, endDate, "benchmark")
	}
}
