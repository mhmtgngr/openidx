package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/syssettings"
)

// DetailedComplianceReport provides an in-depth compliance assessment with
// per-control scoring, evidence gathering, and remediation guidance.
type DetailedComplianceReport struct {
	ID           string              `json:"id"`
	Framework    string              `json:"framework"`
	Period       string              `json:"period"`
	GeneratedAt  time.Time           `json:"generated_at"`
	OverallScore float64             `json:"overall_score"`
	Controls     []ControlAssessment `json:"controls"`
	Summary      string              `json:"summary"`
}

// ControlAssessment represents the evaluation of a single compliance control.
type ControlAssessment struct {
	ControlID   string   `json:"control_id"`
	Name        string   `json:"name"`
	Status      string   `json:"status"` // compliant, partial, non_compliant
	Score       float64  `json:"score"`
	Evidence    []string `json:"evidence"`
	Findings    []string `json:"findings"`
	Remediation []string `json:"remediation,omitempty"`
}

// GenerateSOC2DetailedReport evaluates SOC 2 Trust Service Criteria (CC1-CC9)
// with evidence gathering from audit_events, users, and system settings.
// namedControl pairs a control's identifier with the function that assesses it,
// so a failed assessment names the control an operator has to look at.
type namedControl struct {
	id   string
	eval func(context.Context, time.Time, time.Time) (ControlAssessment, error)
}

// assess runs each control in order and stops at the first that could not be
// measured. Returning a partial report was the alternative and it is the defect
// this whole change is about: a control scored from a query that did not run is
// indistinguishable, in the document, from one scored from real data.
func (s *Service) assess(ctx context.Context, startDate, endDate time.Time, controls []namedControl) ([]ControlAssessment, error) {
	out := make([]ControlAssessment, 0, len(controls))
	for _, c := range controls {
		a, err := c.eval(ctx, startDate, endDate)
		if err != nil {
			return nil, fmt.Errorf("control %s: %w", c.id, err)
		}
		out = append(out, a)
	}
	return out, nil
}

func (s *Service) GenerateSOC2DetailedReport(ctx context.Context, startDate, endDate time.Time) (*DetailedComplianceReport, error) {
	s.logger.Info("Generating detailed SOC 2 report",
		zap.Time("start_date", startDate),
		zap.Time("end_date", endDate))

	report := &DetailedComplianceReport{
		ID:          generateUUID(),
		Framework:   "SOC 2 Type II",
		Period:      fmt.Sprintf("%s to %s", startDate.Format("2006-01-02"), endDate.Format("2006-01-02")),
		GeneratedAt: time.Now(),
	}

	// Each control is a set of measurements. A control that cannot be measured
	// fails the report rather than scoring on the zeros a failed query leaves --
	// see internal/audit/metricquery.go.
	controls, err := s.assess(ctx, startDate, endDate, []namedControl{
		{"CC1", s.evaluateCC1ControlEnvironment},
		{"CC2", s.evaluateCC2Communication},
		{"CC3", s.evaluateCC3RiskAssessment},
		{"CC6", s.evaluateCC6LogicalAccess},
		{"CC7", s.evaluateCC7SystemOperations},
		{"CC8", s.evaluateCC8ChangeManagement},
	})
	if err != nil {
		return nil, err
	}

	report.Controls = controls

	// Calculate overall score
	var totalScore float64
	for _, ctrl := range controls {
		totalScore += ctrl.Score
	}
	if len(controls) > 0 {
		report.OverallScore = totalScore / float64(len(controls))
	}

	// Generate summary
	compliant := 0
	partial := 0
	nonCompliant := 0
	for _, ctrl := range controls {
		switch ctrl.Status {
		case "compliant":
			compliant++
		case "partial":
			partial++
		case "non_compliant":
			nonCompliant++
		}
	}
	report.Summary = fmt.Sprintf("SOC 2 Assessment: %d/%d controls compliant, %d partial, %d non-compliant. Overall score: %.1f%%",
		compliant, len(controls), partial, nonCompliant, report.OverallScore)

	// Store the detailed report. Generation already succeeded, so a
	// persistence failure only degrades later evidence download — log it
	// loudly but still return the report.
	if storeErr := s.storeDetailedReport(ctx, report); storeErr != nil {
		s.logger.Error("Failed to store detailed compliance report",
			zap.Error(storeErr), zap.String("report_id", report.ID))
	}

	return report, nil
}

// evaluateCC1ControlEnvironment assesses control environment (user counts, admin ratios, password policies).
func (s *Service) evaluateCC1ControlEnvironment(ctx context.Context, startDate, endDate time.Time) (ControlAssessment, error) {
	assessment := ControlAssessment{
		ControlID: "CC1",
		Name:      "Control Environment",
		Evidence:  []string{},
		Findings:  []string{},
	}
	score := 100.0
	q := s.newMetricQuery(ctx)

	// Check total users and admin ratio
	var totalUsers, adminUsers int
	q.scan("total users", &totalUsers, `SELECT COUNT(*) FROM users WHERE enabled = true AND org_id = $1`, q.org())
	q.scan("admin users", &adminUsers, `
		SELECT COUNT(DISTINCT ur.user_id)
		FROM user_roles ur
		JOIN roles r ON ur.role_id = r.id AND r.org_id = ur.org_id
		WHERE r.name IN ('admin', 'super_admin')
		AND ur.org_id = $1
	`, q.org())

	assessment.Evidence = append(assessment.Evidence,
		fmt.Sprintf("Total active users: %d", totalUsers))
	assessment.Evidence = append(assessment.Evidence,
		fmt.Sprintf("Admin users: %d", adminUsers))

	if totalUsers > 0 {
		adminRatio := float64(adminUsers) / float64(totalUsers) * 100
		assessment.Evidence = append(assessment.Evidence,
			fmt.Sprintf("Admin ratio: %.1f%%", adminRatio))

		if adminRatio > 20 {
			score -= 30
			assessment.Findings = append(assessment.Findings,
				fmt.Sprintf("Admin ratio is %.1f%% (exceeds 20%% threshold)", adminRatio))
			assessment.Remediation = append(assessment.Remediation,
				"Review admin assignments and apply principle of least privilege")
		}
	}

	// Check password policy in the console's settings document. Keyed
	// 'security' until v1.34.0, a row that has never existed, so this control
	// deducted 15 points and reported "No security settings configured" on
	// every install regardless of its configuration.
	if settings, err := syssettings.Load(ctx, s.db.Pool); err == nil {
		assessment.Evidence = append(assessment.Evidence, "Password policy configured in system settings")
		assessment.Evidence = append(assessment.Evidence,
			fmt.Sprintf("Password policy details: %+v", settings.Security.PasswordPolicy))
	} else {
		score -= 15
		assessment.Findings = append(assessment.Findings,
			"No security settings configured in system_settings")
		assessment.Remediation = append(assessment.Remediation,
			"Configure password policy and security settings")
	}

	if err := q.failed(); err != nil {
		return ControlAssessment{}, err
	}
	assessment.Score = score
	assessment.Status = scoreToStatus(score)
	return assessment, nil
}

// evaluateCC2Communication assesses communication and information controls.
func (s *Service) evaluateCC2Communication(ctx context.Context, startDate, endDate time.Time) (ControlAssessment, error) {
	assessment := ControlAssessment{
		ControlID: "CC2",
		Name:      "Communication and Information",
		Evidence:  []string{},
		Findings:  []string{},
	}
	score := 100.0
	q := s.newMetricQuery(ctx)

	// Check audit log configuration
	var auditCount int
	q.scan("audit events", &auditCount, `
		SELECT COUNT(*) FROM audit_events
		WHERE timestamp BETWEEN $1 AND $2
		AND org_id = $3
	`, startDate, endDate, q.org())

	assessment.Evidence = append(assessment.Evidence,
		fmt.Sprintf("Audit events recorded in period: %d", auditCount))

	if auditCount == 0 {
		score -= 50
		assessment.Findings = append(assessment.Findings,
			"No audit events recorded during the assessment period")
		assessment.Remediation = append(assessment.Remediation,
			"Ensure audit logging is enabled and operational")
	}

	// Check distinct event types captured
	var eventTypeCount int
	q.scan("distinct event types", &eventTypeCount, `
		SELECT COUNT(DISTINCT event_type) FROM audit_events
		WHERE timestamp BETWEEN $1 AND $2
		AND org_id = $3
	`, startDate, endDate, q.org())

	assessment.Evidence = append(assessment.Evidence,
		fmt.Sprintf("Distinct event types captured: %d", eventTypeCount))

	if eventTypeCount < 3 {
		score -= 20
		assessment.Findings = append(assessment.Findings,
			fmt.Sprintf("Only %d event types captured (minimum 3 recommended)", eventTypeCount))
		assessment.Remediation = append(assessment.Remediation,
			"Ensure authentication, authorization, and user_management events are all being logged")
	}

	// Check notification / webhook configuration
	var webhookCount int
	q.scan("active webhook subscriptions", &webhookCount, `
		SELECT COUNT(*) FROM audit_webhook_subscriptions WHERE enabled = true AND org_id = $1
	`, q.org())

	if webhookCount > 0 {
		assessment.Evidence = append(assessment.Evidence,
			fmt.Sprintf("Active webhook subscriptions: %d", webhookCount))
	} else {
		score -= 10
		assessment.Findings = append(assessment.Findings,
			"No webhook subscriptions configured for event notifications")
		assessment.Remediation = append(assessment.Remediation,
			"Configure webhook subscriptions for security event notification")
	}

	if err := q.failed(); err != nil {
		return ControlAssessment{}, err
	}
	assessment.Score = score
	assessment.Status = scoreToStatus(score)
	return assessment, nil
}

// evaluateCC3RiskAssessment assesses risk assessment controls.
func (s *Service) evaluateCC3RiskAssessment(ctx context.Context, startDate, endDate time.Time) (ControlAssessment, error) {
	assessment := ControlAssessment{
		ControlID: "CC3",
		Name:      "Risk Assessment",
		Evidence:  []string{},
		Findings:  []string{},
	}
	score := 100.0
	q := s.newMetricQuery(ctx)

	// Check risk scoring activity
	var riskAssessments int
	q.scan("risk assessments", &riskAssessments, `
		SELECT COUNT(*) FROM login_history
		WHERE risk_score > 0
		  AND created_at BETWEEN $1 AND $2
		  AND org_id = $3
	`, startDate, endDate, q.org())

	assessment.Evidence = append(assessment.Evidence,
		fmt.Sprintf("Login risk assessments performed: %d", riskAssessments))

	if riskAssessments == 0 {
		score -= 30
		assessment.Findings = append(assessment.Findings,
			"No risk-scored logins detected during the assessment period")
		assessment.Remediation = append(assessment.Remediation,
			"Enable risk scoring on authentication events")
	}

	// Check for high-risk login alerts
	var highRiskLogins int
	q.scan("high risk logins", &highRiskLogins, `
		SELECT COUNT(*) FROM login_history
		WHERE risk_score >= 50
		  AND created_at BETWEEN $1 AND $2
		  AND org_id = $3
	`, startDate, endDate, q.org())

	assessment.Evidence = append(assessment.Evidence,
		fmt.Sprintf("High-risk logins (score >= 50): %d", highRiskLogins))

	// Check for security alerts
	var alertCount int
	q.scan("security alerts", &alertCount, `
		SELECT COUNT(*) FROM security_alerts
		WHERE created_at BETWEEN $1 AND $2
		  AND org_id = $3
	`, startDate, endDate, q.org())

	assessment.Evidence = append(assessment.Evidence,
		fmt.Sprintf("Security alerts generated: %d", alertCount))

	if alertCount == 0 && highRiskLogins > 0 {
		score -= 20
		assessment.Findings = append(assessment.Findings,
			"High-risk logins detected but no security alerts were generated")
		assessment.Remediation = append(assessment.Remediation,
			"Configure alert rules to trigger on high-risk login events")
	}

	if err := q.failed(); err != nil {
		return ControlAssessment{}, err
	}
	assessment.Score = score
	assessment.Status = scoreToStatus(score)
	return assessment, nil
}

// evaluateCC6LogicalAccess assesses logical access controls (MFA, sessions, API keys).
func (s *Service) evaluateCC6LogicalAccess(ctx context.Context, startDate, endDate time.Time) (ControlAssessment, error) {
	assessment := ControlAssessment{
		ControlID: "CC6",
		Name:      "Logical and Physical Access Controls",
		Evidence:  []string{},
		Findings:  []string{},
	}
	score := 100.0
	q := s.newMetricQuery(ctx)

	// MFA adoption
	var totalEnabledUsers, mfaTotpUsers, webauthnUsers int
	q.scan("total enabled users", &totalEnabledUsers, `SELECT COUNT(*) FROM users WHERE enabled = true AND org_id = $1`, q.org())
	q.scan("users with TOTP", &mfaTotpUsers, `SELECT COUNT(DISTINCT user_id) FROM mfa_totp WHERE enabled = true AND org_id = $1`, q.org())
	// WebAuthn credentials live in mfa_webauthn (where the wired registration
	// path writes) — not the phantom `webauthn_credentials` table, which no
	// migration creates, so the old query errored and left webauthnUsers=0,
	// under-counting MFA adoption. Org-scoped like its mfa_totp sibling above.
	q.scan("users with WebAuthn", &webauthnUsers, `SELECT COUNT(DISTINCT user_id) FROM mfa_webauthn WHERE org_id = $1`, q.org())

	mfaUsers := mfaTotpUsers + webauthnUsers
	assessment.Evidence = append(assessment.Evidence,
		fmt.Sprintf("Users with MFA enabled: %d/%d (TOTP: %d, WebAuthn: %d)",
			mfaUsers, totalEnabledUsers, mfaTotpUsers, webauthnUsers))

	if totalEnabledUsers > 0 {
		mfaRate := float64(mfaUsers) / float64(totalEnabledUsers) * 100
		if mfaRate < 50 {
			score -= 30
			assessment.Findings = append(assessment.Findings,
				fmt.Sprintf("MFA adoption rate is %.1f%% (below 50%% threshold)", mfaRate))
			assessment.Remediation = append(assessment.Remediation,
				"Enforce MFA for all users or increase MFA adoption through policy")
		} else if mfaRate < 80 {
			score -= 10
			assessment.Findings = append(assessment.Findings,
				fmt.Sprintf("MFA adoption rate is %.1f%% (below recommended 80%%)", mfaRate))
			assessment.Remediation = append(assessment.Remediation,
				"Continue promoting MFA adoption; consider mandatory enrollment")
		}
	}

	// Session policy check
	var activeSessions int
	q.scan("active sessions", &activeSessions, `
		SELECT COUNT(*) FROM sessions WHERE expires_at > NOW() AND org_id = $1
	`, q.org())
	assessment.Evidence = append(assessment.Evidence,
		fmt.Sprintf("Active sessions: %d", activeSessions))

	// Check for session timeout configuration. Read from the row keyed
	// 'security' until v1.34.0 -- a row nothing writes -- so this control
	// docked 10 points for "Session timeout not configured" on every install.
	var sessionTimeout int
	settings, err := syssettings.Load(ctx, s.db.Pool)
	if err == nil {
		sessionTimeout = settings.Security.SessionTimeout
	}
	if err != nil || sessionTimeout == 0 {
		score -= 10
		assessment.Findings = append(assessment.Findings,
			"Session timeout not configured in security settings")
		assessment.Remediation = append(assessment.Remediation,
			"Configure session timeout policy (recommended: 30-60 minutes idle timeout)")
	} else {
		assessment.Evidence = append(assessment.Evidence,
			fmt.Sprintf("Session timeout configured: %d minutes", sessionTimeout))
	}

	// API key management
	var activeAPIKeys, expiredAPIKeys int
	// api_keys records revocation in `status` ('active' / 'revoked'); it has no
	// revoked_at column, so BOTH halves of this control failed to plan and both
	// counts read 0. An expired-key count of zero produces no finding and docks
	// no points: the control has reported compliant on every install, including
	// ones with expired keys still accepted.
	q.scan("active API keys", &activeAPIKeys, `
		SELECT COUNT(*) FROM api_keys WHERE status = 'active' AND (expires_at IS NULL OR expires_at > NOW()) AND org_id = $1
	`, q.org())
	q.scan("expired API keys", &expiredAPIKeys, `
		SELECT COUNT(*) FROM api_keys WHERE expires_at IS NOT NULL AND expires_at <= NOW() AND status = 'active' AND org_id = $1
	`, q.org())

	assessment.Evidence = append(assessment.Evidence,
		fmt.Sprintf("Active API keys: %d, Expired but not revoked: %d", activeAPIKeys, expiredAPIKeys))

	if expiredAPIKeys > 0 {
		score -= 10
		assessment.Findings = append(assessment.Findings,
			fmt.Sprintf("%d expired API keys have not been revoked", expiredAPIKeys))
		assessment.Remediation = append(assessment.Remediation,
			"Revoke expired API keys and implement automatic key rotation")
	}

	if err := q.failed(); err != nil {
		return ControlAssessment{}, err
	}
	assessment.Score = score
	assessment.Status = scoreToStatus(score)
	return assessment, nil
}

// evaluateCC7SystemOperations assesses system operations monitoring.
func (s *Service) evaluateCC7SystemOperations(ctx context.Context, startDate, endDate time.Time) (ControlAssessment, error) {
	assessment := ControlAssessment{
		ControlID: "CC7",
		Name:      "System Operations",
		Evidence:  []string{},
		Findings:  []string{},
	}
	score := 100.0
	q := s.newMetricQuery(ctx)

	// Check health check / monitoring configuration
	var totalEvents int
	q.scan("total events", &totalEvents, `
		SELECT COUNT(*) FROM audit_events
		WHERE timestamp BETWEEN $1 AND $2
		  AND org_id = $3
	`, startDate, endDate, q.org())

	assessment.Evidence = append(assessment.Evidence,
		fmt.Sprintf("Total audit events in period: %d", totalEvents))

	// Check for system events
	var systemEvents int
	q.scan("system events", &systemEvents, `
		SELECT COUNT(*) FROM audit_events
		WHERE event_type = 'system'
		  AND timestamp BETWEEN $1 AND $2
		  AND org_id = $3
	`, startDate, endDate, q.org())

	assessment.Evidence = append(assessment.Evidence,
		fmt.Sprintf("System events logged: %d", systemEvents))

	// Error rate analysis
	var failedEvents int
	q.scan("failed events", &failedEvents, `
		SELECT COUNT(*) FROM audit_events
		WHERE outcome = 'failure'
		  AND timestamp BETWEEN $1 AND $2
		  AND org_id = $3
	`, startDate, endDate, q.org())

	if totalEvents > 0 {
		errorRate := float64(failedEvents) / float64(totalEvents) * 100
		assessment.Evidence = append(assessment.Evidence,
			fmt.Sprintf("Overall failure rate: %.2f%%", errorRate))

		if errorRate > 20 {
			score -= 25
			assessment.Findings = append(assessment.Findings,
				fmt.Sprintf("High failure rate: %.2f%% (exceeds 20%% threshold)", errorRate))
			assessment.Remediation = append(assessment.Remediation,
				"Investigate high failure rates and address root causes")
		} else if errorRate > 10 {
			score -= 10
			assessment.Findings = append(assessment.Findings,
				fmt.Sprintf("Elevated failure rate: %.2f%% (exceeds 10%% threshold)", errorRate))
			assessment.Remediation = append(assessment.Remediation,
				"Monitor failure trends and investigate recurring patterns")
		}
	}

	// Check continuous monitoring (events per day coverage)
	var daysWithEvents int
	totalDays := int(endDate.Sub(startDate).Hours()/24) + 1
	q.scan("days with events", &daysWithEvents, `
		SELECT COUNT(DISTINCT DATE(timestamp))
		FROM audit_events
		WHERE timestamp BETWEEN $1 AND $2
		  AND org_id = $3
	`, startDate, endDate, q.org())

	if totalDays > 0 {
		coverage := float64(daysWithEvents) / float64(totalDays) * 100
		assessment.Evidence = append(assessment.Evidence,
			fmt.Sprintf("Monitoring coverage: %d/%d days (%.1f%%)", daysWithEvents, totalDays, coverage))

		if coverage < 80 {
			score -= 20
			assessment.Findings = append(assessment.Findings,
				fmt.Sprintf("Monitoring coverage is %.1f%% (below 80%% threshold)", coverage))
			assessment.Remediation = append(assessment.Remediation,
				"Ensure continuous audit logging is operational with no gaps")
		}
	}

	if err := q.failed(); err != nil {
		return ControlAssessment{}, err
	}
	assessment.Score = score
	assessment.Status = scoreToStatus(score)
	return assessment, nil
}

// evaluateCC8ChangeManagement assesses change management controls.
func (s *Service) evaluateCC8ChangeManagement(ctx context.Context, startDate, endDate time.Time) (ControlAssessment, error) {
	assessment := ControlAssessment{
		ControlID: "CC8",
		Name:      "Change Management",
		Evidence:  []string{},
		Findings:  []string{},
	}
	score := 100.0
	q := s.newMetricQuery(ctx)

	// Check admin audit log entries (configuration changes)
	var configChanges int
	q.scan("config changes", &configChanges, `
		SELECT COUNT(*) FROM audit_events
		WHERE event_type = 'configuration'
		  AND timestamp BETWEEN $1 AND $2
		  AND org_id = $3
	`, startDate, endDate, q.org())

	assessment.Evidence = append(assessment.Evidence,
		fmt.Sprintf("Configuration change events: %d", configChanges))

	// Check role management events
	var roleChanges int
	q.scan("role changes", &roleChanges, `
		SELECT COUNT(*) FROM audit_events
		WHERE event_type = 'role_management'
		  AND timestamp BETWEEN $1 AND $2
		  AND org_id = $3
	`, startDate, endDate, q.org())

	assessment.Evidence = append(assessment.Evidence,
		fmt.Sprintf("Role management events: %d", roleChanges))

	// Check user management events
	var userMgmtEvents int
	q.scan("user management events", &userMgmtEvents, `
		SELECT COUNT(*) FROM audit_events
		WHERE event_type = 'user_management'
		  AND timestamp BETWEEN $1 AND $2
		  AND org_id = $3
	`, startDate, endDate, q.org())

	assessment.Evidence = append(assessment.Evidence,
		fmt.Sprintf("User management events: %d", userMgmtEvents))

	// Assess change traceability
	totalChanges := configChanges + roleChanges + userMgmtEvents
	if totalChanges == 0 {
		score -= 15
		assessment.Findings = append(assessment.Findings,
			"No administrative change events recorded during assessment period")
		assessment.Remediation = append(assessment.Remediation,
			"Ensure all administrative changes are captured in audit logs")
	}

	// Check if changes have actor attribution
	var unattributedChanges int
	q.scan("unattributed changes", &unattributedChanges, `
		SELECT COUNT(*) FROM audit_events
		WHERE event_type IN ('configuration', 'role_management', 'user_management')
		  AND (actor_id IS NULL OR actor_id = '')
		  AND timestamp BETWEEN $1 AND $2
		  AND org_id = $3
	`, startDate, endDate, q.org())

	if unattributedChanges > 0 {
		score -= 20
		assessment.Findings = append(assessment.Findings,
			fmt.Sprintf("%d changes lack actor attribution", unattributedChanges))
		assessment.Remediation = append(assessment.Remediation,
			"Ensure all administrative actions are performed by authenticated users")
	} else if totalChanges > 0 {
		assessment.Evidence = append(assessment.Evidence,
			"All changes have proper actor attribution")
	}

	if err := q.failed(); err != nil {
		return ControlAssessment{}, err
	}
	assessment.Score = score
	assessment.Status = scoreToStatus(score)
	return assessment, nil
}

// GenerateISO27001DetailedReport evaluates ISO 27001 Annex A controls
// with evidence from audit_events, users, and system_settings.
func (s *Service) GenerateISO27001DetailedReport(ctx context.Context, startDate, endDate time.Time) (*DetailedComplianceReport, error) {
	s.logger.Info("Generating detailed ISO 27001 report",
		zap.Time("start_date", startDate),
		zap.Time("end_date", endDate))

	report := &DetailedComplianceReport{
		ID:          generateUUID(),
		Framework:   "ISO 27001:2022",
		Period:      fmt.Sprintf("%s to %s", startDate.Format("2006-01-02"), endDate.Format("2006-01-02")),
		GeneratedAt: time.Now(),
	}

	controls, err := s.assess(ctx, startDate, endDate, []namedControl{
		{"A.5", s.evaluateA5Policies},
		{"A.6", s.evaluateA6Organization},
		{"A.9", s.evaluateA9AccessControl},
		{"A.12", s.evaluateA12OperationsSecurity},
		{"A.16", s.evaluateA16IncidentManagement},
	})
	if err != nil {
		return nil, err
	}

	report.Controls = controls

	// Calculate overall score
	var totalScore float64
	for _, ctrl := range controls {
		totalScore += ctrl.Score
	}
	if len(controls) > 0 {
		report.OverallScore = totalScore / float64(len(controls))
	}

	// Generate summary
	compliant := 0
	partial := 0
	nonCompliant := 0
	for _, ctrl := range controls {
		switch ctrl.Status {
		case "compliant":
			compliant++
		case "partial":
			partial++
		case "non_compliant":
			nonCompliant++
		}
	}
	report.Summary = fmt.Sprintf("ISO 27001 Assessment: %d/%d controls compliant, %d partial, %d non-compliant. Overall score: %.1f%%",
		compliant, len(controls), partial, nonCompliant, report.OverallScore)

	// Store the detailed report. Generation already succeeded, so a
	// persistence failure only degrades later evidence download — log it
	// loudly but still return the report.
	if storeErr := s.storeDetailedReport(ctx, report); storeErr != nil {
		s.logger.Error("Failed to store detailed compliance report",
			zap.Error(storeErr), zap.String("report_id", report.ID))
	}

	return report, nil
}

// evaluateA5Policies checks information security policies via system_settings.
func (s *Service) evaluateA5Policies(ctx context.Context, startDate, endDate time.Time) (ControlAssessment, error) {
	assessment := ControlAssessment{
		ControlID: "A.5",
		Name:      "Information Security Policies",
		Evidence:  []string{},
		Findings:  []string{},
	}
	score := 100.0
	// This control reads only system_settings, which is install-wide, but it
	// still binds a metricQuery: the report needs a tenant, and a nil pool must
	// be an error rather than a panic on the line below.
	q := s.newMetricQuery(ctx)
	if err := q.failed(); err != nil {
		return ControlAssessment{}, err
	}

	// Check for security configuration in the console's settings document.
	//
	// This read `WHERE key = 'security'` and `WHERE key = 'authentication'`
	// until v1.34.0. Neither row has ever existed: security and authentication
	// are objects INSIDE the single 'system' document. So both queries always
	// returned no rows, and this control deducted 40 points and reported
	// "No security policy configuration found in system_settings" on installs
	// whose security policy was fully configured -- a compliance finding that
	// was simply false, in the report an auditor reads.
	settings, settingsErr := syssettings.Load(ctx, s.db.Pool)
	if settingsErr == nil {
		assessment.Evidence = append(assessment.Evidence, "Security settings configured in system_settings")
		assessment.Evidence = append(assessment.Evidence,
			fmt.Sprintf("Password policy configured: %+v", settings.Security.PasswordPolicy))
		assessment.Evidence = append(assessment.Evidence,
			fmt.Sprintf("MFA requirement: %v", settings.Security.RequireMFA))
	} else {
		score -= 40
		assessment.Findings = append(assessment.Findings,
			"No security policy configuration found in system_settings")
		assessment.Remediation = append(assessment.Remediation,
			"Define and configure information security policies in system settings")
	}

	// Check for authentication settings.
	if settingsErr == nil && len(settings.Authentication.MFAMethods) > 0 {
		assessment.Evidence = append(assessment.Evidence, "Authentication settings configured")
	} else {
		score -= 15
		assessment.Findings = append(assessment.Findings,
			"Authentication policy settings not explicitly configured")
		assessment.Remediation = append(assessment.Remediation,
			"Configure authentication policy settings")
	}

	if err := q.failed(); err != nil {
		return ControlAssessment{}, err
	}
	assessment.Score = score
	assessment.Status = scoreToStatus(score)
	return assessment, nil
}

// evaluateA6Organization checks organizational security (roles, admin assignments).
func (s *Service) evaluateA6Organization(ctx context.Context, startDate, endDate time.Time) (ControlAssessment, error) {
	assessment := ControlAssessment{
		ControlID: "A.6",
		Name:      "Organization of Information Security",
		Evidence:  []string{},
		Findings:  []string{},
	}
	score := 100.0
	q := s.newMetricQuery(ctx)

	// Check role definitions
	var roleCount int
	q.scan("roles defined", &roleCount, `SELECT COUNT(*) FROM roles WHERE org_id = $1`, q.org())
	assessment.Evidence = append(assessment.Evidence,
		fmt.Sprintf("Defined roles: %d", roleCount))

	if roleCount < 2 {
		score -= 20
		assessment.Findings = append(assessment.Findings,
			"Insufficient role definitions for separation of duties")
		assessment.Remediation = append(assessment.Remediation,
			"Define distinct roles for admin, user, and auditor functions")
	}

	// Check admin assignments
	var adminCount int
	q.scan("administrator accounts", &adminCount, `
		SELECT COUNT(DISTINCT ur.user_id)
		FROM user_roles ur
		JOIN roles r ON ur.role_id = r.id AND r.org_id = ur.org_id
		WHERE r.name IN ('admin', 'super_admin')
		  AND ur.org_id = $1
	`, q.org())
	assessment.Evidence = append(assessment.Evidence,
		fmt.Sprintf("Users with admin roles: %d", adminCount))

	if adminCount == 0 {
		score -= 15
		assessment.Findings = append(assessment.Findings,
			"No admin role assignments found")
		assessment.Remediation = append(assessment.Remediation,
			"Assign admin roles to designated personnel")
	}

	// Check group-based access
	var groupCount int
	q.scan("groups defined", &groupCount, `SELECT COUNT(*) FROM groups WHERE org_id = $1`, q.org())
	assessment.Evidence = append(assessment.Evidence,
		fmt.Sprintf("Defined groups: %d", groupCount))

	if groupCount == 0 {
		score -= 10
		assessment.Findings = append(assessment.Findings,
			"No groups defined for organizational access management")
		assessment.Remediation = append(assessment.Remediation,
			"Create groups to organize users by department or function")
	}

	if err := q.failed(); err != nil {
		return ControlAssessment{}, err
	}
	assessment.Score = score
	assessment.Status = scoreToStatus(score)
	return assessment, nil
}

// evaluateA9AccessControl checks MFA, password policies, and session management.
// countMFAEnabledUsers returns the number of distinct users in the org with at
// least one MFA method enrolled — a TOTP secret (mfa_totp) or a WebAuthn
// credential (mfa_webauthn). WebAuthn credentials live in mfa_webauthn, where
// the wired registration path writes; the old queries read a phantom
// `webauthn_credentials` table that no migration creates, which errored and
// silently under-counted MFA adoption (producing the deterministic "MFA
// adoption 0.0%" ISO A.9 finding on every install).
func (s *Service) countMFAEnabledUsers(q *metricQuery) int {
	var n int
	q.scan("users with an MFA factor", &n, `
		SELECT COUNT(DISTINCT user_id) FROM (
			SELECT user_id FROM mfa_totp WHERE enabled = true AND org_id = $1
			UNION
			SELECT user_id FROM mfa_webauthn WHERE org_id = $1
		) mfa_combined
	`, q.org())
	return n
}

func (s *Service) evaluateA9AccessControl(ctx context.Context, startDate, endDate time.Time) (ControlAssessment, error) {
	assessment := ControlAssessment{
		ControlID: "A.9",
		Name:      "Access Control",
		Evidence:  []string{},
		Findings:  []string{},
	}
	score := 100.0
	q := s.newMetricQuery(ctx)

	// MFA adoption check
	var totalUsers int
	q.scan("total users", &totalUsers, `SELECT COUNT(*) FROM users WHERE enabled = true AND org_id = $1`, q.org())
	mfaUsers := s.countMFAEnabledUsers(q)

	assessment.Evidence = append(assessment.Evidence,
		fmt.Sprintf("MFA enabled users: %d/%d", mfaUsers, totalUsers))

	if totalUsers > 0 {
		mfaRate := float64(mfaUsers) / float64(totalUsers) * 100
		if mfaRate < 50 {
			score -= 25
			assessment.Findings = append(assessment.Findings,
				fmt.Sprintf("MFA adoption rate is %.1f%% (below 50%%)", mfaRate))
			assessment.Remediation = append(assessment.Remediation,
				"Mandate MFA enrollment for all users")
		}
	}

	// Password policy check. Read from the console's settings document; this
	// read a system_settings row keyed 'security' until v1.34.0 and, since
	// that row has never existed, the whole block was skipped and the minimum
	// password length was never assessed at all.
	if settings, err := syssettings.Load(ctx, s.db.Pool); err == nil {
		minLen := settings.Security.PasswordPolicy.MinLength
		if minLen < 8 {
			score -= 10
			assessment.Findings = append(assessment.Findings,
				fmt.Sprintf("Password minimum length is %d (below recommended 8)", minLen))
			assessment.Remediation = append(assessment.Remediation,
				"Increase minimum password length to at least 8 characters")
		}
		assessment.Evidence = append(assessment.Evidence,
			fmt.Sprintf("Password min length: %d", minLen))
	}

	// Session management
	var avgSessionHours *float64
	// started_at, not created_at -- see the same correction in compliance.go.
	q.scan("average session length", &avgSessionHours, `
		SELECT AVG(EXTRACT(EPOCH FROM (expires_at - started_at)) / 3600.0)
		FROM sessions
		WHERE started_at > NOW() - INTERVAL '30 days'
		  AND org_id = $1
	`, q.org())
	if avgSessionHours != nil {
		assessment.Evidence = append(assessment.Evidence,
			fmt.Sprintf("Average session duration: %.1f hours", *avgSessionHours))
		if *avgSessionHours > 24 {
			score -= 10
			assessment.Findings = append(assessment.Findings,
				"Average session duration exceeds 24 hours")
			assessment.Remediation = append(assessment.Remediation,
				"Reduce session timeout to enforce re-authentication")
		}
	}

	// Failed authentication analysis
	var failedAuth int
	q.scan("failed authentications", &failedAuth, `
		SELECT COUNT(*) FROM audit_events
		WHERE event_type = 'authentication' AND outcome = 'failure'
		  AND timestamp BETWEEN $1 AND $2
		  AND org_id = $3
	`, startDate, endDate, q.org())

	assessment.Evidence = append(assessment.Evidence,
		fmt.Sprintf("Failed authentication attempts in period: %d", failedAuth))

	if err := q.failed(); err != nil {
		return ControlAssessment{}, err
	}
	assessment.Score = score
	assessment.Status = scoreToStatus(score)
	return assessment, nil
}

// evaluateA12OperationsSecurity checks audit logging and monitoring.
func (s *Service) evaluateA12OperationsSecurity(ctx context.Context, startDate, endDate time.Time) (ControlAssessment, error) {
	assessment := ControlAssessment{
		ControlID: "A.12",
		Name:      "Operations Security",
		Evidence:  []string{},
		Findings:  []string{},
	}
	score := 100.0
	q := s.newMetricQuery(ctx)

	// Audit logging check
	var totalEvents int
	q.scan("total events", &totalEvents, `
		SELECT COUNT(*) FROM audit_events
		WHERE timestamp BETWEEN $1 AND $2
		  AND org_id = $3
	`, startDate, endDate, q.org())

	assessment.Evidence = append(assessment.Evidence,
		fmt.Sprintf("Total audit events: %d", totalEvents))

	if totalEvents == 0 {
		score -= 40
		assessment.Findings = append(assessment.Findings,
			"No audit events recorded during the assessment period")
		assessment.Remediation = append(assessment.Remediation,
			"Enable and verify audit logging across all services")
	}

	// Check monitoring coverage by event type
	if err := q.failed(); err != nil {
		return ControlAssessment{}, err
	}
	eventTypes := map[string]int{}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT event_type, COUNT(*)
		FROM audit_events
		WHERE timestamp BETWEEN $1 AND $2
		  AND org_id = $3
		GROUP BY event_type
	`, startDate, endDate, q.org())
	if err != nil {
		return ControlAssessment{}, fmt.Errorf("monitoring coverage by event type: %w", err)
	}
	for rows.Next() {
		var et string
		var cnt int
		if err := rows.Scan(&et, &cnt); err != nil {
			rows.Close()
			return ControlAssessment{}, fmt.Errorf("monitoring coverage by event type: %w", err)
		}
		eventTypes[et] = cnt
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return ControlAssessment{}, fmt.Errorf("monitoring coverage by event type: %w", err)
	}

	// "identity", not "user_management". This list asked for an event type no
	// writer in this product produces: user_management is a CATEGORY, and the
	// event type stamped on a user lifecycle row is "identity" -- which is why
	// A.12 deducted ten points and reported "Required event type
	// 'user_management' has no events in period" on every install ever
	// assessed. A control that manufactures a finding against a correctly
	// configured system is worth less than no control.
	requiredTypes := []string{"authentication", "authorization", "identity"}
	for _, rt := range requiredTypes {
		if cnt, ok := eventTypes[rt]; ok && cnt > 0 {
			assessment.Evidence = append(assessment.Evidence,
				fmt.Sprintf("Event type '%s': %d events", rt, cnt))
		} else {
			score -= 10
			assessment.Findings = append(assessment.Findings,
				fmt.Sprintf("Required event type '%s' has no events in period", rt))
			assessment.Remediation = append(assessment.Remediation,
				fmt.Sprintf("Ensure '%s' events are being captured", rt))
		}
	}

	// Daily logging consistency
	var daysWithEvents int
	q.scan("days with events", &daysWithEvents, `
		SELECT COUNT(DISTINCT DATE(timestamp))
		FROM audit_events
		WHERE timestamp BETWEEN $1 AND $2
		  AND org_id = $3
	`, startDate, endDate, q.org())

	totalDays := int(endDate.Sub(startDate).Hours()/24) + 1
	if totalDays > 0 {
		coverage := float64(daysWithEvents) / float64(totalDays) * 100
		assessment.Evidence = append(assessment.Evidence,
			fmt.Sprintf("Logging coverage: %d/%d days (%.1f%%)", daysWithEvents, totalDays, coverage))
	}

	if err := q.failed(); err != nil {
		return ControlAssessment{}, err
	}
	assessment.Score = score
	assessment.Status = scoreToStatus(score)
	return assessment, nil
}

// evaluateA16IncidentManagement checks security alert handling and response times.
func (s *Service) evaluateA16IncidentManagement(ctx context.Context, startDate, endDate time.Time) (ControlAssessment, error) {
	assessment := ControlAssessment{
		ControlID: "A.16",
		Name:      "Information Security Incident Management",
		Evidence:  []string{},
		Findings:  []string{},
	}
	score := 100.0
	q := s.newMetricQuery(ctx)

	// Check security alerts
	var totalAlerts, resolvedAlerts int
	q.scan("security alerts in period", &totalAlerts, `
		SELECT COUNT(*) FROM security_alerts
		WHERE created_at BETWEEN $1 AND $2
		  AND org_id = $3
	`, startDate, endDate, q.org())

	q.scan("resolved alerts", &resolvedAlerts, `
		SELECT COUNT(*) FROM security_alerts
		WHERE created_at BETWEEN $1 AND $2
		  AND status = 'resolved'
		  AND org_id = $3
	`, startDate, endDate, q.org())

	assessment.Evidence = append(assessment.Evidence,
		fmt.Sprintf("Security alerts in period: %d (resolved: %d)", totalAlerts, resolvedAlerts))

	if totalAlerts > 0 {
		resolutionRate := float64(resolvedAlerts) / float64(totalAlerts) * 100
		assessment.Evidence = append(assessment.Evidence,
			fmt.Sprintf("Alert resolution rate: %.1f%%", resolutionRate))

		if resolutionRate < 50 {
			score -= 25
			assessment.Findings = append(assessment.Findings,
				fmt.Sprintf("Alert resolution rate is %.1f%% (below 50%%)", resolutionRate))
			assessment.Remediation = append(assessment.Remediation,
				"Improve incident response process to address all security alerts")
		}
	}

	// Check average response time for resolved alerts
	var avgResponseHours *float64
	q.scan("average alert response time", &avgResponseHours, `
		SELECT AVG(EXTRACT(EPOCH FROM (resolved_at - created_at)) / 3600.0)
		FROM security_alerts
		WHERE created_at BETWEEN $1 AND $2
		  AND status = 'resolved'
		  AND resolved_at IS NOT NULL
		  AND org_id = $3
	`, startDate, endDate, q.org())

	if avgResponseHours != nil {
		assessment.Evidence = append(assessment.Evidence,
			fmt.Sprintf("Average incident response time: %.1f hours", *avgResponseHours))

		if *avgResponseHours > 24 {
			score -= 20
			assessment.Findings = append(assessment.Findings,
				fmt.Sprintf("Average response time is %.1f hours (exceeds 24-hour threshold)", *avgResponseHours))
			assessment.Remediation = append(assessment.Remediation,
				"Establish SLAs for incident response and reduce response time to under 24 hours")
		}
	} else if totalAlerts > 0 {
		score -= 15
		assessment.Findings = append(assessment.Findings,
			"No response time data available for resolved alerts")
		assessment.Remediation = append(assessment.Remediation,
			"Track alert resolution timestamps for response time metrics")
	}

	// Check for high-risk events that were not alerted
	var highRiskLogins int
	q.scan("high risk logins", &highRiskLogins, `
		SELECT COUNT(*) FROM login_history
		WHERE risk_score >= 70
		  AND created_at BETWEEN $1 AND $2
		  AND org_id = $3
	`, startDate, endDate, q.org())

	if highRiskLogins > 0 {
		assessment.Evidence = append(assessment.Evidence,
			fmt.Sprintf("High-risk logins (score >= 70): %d", highRiskLogins))
	}

	if err := q.failed(); err != nil {
		return ControlAssessment{}, err
	}
	assessment.Score = score
	assessment.Status = scoreToStatus(score)
	return assessment, nil
}

// handleGenerateSOC2Detailed handles POST requests to generate a detailed SOC 2 report.
func (s *Service) handleGenerateSOC2DetailedV2(c *gin.Context) {
	var req struct {
		StartDate string `json:"start_date"`
		EndDate   string `json:"end_date"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}

	startDate, err := time.Parse("2006-01-02", req.StartDate)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid start_date format, expected YYYY-MM-DD"})
		return
	}

	endDate, err := time.Parse("2006-01-02", req.EndDate)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid end_date format, expected YYYY-MM-DD"})
		return
	}
	// Include the entire end day
	endDate = endDate.Add(24*time.Hour - time.Second)

	report, err := s.GenerateSOC2DetailedReport(c.Request.Context(), startDate, endDate)
	if err != nil {
		s.logger.Error("Failed to generate SOC 2 detailed report", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate report"})
		return
	}

	c.JSON(http.StatusCreated, report)
}

// handleGenerateISO27001Detailed handles POST requests to generate a detailed ISO 27001 report.
func (s *Service) handleGenerateISO27001DetailedV2(c *gin.Context) {
	var req struct {
		StartDate string `json:"start_date"`
		EndDate   string `json:"end_date"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}

	startDate, err := time.Parse("2006-01-02", req.StartDate)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid start_date format, expected YYYY-MM-DD"})
		return
	}

	endDate, err := time.Parse("2006-01-02", req.EndDate)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid end_date format, expected YYYY-MM-DD"})
		return
	}
	endDate = endDate.Add(24*time.Hour - time.Second)

	report, err := s.GenerateISO27001DetailedReport(c.Request.Context(), startDate, endDate)
	if err != nil {
		s.logger.Error("Failed to generate ISO 27001 detailed report", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate report"})
		return
	}

	c.JSON(http.StatusCreated, report)
}

// handleDownloadEvidence returns a JSON evidence package for a stored detailed compliance report.
// GET /reports/:id/evidence
func (s *Service) handleDownloadEvidence(c *gin.Context) {
	reportID := c.Param("id")
	ctx := c.Request.Context()

	// Load the stored detailed report, org-scoped: a report id from another
	// tenant must behave exactly like a missing report (the fallback below is
	// org-scoped too via GetComplianceReport).
	org, orgErr := orgctx.From(ctx)
	if orgErr != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "report not found"})
		return
	}
	var reportJSON []byte
	err := s.db.Pool.QueryRow(ctx, `
		SELECT report_data
		FROM detailed_compliance_reports
		WHERE id = $1 AND org_id = $2
	`, reportID, org.ID).Scan(&reportJSON)
	if err != nil {
		// Fallback: try loading from compliance_reports and reconstruct
		report, fallbackErr := s.GetComplianceReport(ctx, reportID)
		if fallbackErr != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "report not found"})
			return
		}

		// Build evidence package from the basic report
		evidencePackage := map[string]interface{}{
			"report_id":    report.ID,
			"framework":    report.Framework,
			"generated_at": report.GeneratedAt,
			"period": map[string]interface{}{
				"start_date": report.StartDate.Format("2006-01-02"),
				"end_date":   report.EndDate.Format("2006-01-02"),
			},
			"findings": report.Findings,
			"summary":  report.Summary,
		}

		c.Header("Content-Disposition",
			fmt.Sprintf("attachment; filename=evidence_%s_%s.json", report.Framework, report.GeneratedAt.Format("2006-01-02")))
		c.JSON(http.StatusOK, evidencePackage)
		return
	}

	// Parse and return the detailed report as an evidence package
	var report DetailedComplianceReport
	if err := json.Unmarshal(reportJSON, &report); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse stored report"})
		return
	}

	evidencePackage := map[string]interface{}{
		"report_id":     report.ID,
		"framework":     report.Framework,
		"period":        report.Period,
		"generated_at":  report.GeneratedAt,
		"overall_score": report.OverallScore,
		"summary":       report.Summary,
		"controls":      report.Controls,
	}

	c.Header("Content-Disposition",
		fmt.Sprintf("attachment; filename=evidence_%s_%s.json", report.Framework, report.GeneratedAt.Format("2006-01-02")))
	c.JSON(http.StatusOK, evidencePackage)
}

// storeDetailedReport persists a DetailedComplianceReport to the database,
// scoped to the caller's org (detailed_compliance_reports is created by
// migration v74 — it was previously a phantom table and every store silently
// failed). Returns the error so callers surface persistence failures loudly
// instead of swallowing them at Warn.
func (s *Service) storeDetailedReport(ctx context.Context, report *DetailedComplianceReport) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	reportJSON, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("marshal detailed report: %w", err)
	}

	if _, err = s.db.Pool.Exec(ctx, `
		INSERT INTO detailed_compliance_reports (id, org_id, framework, period, generated_at, overall_score, summary, report_data)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (id) DO NOTHING
	`, report.ID, org.ID, report.Framework, report.Period, report.GeneratedAt, report.OverallScore, report.Summary, reportJSON); err != nil {
		return fmt.Errorf("insert detailed report: %w", err)
	}
	return nil
}

// scoreToStatus converts a numeric score (0-100) to a compliance status string.
func scoreToStatus(score float64) string {
	switch {
	case score >= 80:
		return "compliant"
	case score >= 50:
		return "partial"
	default:
		return "non_compliant"
	}
}
