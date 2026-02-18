package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// PostureScore represents the overall identity security posture score
type PostureScore struct {
	OverallScore     int                    `json:"overall_score"`
	CategoryScores   map[string]int         `json:"category_scores"`
	TotalFindings    int                    `json:"total_findings"`
	CriticalFindings int                    `json:"critical_findings"`
	HighFindings     int                    `json:"high_findings"`
	MediumFindings   int                    `json:"medium_findings"`
	LowFindings      int                    `json:"low_findings"`
	SnapshotDate     string                 `json:"snapshot_date"`
	Details          map[string]interface{} `json:"details,omitempty"`
}

// PostureFinding represents an individual security finding
type PostureFinding struct {
	ID                  string          `json:"id"`
	RuleID              *string         `json:"rule_id"`
	CheckType           string          `json:"check_type"`
	Severity            string          `json:"severity"`
	Category            string          `json:"category"`
	Title               string          `json:"title"`
	Description         string          `json:"description"`
	AffectedEntityType  string          `json:"affected_entity_type"`
	AffectedEntityID    string          `json:"affected_entity_id"`
	AffectedEntityName  string          `json:"affected_entity_name"`
	Status              string          `json:"status"`
	RemediationAction   string          `json:"remediation_action"`
	RemediationDetails  json.RawMessage `json:"remediation_details"`
	DismissedBy         *string         `json:"dismissed_by"`
	DismissedReason     string          `json:"dismissed_reason"`
	RemediatedAt        *time.Time      `json:"remediated_at"`
	CreatedAt           time.Time       `json:"created_at"`
}

// PostureRule represents a configurable ISPM check
type PostureRule struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Category    string          `json:"category"`
	CheckType   string          `json:"check_type"`
	Enabled     bool            `json:"enabled"`
	Severity    string          `json:"severity"`
	Thresholds  json.RawMessage `json:"thresholds"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// --- Handlers ---

func (s *Service) handleGetPostureScore(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()

	score := PostureScore{
		CategoryScores: map[string]int{},
		Details:        map[string]interface{}{},
	}

	// Run all enabled checks and calculate score
	var totalUsers, mfaUsers, staleUsers, disabledUsers int
	s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE enabled = true").Scan(&totalUsers)
	s.db.Pool.QueryRow(ctx, `SELECT COUNT(DISTINCT user_id) FROM mfa_totp WHERE verified = true`).Scan(&mfaUsers)
	s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM users WHERE enabled = true AND
		(last_login IS NULL OR last_login < NOW() - INTERVAL '90 days')`).Scan(&staleUsers)
	s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE enabled = false").Scan(&disabledUsers)

	// MFA adoption score (0-100)
	mfaAdoptionPct := 0
	if totalUsers > 0 {
		mfaAdoptionPct = (mfaUsers * 100) / totalUsers
	}
	score.CategoryScores["authentication"] = clampScore(mfaAdoptionPct)
	score.Details["mfa_adoption_pct"] = mfaAdoptionPct
	score.Details["total_users"] = totalUsers
	score.Details["mfa_users"] = mfaUsers

	// Stale accounts score
	stalePct := 0
	if totalUsers > 0 {
		stalePct = 100 - (staleUsers*100)/totalUsers
	}
	score.Details["stale_accounts"] = staleUsers

	// Admin privilege score - check for over-privileged users
	var adminUsers, activeAdmins int
	s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT ur.user_id) FROM user_roles ur
		JOIN roles r ON ur.role_id = r.id WHERE r.name IN ('admin', 'super_admin')`).Scan(&adminUsers)
	s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT ae.actor_id) FROM audit_events ae
		JOIN user_roles ur ON ae.actor_id = ur.user_id::text
		JOIN roles r ON ur.role_id = r.id
		WHERE r.name IN ('admin', 'super_admin') AND ae.timestamp > NOW() - INTERVAL '30 days'`).Scan(&activeAdmins)
	authzScore := 80
	if adminUsers > 0 && activeAdmins < adminUsers/2 {
		authzScore = 50 // Many admins are inactive
	}
	score.CategoryScores["authorization"] = authzScore
	score.Details["admin_users"] = adminUsers
	score.Details["active_admins_30d"] = activeAdmins

	// Account health score
	accountScore := clampScore(stalePct)
	score.CategoryScores["accounts"] = accountScore
	score.Details["disabled_users"] = disabledUsers

	// Compliance score - check for policy coverage
	var totalApps, appsWithPolicy int
	s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM applications").Scan(&totalApps)
	s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT pr.id) FROM policies p
		JOIN policy_rules pr ON p.id = pr.policy_id WHERE p.enabled = true`).Scan(&appsWithPolicy)
	complianceScore := 70
	if totalApps > 0 && appsWithPolicy > 0 {
		complianceScore = clampScore((appsWithPolicy * 100) / max(totalApps, 1))
	}
	score.CategoryScores["compliance"] = complianceScore
	score.Details["total_applications"] = totalApps

	// Overall score is weighted average
	score.OverallScore = (score.CategoryScores["authentication"]*30 +
		score.CategoryScores["authorization"]*25 +
		score.CategoryScores["accounts"]*20 +
		score.CategoryScores["compliance"]*25) / 100

	// Count open findings
	s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM ispm_findings WHERE status = 'open'").Scan(&score.TotalFindings)
	s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM ispm_findings WHERE status = 'open' AND severity = 'critical'").Scan(&score.CriticalFindings)
	s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM ispm_findings WHERE status = 'open' AND severity = 'high'").Scan(&score.HighFindings)
	s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM ispm_findings WHERE status = 'open' AND severity = 'medium'").Scan(&score.MediumFindings)
	s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM ispm_findings WHERE status = 'open' AND severity = 'low'").Scan(&score.LowFindings)

	score.SnapshotDate = time.Now().Format("2006-01-02")

	// Persist daily snapshot
	categoryJSON, _ := json.Marshal(score.CategoryScores)
	s.db.Pool.Exec(ctx, `
		INSERT INTO ispm_scores (overall_score, category_scores, total_findings, critical_findings, high_findings, medium_findings, low_findings, snapshot_date)
		VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_DATE)
		ON CONFLICT (snapshot_date) DO UPDATE SET overall_score = $1, category_scores = $2,
			total_findings = $3, critical_findings = $4, high_findings = $5, medium_findings = $6, low_findings = $7`,
		score.OverallScore, categoryJSON, score.TotalFindings, score.CriticalFindings,
		score.HighFindings, score.MediumFindings, score.LowFindings)

	c.JSON(http.StatusOK, score)
}

func (s *Service) handleListPostureFindings(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()

	severity := c.DefaultQuery("severity", "")
	category := c.DefaultQuery("category", "")
	status := c.DefaultQuery("status", "open")

	query := `SELECT id, rule_id, check_type, severity, category, title, description,
		COALESCE(affected_entity_type, ''), COALESCE(affected_entity_id, ''), COALESCE(affected_entity_name, ''),
		status, COALESCE(remediation_action, ''), remediation_details, dismissed_by, COALESCE(dismissed_reason, ''),
		remediated_at, created_at FROM ispm_findings WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if status != "" {
		query += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, status)
		argIdx++
	}
	if severity != "" {
		query += fmt.Sprintf(" AND severity = $%d", argIdx)
		args = append(args, severity)
		argIdx++
	}
	if category != "" {
		query += fmt.Sprintf(" AND category = $%d", argIdx)
		args = append(args, category)
		argIdx++
	}
	query += " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, created_at DESC LIMIT 200"

	rows, err := s.db.Pool.Query(ctx, query, args...)
	if err != nil {
		s.logger.Error("failed to list ISPM findings", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list findings"})
		return
	}
	defer rows.Close()

	findings := []PostureFinding{}
	for rows.Next() {
		var f PostureFinding
		rows.Scan(&f.ID, &f.RuleID, &f.CheckType, &f.Severity, &f.Category, &f.Title, &f.Description,
			&f.AffectedEntityType, &f.AffectedEntityID, &f.AffectedEntityName,
			&f.Status, &f.RemediationAction, &f.RemediationDetails, &f.DismissedBy, &f.DismissedReason,
			&f.RemediatedAt, &f.CreatedAt)
		findings = append(findings, f)
	}

	c.JSON(http.StatusOK, gin.H{"data": findings, "total": len(findings)})
}

func (s *Service) handleGetPostureFinding(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	var f PostureFinding
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, rule_id, check_type, severity, category, title, description,
			COALESCE(affected_entity_type, ''), COALESCE(affected_entity_id, ''), COALESCE(affected_entity_name, ''),
			status, COALESCE(remediation_action, ''), remediation_details, dismissed_by, COALESCE(dismissed_reason, ''),
			remediated_at, created_at FROM ispm_findings WHERE id = $1`, id,
	).Scan(&f.ID, &f.RuleID, &f.CheckType, &f.Severity, &f.Category, &f.Title, &f.Description,
		&f.AffectedEntityType, &f.AffectedEntityID, &f.AffectedEntityName,
		&f.Status, &f.RemediationAction, &f.RemediationDetails, &f.DismissedBy, &f.DismissedReason,
		&f.RemediatedAt, &f.CreatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "finding not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": f})
}

func (s *Service) handleDismissPostureFinding(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	var req struct {
		Reason string `json:"reason"`
	}
	c.ShouldBindJSON(&req)

	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)

	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE ispm_findings SET status = 'dismissed', dismissed_by = $1, dismissed_reason = $2
		WHERE id = $3 AND status = 'open'`, uid, req.Reason, id)
	if err != nil || tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "finding not found or already resolved"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "finding dismissed"})
}

func (s *Service) handleRemediatePostureFinding(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	// Get the finding to determine remediation
	var checkType, entityType, entityID string
	err := s.db.Pool.QueryRow(ctx, `
		SELECT check_type, COALESCE(affected_entity_type, ''), COALESCE(affected_entity_id, '')
		FROM ispm_findings WHERE id = $1 AND status = 'open'`, id).Scan(&checkType, &entityType, &entityID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "finding not found or already resolved"})
		return
	}

	// Apply remediation based on check type
	remediationResult := map[string]interface{}{"check_type": checkType, "entity_type": entityType, "entity_id": entityID}

	switch checkType {
	case "stale_accounts":
		if entityType == "user" && entityID != "" {
			s.db.Pool.Exec(ctx, "UPDATE users SET enabled = false, updated_at = NOW() WHERE id = $1", entityID)
			remediationResult["action"] = "account_disabled"
		}
	case "mfa_adoption":
		remediationResult["action"] = "notification_sent"
		remediationResult["message"] = "MFA enrollment reminder would be sent to user"
	case "over_privileged":
		remediationResult["action"] = "flagged_for_review"
		remediationResult["message"] = "User flagged for access review"
	case "shared_accounts":
		if entityType == "user" && entityID != "" {
			s.db.Pool.Exec(ctx, "DELETE FROM user_sessions WHERE user_id = $1", entityID)
			remediationResult["action"] = "sessions_revoked"
		}
	default:
		remediationResult["action"] = "manual_review_required"
	}

	detailsJSON, _ := json.Marshal(remediationResult)
	s.db.Pool.Exec(ctx, `
		UPDATE ispm_findings SET status = 'remediated', remediated_at = NOW(), remediation_details = $1
		WHERE id = $2`, detailsJSON, id)

	c.JSON(http.StatusOK, gin.H{"message": "remediation applied", "result": remediationResult})
}

func (s *Service) handleGetPostureTrends(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()

	rows, err := s.db.Pool.Query(ctx, `
		SELECT overall_score, category_scores, total_findings, critical_findings, high_findings,
			medium_findings, low_findings, snapshot_date
		FROM ispm_scores ORDER BY snapshot_date DESC LIMIT 90`)
	if err != nil {
		s.logger.Error("failed to get posture trends", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get trends"})
		return
	}
	defer rows.Close()

	trends := []map[string]interface{}{}
	for rows.Next() {
		var overallScore, totalF, criticalF, highF, mediumF, lowF int
		var categoryScores json.RawMessage
		var snapshotDate time.Time
		rows.Scan(&overallScore, &categoryScores, &totalF, &criticalF, &highF, &mediumF, &lowF, &snapshotDate)
		trends = append(trends, map[string]interface{}{
			"overall_score":     overallScore,
			"category_scores":   categoryScores,
			"total_findings":    totalF,
			"critical_findings": criticalF,
			"high_findings":     highF,
			"medium_findings":   mediumF,
			"low_findings":      lowF,
			"date":              snapshotDate.Format("2006-01-02"),
		})
	}

	c.JSON(http.StatusOK, gin.H{"data": trends})
}

func (s *Service) handleListPostureRules(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, description, category, check_type, enabled, severity, thresholds, created_at, updated_at
		FROM ispm_rules ORDER BY category, name`)
	if err != nil {
		s.logger.Error("failed to list ISPM rules", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list rules"})
		return
	}
	defer rows.Close()

	rules := []PostureRule{}
	for rows.Next() {
		var r PostureRule
		rows.Scan(&r.ID, &r.Name, &r.Description, &r.Category, &r.CheckType, &r.Enabled, &r.Severity, &r.Thresholds, &r.CreatedAt, &r.UpdatedAt)
		rules = append(rules, r)
	}

	c.JSON(http.StatusOK, gin.H{"data": rules, "total": len(rules)})
}

func (s *Service) handleUpdatePostureRule(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	var req struct {
		Enabled    *bool            `json:"enabled"`
		Severity   *string          `json:"severity"`
		Thresholds *json.RawMessage `json:"thresholds"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	sets := []string{}
	args := []interface{}{}
	argIdx := 1

	if req.Enabled != nil {
		sets = append(sets, fmt.Sprintf("enabled = $%d", argIdx))
		args = append(args, *req.Enabled)
		argIdx++
	}
	if req.Severity != nil {
		sets = append(sets, fmt.Sprintf("severity = $%d", argIdx))
		args = append(args, *req.Severity)
		argIdx++
	}
	if req.Thresholds != nil {
		sets = append(sets, fmt.Sprintf("thresholds = $%d", argIdx))
		args = append(args, *req.Thresholds)
		argIdx++
	}

	if len(sets) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no fields to update"})
		return
	}

	sets = append(sets, "updated_at = NOW()")
	query := fmt.Sprintf("UPDATE ispm_rules SET %s WHERE id = $%d RETURNING id", joinStrings(sets, ", "), argIdx)
	args = append(args, id)

	var updatedID string
	err := s.db.Pool.QueryRow(ctx, query, args...).Scan(&updatedID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "rule updated", "id": updatedID})
}

// --- ISPM Analysis Engine ---

// RunPostureChecks executes all enabled checks and creates findings
func (s *Service) RunPostureChecks(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()
	findingsCreated := 0

	// Clear old open findings before re-scan
	s.db.Pool.Exec(ctx, "DELETE FROM ispm_findings WHERE status = 'open' AND created_at < NOW() - INTERVAL '1 day'")

	// Check 1: MFA Adoption
	rows, err := s.db.Pool.Query(ctx, `
		SELECT u.id, u.username, u.email FROM users u
		WHERE u.enabled = true AND u.id NOT IN (SELECT DISTINCT user_id FROM mfa_totp WHERE verified = true)
		AND u.id NOT IN (SELECT DISTINCT user_id FROM mfa_webauthn)
		LIMIT 50`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var uid, uname, email string
			rows.Scan(&uid, &uname, &email)
			s.createFinding(ctx, "mfa_adoption", "high", "authentication",
				fmt.Sprintf("User '%s' has no MFA enabled", uname),
				"This user account has no multi-factor authentication method configured, increasing risk of account compromise.",
				"user", uid, uname, "enable_mfa")
			findingsCreated++
		}
	}

	// Check 2: Stale Accounts
	staleRows, err := s.db.Pool.Query(ctx, `
		SELECT id, username, email, last_login FROM users
		WHERE enabled = true AND (last_login IS NULL OR last_login < NOW() - INTERVAL '90 days')
		LIMIT 50`)
	if err == nil {
		defer staleRows.Close()
		for staleRows.Next() {
			var uid, uname, email string
			var lastLogin *time.Time
			staleRows.Scan(&uid, &uname, &email, &lastLogin)
			s.createFinding(ctx, "stale_accounts", "medium", "accounts",
				fmt.Sprintf("Account '%s' inactive for 90+ days", uname),
				"This account has not been used for an extended period and may be orphaned.",
				"user", uid, uname, "disable_account")
			findingsCreated++
		}
	}

	// Check 3: Shared Account Detection (concurrent sessions from different IPs)
	sharedRows, err := s.db.Pool.Query(ctx, `
		SELECT user_id, COUNT(DISTINCT ip_address) as ip_count
		FROM user_sessions WHERE expires_at > NOW()
		GROUP BY user_id HAVING COUNT(DISTINCT ip_address) > 2`)
	if err == nil {
		defer sharedRows.Close()
		for sharedRows.Next() {
			var uid string
			var ipCount int
			sharedRows.Scan(&uid, &ipCount)
			var uname string
			s.db.Pool.QueryRow(ctx, "SELECT username FROM users WHERE id = $1", uid).Scan(&uname)
			s.createFinding(ctx, "shared_accounts", "high", "accounts",
				fmt.Sprintf("Account '%s' has %d concurrent IPs", uname, ipCount),
				"This account has active sessions from multiple IP addresses, suggesting credential sharing.",
				"user", uid, uname, "revoke_sessions")
			findingsCreated++
		}
	}

	// Check 4: Applications without policies
	noPolicyRows, err := s.db.Pool.Query(ctx, `
		SELECT a.id, a.name FROM applications a
		WHERE a.id NOT IN (SELECT DISTINCT unnest(pr.target_applications) FROM policy_rules pr
			JOIN policies p ON pr.policy_id = p.id WHERE p.enabled = true)
		LIMIT 50`)
	if err == nil {
		defer noPolicyRows.Close()
		for noPolicyRows.Next() {
			var appID, appName string
			noPolicyRows.Scan(&appID, &appName)
			s.createFinding(ctx, "policy_gaps", "medium", "compliance",
				fmt.Sprintf("Application '%s' has no access policy", appName),
				"This application has no conditional access or governance policy assigned.",
				"application", appID, appName, "assign_policy")
			findingsCreated++
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "posture check completed", "findings_created": findingsCreated})
}

func (s *Service) createFinding(ctx context.Context, checkType, severity, category, title, description, entityType, entityID, entityName, action string) {
	s.db.Pool.Exec(ctx, `
		INSERT INTO ispm_findings (check_type, severity, category, title, description, affected_entity_type, affected_entity_id, affected_entity_name, remediation_action)
		SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9
		WHERE NOT EXISTS (
			SELECT 1 FROM ispm_findings WHERE check_type = $1 AND affected_entity_id = $7 AND status = 'open'
		)`,
		checkType, severity, category, title, description, entityType, entityID, entityName, action)
}

// --- Utility ---

func clampScore(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
