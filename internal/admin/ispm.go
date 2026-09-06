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

// Identity Security Posture Management.
//
// Two things about this file were false before v138 and are pinned by
// tenant_isolation_test.go now:
//
//   - The three ispm_* tables had no org_id, and every handler here addressed
//     them by bare id. The posture score added one tenant's identity metrics to
//     the whole install's finding counts; one snapshot row per day was shared
//     by every tenant (whoever scanned last won); "Scan" deleted every other
//     tenant's day-old open findings; and list / get / dismiss / remediate /
//     rule-update all worked across tenants. Each query now carries the org
//     from the request context as an explicit predicate, with the FORCE-RLS
//     policy from v138 as the belt underneath.
//
//   - The Rules page was a display without an enforcement: RunPostureChecks
//     hardcoded its checks and never read ispm_rules, so toggling a rule off or
//     changing its severity or thresholds changed nothing. The scan now loads
//     the org's rules, skips a disabled one, uses its severity and thresholds,
//     and stamps rule_id on the findings it raises. Rules are seeded per org
//     from postureCheckDefs on first use (the install-wide seed in
//     deployments/docker/seed.sql was removed with v138: a single seed row
//     cannot belong to every tenant). A rule row whose check_type has no
//     implementation — the pre-v138 seed shipped six of those — is reported
//     with implemented=false and cannot be enabled, so the page cannot show a
//     live toggle for a check that never runs.
//
// Three of the four checks also referenced columns that do not exist
// (mfa_totp.verified, users.last_login, policy_rules.target_applications) and
// swallowed the error, so a scan silently produced nothing for them. The
// queries below are the ones the schema actually has, and a failing check is
// logged and counted in the response instead of being hidden.

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
	ID                 string          `json:"id"`
	RuleID             *string         `json:"rule_id"`
	CheckType          string          `json:"check_type"`
	Severity           string          `json:"severity"`
	Category           string          `json:"category"`
	Title              string          `json:"title"`
	Description        string          `json:"description"`
	AffectedEntityType string          `json:"affected_entity_type"`
	AffectedEntityID   string          `json:"affected_entity_id"`
	AffectedEntityName string          `json:"affected_entity_name"`
	Status             string          `json:"status"`
	RemediationAction  string          `json:"remediation_action"`
	RemediationDetails json.RawMessage `json:"remediation_details"`
	DismissedBy        *string         `json:"dismissed_by"`
	DismissedReason    string          `json:"dismissed_reason"`
	RemediatedAt       *time.Time      `json:"remediated_at"`
	CreatedAt          time.Time       `json:"created_at"`
}

// PostureRule represents a configurable ISPM check. Implemented reports
// whether the scan engine has code for this check_type: a rule the engine
// cannot run must not render as a live toggle.
type PostureRule struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Category    string          `json:"category"`
	CheckType   string          `json:"check_type"`
	Enabled     bool            `json:"enabled"`
	Severity    string          `json:"severity"`
	Thresholds  json.RawMessage `json:"thresholds"`
	Implemented bool            `json:"implemented"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// postureCheckDef is one check the engine can run, with the rule row it seeds
// for a new org. This slice is the single source of truth for which
// check_types exist: the seeder, the Implemented flag and the scan all read it.
type postureCheckDef struct {
	CheckType   string
	Name        string
	Description string
	Category    string
	Severity    string
	Thresholds  map[string]int
}

var postureCheckDefs = []postureCheckDef{
	{
		CheckType:   "mfa_adoption",
		Name:        "MFA Adoption Check",
		Description: "Enabled users with no MFA method, and org-wide adoption below min_adoption_pct",
		Category:    "authentication",
		Severity:    "high",
		Thresholds:  map[string]int{"min_adoption_pct": 90},
	},
	{
		CheckType:   "stale_accounts",
		Name:        "Stale Account Detection",
		Description: "Enabled accounts with no login for more than inactive_days",
		Category:    "accounts",
		Severity:    "medium",
		Thresholds:  map[string]int{"inactive_days": 90},
	},
	{
		CheckType:   "shared_accounts",
		Name:        "Shared Account Detection",
		Description: "Accounts with live sessions from more than max_concurrent_ips distinct addresses",
		Category:    "accounts",
		Severity:    "high",
		Thresholds:  map[string]int{"max_concurrent_ips": 2},
	},
	{
		CheckType:   "policy_gaps",
		Name:        "Policy Gap Detection",
		Description: "Enabled applications in an organization that has no enabled access policy",
		Category:    "compliance",
		Severity:    "medium",
		Thresholds:  map[string]int{},
	},
}

func postureCheckImplemented(checkType string) bool {
	for _, d := range postureCheckDefs {
		if d.CheckType == checkType {
			return true
		}
	}
	return false
}

// ensureDefaultRules seeds the org's rule rows for every implemented check.
// Idempotent on (org_id, check_type), so it is safe to call on every rules
// list and every scan; an org that already customised a rule keeps it.
func (s *Service) ensureDefaultRules(ctx context.Context, orgID string) error {
	for _, d := range postureCheckDefs {
		thresholds, _ := json.Marshal(d.Thresholds)
		if _, err := s.db.Pool.Exec(ctx, `
			INSERT INTO ispm_rules (org_id, name, description, category, check_type, severity, thresholds)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (org_id, check_type) DO NOTHING`,
			orgID, d.Name, d.Description, d.Category, d.CheckType, d.Severity, thresholds); err != nil {
			return fmt.Errorf("seed rule %s: %w", d.CheckType, err)
		}
	}
	return nil
}

// loadPostureRules returns the org's rules keyed by check_type.
func (s *Service) loadPostureRules(ctx context.Context, orgID string) (map[string]PostureRule, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, description, category, check_type, enabled, severity, thresholds, created_at, updated_at
		FROM ispm_rules WHERE org_id = $1`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]PostureRule{}
	for rows.Next() {
		var r PostureRule
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.Category, &r.CheckType, &r.Enabled, &r.Severity, &r.Thresholds, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		r.Implemented = postureCheckImplemented(r.CheckType)
		out[r.CheckType] = r
	}
	return out, rows.Err()
}

// threshold reads an integer threshold off the rule's JSON, falling back to
// the default when the key is absent or not a number.
func (r PostureRule) threshold(key string, def int) int {
	if len(r.Thresholds) == 0 {
		return def
	}
	var m map[string]json.Number
	if err := json.Unmarshal(r.Thresholds, &m); err != nil {
		return def
	}
	n, ok := m[key]
	if !ok {
		return def
	}
	f, err := n.Float64()
	if err != nil || f <= 0 {
		return def
	}
	return int(f)
}

// scanCount runs a single-value COUNT query. A failing query is logged and
// yields 0 — the previous code discarded the error, which is how three
// mistyped column names went unnoticed while the score displayed zeros.
func (s *Service) scanCount(ctx context.Context, what, query string, args ...interface{}) int {
	var n int
	if err := s.db.Pool.QueryRow(ctx, query, args...).Scan(&n); err != nil {
		s.logger.Warn("ISPM metric query failed", zap.String("metric", what), zap.Error(err))
		return 0
	}
	return n
}

// --- Handlers ---

func (s *Service) handleGetPostureScore(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	org, ok := requireOrg(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()

	score := PostureScore{
		CategoryScores: map[string]int{},
		Details:        map[string]interface{}{},
	}

	// Identity metrics. mfa_totp has `enabled` (no `verified` column) and
	// users has `last_login_at` (no `last_login`).
	totalUsers := s.scanCount(ctx, "total_users", "SELECT COUNT(*) FROM users WHERE enabled = true AND org_id = $1", org.ID)
	mfaUsers := s.scanCount(ctx, "mfa_users", `
		SELECT COUNT(DISTINCT user_id) FROM (
			SELECT user_id FROM mfa_totp WHERE enabled = true AND org_id = $1
			UNION
			SELECT user_id FROM mfa_webauthn WHERE org_id = $1
		) m`, org.ID)
	staleUsers := s.scanCount(ctx, "stale_users", `
		SELECT COUNT(*) FROM users WHERE org_id = $1 AND enabled = true AND
		(last_login_at IS NULL OR last_login_at < NOW() - INTERVAL '90 days')`, org.ID)
	disabledUsers := s.scanCount(ctx, "disabled_users", "SELECT COUNT(*) FROM users WHERE enabled = false AND org_id = $1", org.ID)

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
	adminUsers := s.scanCount(ctx, "admin_users", `
		SELECT COUNT(DISTINCT ur.user_id) FROM user_roles ur
		JOIN roles r ON ur.role_id = r.id AND r.org_id = ur.org_id
		WHERE ur.org_id = $1 AND r.name IN ('admin', 'super_admin')`, org.ID)
	activeAdmins := s.scanCount(ctx, "active_admins", `
		SELECT COUNT(DISTINCT ae.actor_id) FROM audit_events ae
		JOIN user_roles ur ON ae.actor_id = ur.user_id::text AND ur.org_id = ae.org_id
		JOIN roles r ON ur.role_id = r.id AND r.org_id = ur.org_id
		WHERE ae.org_id = $1 AND r.name IN ('admin', 'super_admin') AND ae.timestamp > NOW() - INTERVAL '30 days'`, org.ID)
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

	// Compliance score - policy coverage. There is no app<->policy join in the
	// schema (policy_rules has no target_applications), so coverage is enabled
	// policies against enabled applications.
	totalApps := s.scanCount(ctx, "total_apps", "SELECT COUNT(*) FROM applications WHERE org_id = $1", org.ID)
	enabledPolicies := s.scanCount(ctx, "enabled_policies", "SELECT COUNT(*) FROM policies WHERE org_id = $1 AND enabled = true", org.ID)
	complianceScore := 70
	if totalApps > 0 && enabledPolicies > 0 {
		complianceScore = clampScore((enabledPolicies * 100) / max(totalApps, 1))
	}
	score.CategoryScores["compliance"] = complianceScore
	score.Details["total_applications"] = totalApps
	score.Details["enabled_policies"] = enabledPolicies

	// Overall score is weighted average
	score.OverallScore = (score.CategoryScores["authentication"]*30 +
		score.CategoryScores["authorization"]*25 +
		score.CategoryScores["accounts"]*20 +
		score.CategoryScores["compliance"]*25) / 100

	// Count this org's open findings
	score.TotalFindings = s.scanCount(ctx, "open_findings", "SELECT COUNT(*) FROM ispm_findings WHERE org_id = $1 AND status = 'open'", org.ID)
	score.CriticalFindings = s.scanCount(ctx, "open_critical", "SELECT COUNT(*) FROM ispm_findings WHERE org_id = $1 AND status = 'open' AND severity = 'critical'", org.ID)
	score.HighFindings = s.scanCount(ctx, "open_high", "SELECT COUNT(*) FROM ispm_findings WHERE org_id = $1 AND status = 'open' AND severity = 'high'", org.ID)
	score.MediumFindings = s.scanCount(ctx, "open_medium", "SELECT COUNT(*) FROM ispm_findings WHERE org_id = $1 AND status = 'open' AND severity = 'medium'", org.ID)
	score.LowFindings = s.scanCount(ctx, "open_low", "SELECT COUNT(*) FROM ispm_findings WHERE org_id = $1 AND status = 'open' AND severity = 'low'", org.ID)

	score.SnapshotDate = time.Now().Format("2006-01-02")

	// Persist the daily snapshot — one per org per day (v138), not one per install.
	categoryJSON, _ := json.Marshal(score.CategoryScores)
	if _, err := s.db.Pool.Exec(ctx, `
		INSERT INTO ispm_scores (org_id, overall_score, category_scores, total_findings, critical_findings, high_findings, medium_findings, low_findings, snapshot_date)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_DATE)
		ON CONFLICT (org_id, snapshot_date) DO UPDATE SET overall_score = $2, category_scores = $3,
			total_findings = $4, critical_findings = $5, high_findings = $6, medium_findings = $7, low_findings = $8`,
		org.ID, score.OverallScore, categoryJSON, score.TotalFindings, score.CriticalFindings,
		score.HighFindings, score.MediumFindings, score.LowFindings); err != nil {
		s.logger.Warn("failed to persist ISPM score snapshot", zap.Error(err))
	}

	c.JSON(http.StatusOK, score)
}

func (s *Service) handleListPostureFindings(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	org, ok := requireOrg(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()

	severity := c.DefaultQuery("severity", "")
	category := c.DefaultQuery("category", "")
	status := c.DefaultQuery("status", "open")

	query := `SELECT id, rule_id, check_type, severity, category, title, description,
		COALESCE(affected_entity_type, ''), COALESCE(affected_entity_id, ''), COALESCE(affected_entity_name, ''),
		status, COALESCE(remediation_action, ''), remediation_details, dismissed_by, COALESCE(dismissed_reason, ''),
		remediated_at, created_at FROM ispm_findings WHERE org_id = $1`
	args := []interface{}{org.ID}
	argIdx := 2

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
	org, ok := requireOrg(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	var f PostureFinding
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, rule_id, check_type, severity, category, title, description,
			COALESCE(affected_entity_type, ''), COALESCE(affected_entity_id, ''), COALESCE(affected_entity_name, ''),
			status, COALESCE(remediation_action, ''), remediation_details, dismissed_by, COALESCE(dismissed_reason, ''),
			remediated_at, created_at FROM ispm_findings WHERE id = $1 AND org_id = $2`, id, org.ID,
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
	org, ok := requireOrg(c)
	if !ok {
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
		WHERE id = $3 AND org_id = $4 AND status = 'open'`, uid, req.Reason, id, org.ID)
	if err != nil || tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "finding not found or already resolved"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "finding dismissed"})
}

// remediationOutcome is what a remediation actually did. resolved is the only
// thing that may move a finding out of 'open': the posture score counts open
// findings, so marking a finding resolved is the same as raising the score,
// and doing that for an action that changed nothing is how a dashboard comes
// to report a posture the install does not have.
type remediationOutcome struct {
	Action   string `json:"action"`
	Message  string `json:"message"`
	Resolved bool   `json:"resolved"`
}

func (s *Service) handleRemediatePostureFinding(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	org, ok := requireOrg(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	var checkType, entityType, entityID string
	err := s.db.Pool.QueryRow(ctx, `
		SELECT check_type, COALESCE(affected_entity_type, ''), COALESCE(affected_entity_id, '')
		FROM ispm_findings WHERE id = $1 AND org_id = $2 AND status = 'open'`, id, org.ID).Scan(&checkType, &entityType, &entityID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "finding not found or already resolved"})
		return
	}

	out := s.remediateFinding(ctx, org.ID, checkType, entityType, entityID)

	details := map[string]interface{}{
		"check_type":   checkType,
		"entity_type":  entityType,
		"entity_id":    entityID,
		"action":       out.Action,
		"message":      out.Message,
		"resolved":     out.Resolved,
		"attempted_at": time.Now().UTC(),
	}
	detailsJSON, _ := json.Marshal(details)

	if out.Resolved {
		if _, err := s.db.Pool.Exec(ctx, `
			UPDATE ispm_findings SET status = 'remediated', remediated_at = NOW(), remediation_details = $1
			WHERE id = $2 AND org_id = $3`, detailsJSON, id, org.ID); err != nil {
			s.logger.Error("failed to record ISPM remediation", zap.Error(err))
		}
	} else {
		// The attempt is recorded, the finding stays OPEN. It leaves 'open'
		// when a scan observes the underlying condition is gone -- not when
		// somebody presses a button.
		if _, err := s.db.Pool.Exec(ctx, `
			UPDATE ispm_findings SET remediation_details = $1
			WHERE id = $2 AND org_id = $3`, detailsJSON, id, org.ID); err != nil {
			s.logger.Error("failed to record ISPM remediation attempt", zap.Error(err))
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  out.Message,
		"resolved": out.Resolved,
		"result":   out,
	})
}

// remediateFinding performs the action a check's remediation means, and says
// truthfully whether the finding is resolved by it.
//
// Two of these used to return a string and nothing else -- mfa_adoption
// answered "MFA enrollment reminder WOULD be sent to user" and over_privileged
// answered "flagged for review" -- and the caller then marked the finding
// remediated regardless, which lowered the open-finding count and raised the
// posture score for work nobody had done. mfa_adoption now really writes the
// notification; the rest say plainly that a human has to act, and leave the
// finding open.
func (s *Service) remediateFinding(ctx context.Context, orgID, checkType, entityType, entityID string) remediationOutcome {
	switch checkType {
	case "stale_accounts":
		if entityType != "user" || entityID == "" {
			return remediationOutcome{Action: "manual_review_required", Message: "the finding names no user to disable", Resolved: false}
		}
		tag, err := s.db.Pool.Exec(ctx,
			"UPDATE users SET enabled = false, updated_at = NOW() WHERE id = $1 AND org_id = $2 AND enabled = true", entityID, orgID)
		if err != nil {
			s.logger.Error("ISPM remediation: disable account failed", zap.Error(err))
			return remediationOutcome{Action: "failed", Message: "could not disable the account", Resolved: false}
		}
		if tag.RowsAffected() == 0 {
			return remediationOutcome{Action: "already_disabled", Message: "the account was already disabled", Resolved: true}
		}
		return remediationOutcome{Action: "account_disabled", Message: "the account has been disabled", Resolved: true}

	case "shared_accounts":
		if entityType != "user" || entityID == "" {
			return remediationOutcome{Action: "manual_review_required", Message: "the finding names no user whose sessions to revoke", Resolved: false}
		}
		tag, err := s.db.Pool.Exec(ctx, "DELETE FROM user_sessions WHERE user_id = $1 AND org_id = $2", entityID, orgID)
		if err != nil {
			s.logger.Error("ISPM remediation: revoke sessions failed", zap.Error(err))
			return remediationOutcome{Action: "failed", Message: "could not revoke the sessions", Resolved: false}
		}
		return remediationOutcome{
			Action:   "sessions_revoked",
			Message:  fmt.Sprintf("%d session(s) revoked", tag.RowsAffected()),
			Resolved: true,
		}

	case "mfa_adoption":
		if entityType != "user" || entityID == "" {
			return remediationOutcome{Action: "manual_review_required", Message: "the finding names no user to remind", Resolved: false}
		}
		// A real notification row, on the same table and shape the broadcast
		// and device-trust paths use (internal/admin/notification_management.go,
		// internal/identity/device_trust_approval.go).
		_, err := s.db.Pool.Exec(ctx, `
			INSERT INTO notifications (user_id, channel, type, title, body, metadata, org_id)
			SELECT id, 'in_app', 'security', $2, $3, jsonb_build_object('source', 'ispm', 'check_type', 'mfa_adoption'), org_id
			FROM users WHERE id = $1 AND org_id = $4`,
			entityID,
			"Set up multi-factor authentication",
			"Your account has no second factor. Add one from Security settings to keep access to your applications.",
			orgID)
		if err != nil {
			s.logger.Error("ISPM remediation: MFA reminder failed", zap.Error(err))
			return remediationOutcome{Action: "failed", Message: "could not queue the MFA reminder", Resolved: false}
		}
		// The reminder is sent; the user still has no MFA. The finding stays
		// open until a scan sees a factor enrolled.
		return remediationOutcome{
			Action:   "reminder_sent",
			Message:  "an MFA enrolment reminder was sent; the finding stays open until the next scan sees a factor enrolled",
			Resolved: false,
		}

	default:
		return remediationOutcome{
			Action:   "manual_review_required",
			Message:  fmt.Sprintf("no automatic remediation exists for %q; the finding stays open until it is fixed or dismissed", checkType),
			Resolved: false,
		}
	}
}

func (s *Service) handleGetPostureTrends(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	org, ok := requireOrg(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()

	rows, err := s.db.Pool.Query(ctx, `
		SELECT overall_score, category_scores, total_findings, critical_findings, high_findings,
			medium_findings, low_findings, snapshot_date
		FROM ispm_scores WHERE org_id = $1 ORDER BY snapshot_date DESC LIMIT 90`, org.ID)
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
	org, ok := requireOrg(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()

	if err := s.ensureDefaultRules(ctx, org.ID); err != nil {
		s.logger.Error("failed to seed ISPM rules", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list rules"})
		return
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, description, category, check_type, enabled, severity, thresholds, created_at, updated_at
		FROM ispm_rules WHERE org_id = $1 ORDER BY category, name`, org.ID)
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
		r.Implemented = postureCheckImplemented(r.CheckType)
		rules = append(rules, r)
	}

	c.JSON(http.StatusOK, gin.H{"data": rules, "total": len(rules)})
}

func (s *Service) handleUpdatePostureRule(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	org, ok := requireOrg(c)
	if !ok {
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

	var checkType string
	if err := s.db.Pool.QueryRow(ctx, "SELECT check_type FROM ispm_rules WHERE id = $1 AND org_id = $2", id, org.ID).Scan(&checkType); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}
	// Enabling a rule the engine cannot run would put a live toggle on the page
	// for a check that never happens — refuse it, and say why.
	if req.Enabled != nil && *req.Enabled && !postureCheckImplemented(checkType) {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("check_type %q is not implemented by this version and cannot be enabled", checkType)})
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
	// SECURITY: Column names in 'sets' are hardcoded string literals from the if-blocks above,
	// not user input. This is safe from SQL injection.
	query := fmt.Sprintf("UPDATE ispm_rules SET %s WHERE id = $%d AND org_id = $%d RETURNING id", joinStrings(sets, ", "), argIdx, argIdx+1)
	args = append(args, id, org.ID)

	var updatedID string
	err := s.db.Pool.QueryRow(ctx, query, args...).Scan(&updatedID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "rule updated", "id": updatedID})
}

// --- ISPM Analysis Engine ---

// RunPostureChecks executes the org's enabled checks and creates findings.
// The response counts what really happened: findings actually inserted,
// checks run, checks skipped because their rule is disabled, and checks whose
// query failed (logged, never hidden).
func (s *Service) RunPostureChecks(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	org, ok := requireOrg(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()

	if err := s.ensureDefaultRules(ctx, org.ID); err != nil {
		s.logger.Error("failed to seed ISPM rules", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "posture check failed"})
		return
	}
	rules, err := s.loadPostureRules(ctx, org.ID)
	if err != nil {
		s.logger.Error("failed to load ISPM rules", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "posture check failed"})
		return
	}

	findingsCreated, checksRun, checksSkipped, checksFailed := 0, 0, 0, 0

	// Clear this org's day-old open findings before the re-scan. Before v138
	// this statement had no org predicate and deleted every tenant's.
	if _, err := s.db.Pool.Exec(ctx, "DELETE FROM ispm_findings WHERE org_id = $1 AND status = 'open' AND created_at < NOW() - INTERVAL '1 day'", org.ID); err != nil {
		s.logger.Warn("ISPM: clearing stale findings failed", zap.Error(err))
	}

	// enabled reports whether the org's rule for checkType is on; the caller
	// skips the check otherwise. A missing rule cannot happen after
	// ensureDefaultRules, but is treated as disabled rather than as "run with
	// defaults" so the Rules page is always the authority.
	enabled := func(checkType string) (PostureRule, bool) {
		r, ok := rules[checkType]
		if !ok || !r.Enabled {
			checksSkipped++
			return r, false
		}
		checksRun++
		return r, true
	}
	failed := func(check string, err error) {
		checksFailed++
		s.logger.Warn("ISPM check failed", zap.String("check", check), zap.Error(err))
	}

	// Check 1: MFA adoption — per user, plus one org-level finding when
	// adoption is below the rule's min_adoption_pct.
	if rule, on := enabled("mfa_adoption"); on {
		rows, err := s.db.Pool.Query(ctx, `
			SELECT u.id, u.username FROM users u
			WHERE u.org_id = $1 AND u.enabled = true
			AND u.id NOT IN (SELECT DISTINCT user_id FROM mfa_totp WHERE enabled = true AND org_id = $1)
			AND u.id NOT IN (SELECT DISTINCT user_id FROM mfa_webauthn WHERE org_id = $1)
			ORDER BY u.username LIMIT 50`, org.ID)
		if err != nil {
			failed("mfa_adoption", err)
		} else {
			for rows.Next() {
				var uid, uname string
				rows.Scan(&uid, &uname)
				if s.createFinding(ctx, org.ID, rule,
					fmt.Sprintf("User '%s' has no MFA enabled", uname),
					"This user account has no multi-factor authentication method configured, increasing risk of account compromise.",
					"user", uid, uname, "enable_mfa") {
					findingsCreated++
				}
			}
			rows.Close()
		}
		total := s.scanCount(ctx, "total_users", "SELECT COUNT(*) FROM users WHERE enabled = true AND org_id = $1", org.ID)
		withMFA := s.scanCount(ctx, "mfa_users", `
			SELECT COUNT(DISTINCT user_id) FROM (
				SELECT user_id FROM mfa_totp WHERE enabled = true AND org_id = $1
				UNION
				SELECT user_id FROM mfa_webauthn WHERE org_id = $1
			) m`, org.ID)
		if total > 0 {
			pct := (withMFA * 100) / total
			if minPct := rule.threshold("min_adoption_pct", 90); pct < minPct {
				if s.createFinding(ctx, org.ID, rule,
					fmt.Sprintf("MFA adoption is %d%%, below the %d%% target", pct, minPct),
					fmt.Sprintf("%d of %d enabled users have an MFA method. The rule's min_adoption_pct threshold is %d.", withMFA, total, minPct),
					"organization", org.ID, "", "enforce_mfa_policy") {
					findingsCreated++
				}
			}
		}
	}

	// Check 2: Stale accounts — the rule's inactive_days decides "stale".
	if rule, on := enabled("stale_accounts"); on {
		days := rule.threshold("inactive_days", 90)
		rows, err := s.db.Pool.Query(ctx, `
			SELECT id, username FROM users
			WHERE org_id = $1 AND enabled = true AND (last_login_at IS NULL OR last_login_at < NOW() - make_interval(days => $2))
			ORDER BY username LIMIT 50`, org.ID, days)
		if err != nil {
			failed("stale_accounts", err)
		} else {
			for rows.Next() {
				var uid, uname string
				rows.Scan(&uid, &uname)
				if s.createFinding(ctx, org.ID, rule,
					fmt.Sprintf("Account '%s' inactive for %d+ days", uname, days),
					"This account has not been used for an extended period and may be orphaned.",
					"user", uid, uname, "disable_account") {
					findingsCreated++
				}
			}
			rows.Close()
		}
	}

	// Check 3: Shared accounts — live sessions from more than
	// max_concurrent_ips distinct addresses.
	if rule, on := enabled("shared_accounts"); on {
		maxIPs := rule.threshold("max_concurrent_ips", 2)
		rows, err := s.db.Pool.Query(ctx, `
			SELECT s.user_id, u.username, COUNT(DISTINCT s.ip_address) AS ip_count
			FROM user_sessions s JOIN users u ON u.id = s.user_id AND u.org_id = s.org_id
			WHERE s.org_id = $1 AND s.expires_at > NOW()
			GROUP BY s.user_id, u.username HAVING COUNT(DISTINCT s.ip_address) > $2`, org.ID, maxIPs)
		if err != nil {
			failed("shared_accounts", err)
		} else {
			for rows.Next() {
				var uid, uname string
				var ipCount int
				rows.Scan(&uid, &uname, &ipCount)
				if s.createFinding(ctx, org.ID, rule,
					fmt.Sprintf("Account '%s' has %d concurrent IPs", uname, ipCount),
					"This account has active sessions from multiple IP addresses, suggesting credential sharing.",
					"user", uid, uname, "revoke_sessions") {
					findingsCreated++
				}
			}
			rows.Close()
		}
	}

	// Check 4: Policy gaps — enabled applications in an org with no enabled
	// access policy at all (there is no app<->policy join in the schema).
	if rule, on := enabled("policy_gaps"); on {
		rows, err := s.db.Pool.Query(ctx, `
			SELECT a.id, a.name FROM applications a
			WHERE a.org_id = $1 AND a.enabled = true
			AND NOT EXISTS (SELECT 1 FROM policies p WHERE p.org_id = $1 AND p.enabled = true)
			ORDER BY a.name LIMIT 50`, org.ID)
		if err != nil {
			failed("policy_gaps", err)
		} else {
			for rows.Next() {
				var appID, appName string
				rows.Scan(&appID, &appName)
				if s.createFinding(ctx, org.ID, rule,
					fmt.Sprintf("Application '%s' has no access policy", appName),
					"This application has no conditional access or governance policy assigned.",
					"application", appID, appName, "assign_policy") {
					findingsCreated++
				}
			}
			rows.Close()
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message":          "posture check completed",
		"findings_created": findingsCreated,
		"checks_run":       checksRun,
		"checks_skipped":   checksSkipped,
		"checks_failed":    checksFailed,
	})
}

// createFinding inserts an open finding for the org unless an open one for
// the same check and entity already exists there. Severity and rule_id come
// from the rule, so a severity edit on the Rules page is what the next scan
// reports. Returns true only when a row was written.
func (s *Service) createFinding(ctx context.Context, orgID string, rule PostureRule, title, description, entityType, entityID, entityName, action string) bool {
	tag, err := s.db.Pool.Exec(ctx, `
		INSERT INTO ispm_findings (org_id, rule_id, check_type, severity, category, title, description, affected_entity_type, affected_entity_id, affected_entity_name, remediation_action)
		SELECT $1::uuid, $2::uuid, $3::varchar, $4::varchar, $5::varchar, $6::varchar, $7::text, $8::varchar, $9::varchar, $10::varchar, $11::varchar
		WHERE NOT EXISTS (
			SELECT 1 FROM ispm_findings WHERE org_id = $1 AND check_type = $3 AND affected_entity_id = $9 AND status = 'open'
		)`,
		orgID, rule.ID, rule.CheckType, rule.Severity, rule.Category, title, description, entityType, entityID, entityName, action)
	if err != nil {
		s.logger.Warn("ISPM: failed to insert finding", zap.String("check", rule.CheckType), zap.Error(err))
		return false
	}
	return tag.RowsAffected() > 0
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
