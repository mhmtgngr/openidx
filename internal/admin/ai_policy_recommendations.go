// Package admin provides AI-powered IGA (Identity Governance & Administration) policy recommendations
// This module uses machine learning to analyze access patterns and recommend policy changes.
package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// PolicyRecommendationType represents the type of policy recommendation
type PolicyRecommendationType string

const (
	// RecommendationRoleSizing suggests role size adjustments
	RecommendationRoleSizing PolicyRecommendationType = "role_sizing"
	// RecommendationAccessRevocation suggests access revocation
	RecommendationAccessRevocation PolicyRecommendationType = "access_revocation"
	// RecommendationRoleConsolidation suggests role consolidation
	RecommendationRoleConsolidation PolicyRecommendationType = "role_consolidation"
	// RecommendationJustificationCollection suggests collecting justifications
	RecommendationJustificationCollection PolicyRecommendationType = "justification_collection"
	// RecommendationReviewFrequency suggests review frequency changes
	RecommendationReviewFrequency PolicyRecommendationType = "review_frequency"
	// RecommendationSeparationOfDuties identifies SoD conflicts
	RecommendationSeparationOfDuties PolicyRecommendationType = "separation_of_duties"
	// RecommendationLeastPrivilege suggests applying least privilege
	RecommendationLeastPrivilege PolicyRecommendationType = "least_privilege"
)

// PolicyRecommendationPriority represents the priority of a recommendation
type PolicyRecommendationPriority string

const (
	PriorityCritical PolicyRecommendationPriority = "critical"
	PriorityHigh     PolicyRecommendationPriority = "high"
	PriorityMedium   PolicyRecommendationPriority = "medium"
	PriorityLow      PolicyRecommendationPriority = "low"
)

// AccessPattern represents user access behavior over time
type AccessPattern struct {
	UserID           string     `json:"user_id"`
	RoleID           string     `json:"role_id"`
	ResourceType     string     `json:"resource_type"`
	LastAccessed     *time.Time `json:"last_accessed"`
	AccessCount      int        `json:"access_count"`
	AccessFrequency  float64    `json:"access_frequency"` // accesses per day
	AverageSession   float64    `json:"average_session"`  // minutes
	IsUnused         bool       `json:"is_unused"`
	IsRarelyUsed     bool       `json:"is_rarely_used"`
	IsHeavilyUsed    bool       `json:"is_heavily_used"`
	PeakUsageHours   []int      `json:"peak_usage_hours"`
	AnomalyScore     float64    `json:"anomaly_score"`
}

// PolicyRecommendation represents an AI-generated policy recommendation
type PolicyRecommendation struct {
	ID              string                       `json:"id"`
	Type            PolicyRecommendationType     `json:"type"`
	Priority        PolicyRecommendationPriority `json:"priority"`
	Title           string                       `json:"title"`
	Description     string                       `json:"description"`
	Impact          string                       `json:"impact"`
	EstimatedEffort string                       `json:"estimated_effort"`
	Confidence      float64                      `json:"confidence"`
	Reasoning       []string                     `json:"reasoning"`
	AffectedUsers   int                          `json:"affected_users"`
	AffectedRoles   int                          `json:"affected_roles"`
	AffectedResources []string                   `json:"affected_resources"`
	Metadata        json.RawMessage              `json:"metadata"`
	Status          string                       `json:"status"` // pending, approved, rejected, implemented
	CreatedAt       time.Time                    `json:"created_at"`
	UpdatedAt       time.Time                    `json:"updated_at"`
	ApprovedBy      *string                      `json:"approved_by,omitempty"`
	ApprovedAt      *time.Time                   `json:"approved_at,omitempty"`
	ImplementedAt   *time.Time                   `json:"implemented_at,omitempty"`
}

// ComplianceGap represents a gap between current and desired compliance state
type ComplianceGap struct {
	ID              string    `json:"id"`
	Standard        string    `json:"standard"`        // SOC2, ISO27001, HIPAA, GDPR
	ControlID       string    `json:"control_id"`
	ControlName     string    `json:"control_name"`
	CurrentState    string    `json:"current_state"`
	DesiredState    string    `json:"desired_state"`
	GapDescription  string    `json:"gap_description"`
	RemediationPlan string    `json:"remediation_plan"`
	Priority        string    `json:"priority"`
	EstimatedEffort int       `json:"estimated_effort"` // days
	DueDate         *time.Time `json:"due_date"`
	Status          string    `json:"status"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// AccessAnalysisResult represents the result of access pattern analysis
type AccessAnalysisResult struct {
	AnalyzedAt         time.Time                   `json:"analyzed_at"`
	TimeWindow         time.Duration               `json:"time_window"`
	TotalUsers         int                         `json:"total_users"`
	TotalRoles         int                         `json:"total_roles"`
	UnusedAccessCount  int                         `json:"unused_access_count"`
	RarelyUsedCount    int                         `json:"rarely_used_count"`
	OverprivilegedUsers int                        `json:"overprivileged_users"`
	Recommendations    []PolicyRecommendation      `json:"recommendations"`
	AccessPatterns     []AccessPattern             `json:"access_patterns"`
	ComplianceGaps     []ComplianceGap             `json:"compliance_gaps"`
	RiskScore          float64                     `json:"risk_score"`
}

// RoleSuggestion suggests a role for a user based on their access patterns
type RoleSuggestion struct {
	UserID           string   `json:"user_id"`
	SuggestedRoles   []string `json:"suggested_roles"`
	Confidence       float64  `json:"confidence"`
	Reasoning        []string `json:"reasoning"`
	CurrentRoles     []string `json:"current_roles"`
	RecommendedRole  string   `json:"recommended_role"`
}

// aiPolicyRecommendationsService handles AI-powered policy recommendations
type aiPolicyRecommendationsService struct {
	db     *database.PostgresDB
	logger *zap.Logger
}

// AnalyzeAccessPatterns analyzes user access patterns to generate recommendations
func (s *aiPolicyRecommendationsService) AnalyzeAccessPatterns(ctx context.Context, timeWindow time.Duration) (*AccessAnalysisResult, error) {
	result := &AccessAnalysisResult{
		AnalyzedAt:     time.Now(),
		TimeWindow:     timeWindow,
		Recommendations: []PolicyRecommendation{},
		AccessPatterns:  []AccessPattern{},
		ComplianceGaps:  []ComplianceGap{},
	}

	// Get access patterns from audit logs
	rows, err := s.db.Pool.Query(ctx, `
		WITH access_stats AS (
			SELECT
				user_id,
				role_id,
				resource_type,
				MAX(accessed_at) as last_accessed,
				COUNT(*) as access_count,
				COUNT(*)::float / EXTRACT(EPOCH FROM (NOW() - MIN(accessed_at))) * 86400 as access_frequency,
				AVG(EXTRACT(EPOCH FROM (session_ended_at - session_started_at)) / 60) as avg_session_minutes,
				EXTRACT(HOUR FROM accessed_at) as peak_hour
			FROM audit_logs
			WHERE accessed_at > NOW() - $1::interval
			GROUP BY user_id, role_id, resource_type, EXTRACT(HOUR FROM accessed_at)
		)
		SELECT
			user_id, role_id, resource_type, last_accessed,
			COALESCE(access_count, 0),
			COALESCE(access_frequency, 0),
			COALESCE(avg_session_minutes, 0)
		FROM access_stats
	`, fmt.Sprintf("%d seconds", int(timeWindow.Seconds())))
	if err != nil {
		return nil, fmt.Errorf("failed to query access patterns: %w", err)
	}
	defer rows.Close()

	patterns := map[string]*AccessPattern{}
	unusedThreshold := 30 * 24 * time.Hour // 30 days
	rarelyUsedThreshold := 1.0              // less than 1 access per day

	for rows.Next() {
		var p AccessPattern
		var lastAccessed time.Time
		err := rows.Scan(&p.UserID, &p.RoleID, &p.ResourceType,
			&lastAccessed, &p.AccessCount, &p.AccessFrequency, &p.AverageSession)
		if err != nil {
			continue
		}
		p.LastAccessed = &lastAccessed

		// Classify usage
		timeSinceAccess := time.Since(lastAccessed)
		p.IsUnused = timeSinceAccess > unusedThreshold
		p.IsRarelyUsed = p.AccessFrequency < rarelyUsedThreshold && !p.IsUnused
		p.IsHeavilyUsed = p.AccessFrequency > 10

		key := fmt.Sprintf("%s:%s:%s", p.UserID, p.RoleID, p.ResourceType)
		patterns[key] = &p
		result.AccessPatterns = append(result.AccessPatterns, p)

		if p.IsUnused {
			result.UnusedAccessCount++
		} else if p.IsRarelyUsed {
			result.RarelyUsedCount++
		}
	}

	// Generate recommendations based on patterns
	s.generateAccessRevocationRecommendations(ctx, result, patterns)
	s.generateRoleSizingRecommendations(ctx, result)
	s.generateSoDRecommendations(ctx, result)

	// Calculate overall risk score
	result.RiskScore = s.calculateRiskScore(ctx, result)

	return result, nil
}

// generateAccessRevocationRecommendations creates recommendations for unused access
func (s *aiPolicyRecommendationsService) generateAccessRevocationRecommendations(ctx context.Context, result *AccessAnalysisResult, patterns map[string]*AccessPattern) {
	for _, p := range patterns {
		if p.IsUnused {
			rec := PolicyRecommendation{
				ID:          uuid.New().String(),
				Type:        RecommendationAccessRevocation,
				Priority:    PriorityMedium,
				Title:       fmt.Sprintf("Revoke unused access for user %s", p.UserID),
				Description: fmt.Sprintf("User %s has not accessed resource %s (role: %s) in over 30 days", p.UserID, p.ResourceType, p.RoleID),
				Impact:      "Reduces attack surface by removing unused privileges",
				EstimatedEffort: "Low",
				Confidence:  0.85,
				Reasoning: []string{
					fmt.Sprintf("Last accessed %s ago", time.Since(*p.LastAccessed)),
					"Zero accesses in the last 30 days",
					"Removal reduces compliance scope",
				},
				AffectedUsers:   1,
				AffectedResources: []string{p.ResourceType},
				Status:      "pending",
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			}
			result.Recommendations = append(result.Recommendations, rec)
		}
	}
}

// generateRoleSizingRecommendations creates recommendations for role size optimization
func (s *aiPolicyRecommendationsService) generateRoleSizingRecommendations(ctx context.Context, result *AccessAnalysisResult) {
	// Find oversized roles (>100 users with varying access patterns)
	rows, err := s.db.Pool.Query(ctx, `
		SELECT role_id, COUNT(DISTINCT user_id) as user_count,
			COUNT(DISTINCT resource_type) as resource_count
		FROM role_assignments
		WHERE active = true
		GROUP BY role_id
		HAVING COUNT(DISTINCT user_id) > 100
			AND COUNT(DISTINCT resource_type) > 50
		ORDER BY user_count DESC
	`)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var roleID string
		var userCount, resourceCount int
		rows.Scan(&roleID, &userCount, &resourceCount)

		rec := PolicyRecommendation{
			ID:          uuid.New().String(),
			Type:        RecommendationRoleConsolidation,
			Priority:    PriorityMedium,
			Title:       fmt.Sprintf("Consider splitting oversized role %s", roleID),
			Description: fmt.Sprintf("Role %s has %d users and %d resources, making it difficult to manage and audit", roleID, userCount, resourceCount),
			Impact:      "Improved security posture and easier compliance",
			EstimatedEffort: "Medium",
			Confidence:  0.7,
			Reasoning: []string{
				fmt.Sprintf("Role has %d users (threshold: 100)", userCount),
				fmt.Sprintf("Role has %d distinct resources (threshold: 50)", resourceCount),
				"Large roles increase blast radius of compromise",
			},
			AffectedUsers:   userCount,
			AffectedRoles:   1,
			Status:      "pending",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		result.Recommendations = append(result.Recommendations, rec)
	}
}

// generateSoDRecommendations identifies Separation of Duties conflicts
func (s *aiPolicyRecommendationsService) generateSoDRecommendations(ctx context.Context, result *AccessAnalysisResult) {
	// Check for users with conflicting roles (e.g., can approve and payments)
	conflictingPairs := []struct {
		role1    string
		role2    string
		reason   string
	}{
		{"payment_creator", "payment_approver", "User can create and approve payments"},
		{"user_creator", "user_deleter", "User can create and delete users"},
		{"vendor_creator", "vendor_approver", "User can create and approve vendors"},
	}

	for _, cp := range conflictingPairs {
		rows, err := s.db.Pool.Query(ctx, `
			SELECT u.id, u.email
			FROM users u
			WHERE u.id IN (
				SELECT user_id FROM role_assignments WHERE role_id = $1
			) AND u.id IN (
				SELECT user_id FROM role_assignments WHERE role_id = $2
			)
		`, cp.role1, cp.role2)
		if err != nil {
			continue
		}

		conflictingUsers := []string{}
		for rows.Next() {
			var userID, email string
			rows.Scan(&userID, &email)
			conflictingUsers = append(conflictingUsers, email)
		}
		rows.Close()

		if len(conflictingUsers) > 0 {
			rec := PolicyRecommendation{
				ID:          uuid.New().String(),
				Type:        RecommendationSeparationOfDuties,
				Priority:    PriorityHigh,
				Title:       fmt.Sprintf("Separation of Duties conflict: %s vs %s", cp.role1, cp.role2),
				Description: fmt.Sprintf("%d users have both %s and %s roles", len(conflictingUsers), cp.role1, cp.role2),
				Impact:      "Critical security risk allowing fraud",
				EstimatedEffort: "High",
				Confidence:  0.95,
				Reasoning: []string{
					cp.reason,
					fmt.Sprintf("Affected users: %d", len(conflictingUsers)),
					"Violates SoD compliance requirements",
				},
				AffectedUsers: len(conflictingUsers),
				AffectedRoles: 2,
				Status:      "pending",
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			}
			result.Recommendations = append(result.Recommendations, rec)
		}
	}
}

// GetPolicySuggestion retrieves a specific policy recommendation
func (s *aiPolicyRecommendationsService) GetPolicySuggestion(ctx context.Context, id string) (*PolicyRecommendation, error) {
	var rec PolicyRecommendation
	var metadata []byte

	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, type, priority, title, description, impact, estimated_effort,
			confidence, reasoning, affected_users, affected_roles, affected_resources,
			metadata, status, created_at, updated_at, approved_by, approved_at, implemented_at
		FROM policy_recommendations
		WHERE id = $1
	`, id).Scan(
		&rec.ID, &rec.Type, &rec.Priority, &rec.Title, &rec.Description,
		&rec.Impact, &rec.EstimatedEffort, &rec.Confidence,
		&rec.Reasoning, &rec.AffectedUsers, &rec.AffectedRoles,
		&rec.AffectedResources, &metadata, &rec.Status,
		&rec.CreatedAt, &rec.UpdatedAt, &rec.ApprovedBy,
		&rec.ApprovedAt, &rec.ImplementedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("recommendation not found: %w", err)
	}

	rec.Metadata = metadata
	return &rec, nil
}

// ApplyRecommendedPolicy implements a recommended policy change
func (s *aiPolicyRecommendationsService) ApplyRecommendedPolicy(ctx context.Context, id string, actorID string) error {
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Get the recommendation
	rec, err := s.GetPolicySuggestion(ctx, id)
	if err != nil {
		return err
	}

	// Apply based on recommendation type
	switch rec.Type {
	case RecommendationAccessRevocation:
		// Revoke the access
		_, err = tx.Exec(ctx, `
			UPDATE role_assignments
			SET active = false, revoked_at = NOW(), revoked_by = $1
			WHERE id = $2
		`, actorID, rec.Metadata)

	case RecommendationRoleSizing:
		// Update role configuration
		_, err = tx.Exec(ctx, `
			UPDATE roles
			SET max_users = $1, updated_at = NOW()
			WHERE id = $2
		`, rec.Metadata, actorID)
	}

	if err != nil {
		return fmt.Errorf("failed to apply recommendation: %w", err)
	}

	// Update recommendation status
	now := time.Now()
	_, err = tx.Exec(ctx, `
		UPDATE policy_recommendations
		SET status = 'implemented', implemented_at = $1, updated_at = $1, approved_by = $2
		WHERE id = $3
	`, now, actorID, id)

	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// GetComplianceGaps retrieves compliance gaps for specified standard
func (s *aiPolicyRecommendationsService) GetComplianceGaps(ctx context.Context, standard string) ([]ComplianceGap, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, standard, control_id, control_name, current_state, desired_state,
			gap_description, remediation_plan, priority, estimated_effort, due_date, status, created_at, updated_at
		FROM compliance_gaps
		WHERE standard = $1 OR $1 = ''
		ORDER BY priority DESC, due_date ASC
	`, standard)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	gaps := []ComplianceGap{}
	for rows.Next() {
		var g ComplianceGap
		rows.Scan(&g.ID, &g.Standard, &g.ControlID, &g.ControlName,
			&g.CurrentState, &g.DesiredState, &g.GapDescription,
			&g.RemediationPlan, &g.Priority, &g.EstimatedEffort,
			&g.DueDate, &g.Status, &g.CreatedAt, &g.UpdatedAt)
		gaps = append(gaps, g)
	}

	return gaps, nil
}

// calculateRiskScore calculates an overall risk score based on analysis results
func (s *aiPolicyRecommendationsService) calculateRiskScore(ctx context.Context, result *AccessAnalysisResult) float64 {
	risk := 0.0

	// Unused access risk
	if result.UnusedAccessCount > 100 {
		risk += 0.3
	} else if result.UnusedAccessCount > 50 {
		risk += 0.2
	} else if result.UnusedAccessCount > 10 {
		risk += 0.1
	}

	// Overprivileged users risk
	if result.OverprivilegedUsers > 50 {
		risk += 0.4
	} else if result.OverprivilegedUsers > 20 {
		risk += 0.3
	} else if result.OverprivilegedUsers > 5 {
		risk += 0.1
	}

	// Compliance gaps risk
	if len(result.ComplianceGaps) > 10 {
		risk += 0.3
	} else if len(result.ComplianceGaps) > 5 {
		risk += 0.2
	}

	return math.Min(risk, 1.0) * 100
}

// Handlers

func (s *Service) handleAIAnalyzeAccess(c *gin.Context) {
	// Require admin role for access pattern analysis
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()

	// Parse time window from query (default 90 days)
	days := 90
	if d := c.Query("days"); d != "" {
		fmt.Sscanf(d, "%d", &days)
	}
	timeWindow := time.Duration(days) * 24 * time.Hour

	analyzer := &aiPolicyRecommendationsService{db: s.db, logger: s.logger}
	result, err := analyzer.AnalyzeAccessPatterns(ctx, timeWindow)
	if err != nil {
		s.logger.Error("failed to analyze access patterns", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to analyze access patterns"})
		return
	}

	c.JSON(http.StatusOK, result)
}

func (s *Service) handleAIPolicyRecommendations(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, type, priority, title, description, impact, estimated_effort,
			confidence, affected_users, affected_roles, status, created_at
		FROM policy_recommendations
		WHERE status = 'pending'
		ORDER BY priority DESC, confidence DESC
		LIMIT 100
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list recommendations"})
		return
	}
	defer rows.Close()

	recs := []PolicyRecommendation{}
	for rows.Next() {
		var rec PolicyRecommendation
		rows.Scan(&rec.ID, &rec.Type, &rec.Priority, &rec.Title,
			&rec.Description, &rec.Impact, &rec.EstimatedEffort,
			&rec.Confidence, &rec.AffectedUsers, &rec.AffectedRoles,
			&rec.Status, &rec.CreatedAt)
		recs = append(recs, rec)
	}

	c.JSON(http.StatusOK, gin.H{"data": recs})
}

func (s *Service) handleAIApplyRecommendation(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	analyzer := &aiPolicyRecommendationsService{db: s.db, logger: s.logger}
	err := analyzer.ApplyRecommendedPolicy(ctx, id, c.GetString("user_id"))
	if err != nil {
		s.logger.Error("failed to apply recommendation", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to apply recommendation"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "recommendation applied"})
}

func (s *Service) handleAIComplianceGaps(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()
	standard := c.Query("standard")

	analyzer := &aiPolicyRecommendationsService{db: s.db, logger: s.logger}
	gaps, err := analyzer.GetComplianceGaps(ctx, standard)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get compliance gaps"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": gaps})
}
