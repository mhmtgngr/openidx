// Package governance provides access governance and compliance functionality
package governance

import (
	"context"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
)

// AccessReview represents an access certification review
type AccessReview struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Description  string            `json:"description"`
	Type         ReviewType        `json:"type"`
	Status       ReviewStatus      `json:"status"`
	ReviewerID   string            `json:"reviewer_id"`
	Scope        ReviewScope       `json:"scope"`
	StartDate    time.Time         `json:"start_date"`
	EndDate      time.Time         `json:"end_date"`
	CreatedAt    time.Time         `json:"created_at"`
	CompletedAt  *time.Time        `json:"completed_at,omitempty"`
	TotalItems   int               `json:"total_items"`
	ReviewedItems int              `json:"reviewed_items"`
}

// ReviewType defines the type of access review
type ReviewType string

const (
	ReviewTypeUserAccess      ReviewType = "user_access"
	ReviewTypeRoleAssignment  ReviewType = "role_assignment"
	ReviewTypeApplicationAccess ReviewType = "application_access"
	ReviewTypePrivilegedAccess ReviewType = "privileged_access"
)

// ReviewStatus defines the status of an access review
type ReviewStatus string

const (
	ReviewStatusPending    ReviewStatus = "pending"
	ReviewStatusInProgress ReviewStatus = "in_progress"
	ReviewStatusCompleted  ReviewStatus = "completed"
	ReviewStatusExpired    ReviewStatus = "expired"
	ReviewStatusCanceled   ReviewStatus = "canceled"
)

// ReviewScope defines what's included in the review
type ReviewScope struct {
	Users        []string `json:"users,omitempty"`
	Groups       []string `json:"groups,omitempty"`
	Applications []string `json:"applications,omitempty"`
	Roles        []string `json:"roles,omitempty"`
}

// ReviewItem represents a single item to be reviewed
type ReviewItem struct {
	ID           string           `json:"id"`
	ReviewID     string           `json:"review_id"`
	UserID       string           `json:"user_id"`
	ResourceType string           `json:"resource_type"`
	ResourceID   string           `json:"resource_id"`
	ResourceName string           `json:"resource_name"`
	Decision     ReviewDecision   `json:"decision"`
	DecidedBy    string           `json:"decided_by,omitempty"`
	DecidedAt    *time.Time       `json:"decided_at,omitempty"`
	Comments     string           `json:"comments,omitempty"`
}

// ReviewDecision represents the decision made on a review item
type ReviewDecision string

const (
	ReviewDecisionPending  ReviewDecision = "pending"
	ReviewDecisionApproved ReviewDecision = "approved"
	ReviewDecisionRevoked  ReviewDecision = "revoked"
	ReviewDecisionFlagged  ReviewDecision = "flagged"
)

// Policy represents an access policy
type Policy struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Type        PolicyType      `json:"type"`
	Rules       []PolicyRule    `json:"rules"`
	Enabled     bool            `json:"enabled"`
	Priority    int             `json:"priority"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// PolicyType defines the type of policy
type PolicyType string

const (
	PolicyTypeSoD       PolicyType = "separation_of_duty"
	PolicyTypeRiskBased PolicyType = "risk_based"
	PolicyTypeTimebound PolicyType = "timebound"
	PolicyTypeLocation  PolicyType = "location"
)

// PolicyRule defines a rule within a policy
type PolicyRule struct {
	ID         string                 `json:"id"`
	Condition  map[string]interface{} `json:"condition"`
	Effect     string                 `json:"effect"`
	Priority   int                    `json:"priority"`
}

// Service provides governance operations
type Service struct {
	db     *database.PostgresDB
	redis  *database.RedisClient
	config *config.Config
	logger *zap.Logger
}

// NewService creates a new governance service
func NewService(db *database.PostgresDB, redis *database.RedisClient, cfg *config.Config, logger *zap.Logger) *Service {
	return &Service{
		db:     db,
		redis:  redis,
		config: cfg,
		logger: logger.With(zap.String("service", "governance")),
	}
}

// CreateAccessReview creates a new access review campaign
func (s *Service) CreateAccessReview(ctx context.Context, review *AccessReview) error {
	s.logger.Info("Creating access review", zap.String("name", review.Name))
	
	now := time.Now()
	review.CreatedAt = now
	review.Status = ReviewStatusPending
	
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO access_reviews (id, name, description, type, status, reviewer_id,
		                           start_date, end_date, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, review.ID, review.Name, review.Description, review.Type, review.Status,
		review.ReviewerID, review.StartDate, review.EndDate, review.CreatedAt)
	
	return err
}

// GetAccessReview retrieves an access review by ID
func (s *Service) GetAccessReview(ctx context.Context, reviewID string) (*AccessReview, error) {
	var review AccessReview
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, name, description, type, status, reviewer_id,
		       start_date, end_date, created_at, completed_at
		FROM access_reviews WHERE id = $1
	`, reviewID).Scan(
		&review.ID, &review.Name, &review.Description, &review.Type, &review.Status,
		&review.ReviewerID, &review.StartDate, &review.EndDate, &review.CreatedAt, &review.CompletedAt,
	)
	return &review, err
}

// ListAccessReviews retrieves all access reviews
func (s *Service) ListAccessReviews(ctx context.Context, offset, limit int) ([]AccessReview, int, error) {
	var total int
	err := s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM access_reviews").Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT ar.id, ar.name, ar.description, ar.type, ar.status, ar.reviewer_id,
		       ar.start_date, ar.end_date, ar.created_at, ar.completed_at,
		       COUNT(ri.id) as total_items,
		       COUNT(CASE WHEN ri.decision != 'pending' THEN 1 END) as reviewed_items
		FROM access_reviews ar
		LEFT JOIN review_items ri ON ar.id = ri.review_id
		GROUP BY ar.id, ar.name, ar.description, ar.type, ar.status, ar.reviewer_id,
		         ar.start_date, ar.end_date, ar.created_at, ar.completed_at
		ORDER BY ar.created_at DESC
		OFFSET $1 LIMIT $2
	`, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var reviews []AccessReview
	for rows.Next() {
		var r AccessReview
		if err := rows.Scan(
			&r.ID, &r.Name, &r.Description, &r.Type, &r.Status,
			&r.ReviewerID, &r.StartDate, &r.EndDate, &r.CreatedAt, &r.CompletedAt,
			&r.TotalItems, &r.ReviewedItems,
		); err != nil {
			return nil, 0, err
		}
		reviews = append(reviews, r)
	}

	return reviews, total, nil
}

// SubmitReviewDecision submits a decision for a review item
func (s *Service) SubmitReviewDecision(ctx context.Context, itemID string, decision ReviewDecision, comments string, decidedBy string) error {
	s.logger.Info("Submitting review decision",
		zap.String("item_id", itemID),
		zap.String("decision", string(decision)))
	
	now := time.Now()
	_, err := s.db.Pool.Exec(ctx, `
		UPDATE review_items
		SET decision = $2, comments = $3, decided_by = $4, decided_at = $5
		WHERE id = $1
	`, itemID, decision, comments, decidedBy, now)
	
	return err
}

// CreatePolicy creates a new policy
func (s *Service) CreatePolicy(ctx context.Context, policy *Policy) error {
	s.logger.Info("Creating policy", zap.String("name", policy.Name))

	now := time.Now()
	policy.CreatedAt = now
	policy.UpdatedAt = now

	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO policies (id, name, description, type, enabled, priority, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, policy.ID, policy.Name, policy.Description, policy.Type, policy.Enabled,
		policy.Priority, policy.CreatedAt, policy.UpdatedAt)

	return err
}

// GetPolicy retrieves a policy by ID
func (s *Service) GetPolicy(ctx context.Context, policyID string) (*Policy, error) {
	var policy Policy
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, name, description, type, enabled, priority, created_at, updated_at
		FROM policies WHERE id = $1
	`, policyID).Scan(
		&policy.ID, &policy.Name, &policy.Description, &policy.Type,
		&policy.Enabled, &policy.Priority, &policy.CreatedAt, &policy.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &policy, nil
}

// ListPolicies retrieves all policies
func (s *Service) ListPolicies(ctx context.Context, offset, limit int) ([]Policy, int, error) {
	var total int
	err := s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM policies").Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, description, type, enabled, priority, created_at, updated_at
		FROM policies
		ORDER BY priority DESC, created_at DESC
		OFFSET $1 LIMIT $2
	`, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var policies []Policy
	for rows.Next() {
		var p Policy
		if err := rows.Scan(
			&p.ID, &p.Name, &p.Description, &p.Type,
			&p.Enabled, &p.Priority, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		policies = append(policies, p)
	}

	return policies, total, nil
}

// UpdatePolicy updates an existing policy
func (s *Service) UpdatePolicy(ctx context.Context, policyID string, policy *Policy) error {
	s.logger.Info("Updating policy", zap.String("policy_id", policyID))

	now := time.Now()
	policy.UpdatedAt = now

	_, err := s.db.Pool.Exec(ctx, `
		UPDATE policies
		SET name = $2, description = $3, type = $4, enabled = $5, priority = $6, updated_at = $7
		WHERE id = $1
	`, policyID, policy.Name, policy.Description, policy.Type, policy.Enabled, policy.Priority, now)

	return err
}

// DeletePolicy deletes a policy
func (s *Service) DeletePolicy(ctx context.Context, policyID string) error {
	s.logger.Info("Deleting policy", zap.String("policy_id", policyID))

	_, err := s.db.Pool.Exec(ctx, "DELETE FROM policies WHERE id = $1", policyID)
	return err
}

// EvaluatePolicy evaluates a policy against a request
func (s *Service) EvaluatePolicy(ctx context.Context, policyID string, request map[string]interface{}) (bool, error) {
	s.logger.Debug("Evaluating policy", zap.String("policy_id", policyID))

	// Get the policy
	policy, err := s.GetPolicy(ctx, policyID)
	if err != nil {
		return false, err
	}

	// If policy is disabled, allow by default
	if !policy.Enabled {
		return true, nil
	}

	// Basic rule evaluation based on policy type
	switch policy.Type {
	case PolicyTypeSoD:
		// Separation of Duty: check if user has conflicting roles
		return s.evaluateSoDPolicy(ctx, policy, request)
	case PolicyTypeTimebound:
		// Timebound: check if current time is within allowed window
		return s.evaluateTimeboundPolicy(ctx, policy, request)
	case PolicyTypeLocation:
		// Location-based: check if request IP is from allowed location
		return s.evaluateLocationPolicy(ctx, policy, request)
	case PolicyTypeRiskBased:
		// Risk-based: evaluate risk score
		return s.evaluateRiskBasedPolicy(ctx, policy, request)
	default:
		return true, nil
	}
}

func (s *Service) evaluateSoDPolicy(ctx context.Context, policy *Policy, request map[string]interface{}) (bool, error) {
	// Get user roles from request
	userRoles, ok := request["roles"].([]interface{})
	if !ok {
		return true, nil // No roles to check
	}

	// Check for conflicting role pairs (example: admin and auditor cannot be combined)
	conflictPairs := map[string]string{
		"admin":   "auditor",
		"finance": "approver",
	}

	roleSet := make(map[string]bool)
	for _, r := range userRoles {
		if role, ok := r.(string); ok {
			roleSet[role] = true
		}
	}

	for role1, role2 := range conflictPairs {
		if roleSet[role1] && roleSet[role2] {
			s.logger.Warn("SoD policy violation detected",
				zap.String("policy_id", policy.ID),
				zap.String("conflicting_roles", role1+"/"+role2))
			return false, nil
		}
	}

	return true, nil
}

func (s *Service) evaluateTimeboundPolicy(ctx context.Context, policy *Policy, request map[string]interface{}) (bool, error) {
	// Check if current time is within business hours (9 AM - 6 PM, Mon-Fri)
	now := time.Now()
	hour := now.Hour()
	weekday := now.Weekday()

	// Weekend check
	if weekday == time.Saturday || weekday == time.Sunday {
		s.logger.Info("Timebound policy: access outside business days",
			zap.String("policy_id", policy.ID))
		return false, nil
	}

	// Business hours check (default 9-18)
	if hour < 9 || hour >= 18 {
		s.logger.Info("Timebound policy: access outside business hours",
			zap.String("policy_id", policy.ID))
		return false, nil
	}

	return true, nil
}

func (s *Service) evaluateLocationPolicy(ctx context.Context, policy *Policy, request map[string]interface{}) (bool, error) {
	// Check if IP is from allowed locations
	ip, ok := request["ip"].(string)
	if !ok {
		return true, nil // No IP to check
	}

	// Example: Allow only internal IPs (10.x.x.x, 192.168.x.x, 172.16-31.x.x)
	allowedPrefixes := []string{"10.", "192.168.", "172.16.", "172.17.", "172.18.", "127.0.0.1"}

	for _, prefix := range allowedPrefixes {
		if len(ip) >= len(prefix) && ip[:len(prefix)] == prefix {
			return true, nil
		}
	}

	s.logger.Warn("Location policy: access from unauthorized IP",
		zap.String("policy_id", policy.ID),
		zap.String("ip", ip))
	return false, nil
}

func (s *Service) evaluateRiskBasedPolicy(ctx context.Context, policy *Policy, request map[string]interface{}) (bool, error) {
	// Calculate risk score based on various factors
	riskScore := 0

	// Check for new device
	if isNewDevice, ok := request["is_new_device"].(bool); ok && isNewDevice {
		riskScore += 30
	}

	// Check for unusual location
	if isUnusualLocation, ok := request["is_unusual_location"].(bool); ok && isUnusualLocation {
		riskScore += 25
	}

	// Check for failed attempts
	if failedAttempts, ok := request["failed_attempts"].(float64); ok {
		riskScore += int(failedAttempts) * 10
	}

	// Risk threshold (default 50)
	threshold := 50
	if riskScore >= threshold {
		s.logger.Warn("Risk-based policy: high risk score",
			zap.String("policy_id", policy.ID),
			zap.Int("risk_score", riskScore))
		return false, nil
	}

	return true, nil
}

// UpdateAccessReview updates an existing access review
func (s *Service) UpdateAccessReview(ctx context.Context, reviewID string, update *AccessReview) error {
	s.logger.Info("Updating access review", zap.String("review_id", reviewID))

	// Check if review exists and is not completed
	existing, err := s.GetAccessReview(ctx, reviewID)
	if err != nil {
		return err
	}

	if existing.Status == ReviewStatusCompleted {
		return ErrReviewCompleted
	}

	_, err = s.db.Pool.Exec(ctx, `
		UPDATE access_reviews
		SET name = $2, description = $3, start_date = $4, end_date = $5
		WHERE id = $1
	`, reviewID, update.Name, update.Description, update.StartDate, update.EndDate)

	return err
}

// UpdateReviewStatus updates the status of an access review
func (s *Service) UpdateReviewStatus(ctx context.Context, reviewID string, newStatus ReviewStatus) error {
	s.logger.Info("Updating review status",
		zap.String("review_id", reviewID),
		zap.String("new_status", string(newStatus)))

	// Get current review
	review, err := s.GetAccessReview(ctx, reviewID)
	if err != nil {
		return err
	}

	// Validate status transition
	if !isValidStatusTransition(review.Status, newStatus) {
		return ErrInvalidStatusTransition
	}

	// Start transaction
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Update status
	var completedAt *time.Time
	if newStatus == ReviewStatusCompleted {
		now := time.Now()
		completedAt = &now
	}

	_, err = tx.Exec(ctx, `
		UPDATE access_reviews
		SET status = $2, completed_at = $3
		WHERE id = $1
	`, reviewID, newStatus, completedAt)
	if err != nil {
		return err
	}

	// If starting review, populate review items
	if newStatus == ReviewStatusInProgress && review.Status == ReviewStatusPending {
		if err := s.populateReviewItems(ctx, tx, review); err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

// ListReviewItems returns the items for a specific review
func (s *Service) ListReviewItems(ctx context.Context, reviewID string, offset, limit int, decisionFilter string) ([]ReviewItem, int, error) {
	s.logger.Debug("Listing review items", zap.String("review_id", reviewID))

	// Build query based on filter
	baseQuery := `
		SELECT ri.id, ri.review_id, ri.user_id, ri.resource_type, ri.resource_id,
		       COALESCE(ri.resource_name, ''), ri.decision,
		       COALESCE(ri.decided_by::text, ''), ri.decided_at, COALESCE(ri.comments, ''),
		       COALESCE(u.first_name || ' ' || u.last_name, u.username, '') as user_name,
		       COALESCE(u.email, '') as user_email
		FROM review_items ri
		LEFT JOIN users u ON ri.user_id = u.id
		WHERE ri.review_id = $1
	`
	countQuery := "SELECT COUNT(*) FROM review_items WHERE review_id = $1"

	args := []interface{}{reviewID}
	countArgs := []interface{}{reviewID}

	if decisionFilter != "" {
		baseQuery += " AND ri.decision = $2"
		countQuery += " AND decision = $2"
		args = append(args, decisionFilter)
		countArgs = append(countArgs, decisionFilter)
	}

	baseQuery += " ORDER BY ri.created_at DESC OFFSET $" + strconv.Itoa(len(args)+1) + " LIMIT $" + strconv.Itoa(len(args)+2)
	args = append(args, offset, limit)

	// Get total count
	var total int
	err := s.db.Pool.QueryRow(ctx, countQuery, countArgs...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// Get items
	rows, err := s.db.Pool.Query(ctx, baseQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var items []ReviewItem
	for rows.Next() {
		var item ReviewItem
		var userName, userEmail string
		if err := rows.Scan(
			&item.ID, &item.ReviewID, &item.UserID, &item.ResourceType, &item.ResourceID,
			&item.ResourceName, &item.Decision, &item.DecidedBy, &item.DecidedAt, &item.Comments,
			&userName, &userEmail,
		); err != nil {
			return nil, 0, err
		}
		items = append(items, item)
	}

	return items, total, nil
}

// BatchSubmitDecisions submits decisions for multiple review items
func (s *Service) BatchSubmitDecisions(ctx context.Context, reviewID string, itemIDs []string, decision ReviewDecision, comments string, decidedBy string) error {
	s.logger.Info("Batch submitting decisions",
		zap.String("review_id", reviewID),
		zap.Int("item_count", len(itemIDs)),
		zap.String("decision", string(decision)))

	if len(itemIDs) == 0 {
		return nil
	}

	now := time.Now()

	// Use a transaction for batch update
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Update each item
	for _, itemID := range itemIDs {
		_, err := tx.Exec(ctx, `
			UPDATE review_items
			SET decision = $2, comments = $3, decided_by = $4, decided_at = $5
			WHERE id = $1 AND review_id = $6
		`, itemID, decision, comments, decidedBy, now, reviewID)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

// populateReviewItems generates review items when a review is started
func (s *Service) populateReviewItems(ctx context.Context, tx interface{ Exec(ctx context.Context, sql string, arguments ...interface{}) (interface{}, error) }, review *AccessReview) error {
	s.logger.Info("Populating review items", zap.String("review_id", review.ID))

	switch review.Type {
	case ReviewTypeUserAccess:
		// Get all users and their role assignments
		return s.populateUserAccessItems(ctx, tx, review.ID)
	case ReviewTypeRoleAssignment:
		// Get all role assignments
		return s.populateRoleAssignmentItems(ctx, tx, review.ID)
	case ReviewTypeApplicationAccess:
		// Get all application access
		return s.populateApplicationAccessItems(ctx, tx, review.ID)
	case ReviewTypePrivilegedAccess:
		// Get privileged role assignments (admin, etc.)
		return s.populatePrivilegedAccessItems(ctx, tx, review.ID)
	default:
		return nil
	}
}

func (s *Service) populateUserAccessItems(ctx context.Context, tx interface{ Exec(ctx context.Context, sql string, arguments ...interface{}) (interface{}, error) }, reviewID string) error {
	// Get all user-role assignments
	rows, err := s.db.Pool.Query(ctx, `
		SELECT ur.user_id, r.id as role_id, r.name as role_name
		FROM user_roles ur
		JOIN roles r ON ur.role_id = r.id
		JOIN users u ON ur.user_id = u.id
		WHERE u.enabled = true
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var userID, roleID, roleName string
		if err := rows.Scan(&userID, &roleID, &roleName); err != nil {
			return err
		}

		_, err := tx.Exec(ctx, `
			INSERT INTO review_items (id, review_id, user_id, resource_type, resource_id, resource_name, decision)
			VALUES (gen_random_uuid(), $1, $2, 'role', $3, $4, 'pending')
		`, reviewID, userID, roleID, roleName)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) populateRoleAssignmentItems(ctx context.Context, tx interface{ Exec(ctx context.Context, sql string, arguments ...interface{}) (interface{}, error) }, reviewID string) error {
	// Same as user access for now
	return s.populateUserAccessItems(ctx, tx, reviewID)
}

func (s *Service) populateApplicationAccessItems(ctx context.Context, tx interface{ Exec(ctx context.Context, sql string, arguments ...interface{}) (interface{}, error) }, reviewID string) error {
	// Get all users with their group memberships (groups often map to app access)
	rows, err := s.db.Pool.Query(ctx, `
		SELECT gm.user_id, g.id as group_id, g.name as group_name
		FROM group_memberships gm
		JOIN groups g ON gm.group_id = g.id
		JOIN users u ON gm.user_id = u.id
		WHERE u.enabled = true
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var userID, groupID, groupName string
		if err := rows.Scan(&userID, &groupID, &groupName); err != nil {
			return err
		}

		_, err := tx.Exec(ctx, `
			INSERT INTO review_items (id, review_id, user_id, resource_type, resource_id, resource_name, decision)
			VALUES (gen_random_uuid(), $1, $2, 'group', $3, $4, 'pending')
		`, reviewID, userID, groupID, groupName)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) populatePrivilegedAccessItems(ctx context.Context, tx interface{ Exec(ctx context.Context, sql string, arguments ...interface{}) (interface{}, error) }, reviewID string) error {
	// Get privileged role assignments (admin, manager, etc.)
	rows, err := s.db.Pool.Query(ctx, `
		SELECT ur.user_id, r.id as role_id, r.name as role_name
		FROM user_roles ur
		JOIN roles r ON ur.role_id = r.id
		JOIN users u ON ur.user_id = u.id
		WHERE u.enabled = true
		AND r.name IN ('admin', 'manager', 'auditor')
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var userID, roleID, roleName string
		if err := rows.Scan(&userID, &roleID, &roleName); err != nil {
			return err
		}

		_, err := tx.Exec(ctx, `
			INSERT INTO review_items (id, review_id, user_id, resource_type, resource_id, resource_name, decision)
			VALUES (gen_random_uuid(), $1, $2, 'privileged_role', $3, $4, 'pending')
		`, reviewID, userID, roleID, roleName)
		if err != nil {
			return err
		}
	}

	return nil
}

func isValidStatusTransition(current, next ReviewStatus) bool {
	transitions := map[ReviewStatus][]ReviewStatus{
		ReviewStatusPending:    {ReviewStatusInProgress, ReviewStatusCanceled},
		ReviewStatusInProgress: {ReviewStatusCompleted, ReviewStatusCanceled},
		ReviewStatusCompleted:  {},
		ReviewStatusExpired:    {},
		ReviewStatusCanceled:   {},
	}

	allowed, ok := transitions[current]
	if !ok {
		return false
	}

	for _, s := range allowed {
		if s == next {
			return true
		}
	}
	return false
}

// Custom errors
var (
	ErrReviewCompleted         = &ServiceError{Message: "cannot modify completed review"}
	ErrInvalidStatusTransition = &ServiceError{Message: "invalid status transition"}
)

type ServiceError struct {
	Message string
}

func (e *ServiceError) Error() string {
	return e.Message
}

// RegisterRoutes registers governance service routes
func RegisterRoutes(router *gin.Engine, svc *Service) {
	gov := router.Group("/api/v1/governance")
	{
		// Access reviews
		gov.GET("/reviews", svc.handleListReviews)
		gov.POST("/reviews", svc.handleCreateReview)
		gov.GET("/reviews/:id", svc.handleGetReview)
		gov.PUT("/reviews/:id", svc.handleUpdateReview)
		gov.PATCH("/reviews/:id/status", svc.handleUpdateReviewStatus)
		gov.GET("/reviews/:id/items", svc.handleListReviewItems)
		gov.POST("/reviews/:id/items/:itemId/decision", svc.handleSubmitDecision)
		gov.POST("/reviews/:id/items/batch-decision", svc.handleBatchDecision)

		// Policies
		gov.GET("/policies", svc.handleListPolicies)
		gov.POST("/policies", svc.handleCreatePolicy)
		gov.GET("/policies/:id", svc.handleGetPolicy)
		gov.PUT("/policies/:id", svc.handleUpdatePolicy)
		gov.DELETE("/policies/:id", svc.handleDeletePolicy)
		gov.POST("/policies/:id/evaluate", svc.handleEvaluatePolicy)
	}
}

// HTTP Handlers

func (s *Service) handleListReviews(c *gin.Context) {
	reviews, total, err := s.ListAccessReviews(c.Request.Context(), 0, 20)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.Header("X-Total-Count", strconv.Itoa(total))
	c.JSON(200, reviews)
}

func (s *Service) handleCreateReview(c *gin.Context) {
	var review AccessReview
	if err := c.ShouldBindJSON(&review); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if err := s.CreateAccessReview(c.Request.Context(), &review); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(201, review)
}

func (s *Service) handleGetReview(c *gin.Context) {
	review, err := s.GetAccessReview(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(404, gin.H{"error": "review not found"})
		return
	}
	c.JSON(200, review)
}

func (s *Service) handleUpdateReview(c *gin.Context) {
	var review AccessReview
	if err := c.ShouldBindJSON(&review); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if err := s.UpdateAccessReview(c.Request.Context(), c.Param("id"), &review); err != nil {
		if err == ErrReviewCompleted {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, review)
}

func (s *Service) handleUpdateReviewStatus(c *gin.Context) {
	var req struct {
		Status ReviewStatus `json:"status"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if err := s.UpdateReviewStatus(c.Request.Context(), c.Param("id"), req.Status); err != nil {
		if err == ErrInvalidStatusTransition {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	// Return updated review
	review, _ := s.GetAccessReview(c.Request.Context(), c.Param("id"))
	c.JSON(200, review)
}

func (s *Service) handleListReviewItems(c *gin.Context) {
	offset := 0
	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil {
			offset = parsed
		}
	}

	limit := 50
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil {
			limit = parsed
		}
	}

	decisionFilter := c.Query("decision")

	items, total, err := s.ListReviewItems(c.Request.Context(), c.Param("id"), offset, limit, decisionFilter)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.Header("X-Total-Count", strconv.Itoa(total))
	c.JSON(200, items)
}

func (s *Service) handleBatchDecision(c *gin.Context) {
	var req struct {
		ItemIDs  []string       `json:"item_ids"`
		Decision ReviewDecision `json:"decision"`
		Comments string         `json:"comments"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	userID, exists := c.Get("user_id")
	decidedBy := ""
	if exists {
		if str, ok := userID.(string); ok {
			decidedBy = str
		}
	}

	if err := s.BatchSubmitDecisions(c.Request.Context(), c.Param("id"), req.ItemIDs, req.Decision, req.Comments, decidedBy); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"status": "submitted", "count": len(req.ItemIDs)})
}

func (s *Service) handleSubmitDecision(c *gin.Context) {
	var req struct {
		Decision ReviewDecision `json:"decision"`
		Comments string         `json:"comments"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(401, gin.H{"error": "user not authenticated"})
		return
	}
	userIDStr, ok := userID.(string)
	if !ok {
		c.JSON(500, gin.H{"error": "invalid user ID format"})
		return
	}
	if err := s.SubmitReviewDecision(c.Request.Context(), c.Param("itemId"), req.Decision, req.Comments, userIDStr); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"status": "submitted"})
}

func (s *Service) handleListPolicies(c *gin.Context) {
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

	policies, total, err := s.ListPolicies(c.Request.Context(), offset, limit)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.Header("X-Total-Count", strconv.Itoa(total))
	c.JSON(200, policies)
}

func (s *Service) handleCreatePolicy(c *gin.Context) {
	var policy Policy
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if err := s.CreatePolicy(c.Request.Context(), &policy); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(201, policy)
}

func (s *Service) handleGetPolicy(c *gin.Context) {
	policy, err := s.GetPolicy(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(404, gin.H{"error": "policy not found"})
		return
	}
	c.JSON(200, policy)
}

func (s *Service) handleUpdatePolicy(c *gin.Context) {
	var policy Policy
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if err := s.UpdatePolicy(c.Request.Context(), c.Param("id"), &policy); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, policy)
}

func (s *Service) handleDeletePolicy(c *gin.Context) {
	if err := s.DeletePolicy(c.Request.Context(), c.Param("id")); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(204, nil)
}

func (s *Service) handleEvaluatePolicy(c *gin.Context) {
	var req map[string]interface{}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	
	allowed, err := s.EvaluatePolicy(c.Request.Context(), c.Param("id"), req)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"allowed": allowed})
}
