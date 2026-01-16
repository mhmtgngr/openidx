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
		SELECT id, name, description, type, status, reviewer_id,
		       start_date, end_date, created_at, completed_at
		FROM access_reviews
		ORDER BY created_at DESC
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

// EvaluatePolicy evaluates a policy against a request
func (s *Service) EvaluatePolicy(ctx context.Context, policyID string, request map[string]interface{}) (bool, error) {
	s.logger.Debug("Evaluating policy", zap.String("policy_id", policyID))
	
	// In production, delegate to OPA for policy evaluation
	// For now, return true (allow)
	return true, nil
}

// RegisterRoutes registers governance service routes
func RegisterRoutes(router *gin.Engine, svc *Service) {
	gov := router.Group("/api/v1/governance")
	{
		// Access reviews
		gov.GET("/reviews", svc.handleListReviews)
		gov.POST("/reviews", svc.handleCreateReview)
		gov.GET("/reviews/:id", svc.handleGetReview)
		gov.POST("/reviews/:id/items/:itemId/decision", svc.handleSubmitDecision)
		
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
	c.JSON(200, []Policy{})
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
	c.JSON(200, Policy{})
}

func (s *Service) handleUpdatePolicy(c *gin.Context) {
	c.JSON(200, Policy{})
}

func (s *Service) handleDeletePolicy(c *gin.Context) {
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
