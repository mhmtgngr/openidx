// Package governance provides access certification campaign functionality
package governance

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// CampaignStatus represents the state of a certification campaign
type CampaignStatus string

const (
	CampaignStatusDraft      CampaignStatus = "draft"
	CampaignStatusActive     CampaignStatus = "active"
	CampaignStatusCompleted  CampaignStatus = "completed"
	CampaignStatusExpired    CampaignStatus = "expired"
	CampaignStatusCancelled  CampaignStatus = "cancelled"
)

// CertificationDecision represents the decision on a certification review item
type CertificationDecision string

const (
	DecisionConfirm    CertificationDecision = "confirm"
	DecisionRevoke     CertificationDecision = "revoke"
	DecisionModify     CertificationDecision = "modify"
	DecisionPending    CertificationDecision = "pending"
)

// CampaignScope defines what resources are included in the campaign
type CampaignScope struct {
	ResourceTypes []string `json:"resource_types"` // e.g., ["role", "group", "application"]
	ResourceIDs   []string `json:"resource_ids"`   // Specific resources, or empty for all
	UserIDs       []string `json:"user_ids"`       // Specific users to review, or empty for all with access
	OUPaths       []string `json:"ou_paths"`       // Organizational unit paths
	Tags          []string `json:"tags"`           // Tag-based filtering
}

// CampaignReviewer defines who should perform reviews
type CampaignReviewer struct {
	Type string `json:"type"` // "user", "role", "manager", "resource_owner"
	ID   string `json:"id"`   // User ID, role ID, or empty for manager-based
}

// CertificationCampaign represents an access certification campaign
type CertificationCampaign struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Description     string          `json:"description"`
	Status          CampaignStatus  `json:"status"`
	Scope           CampaignScope   `json:"scope"`
	Reviewers       []CampaignReviewer `json:"reviewers"`
	Deadline        time.Time       `json:"deadline"`
	CreatedBy       string          `json:"created_by"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
	StartedAt       *time.Time      `json:"started_at,omitempty"`
	CompletedAt     *time.Time      `json:"completed_at,omitempty"`
	TotalItems      int             `json:"total_items"`
	ReviewedItems   int             `json:"reviewed_items"`
	AutoRevoke      bool            `json:"auto_revoke"`
	GracePeriodDays int             `json:"grace_period_days"`
}

// CertificationItem represents a single access assignment to be reviewed
type CertificationItem struct {
	ID               string         `json:"id"`
	CampaignID       string         `json:"campaign_id"`
	UserID           string         `json:"user_id"`
	UserName         string         `json:"user_name,omitempty"`
	ResourceType     string         `json:"resource_type"`
	ResourceID       string         `json:"resource_id"`
	ResourceName     string         `json:"resource_name,omitempty"`
	ReviewerID       string         `json:"reviewer_id"`
	ReviewerName     string         `json:"reviewer_name,omitempty"`
	Decision         CertificationDecision `json:"decision"`
	Comments         string         `json:"comments"`
	ReviewedAt       *time.Time     `json:"reviewed_at,omitempty"`
	OriginalGrantDate time.Time     `json:"original_grant_date"`
	CreatedAt        time.Time      `json:"created_at"`
}

// CertificationService handles access certification operations
type CertificationService struct {
	db     *database.PostgresDB
	logger *zap.Logger
}

// NewCertificationService creates a new certification service instance
func NewCertificationService(db *database.PostgresDB, logger *zap.Logger) *CertificationService {
	return &CertificationService{
		db:     db,
		logger: logger,
	}
}

// CreateCampaign creates a new access certification campaign
func (s *CertificationService) CreateCampaign(ctx context.Context, name, description, createdBy string, scope CampaignScope, reviewers []CampaignReviewer, deadline time.Time, autoRevoke bool, gracePeriodDays int) (*CertificationCampaign, error) {
	if name == "" {
		return nil, fmt.Errorf("campaign name is required")
	}
	if createdBy == "" {
		return nil, fmt.Errorf("created_by is required")
	}
	if len(reviewers) == 0 {
		return nil, fmt.Errorf("at least one reviewer is required")
	}
	if deadline.Before(time.Now()) {
		return nil, fmt.Errorf("deadline must be in the future")
	}

	id := uuid.New().String()
	now := time.Now()

	// Serialize scope and reviewers
	scopeJSON, err := json.Marshal(scope)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize scope: %w", err)
	}

	reviewersJSON, err := json.Marshal(reviewers)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize reviewers: %w", err)
	}

	// Create the campaign
	_, err = s.db.Pool.Exec(ctx,
		`INSERT INTO certification_campaigns (id, name, description, status, scope, reviewers, deadline, created_by, created_at, updated_at, auto_revoke, grace_period_days)
		 VALUES ($1, $2, $3, 'draft', $4, $5, $6, $7, $8, $8, $9, $10)`,
		id, name, description, scopeJSON, reviewersJSON, deadline, createdBy, now, autoRevoke, gracePeriodDays)
	if err != nil {
		s.logger.Error("Failed to create certification campaign",
			zap.String("name", name),
			zap.Error(err))
		return nil, fmt.Errorf("failed to create certification campaign: %w", err)
	}

	campaign := &CertificationCampaign{
		ID:              id,
		Name:            name,
		Description:     description,
		Status:          CampaignStatusDraft,
		Scope:           scope,
		Reviewers:       reviewers,
		Deadline:        deadline,
		CreatedBy:       createdBy,
		CreatedAt:       now,
		UpdatedAt:       now,
		AutoRevoke:      autoRevoke,
		GracePeriodDays: gracePeriodDays,
	}

	s.logger.Info("Certification campaign created",
		zap.String("campaign_id", id),
		zap.String("name", name),
		zap.Time("deadline", deadline))

	return campaign, nil
}

// StartCampaign activates a campaign and generates review items
func (s *CertificationService) StartCampaign(ctx context.Context, campaignID string) error {
	// Get the campaign
	campaign, err := s.getCampaign(ctx, campaignID)
	if err != nil {
		return err
	}

	if campaign.Status != CampaignStatusDraft {
		return fmt.Errorf("campaign is not in draft status: %s", campaign.Status)
	}

	// Generate review items from current role assignments
	items, err := s.generateReviewItems(ctx, campaign)
	if err != nil {
		return fmt.Errorf("failed to generate review items: %w", err)
	}

	now := time.Now()

	// Update campaign status
	_, err = s.db.Pool.Exec(ctx,
		`UPDATE certification_campaigns SET status = 'active', started_at = $1, updated_at = $1, total_items = $2 WHERE id = $3`,
		now, len(items), campaignID)
	if err != nil {
		return fmt.Errorf("failed to update campaign status: %w", err)
	}

	s.logger.Info("Certification campaign started",
		zap.String("campaign_id", campaignID),
		zap.Int("total_items", len(items)))

	return nil
}

// generateReviewItems creates certification items from current access assignments
func (s *CertificationService) generateReviewItems(ctx context.Context, campaign *CertificationCampaign) ([]CertificationItem, error) {
	var items []CertificationItem

	// Build query based on scope
	query := `
		SELECT ur.user_id, u.username, ur.role_id, r.name as role_name, ur.created_at
		FROM user_roles ur
		INNER JOIN users u ON u.id = ur.user_id
		INNER JOIN roles r ON r.id = ur.role_id
		WHERE ur.expires_at IS NULL OR ur.expires_at > NOW()`

	args := []interface{}{}
	argIdx := 1

	// Apply scope filters
	if len(campaign.Scope.UserIDs) > 0 {
		query += fmt.Sprintf(" AND ur.user_id = ANY($%d)", argIdx)
		args = append(args, campaign.Scope.UserIDs)
		argIdx++
	}
	if len(campaign.Scope.ResourceIDs) > 0 {
		query += fmt.Sprintf(" AND ur.role_id = ANY($%d)", argIdx)
		args = append(args, campaign.Scope.ResourceIDs)
		argIdx++
	}

	rows, err := s.db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query role assignments: %w", err)
	}
	defer rows.Close()

	// Map of items to insert
	itemMap := make(map[string]*CertificationItem)

	for rows.Next() {
		var userID, userName, roleID, roleName string
		var grantedAt time.Time

		if err := rows.Scan(&userID, &userName, &roleID, &roleName, &grantedAt); err != nil {
			continue
		}

		// Determine reviewer for this item
		reviewerID, err := s.resolveReviewer(ctx, campaign, userID, roleID)
		if err != nil {
			s.logger.Warn("Failed to resolve reviewer",
				zap.String("user_id", userID),
				zap.String("role_id", roleID),
				zap.Error(err))
			continue
		}

		itemID := uuid.New().String()
		item := &CertificationItem{
			ID:                itemID,
			CampaignID:        campaign.ID,
			UserID:            userID,
			UserName:          userName,
			ResourceType:      "role",
			ResourceID:        roleID,
			ResourceName:      roleName,
			ReviewerID:        reviewerID,
			Decision:          DecisionPending,
			OriginalGrantDate: grantedAt,
			CreatedAt:         time.Now(),
		}

		itemMap[itemID] = item
		items = append(items, *item)
	}

	// Batch insert items
	if len(items) > 0 {
		batchQuery := `
			INSERT INTO certification_items (id, campaign_id, user_id, resource_type, resource_id, reviewer_id, decision, created_at)
			VALUES `

		vals := []interface{}{}
		for i, item := range items {
			if i > 0 {
				batchQuery += ", "
			}
			batchQuery += fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d)",
				i*8+1, i*8+2, i*8+3, i*8+4, i*8+5, i*8+6, i*8+7, i*8+8)
			vals = append(vals, item.ID, item.CampaignID, item.UserID, item.ResourceType,
				item.ResourceID, item.ReviewerID, string(item.Decision), item.CreatedAt)
		}

		_, err = s.db.Pool.Exec(ctx, batchQuery, vals...)
		if err != nil {
			return nil, fmt.Errorf("failed to insert certification items: %w", err)
		}
	}

	return items, nil
}

// resolveReviewer determines which reviewer should review a specific item
func (s *CertificationService) resolveReviewer(ctx context.Context, campaign *CertificationCampaign, userID, resourceID string) (string, error) {
	// For each reviewer type in the campaign, find the actual reviewer
	for _, reviewerConfig := range campaign.Reviewers {
		switch reviewerConfig.Type {
		case "manager":
			// Get user's manager
			var managerID string
			err := s.db.Pool.QueryRow(ctx,
				`SELECT manager_id FROM users WHERE id = $1`, userID).Scan(&managerID)
			if err == nil && managerID != "" {
				return managerID, nil
			}
		case "resource_owner":
			// Get resource owner
			var ownerID string
			err := s.db.Pool.QueryRow(ctx,
				`SELECT owner_id FROM entitlement_metadata WHERE entitlement_type = 'role' AND entitlement_id = $1`,
				resourceID).Scan(&ownerID)
			if err == nil && ownerID != "" {
				return ownerID, nil
			}
		case "user":
			// Direct user assignment
			if reviewerConfig.ID != "" {
				return reviewerConfig.ID, nil
			}
		case "role":
			// Find users with this reviewer role and assign round-robin
			// For simplicity, return the first user with this role
			var reviewerUserID string
			err := s.db.Pool.QueryRow(ctx,
				`SELECT user_id FROM user_roles WHERE role_id = $1 LIMIT 1`,
				reviewerConfig.ID).Scan(&reviewerUserID)
			if err == nil && reviewerUserID != "" {
				return reviewerUserID, nil
			}
		}
	}

	// Default: return a system admin
	return "00000000-0000-0000-0000-000000000001", nil
}

// ReviewItem records a decision on a certification item
func (s *CertificationService) ReviewItem(ctx context.Context, itemID string, decision CertificationDecision, reviewerID, comments string) error {
	// Verify the item exists and is pending
	var currentReviewerID string
	var currentStatus string
	err := s.db.Pool.QueryRow(ctx,
		`SELECT reviewer_id, decision FROM certification_items WHERE id = $1`,
		itemID).Scan(&currentReviewerID, &currentStatus)
	if err != nil {
		return fmt.Errorf("certification item not found: %w", err)
	}

	// Verify reviewer (optional - can be bypassed for admin)
	if currentReviewerID != reviewerID {
		// Check if requester is an admin
		var isAdmin bool
		s.db.Pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM user_roles ur INNER JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = $1 AND r.name = 'admin')`,
			reviewerID).Scan(&isAdmin)
		if !isAdmin {
			return fmt.Errorf("user is not authorized to review this item")
		}
	}

	now := time.Now()

	// Update the item
	_, err = s.db.Pool.Exec(ctx,
		`UPDATE certification_items SET decision = $1, comments = $2, reviewed_at = $3 WHERE id = $4`,
		string(decision), comments, now, itemID)
	if err != nil {
		return fmt.Errorf("failed to update certification item: %w", err)
	}

	// Update campaign reviewed items count
	_, err = s.db.Pool.Exec(ctx,
		`UPDATE certification_campaigns c
		 SET reviewed_items = (
		     SELECT COUNT(*) FROM certification_items WHERE campaign_id = c.id AND decision != 'pending'
		 ),
		 updated_at = $1
		 WHERE id = (SELECT campaign_id FROM certification_items WHERE id = $2)`,
		now, itemID)
	if err != nil {
		s.logger.Error("Failed to update campaign review count",
			zap.String("item_id", itemID),
			zap.Error(err))
	}

	s.logger.Info("Certification item reviewed",
		zap.String("item_id", itemID),
		zap.String("decision", string(decision)),
		zap.String("reviewer_id", reviewerID))

	return nil
}

// GetCampaign retrieves a certification campaign by ID
func (s *CertificationService) GetCampaign(ctx context.Context, campaignID string) (*CertificationCampaign, error) {
	return s.getCampaign(ctx, campaignID)
}

// getCampaign retrieves the campaign from the database
func (s *CertificationService) getCampaign(ctx context.Context, campaignID string) (*CertificationCampaign, error) {
	var campaign CertificationCampaign
	var scopeJSON, reviewersJSON []byte
	var startedAt, completedAt *time.Time

	err := s.db.Pool.QueryRow(ctx,
		`SELECT id, name, description, status, scope, reviewers, deadline, created_by, created_at, updated_at, started_at, completed_at, total_items, reviewed_items, auto_revoke, grace_period_days
		 FROM certification_campaigns WHERE id = $1`,
		campaignID).Scan(
		&campaign.ID, &campaign.Name, &campaign.Description, &campaign.Status,
		&scopeJSON, &reviewersJSON, &campaign.Deadline, &campaign.CreatedBy,
		&campaign.CreatedAt, &campaign.UpdatedAt, &startedAt, &completedAt,
		&campaign.TotalItems, &campaign.ReviewedItems, &campaign.AutoRevoke,
		&campaign.GracePeriodDays)

	if err != nil {
		return nil, fmt.Errorf("campaign not found: %w", err)
	}

	campaign.StartedAt = startedAt
	campaign.CompletedAt = completedAt

	if scopeJSON != nil {
		json.Unmarshal(scopeJSON, &campaign.Scope)
	}
	if reviewersJSON != nil {
		json.Unmarshal(reviewersJSON, &campaign.Reviewers)
	}

	return &campaign, nil
}

// GetCampaignItems retrieves all certification items for a campaign
func (s *CertificationService) GetCampaignItems(ctx context.Context, campaignID string) ([]CertificationItem, error) {
	rows, err := s.db.Pool.Query(ctx,
		`SELECT id, campaign_id, user_id, resource_type, resource_id, reviewer_id, decision, comments, reviewed_at, created_at
		 FROM certification_items WHERE campaign_id = $1 ORDER BY created_at ASC`,
		campaignID)
	if err != nil {
		return nil, fmt.Errorf("failed to query certification items: %w", err)
	}
	defer rows.Close()

	var items []CertificationItem
	for rows.Next() {
		var item CertificationItem
		var reviewedAt *time.Time

		if err := rows.Scan(&item.ID, &item.CampaignID, &item.UserID,
			&item.ResourceType, &item.ResourceID, &item.ReviewerID,
			&item.Decision, &item.Comments, &reviewedAt, &item.CreatedAt); err != nil {
			continue
		}

		item.ReviewedAt = reviewedAt
		items = append(items, item)
	}

	if items == nil {
		return []CertificationItem{}, nil
	}
	return items, nil
}

// GetReviewerItems retrieves all pending items for a specific reviewer
func (s *CertificationService) GetReviewerItems(ctx context.Context, reviewerID string) ([]CertificationItem, error) {
	rows, err := s.db.Pool.Query(ctx,
		`SELECT ci.id, ci.campaign_id, ci.user_id, u.username, ci.resource_type, ci.resource_id, r.name as resource_name,
		        ci.reviewer_id, rev.username as reviewer_name, ci.decision, ci.comments, ci.reviewed_at, ci.created_at
		 FROM certification_items ci
		 LEFT JOIN users u ON u.id = ci.user_id
		 LEFT JOIN roles r ON r.id = ci.resource_id
		 LEFT JOIN users rev ON rev.id = ci.reviewer_id
		 WHERE ci.reviewer_id = $1 AND ci.decision = 'pending'
		 ORDER BY ci.created_at ASC`,
		reviewerID)
	if err != nil {
		return nil, fmt.Errorf("failed to query reviewer items: %w", err)
	}
	defer rows.Close()

	var items []CertificationItem
	for rows.Next() {
		var item CertificationItem
		var reviewedAt *time.Time

		if err := rows.Scan(&item.ID, &item.CampaignID, &item.UserID, &item.UserName,
			&item.ResourceType, &item.ResourceID, &item.ResourceName,
			&item.ReviewerID, &item.ReviewerName, &item.Decision, &item.Comments,
			&reviewedAt, &item.CreatedAt); err != nil {
			continue
		}

		item.ReviewedAt = reviewedAt
		items = append(items, item)
	}

	if items == nil {
		return []CertificationItem{}, nil
	}
	return items, nil
}

// GetCompletionPercentage returns the completion percentage of a campaign
func (s *CertificationService) GetCompletionPercentage(ctx context.Context, campaignID string) (float64, error) {
	var total, reviewed int

	err := s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM certification_items WHERE campaign_id = $1`,
		campaignID).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("failed to count total items: %w", err)
	}

	if total == 0 {
		return 0, nil
	}

	err = s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM certification_items WHERE campaign_id = $1 AND decision != 'pending'`,
		campaignID).Scan(&reviewed)
	if err != nil {
		return 0, fmt.Errorf("failed to count reviewed items: %w", err)
	}

	return float64(reviewed) / float64(total) * 100, nil
}

// CompleteCampaign marks a campaign as completed
func (s *CertificationService) CompleteCampaign(ctx context.Context, campaignID string) error {
	// Check if all items are reviewed
	var pendingCount int
	err := s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM certification_items WHERE campaign_id = $1 AND decision = 'pending'`,
		campaignID).Scan(&pendingCount)
	if err != nil {
		return fmt.Errorf("failed to check pending items: %w", err)
	}

	if pendingCount > 0 {
		return fmt.Errorf("campaign has %d pending items remaining", pendingCount)
	}

	now := time.Now()
	_, err = s.db.Pool.Exec(ctx,
		`UPDATE certification_campaigns SET status = 'completed', completed_at = $1, updated_at = $1 WHERE id = $2`,
		now, campaignID)
	if err != nil {
		return fmt.Errorf("failed to complete campaign: %w", err)
	}

	s.logger.Info("Certification campaign completed",
		zap.String("campaign_id", campaignID))

	return nil
}

// ProcessExpiredCampaigns finds campaigns past their deadline and processes unreviewed items
func (s *CertificationService) ProcessExpiredCampaigns(ctx context.Context) error {
	// Find active campaigns past deadline
	rows, err := s.db.Pool.Query(ctx,
		`SELECT id, auto_revoke FROM certification_campaigns WHERE status = 'active' AND deadline < NOW()`)
	if err != nil {
		return fmt.Errorf("failed to query expired campaigns: %w", err)
	}
	defer rows.Close()

	var expiredCampaigns []struct {
		ID        string
		AutoRevoke bool
	}

	for rows.Next() {
		var c struct {
			ID        string
			AutoRevoke bool
		}
		if err := rows.Scan(&c.ID, &c.AutoRevoke); err != nil {
			continue
		}
		expiredCampaigns = append(expiredCampaigns, c)
	}

	for _, c := range expiredCampaigns {
		// Mark campaign as expired
		now := time.Now()
		_, err := s.db.Pool.Exec(ctx,
			`UPDATE certification_campaigns SET status = 'expired', completed_at = $1, updated_at = $1 WHERE id = $2`,
			now, c.ID)
		if err != nil {
			s.logger.Error("Failed to mark campaign as expired",
				zap.String("campaign_id", c.ID),
				zap.Error(err))
			continue
		}

		// Process unreviewed items if auto-revoke is enabled
		if c.AutoRevoke {
			s.revokeUnreviewedItems(ctx, c.ID)
		}

		s.logger.Info("Certification campaign expired",
			zap.String("campaign_id", c.ID),
			zap.Bool("auto_revoke_enabled", c.AutoRevoke))
	}

	return nil
}

// revokeUnreviewedItems revokes access for all pending items in a campaign
func (s *CertificationService) revokeUnreviewedItems(ctx context.Context, campaignID string) {
	// Get all pending items
	rows, err := s.db.Pool.Query(ctx,
		`SELECT id, user_id, resource_type, resource_id FROM certification_items WHERE campaign_id = $1 AND decision = 'pending'`,
		campaignID)
	if err != nil {
		s.logger.Error("Failed to query pending items for revocation",
			zap.String("campaign_id", campaignID),
			zap.Error(err))
		return
	}
	defer rows.Close()

	var revokedCount int
	for rows.Next() {
		var itemID, userID, resourceType, resourceID string
		if err := rows.Scan(&itemID, &userID, &resourceType, &resourceID); err != nil {
			continue
		}

		// Revoke the access based on resource type
		switch resourceType {
		case "role":
			_, err := s.db.Pool.Exec(ctx,
				`DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`,
				userID, resourceID)
			if err != nil {
				s.logger.Error("Failed to revoke role",
					zap.String("user_id", userID),
					zap.String("role_id", resourceID),
					zap.Error(err))
				continue
			}
		}

		// Mark item as revoked
		_, err = s.db.Pool.Exec(ctx,
			`UPDATE certification_items SET decision = 'revoke', comments = 'Auto-revoked after campaign deadline', reviewed_at = NOW() WHERE id = $1`,
			itemID)
		if err != nil {
			s.logger.Error("Failed to mark item as revoked",
				zap.String("item_id", itemID),
				zap.Error(err))
			continue
		}

		revokedCount++
		s.logger.Info("Auto-revoked unreviewed certification item",
			zap.String("item_id", itemID),
			zap.String("user_id", userID),
			zap.String("resource_id", resourceID))
	}

	s.logger.Info("Campaign unreviewed items processed",
		zap.String("campaign_id", campaignID),
		zap.Int("revoked_count", revokedCount))
}

// ListCampaigns returns all campaigns with optional status filter
func (s *CertificationService) ListCampaigns(ctx context.Context, status *CampaignStatus) ([]CertificationCampaign, error) {
	query := `SELECT id, name, description, status, scope, reviewers, deadline, created_by, created_at, updated_at, started_at, completed_at, total_items, reviewed_items, auto_revoke, grace_period_days
	          FROM certification_campaigns`

	args := []interface{}{}
	if status != nil {
		query += " WHERE status = $1"
		args = append(args, string(*status))
	}

	query += " ORDER BY created_at DESC"

	rows, err := s.db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list campaigns: %w", err)
	}
	defer rows.Close()

	var campaigns []CertificationCampaign
	for rows.Next() {
		var c CertificationCampaign
		var scopeJSON, reviewersJSON []byte
		var startedAt, completedAt *time.Time

		if err := rows.Scan(&c.ID, &c.Name, &c.Description, &c.Status,
			&scopeJSON, &reviewersJSON, &c.Deadline, &c.CreatedBy,
			&c.CreatedAt, &c.UpdatedAt, &startedAt, &completedAt,
			&c.TotalItems, &c.ReviewedItems, &c.AutoRevoke, &c.GracePeriodDays); err != nil {
			continue
		}

		c.StartedAt = startedAt
		c.CompletedAt = completedAt

		if scopeJSON != nil {
			json.Unmarshal(scopeJSON, &c.Scope)
		}
		if reviewersJSON != nil {
			json.Unmarshal(reviewersJSON, &c.Reviewers)
		}

		campaigns = append(campaigns, c)
	}

	if campaigns == nil {
		return []CertificationCampaign{}, nil
	}
	return campaigns, nil
}

// DeleteCampaign deletes a campaign (only if in draft status)
func (s *CertificationService) DeleteCampaign(ctx context.Context, campaignID string) error {
	// Check status
	var status string
	err := s.db.Pool.QueryRow(ctx,
		`SELECT status FROM certification_campaigns WHERE id = $1`, campaignID).Scan(&status)
	if err != nil {
		return fmt.Errorf("campaign not found: %w", err)
	}

	if status != string(CampaignStatusDraft) {
		return fmt.Errorf("can only delete campaigns in draft status")
	}

	// Delete campaign (cascade will delete items)
	_, err = s.db.Pool.Exec(ctx, `DELETE FROM certification_campaigns WHERE id = $1`, campaignID)
	if err != nil {
		return fmt.Errorf("failed to delete campaign: %w", err)
	}

	s.logger.Info("Certification campaign deleted",
		zap.String("campaign_id", campaignID))

	return nil
}
