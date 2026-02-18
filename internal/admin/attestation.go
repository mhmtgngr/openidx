package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// AttestationCampaign represents a certification/attestation campaign
type AttestationCampaign struct {
	ID                  string          `json:"id"`
	Name                string          `json:"name"`
	Description         string          `json:"description"`
	CampaignType        string          `json:"campaign_type"`
	Scope               json.RawMessage `json:"scope"`
	ReviewerStrategy    string          `json:"reviewer_strategy"`
	Status              string          `json:"status"`
	DueDate             *time.Time      `json:"due_date"`
	ReminderDays        json.RawMessage `json:"reminder_days"`
	EscalationAfterDays int             `json:"escalation_after_days"`
	AutoRevokeOnExpiry  bool            `json:"auto_revoke_on_expiry"`
	CreatedBy           *string         `json:"created_by"`
	CreatedAt           time.Time       `json:"created_at"`
	CompletedAt         *time.Time      `json:"completed_at"`
	// Computed fields
	TotalItems    int `json:"total_items,omitempty"`
	CertifiedCount int `json:"certified_count,omitempty"`
	RevokedCount  int `json:"revoked_count,omitempty"`
	PendingCount  int `json:"pending_count,omitempty"`
}

// AttestationItem represents an individual item in an attestation campaign
type AttestationItem struct {
	ID           string     `json:"id"`
	CampaignID   string     `json:"campaign_id"`
	ReviewerID   *string    `json:"reviewer_id"`
	ReviewerName string     `json:"reviewer_name,omitempty"`
	UserID       *string    `json:"user_id"`
	UserName     string     `json:"user_name,omitempty"`
	ResourceType string     `json:"resource_type"`
	ResourceID   *string    `json:"resource_id"`
	ResourceName string     `json:"resource_name"`
	Decision     string     `json:"decision"`
	DelegatedTo  *string    `json:"delegated_to"`
	DelegatedAt  *time.Time `json:"delegated_at"`
	Comments     string     `json:"comments"`
	DecidedAt    *time.Time `json:"decided_at"`
	RemindedAt   *time.Time `json:"reminded_at"`
	CreatedAt    time.Time  `json:"created_at"`
}

// --- Handlers ---

func (s *Service) handleListAttestationCampaigns(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT ac.id, ac.name, ac.description, ac.campaign_type, ac.scope, ac.reviewer_strategy,
		        ac.status, ac.due_date, ac.reminder_days, ac.escalation_after_days, ac.auto_revoke_on_expiry,
		        ac.created_by, ac.created_at, ac.completed_at,
		        COALESCE((SELECT COUNT(*) FROM attestation_items WHERE campaign_id = ac.id), 0),
		        COALESCE((SELECT COUNT(*) FROM attestation_items WHERE campaign_id = ac.id AND decision = 'certified'), 0),
		        COALESCE((SELECT COUNT(*) FROM attestation_items WHERE campaign_id = ac.id AND decision = 'revoked'), 0),
		        COALESCE((SELECT COUNT(*) FROM attestation_items WHERE campaign_id = ac.id AND decision = 'pending'), 0)
		 FROM attestation_campaigns ac ORDER BY ac.created_at DESC`)
	if err != nil {
		s.logger.Error("Failed to list attestation campaigns", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list campaigns"})
		return
	}
	defer rows.Close()

	var campaigns []AttestationCampaign
	for rows.Next() {
		var ac AttestationCampaign
		if err := rows.Scan(&ac.ID, &ac.Name, &ac.Description, &ac.CampaignType, &ac.Scope,
			&ac.ReviewerStrategy, &ac.Status, &ac.DueDate, &ac.ReminderDays,
			&ac.EscalationAfterDays, &ac.AutoRevokeOnExpiry, &ac.CreatedBy,
			&ac.CreatedAt, &ac.CompletedAt,
			&ac.TotalItems, &ac.CertifiedCount, &ac.RevokedCount, &ac.PendingCount); err != nil {
			continue
		}
		campaigns = append(campaigns, ac)
	}
	if campaigns == nil {
		campaigns = []AttestationCampaign{}
	}
	c.JSON(http.StatusOK, gin.H{"data": campaigns})
}

func (s *Service) handleCreateAttestationCampaign(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	var req struct {
		Name                string          `json:"name"`
		Description         string          `json:"description"`
		CampaignType        string          `json:"campaign_type"`
		Scope               json.RawMessage `json:"scope"`
		ReviewerStrategy    string          `json:"reviewer_strategy"`
		DueDate             *time.Time      `json:"due_date"`
		ReminderDays        json.RawMessage `json:"reminder_days"`
		EscalationAfterDays int             `json:"escalation_after_days"`
		AutoRevokeOnExpiry  bool            `json:"auto_revoke_on_expiry"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if req.Name == "" || req.CampaignType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name and campaign_type are required"})
		return
	}

	validTypes := map[string]bool{
		"manager_review": true, "application_access": true,
		"role_certification": true, "entitlement_review": true,
	}
	if !validTypes[req.CampaignType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid campaign type"})
		return
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	scope := req.Scope
	if scope == nil {
		scope = json.RawMessage("{}")
	}
	reminderDays := req.ReminderDays
	if reminderDays == nil {
		reminderDays = json.RawMessage("[7, 3, 1]")
	}
	if req.ReviewerStrategy == "" {
		req.ReviewerStrategy = "manager"
	}
	if req.EscalationAfterDays <= 0 {
		req.EscalationAfterDays = 14
	}

	var id string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`INSERT INTO attestation_campaigns (name, description, campaign_type, scope, reviewer_strategy,
		  due_date, reminder_days, escalation_after_days, auto_revoke_on_expiry, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`,
		req.Name, req.Description, req.CampaignType, scope, req.ReviewerStrategy,
		req.DueDate, reminderDays, req.EscalationAfterDays, req.AutoRevokeOnExpiry, nilIfEmpty(userIDStr),
	).Scan(&id)
	if err != nil {
		s.logger.Error("Failed to create attestation campaign", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create campaign"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id, "status": "draft"})
}

func (s *Service) handleGetAttestationCampaign(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	var ac AttestationCampaign
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT id, name, description, campaign_type, scope, reviewer_strategy, status, due_date,
		        reminder_days, escalation_after_days, auto_revoke_on_expiry, created_by, created_at, completed_at
		 FROM attestation_campaigns WHERE id = $1`, id,
	).Scan(&ac.ID, &ac.Name, &ac.Description, &ac.CampaignType, &ac.Scope, &ac.ReviewerStrategy,
		&ac.Status, &ac.DueDate, &ac.ReminderDays, &ac.EscalationAfterDays,
		&ac.AutoRevokeOnExpiry, &ac.CreatedBy, &ac.CreatedAt, &ac.CompletedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Campaign not found"})
		return
	}

	// Get item counts
	_ = s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT COUNT(*) FROM attestation_items WHERE campaign_id = $1", id).Scan(&ac.TotalItems)
	_ = s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT COUNT(*) FROM attestation_items WHERE campaign_id = $1 AND decision = 'certified'", id).Scan(&ac.CertifiedCount)
	_ = s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT COUNT(*) FROM attestation_items WHERE campaign_id = $1 AND decision = 'revoked'", id).Scan(&ac.RevokedCount)
	_ = s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT COUNT(*) FROM attestation_items WHERE campaign_id = $1 AND decision = 'pending'", id).Scan(&ac.PendingCount)

	c.JSON(http.StatusOK, ac)
}

func (s *Service) handleUpdateAttestationCampaign(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")

	// Only allow updating draft campaigns
	var status string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT status FROM attestation_campaigns WHERE id = $1", id).Scan(&status)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Campaign not found"})
		return
	}
	if status != "draft" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Can only update draft campaigns"})
		return
	}

	var req struct {
		Name                *string          `json:"name"`
		Description         *string          `json:"description"`
		Scope               *json.RawMessage `json:"scope"`
		ReviewerStrategy    *string          `json:"reviewer_strategy"`
		DueDate             *time.Time       `json:"due_date"`
		EscalationAfterDays *int             `json:"escalation_after_days"`
		AutoRevokeOnExpiry  *bool            `json:"auto_revoke_on_expiry"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	sets := []string{}
	args := []interface{}{}
	argIdx := 1

	if req.Name != nil {
		sets = append(sets, pf("name = $%d", argIdx))
		args = append(args, *req.Name)
		argIdx++
	}
	if req.Description != nil {
		sets = append(sets, pf("description = $%d", argIdx))
		args = append(args, *req.Description)
		argIdx++
	}
	if req.Scope != nil {
		sets = append(sets, pf("scope = $%d", argIdx))
		args = append(args, *req.Scope)
		argIdx++
	}
	if req.ReviewerStrategy != nil {
		sets = append(sets, pf("reviewer_strategy = $%d", argIdx))
		args = append(args, *req.ReviewerStrategy)
		argIdx++
	}
	if req.DueDate != nil {
		sets = append(sets, pf("due_date = $%d", argIdx))
		args = append(args, *req.DueDate)
		argIdx++
	}
	if req.EscalationAfterDays != nil {
		sets = append(sets, pf("escalation_after_days = $%d", argIdx))
		args = append(args, *req.EscalationAfterDays)
		argIdx++
	}
	if req.AutoRevokeOnExpiry != nil {
		sets = append(sets, pf("auto_revoke_on_expiry = $%d", argIdx))
		args = append(args, *req.AutoRevokeOnExpiry)
		argIdx++
	}

	if len(sets) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No fields to update"})
		return
	}

	args = append(args, id)
	query := pf("UPDATE attestation_campaigns SET %s WHERE id = $%d", joinSetClauses(sets), argIdx)
	_, err = s.db.Pool.Exec(c.Request.Context(), query, args...)
	if err != nil {
		s.logger.Error("Failed to update campaign", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update campaign"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Campaign updated"})
}

func (s *Service) handleLaunchAttestationCampaign(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	var ac AttestationCampaign
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT id, campaign_type, scope, reviewer_strategy, status
		 FROM attestation_campaigns WHERE id = $1`, id,
	).Scan(&ac.ID, &ac.CampaignType, &ac.Scope, &ac.ReviewerStrategy, &ac.Status)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Campaign not found"})
		return
	}
	if ac.Status != "draft" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Campaign is already launched"})
		return
	}

	// Generate attestation items based on campaign type
	itemsCreated := s.generateAttestationItems(c.Request.Context(), ac)

	// Update campaign status
	_, _ = s.db.Pool.Exec(c.Request.Context(),
		"UPDATE attestation_campaigns SET status = 'active' WHERE id = $1", id)

	c.JSON(http.StatusOK, gin.H{"message": "Campaign launched", "items_created": itemsCreated})
}

func (s *Service) generateAttestationItems(ctx context.Context, ac AttestationCampaign) int {
	count := 0

	switch ac.CampaignType {
	case "role_certification":
		// Create items for each user-role assignment
		rows, err := s.db.Pool.Query(ctx,
			`SELECT ur.user_id, u.username, ur.role_id, r.name
			 FROM user_roles ur
			 JOIN users u ON ur.user_id = u.id
			 JOIN roles r ON ur.role_id = r.id
			 WHERE u.enabled = true`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var userID, username, roleID, roleName string
				if err := rows.Scan(&userID, &username, &roleID, &roleName); err == nil {
					// Use admin as default reviewer
					_, err := s.db.Pool.Exec(ctx,
						`INSERT INTO attestation_items (campaign_id, reviewer_id, user_id, resource_type, resource_id, resource_name)
						 VALUES ($1, (SELECT id FROM users WHERE username = 'admin' LIMIT 1), $2, 'role', $3, $4)`,
						ac.ID, userID, roleID, roleName)
					if err == nil {
						count++
					}
				}
			}
		}

	case "application_access":
		// Create items for each user-application assignment
		rows, err := s.db.Pool.Query(ctx,
			`SELECT uaa.user_id, u.username, uaa.application_id, a.name
			 FROM user_application_assignments uaa
			 JOIN users u ON uaa.user_id = u.id
			 JOIN applications a ON uaa.application_id = a.id
			 WHERE u.enabled = true`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var userID, username, appID, appName string
				if err := rows.Scan(&userID, &username, &appID, &appName); err == nil {
					_, err := s.db.Pool.Exec(ctx,
						`INSERT INTO attestation_items (campaign_id, reviewer_id, user_id, resource_type, resource_id, resource_name)
						 VALUES ($1, (SELECT id FROM users WHERE username = 'admin' LIMIT 1), $2, 'application', $3, $4)`,
						ac.ID, userID, appID, appName)
					if err == nil {
						count++
					}
				}
			}
		}

	case "manager_review":
		// Create items for each user's group memberships
		rows, err := s.db.Pool.Query(ctx,
			`SELECT gm.user_id, u.username, gm.group_id, g.name
			 FROM group_memberships gm
			 JOIN users u ON gm.user_id = u.id
			 JOIN groups g ON gm.group_id = g.id
			 WHERE u.enabled = true`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var userID, username, groupID, groupName string
				if err := rows.Scan(&userID, &username, &groupID, &groupName); err == nil {
					_, err := s.db.Pool.Exec(ctx,
						`INSERT INTO attestation_items (campaign_id, reviewer_id, user_id, resource_type, resource_id, resource_name)
						 VALUES ($1, (SELECT id FROM users WHERE username = 'admin' LIMIT 1), $2, 'group', $3, $4)`,
						ac.ID, userID, groupID, groupName)
					if err == nil {
						count++
					}
				}
			}
		}

	case "entitlement_review":
		// Create items for role-permission combinations
		rows, err := s.db.Pool.Query(ctx,
			`SELECT ur.user_id, u.username, r.id, r.name
			 FROM user_roles ur
			 JOIN users u ON ur.user_id = u.id
			 JOIN roles r ON ur.role_id = r.id
			 WHERE u.enabled = true AND r.name IN ('admin', 'manager')`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var userID, username, roleID, roleName string
				if err := rows.Scan(&userID, &username, &roleID, &roleName); err == nil {
					_, err := s.db.Pool.Exec(ctx,
						`INSERT INTO attestation_items (campaign_id, reviewer_id, user_id, resource_type, resource_id, resource_name)
						 VALUES ($1, (SELECT id FROM users WHERE username = 'admin' LIMIT 1), $2, 'entitlement', $3, $4)`,
						ac.ID, userID, roleID, pf("Role: %s", roleName))
					if err == nil {
						count++
					}
				}
			}
		}
	}

	return count
}

func (s *Service) handleListAttestationItems(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	campaignID := c.Param("id")
	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT ai.id, ai.campaign_id, ai.reviewer_id, COALESCE(r.username, '') as reviewer_name,
		        ai.user_id, COALESCE(u.username, '') as user_name,
		        ai.resource_type, ai.resource_id, ai.resource_name,
		        ai.decision, ai.delegated_to, ai.delegated_at, ai.comments, ai.decided_at, ai.reminded_at, ai.created_at
		 FROM attestation_items ai
		 LEFT JOIN users r ON ai.reviewer_id = r.id
		 LEFT JOIN users u ON ai.user_id = u.id
		 WHERE ai.campaign_id = $1
		 ORDER BY ai.decision = 'pending' DESC, ai.created_at`, campaignID)
	if err != nil {
		s.logger.Error("Failed to list attestation items", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list items"})
		return
	}
	defer rows.Close()

	var items []AttestationItem
	for rows.Next() {
		var item AttestationItem
		if err := rows.Scan(&item.ID, &item.CampaignID, &item.ReviewerID, &item.ReviewerName,
			&item.UserID, &item.UserName, &item.ResourceType, &item.ResourceID, &item.ResourceName,
			&item.Decision, &item.DelegatedTo, &item.DelegatedAt, &item.Comments,
			&item.DecidedAt, &item.RemindedAt, &item.CreatedAt); err != nil {
			continue
		}
		items = append(items, item)
	}
	if items == nil {
		items = []AttestationItem{}
	}
	c.JSON(http.StatusOK, gin.H{"data": items})
}

func (s *Service) handleDecideAttestationItem(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	campaignID := c.Param("id")
	itemID := c.Param("itemId")

	var req struct {
		Decision string `json:"decision"`
		Comments string `json:"comments"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if req.Decision != "certified" && req.Decision != "revoked" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Decision must be 'certified' or 'revoked'"})
		return
	}

	tag, err := s.db.Pool.Exec(c.Request.Context(),
		`UPDATE attestation_items SET decision = $1, comments = $2, decided_at = NOW()
		 WHERE id = $3 AND campaign_id = $4 AND decision = 'pending'`,
		req.Decision, req.Comments, itemID, campaignID)
	if err != nil {
		s.logger.Error("Failed to decide attestation item", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update decision"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Item not found or already decided"})
		return
	}

	// If revoked and campaign type involves access removal, handle it
	if req.Decision == "revoked" {
		var resourceType string
		var userID, resourceID *string
		_ = s.db.Pool.QueryRow(c.Request.Context(),
			"SELECT resource_type, user_id, resource_id FROM attestation_items WHERE id = $1", itemID,
		).Scan(&resourceType, &userID, &resourceID)

		if userID != nil && resourceID != nil {
			switch resourceType {
			case "role":
				_, _ = s.db.Pool.Exec(c.Request.Context(),
					"DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2", *userID, *resourceID)
			case "application":
				_, _ = s.db.Pool.Exec(c.Request.Context(),
					"DELETE FROM user_application_assignments WHERE user_id = $1 AND application_id = $2", *userID, *resourceID)
			case "group":
				_, _ = s.db.Pool.Exec(c.Request.Context(),
					"DELETE FROM group_memberships WHERE user_id = $1 AND group_id = $2", *userID, *resourceID)
			}
		}
	}

	// Check if all items are decided - auto-complete campaign
	var pendingCount int
	_ = s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT COUNT(*) FROM attestation_items WHERE campaign_id = $1 AND decision = 'pending'", campaignID,
	).Scan(&pendingCount)
	if pendingCount == 0 {
		_, _ = s.db.Pool.Exec(c.Request.Context(),
			"UPDATE attestation_campaigns SET status = 'completed', completed_at = NOW() WHERE id = $1", campaignID)
	}

	c.JSON(http.StatusOK, gin.H{"message": "Decision recorded", "decision": req.Decision})
}

func (s *Service) handleDelegateAttestationItem(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	campaignID := c.Param("id")
	itemID := c.Param("itemId")

	var req struct {
		DelegateTo string `json:"delegate_to"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.DelegateTo == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "delegate_to user ID is required"})
		return
	}

	tag, err := s.db.Pool.Exec(c.Request.Context(),
		`UPDATE attestation_items SET reviewer_id = $1, delegated_to = $1, delegated_at = NOW()
		 WHERE id = $2 AND campaign_id = $3 AND decision = 'pending'`,
		req.DelegateTo, itemID, campaignID)
	if err != nil {
		s.logger.Error("Failed to delegate attestation item", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delegate"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Item not found or already decided"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Item delegated"})
}

func (s *Service) handleAttestationProgress(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	campaignID := c.Param("id")

	var total, certified, revoked, pending, delegated int
	_ = s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT COUNT(*) FROM attestation_items WHERE campaign_id = $1", campaignID).Scan(&total)
	_ = s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT COUNT(*) FROM attestation_items WHERE campaign_id = $1 AND decision = 'certified'", campaignID).Scan(&certified)
	_ = s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT COUNT(*) FROM attestation_items WHERE campaign_id = $1 AND decision = 'revoked'", campaignID).Scan(&revoked)
	_ = s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT COUNT(*) FROM attestation_items WHERE campaign_id = $1 AND decision = 'pending'", campaignID).Scan(&pending)
	_ = s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT COUNT(*) FROM attestation_items WHERE campaign_id = $1 AND delegated_to IS NOT NULL", campaignID).Scan(&delegated)

	completionPct := 0.0
	if total > 0 {
		completionPct = float64(certified+revoked) / float64(total) * 100
	}

	c.JSON(http.StatusOK, gin.H{
		"total":          total,
		"certified":      certified,
		"revoked":        revoked,
		"pending":        pending,
		"delegated":      delegated,
		"completion_pct": completionPct,
	})
}
