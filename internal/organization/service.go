// Package organization provides multi-tenant organization management functionality
package organization

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
)

// Organization represents a tenant organization in the system
type Organization struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Slug            string                 `json:"slug"`
	Domain          *string                `json:"domain,omitempty"`
	Plan            string                 `json:"plan"`
	Status          string                 `json:"status"`
	Settings        map[string]interface{} `json:"settings,omitempty"`
	MaxUsers        int                    `json:"max_users"`
	MaxApplications int                    `json:"max_applications"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
	MemberCount     int                    `json:"member_count,omitempty"`
}

// OrganizationMember represents a user's membership in an organization
type OrganizationMember struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	UserID         string    `json:"user_id"`
	Role           string    `json:"role"`
	JoinedAt       time.Time `json:"joined_at"`
	InvitedBy      *string   `json:"invited_by,omitempty"`
	UserEmail      string    `json:"user_email"`
	UserName       string    `json:"user_name"`
}

// Service provides organization management operations
type Service struct {
	db     *database.PostgresDB
	redis  *database.RedisClient
	config *config.Config
	logger *zap.Logger
}

// NewService creates a new organization service instance
func NewService(db *database.PostgresDB, redis *database.RedisClient, cfg *config.Config, logger *zap.Logger) *Service {
	return &Service{
		db:     db,
		redis:  redis,
		config: cfg,
		logger: logger.With(zap.String("service", "organization")),
	}
}

// CreateOrganization creates a new organization and adds the creator as the owner
func (s *Service) CreateOrganization(ctx context.Context, org *Organization, creatorUserID string) error {
	org.ID = uuid.New().String()
	now := time.Now().UTC()
	org.CreatedAt = now
	org.UpdatedAt = now

	if org.Status == "" {
		org.Status = "active"
	}
	if org.Plan == "" {
		org.Plan = "free"
	}

	settingsJSON, err := json.Marshal(org.Settings)
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx,
		`INSERT INTO organizations (id, name, slug, domain, plan, status, settings, max_users, max_applications, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		org.ID, org.Name, org.Slug, org.Domain, org.Plan, org.Status, settingsJSON,
		org.MaxUsers, org.MaxApplications, org.CreatedAt, org.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to insert organization: %w", err)
	}

	memberID := uuid.New().String()
	_, err = tx.Exec(ctx,
		`INSERT INTO organization_members (id, organization_id, user_id, role, joined_at, invited_by)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		memberID, org.ID, creatorUserID, "owner", now, nil,
	)
	if err != nil {
		return fmt.Errorf("failed to add creator as owner: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	s.logger.Info("organization created",
		zap.String("org_id", org.ID),
		zap.String("creator_id", creatorUserID),
	)

	return nil
}

// GetOrganization retrieves an organization by ID with its member count
func (s *Service) GetOrganization(ctx context.Context, orgID string) (*Organization, error) {
	var org Organization
	var settingsBytes []byte

	err := s.db.Pool.QueryRow(ctx,
		`SELECT o.id, o.name, o.slug, o.domain, o.plan, o.status, o.settings,
		        o.max_users, o.max_applications, o.created_at, o.updated_at,
		        COUNT(m.id) AS member_count
		 FROM organizations o
		 LEFT JOIN organization_members m ON o.id = m.organization_id
		 WHERE o.id = $1
		 GROUP BY o.id`, orgID,
	).Scan(
		&org.ID, &org.Name, &org.Slug, &org.Domain, &org.Plan, &org.Status,
		&settingsBytes, &org.MaxUsers, &org.MaxApplications,
		&org.CreatedAt, &org.UpdatedAt, &org.MemberCount,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}

	if settingsBytes != nil {
		if err := json.Unmarshal(settingsBytes, &org.Settings); err != nil {
			return nil, fmt.Errorf("failed to unmarshal settings: %w", err)
		}
	}

	return &org, nil
}

// ListOrganizations returns a paginated list of organizations with a total count
func (s *Service) ListOrganizations(ctx context.Context, limit, offset int) ([]Organization, int, error) {
	var total int
	err := s.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM organizations`).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count organizations: %w", err)
	}

	rows, err := s.db.Pool.Query(ctx,
		`SELECT o.id, o.name, o.slug, o.domain, o.plan, o.status, o.settings,
		        o.max_users, o.max_applications, o.created_at, o.updated_at,
		        COUNT(m.id) AS member_count
		 FROM organizations o
		 LEFT JOIN organization_members m ON o.id = m.organization_id
		 GROUP BY o.id
		 ORDER BY o.created_at DESC
		 LIMIT $1 OFFSET $2`, limit, offset,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list organizations: %w", err)
	}
	defer rows.Close()

	var orgs []Organization
	for rows.Next() {
		var org Organization
		var settingsBytes []byte
		if err := rows.Scan(
			&org.ID, &org.Name, &org.Slug, &org.Domain, &org.Plan, &org.Status,
			&settingsBytes, &org.MaxUsers, &org.MaxApplications,
			&org.CreatedAt, &org.UpdatedAt, &org.MemberCount,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan organization: %w", err)
		}
		if settingsBytes != nil {
			if err := json.Unmarshal(settingsBytes, &org.Settings); err != nil {
				return nil, 0, fmt.Errorf("failed to unmarshal settings: %w", err)
			}
		}
		orgs = append(orgs, org)
	}

	return orgs, total, nil
}

// UpdateOrganization updates an organization's name, plan, and status
func (s *Service) UpdateOrganization(ctx context.Context, orgID string, name, plan, status string) error {
	now := time.Now().UTC()

	result, err := s.db.Pool.Exec(ctx,
		`UPDATE organizations SET name = $1, plan = $2, status = $3, updated_at = $4 WHERE id = $5`,
		name, plan, status, now, orgID,
	)
	if err != nil {
		return fmt.Errorf("failed to update organization: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("organization not found")
	}

	s.logger.Info("organization updated",
		zap.String("org_id", orgID),
	)

	return nil
}

// GetUserOrganizations returns all organizations where the user is a member
func (s *Service) GetUserOrganizations(ctx context.Context, userID string) ([]Organization, error) {
	rows, err := s.db.Pool.Query(ctx,
		`SELECT o.id, o.name, o.slug, o.domain, o.plan, o.status, o.settings,
		        o.max_users, o.max_applications, o.created_at, o.updated_at
		 FROM organizations o
		 INNER JOIN organization_members m ON o.id = m.organization_id
		 WHERE m.user_id = $1
		 ORDER BY o.name ASC`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get user organizations: %w", err)
	}
	defer rows.Close()

	var orgs []Organization
	for rows.Next() {
		var org Organization
		var settingsBytes []byte
		if err := rows.Scan(
			&org.ID, &org.Name, &org.Slug, &org.Domain, &org.Plan, &org.Status,
			&settingsBytes, &org.MaxUsers, &org.MaxApplications,
			&org.CreatedAt, &org.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan organization: %w", err)
		}
		if settingsBytes != nil {
			if err := json.Unmarshal(settingsBytes, &org.Settings); err != nil {
				return nil, fmt.Errorf("failed to unmarshal settings: %w", err)
			}
		}
		orgs = append(orgs, org)
	}

	return orgs, nil
}

// AddMember adds or updates a member in an organization
func (s *Service) AddMember(ctx context.Context, orgID, userID, role, invitedBy string) error {
	memberID := uuid.New().String()
	now := time.Now().UTC()

	_, err := s.db.Pool.Exec(ctx,
		`INSERT INTO organization_members (id, organization_id, user_id, role, joined_at, invited_by)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (organization_id, user_id)
		 DO UPDATE SET role = EXCLUDED.role`,
		memberID, orgID, userID, role, now, invitedBy,
	)
	if err != nil {
		return fmt.Errorf("failed to add member: %w", err)
	}

	s.logger.Info("member added to organization",
		zap.String("org_id", orgID),
		zap.String("user_id", userID),
		zap.String("role", role),
	)

	return nil
}

// RemoveMember removes a member from an organization
func (s *Service) RemoveMember(ctx context.Context, orgID, userID string) error {
	result, err := s.db.Pool.Exec(ctx,
		`DELETE FROM organization_members WHERE organization_id = $1 AND user_id = $2`,
		orgID, userID,
	)
	if err != nil {
		return fmt.Errorf("failed to remove member: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("member not found")
	}

	s.logger.Info("member removed from organization",
		zap.String("org_id", orgID),
		zap.String("user_id", userID),
	)

	return nil
}

// ListMembers returns a paginated list of organization members with user info
func (s *Service) ListMembers(ctx context.Context, orgID string, limit, offset int) ([]OrganizationMember, int, error) {
	var total int
	err := s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM organization_members WHERE organization_id = $1`, orgID,
	).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count members: %w", err)
	}

	rows, err := s.db.Pool.Query(ctx,
		`SELECT m.id, m.organization_id, m.user_id, m.role, m.joined_at, m.invited_by,
		        COALESCE(u.email, '') AS user_email, COALESCE(u.username, '') AS user_name
		 FROM organization_members m
		 LEFT JOIN users u ON m.user_id = u.id
		 WHERE m.organization_id = $1
		 ORDER BY m.joined_at ASC
		 LIMIT $2 OFFSET $3`, orgID, limit, offset,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list members: %w", err)
	}
	defer rows.Close()

	var members []OrganizationMember
	for rows.Next() {
		var member OrganizationMember
		if err := rows.Scan(
			&member.ID, &member.OrganizationID, &member.UserID, &member.Role,
			&member.JoinedAt, &member.InvitedBy, &member.UserEmail, &member.UserName,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan member: %w", err)
		}
		members = append(members, member)
	}

	return members, total, nil
}

// HTTP Handlers

func (s *Service) handleListOrganizations(c *gin.Context) {
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

	orgs, total, err := s.ListOrganizations(c.Request.Context(), limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Header("X-Total-Count", strconv.Itoa(total))
	c.JSON(http.StatusOK, orgs)
}

func (s *Service) handleCreateOrganization(c *gin.Context) {
	var req struct {
		Name            string `json:"name" binding:"required"`
		Slug            string `json:"slug" binding:"required"`
		Plan            string `json:"plan"`
		MaxUsers        int    `json:"max_users"`
		MaxApplications int    `json:"max_applications"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, _ := c.Get("user_id")
	creatorUserID, _ := userID.(string)
	if creatorUserID == "" {
		creatorUserID = "00000000-0000-0000-0000-000000000001"
	}

	org := &Organization{
		Name:            req.Name,
		Slug:            req.Slug,
		Plan:            req.Plan,
		MaxUsers:        req.MaxUsers,
		MaxApplications: req.MaxApplications,
	}

	if err := s.CreateOrganization(c.Request.Context(), org, creatorUserID); err != nil {
		s.logger.Error("failed to create organization", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, org)
}

func (s *Service) handleGetOrganization(c *gin.Context) {
	orgID := c.Param("id")

	org, err := s.GetOrganization(c.Request.Context(), orgID)
	if err != nil {
		s.logger.Error("failed to get organization", zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "organization not found"})
		return
	}

	c.JSON(http.StatusOK, org)
}

func (s *Service) handleUpdateOrganization(c *gin.Context) {
	orgID := c.Param("id")

	var req struct {
		Name   string `json:"name" binding:"required"`
		Plan   string `json:"plan" binding:"required"`
		Status string `json:"status" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := s.UpdateOrganization(c.Request.Context(), orgID, req.Name, req.Plan, req.Status); err != nil {
		s.logger.Error("failed to update organization", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "organization updated"})
}

func (s *Service) handleListMembers(c *gin.Context) {
	orgID := c.Param("id")

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

	members, total, err := s.ListMembers(c.Request.Context(), orgID, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Header("X-Total-Count", strconv.Itoa(total))
	c.JSON(http.StatusOK, members)
}

func (s *Service) handleAddMember(c *gin.Context) {
	orgID := c.Param("id")

	var req struct {
		UserID string `json:"user_id" binding:"required"`
		Role   string `json:"role" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	inviterID, _ := c.Get("user_id")
	invitedBy, _ := inviterID.(string)
	if invitedBy == "" {
		invitedBy = "00000000-0000-0000-0000-000000000001"
	}

	if err := s.AddMember(c.Request.Context(), orgID, req.UserID, req.Role, invitedBy); err != nil {
		s.logger.Error("failed to add member", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "member added"})
}

func (s *Service) handleRemoveMember(c *gin.Context) {
	orgID := c.Param("id")
	userID := c.Param("userId")

	if err := s.RemoveMember(c.Request.Context(), orgID, userID); err != nil {
		s.logger.Error("failed to remove member", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "member removed"})
}

func (s *Service) handleGetMyOrganizations(c *gin.Context) {
	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)
	if uid == "" {
		uid = "00000000-0000-0000-0000-000000000001"
	}

	orgs, err := s.GetUserOrganizations(c.Request.Context(), uid)
	if err != nil {
		s.logger.Error("failed to get user organizations", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, orgs)
}

// RegisterRoutes registers organization HTTP routes on the given router group
func RegisterRoutes(router *gin.RouterGroup, svc *Service) {
	router.GET("/organizations", svc.handleListOrganizations)
	router.POST("/organizations", svc.handleCreateOrganization)
	router.GET("/organizations/:id", svc.handleGetOrganization)
	router.PUT("/organizations/:id", svc.handleUpdateOrganization)
	router.GET("/organizations/:id/members", svc.handleListMembers)
	router.POST("/organizations/:id/members", svc.handleAddMember)
	router.DELETE("/organizations/:id/members/:userId", svc.handleRemoveMember)
	router.GET("/me/organizations", svc.handleGetMyOrganizations)
}
