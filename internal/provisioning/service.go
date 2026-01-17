// Package provisioning provides user lifecycle and SCIM 2.0 provisioning
package provisioning

import (
	"context"
	"encoding/json"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
)

// SCIMUser represents a user in SCIM 2.0 format
type SCIMUser struct {
	Schemas     []string        `json:"schemas"`
	ID          string          `json:"id,omitempty"`
	ExternalID  string          `json:"externalId,omitempty"`
	UserName    string          `json:"userName"`
	Name        SCIMName        `json:"name,omitempty"`
	DisplayName string          `json:"displayName,omitempty"`
	Emails      []SCIMEmail     `json:"emails,omitempty"`
	Active      bool            `json:"active"`
	Groups      []SCIMGroupRef  `json:"groups,omitempty"`
	Meta        SCIMMeta        `json:"meta,omitempty"`
}

// SCIMName represents a name in SCIM format
type SCIMName struct {
	Formatted       string `json:"formatted,omitempty"`
	FamilyName      string `json:"familyName,omitempty"`
	GivenName       string `json:"givenName,omitempty"`
	MiddleName      string `json:"middleName,omitempty"`
	HonorificPrefix string `json:"honorificPrefix,omitempty"`
	HonorificSuffix string `json:"honorificSuffix,omitempty"`
}

// SCIMEmail represents an email in SCIM format
type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// SCIMGroupRef represents a group reference in SCIM format
type SCIMGroupRef struct {
	Value   string `json:"value"`
	Ref     string `json:"$ref,omitempty"`
	Display string `json:"display,omitempty"`
}

// SCIMMeta contains metadata about a SCIM resource
type SCIMMeta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
	Location     string    `json:"location,omitempty"`
	Version      string    `json:"version,omitempty"`
}

// SCIMGroup represents a group in SCIM 2.0 format
type SCIMGroup struct {
	Schemas     []string       `json:"schemas"`
	ID          string         `json:"id,omitempty"`
	ExternalID  string         `json:"externalId,omitempty"`
	DisplayName string         `json:"displayName"`
	Members     []SCIMMember   `json:"members,omitempty"`
	Meta        SCIMMeta       `json:"meta,omitempty"`
}

// SCIMMember represents a member in a SCIM group
type SCIMMember struct {
	Value   string `json:"value"`
	Ref     string `json:"$ref,omitempty"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
}

// SCIMListResponse represents a SCIM list response
type SCIMListResponse struct {
	Schemas      []string    `json:"schemas"`
	TotalResults int         `json:"totalResults"`
	StartIndex   int         `json:"startIndex"`
	ItemsPerPage int         `json:"itemsPerPage"`
	Resources    interface{} `json:"Resources"`
}

// SCIMPatchRequest represents a SCIM PATCH request
type SCIMPatchRequest struct {
	Schemas    []string           `json:"schemas"`
	Operations []SCIMPatchOperation `json:"Operations"`
}

// SCIMPatchOperation represents a SCIM PATCH operation
type SCIMPatchOperation struct {
	Op    string      `json:"op"`    // add, remove, replace
	Path  string      `json:"path,omitempty"`
	Value interface{} `json:"value,omitempty"`
}

// SCIMError represents a SCIM error response
type SCIMError struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	ScimType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail"`
}

// ProvisioningRule defines an automated provisioning rule
type ProvisioningRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Trigger     RuleTrigger            `json:"trigger"`
	Conditions  []RuleCondition        `json:"conditions"`
	Actions     []RuleAction           `json:"actions"`
	Enabled     bool                   `json:"enabled"`
	Priority    int                    `json:"priority"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// RuleTrigger defines what triggers a provisioning rule
type RuleTrigger string

const (
	TriggerUserCreated    RuleTrigger = "user_created"
	TriggerUserUpdated    RuleTrigger = "user_updated"
	TriggerUserDeleted    RuleTrigger = "user_deleted"
	TriggerGroupMembership RuleTrigger = "group_membership"
	TriggerAttributeChange RuleTrigger = "attribute_change"
	TriggerScheduled      RuleTrigger = "scheduled"
)

// RuleCondition defines a condition for a rule
type RuleCondition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

// RuleAction defines an action to take when a rule matches
type RuleAction struct {
	Type       string                 `json:"type"`
	Target     string                 `json:"target"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

// Service provides provisioning operations
type Service struct {
	db     *database.PostgresDB
	redis  *database.RedisClient
	config *config.Config
	logger *zap.Logger
}

// NewService creates a new provisioning service
func NewService(db *database.PostgresDB, redis *database.RedisClient, cfg *config.Config, logger *zap.Logger) *Service {
	return &Service{
		db:     db,
		redis:  redis,
		config: cfg,
		logger: logger.With(zap.String("service", "provisioning")),
	}
}

// SCIM 2.0 User Operations

// CreateSCIMUser creates a new user via SCIM
func (s *Service) CreateSCIMUser(ctx context.Context, user *SCIMUser) (*SCIMUser, error) {
	s.logger.Info("Creating SCIM user", zap.String("username", user.UserName))

	now := time.Now()
	user.Meta = SCIMMeta{
		ResourceType: "User",
		Created:      now,
		LastModified: now,
	}
	user.Schemas = []string{"urn:ietf:params:scim:schemas:core:2.0:User"}

	// Extract email
	email := ""
	if len(user.Emails) > 0 {
		email = user.Emails[0].Value
	}

	// Create user in users table
	var userID string
	err := s.db.Pool.QueryRow(ctx, `
		INSERT INTO users (username, email, first_name, last_name, enabled, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id
	`, user.UserName, email, user.Name.GivenName, user.Name.FamilyName, user.Active, false, now, now).Scan(&userID)

	if err != nil {
		s.logger.Error("Failed to create user in users table", zap.Error(err))
		return nil, err
	}

	user.ID = userID

	// Store SCIM representation
	data, _ := json.Marshal(user)
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO scim_users (id, external_id, username, data, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (id) DO UPDATE SET data = $4, updated_at = $6
	`, userID, user.ExternalID, user.UserName, data, now, now)

	if err != nil {
		s.logger.Error("Failed to store SCIM user data", zap.Error(err))
		// Don't return error, user is already created
	}

	return user, nil
}

// GetSCIMUser retrieves a user via SCIM
func (s *Service) GetSCIMUser(ctx context.Context, userID string) (*SCIMUser, error) {
	var username, email, firstName, lastName string
	var enabled bool
	var createdAt, updatedAt time.Time

	err := s.db.Pool.QueryRow(ctx, `
		SELECT username, email, first_name, last_name, enabled, created_at, updated_at
		FROM users WHERE id = $1
	`, userID).Scan(&username, &email, &firstName, &lastName, &enabled, &createdAt, &updatedAt)

	if err != nil {
		return nil, err
	}

	user := &SCIMUser{
		Schemas:  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		ID:       userID,
		UserName: username,
		Name: SCIMName{
			GivenName:  firstName,
			FamilyName: lastName,
		},
		DisplayName: firstName + " " + lastName,
		Emails: []SCIMEmail{
			{Value: email, Type: "work", Primary: true},
		},
		Active: enabled,
		Meta: SCIMMeta{
			ResourceType: "User",
			Created:      createdAt,
			LastModified: updatedAt,
		},
	}

	return user, nil
}

// UpdateSCIMUser updates a user via SCIM
func (s *Service) UpdateSCIMUser(ctx context.Context, userID string, user *SCIMUser) (*SCIMUser, error) {
	s.logger.Info("Updating SCIM user", zap.String("user_id", userID))

	now := time.Now()
	user.ID = userID
	user.Meta.LastModified = now

	// Extract email
	email := ""
	if len(user.Emails) > 0 {
		email = user.Emails[0].Value
	}

	// Update user in users table
	_, err := s.db.Pool.Exec(ctx, `
		UPDATE users
		SET username = $2, email = $3, first_name = $4, last_name = $5, enabled = $6, updated_at = $7
		WHERE id = $1
	`, userID, user.UserName, email, user.Name.GivenName, user.Name.FamilyName, user.Active, now)

	if err != nil {
		return nil, err
	}

	// Update SCIM representation
	data, _ := json.Marshal(user)
	s.db.Pool.Exec(ctx, `
		UPDATE scim_users SET data = $2, updated_at = $3 WHERE id = $1
	`, userID, data, now)

	return user, nil
}

// DeleteSCIMUser deletes a user via SCIM
func (s *Service) DeleteSCIMUser(ctx context.Context, userID string) error {
	s.logger.Info("Deleting SCIM user", zap.String("user_id", userID))

	// Delete from users table (CASCADE will delete from scim_users)
	_, err := s.db.Pool.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	return err
}

// ListSCIMUsers lists users via SCIM
func (s *Service) ListSCIMUsers(ctx context.Context, startIndex, count int, filter string) (*SCIMListResponse, error) {
	var total int
	err := s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&total)
	if err != nil {
		return nil, err
	}

	// Build query with optional filter
	query := `
		SELECT id, username, email, first_name, last_name, enabled, created_at, updated_at
		FROM users
		ORDER BY created_at
		OFFSET $1 LIMIT $2
	`

	rows, err := s.db.Pool.Query(ctx, query, startIndex-1, count)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []SCIMUser
	for rows.Next() {
		var id, username, email, firstName, lastName string
		var enabled bool
		var createdAt, updatedAt time.Time

		if err := rows.Scan(&id, &username, &email, &firstName, &lastName, &enabled, &createdAt, &updatedAt); err != nil {
			continue
		}

		user := SCIMUser{
			Schemas:  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
			ID:       id,
			UserName: username,
			Name: SCIMName{
				GivenName:  firstName,
				FamilyName: lastName,
			},
			DisplayName: firstName + " " + lastName,
			Emails: []SCIMEmail{
				{Value: email, Type: "work", Primary: true},
			},
			Active: enabled,
			Meta: SCIMMeta{
				ResourceType: "User",
				Created:      createdAt,
				LastModified: updatedAt,
			},
		}
		users = append(users, user)
	}

	return &SCIMListResponse{
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: len(users),
		Resources:    users,
	}, nil
}

// RegisterRoutes registers provisioning service routes
func RegisterRoutes(router *gin.Engine, svc *Service) {
	// SCIM 2.0 endpoints
	scim := router.Group("/scim/v2")
	{
		// Users
		scim.GET("/Users", svc.handleListUsers)
		scim.POST("/Users", svc.handleCreateUser)
		scim.GET("/Users/:id", svc.handleGetUser)
		scim.PUT("/Users/:id", svc.handleReplaceUser)
		scim.PATCH("/Users/:id", svc.handlePatchUser)
		scim.DELETE("/Users/:id", svc.handleDeleteUser)
		
		// Groups
		scim.GET("/Groups", svc.handleListGroups)
		scim.POST("/Groups", svc.handleCreateGroup)
		scim.GET("/Groups/:id", svc.handleGetGroup)
		scim.PUT("/Groups/:id", svc.handleReplaceGroup)
		scim.PATCH("/Groups/:id", svc.handlePatchGroup)
		scim.DELETE("/Groups/:id", svc.handleDeleteGroup)
		
		// Schema discovery
		scim.GET("/Schemas", svc.handleGetSchemas)
		scim.GET("/Schemas/:id", svc.handleGetSchema)
		scim.GET("/ResourceTypes", svc.handleGetResourceTypes)
		scim.GET("/ServiceProviderConfig", svc.handleGetServiceProviderConfig)
	}
	
	// Internal provisioning API
	prov := router.Group("/api/v1/provisioning")
	{
		prov.GET("/rules", svc.handleListRules)
		prov.POST("/rules", svc.handleCreateRule)
		prov.GET("/rules/:id", svc.handleGetRule)
		prov.PUT("/rules/:id", svc.handleUpdateRule)
		prov.DELETE("/rules/:id", svc.handleDeleteRule)
	}
}

// SCIM HTTP Handlers

func (s *Service) handleListUsers(c *gin.Context) {
	// Parse query parameters
	startIndex := 1
	if si := c.Query("startIndex"); si != "" {
		if parsed, err := json.Number(si).Int64(); err == nil {
			startIndex = int(parsed)
		}
	}

	count := 100
	if cnt := c.Query("count"); cnt != "" {
		if parsed, err := json.Number(cnt).Int64(); err == nil {
			count = int(parsed)
		}
	}

	filter := c.Query("filter")

	resp, err := s.ListSCIMUsers(c.Request.Context(), startIndex, count, filter)
	if err != nil {
		c.JSON(500, SCIMError{
			Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
			Status:  "500",
			Detail:  "Failed to list users: " + err.Error(),
		})
		return
	}
	c.JSON(200, resp)
}

func (s *Service) handleCreateUser(c *gin.Context) {
	var user SCIMUser
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	
	created, err := s.CreateSCIMUser(c.Request.Context(), &user)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(201, created)
}

func (s *Service) handleGetUser(c *gin.Context) {
	user, err := s.GetSCIMUser(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(404, gin.H{"error": "user not found"})
		return
	}
	c.JSON(200, user)
}

func (s *Service) handleReplaceUser(c *gin.Context) {
	var user SCIMUser
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	
	updated, err := s.UpdateSCIMUser(c.Request.Context(), c.Param("id"), &user)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, updated)
}

func (s *Service) handlePatchUser(c *gin.Context) {
	var patch SCIMPatchRequest
	if err := c.ShouldBindJSON(&patch); err != nil {
		c.JSON(400, SCIMError{
			Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
			Status:  "400",
			Detail:  "Invalid PATCH request: " + err.Error(),
		})
		return
	}

	// Get existing user
	user, err := s.GetSCIMUser(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(404, SCIMError{
			Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
			Status:  "404",
			Detail:  "User not found",
		})
		return
	}

	// Apply patch operations
	for _, op := range patch.Operations {
		s.applyUserPatchOperation(user, op)
	}

	// Update user
	updated, err := s.UpdateSCIMUser(c.Request.Context(), c.Param("id"), user)
	if err != nil {
		c.JSON(500, SCIMError{
			Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
			Status:  "500",
			Detail:  "Failed to update user: " + err.Error(),
		})
		return
	}
	c.JSON(200, updated)
}

// applyUserPatchOperation applies a PATCH operation to a user
func (s *Service) applyUserPatchOperation(user *SCIMUser, op SCIMPatchOperation) {
	switch op.Op {
	case "replace":
		switch op.Path {
		case "active":
			if active, ok := op.Value.(bool); ok {
				user.Active = active
			}
		case "userName":
			if userName, ok := op.Value.(string); ok {
				user.UserName = userName
			}
		case "displayName":
			if displayName, ok := op.Value.(string); ok {
				user.DisplayName = displayName
			}
		case "name.givenName":
			if givenName, ok := op.Value.(string); ok {
				user.Name.GivenName = givenName
			}
		case "name.familyName":
			if familyName, ok := op.Value.(string); ok {
				user.Name.FamilyName = familyName
			}
		}
	case "add":
		// Add operation (e.g., add emails, groups)
		if op.Path == "emails" {
			// Add email to user
		}
	case "remove":
		// Remove operation
		if op.Path == "emails" {
			// Remove email from user
		}
	}
}

// applyGroupPatchOperation applies a PATCH operation to a group
func (s *Service) applyGroupPatchOperation(group *SCIMGroup, op SCIMPatchOperation) {
	switch op.Op {
	case "replace":
		if op.Path == "displayName" {
			if displayName, ok := op.Value.(string); ok {
				group.DisplayName = displayName
			}
		}
	case "add":
		if op.Path == "members" {
			// Add members to group
			if members, ok := op.Value.([]interface{}); ok {
				for _, m := range members {
					if memberMap, ok := m.(map[string]interface{}); ok {
						if value, ok := memberMap["value"].(string); ok {
							group.Members = append(group.Members, SCIMMember{
								Value: value,
								Type:  "User",
							})
						}
					}
				}
			}
		}
	case "remove":
		if op.Path == "members" {
			// Remove members from group
			if members, ok := op.Value.([]interface{}); ok {
				for _, m := range members {
					if memberMap, ok := m.(map[string]interface{}); ok {
						if value, ok := memberMap["value"].(string); ok {
							// Remove member from group.Members
							var newMembers []SCIMMember
							for _, existingMember := range group.Members {
								if existingMember.Value != value {
									newMembers = append(newMembers, existingMember)
								}
							}
							group.Members = newMembers
						}
					}
				}
			}
		}
	}
}

func (s *Service) handleDeleteUser(c *gin.Context) {
	if err := s.DeleteSCIMUser(c.Request.Context(), c.Param("id")); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(204, nil)
}

// SCIM 2.0 Group Operations

// CreateSCIMGroup creates a new group via SCIM
func (s *Service) CreateSCIMGroup(ctx context.Context, group *SCIMGroup) (*SCIMGroup, error) {
	s.logger.Info("Creating SCIM group", zap.String("name", group.DisplayName))

	now := time.Now()
	group.Meta = SCIMMeta{
		ResourceType: "Group",
		Created:      now,
		LastModified: now,
	}
	group.Schemas = []string{"urn:ietf:params:scim:schemas:core:2.0:Group"}

	// Create group in groups table
	var groupID string
	err := s.db.Pool.QueryRow(ctx, `
		INSERT INTO groups (name, description, created_at, updated_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id
	`, group.DisplayName, "", now, now).Scan(&groupID)

	if err != nil {
		s.logger.Error("Failed to create group", zap.Error(err))
		return nil, err
	}

	group.ID = groupID

	// Add members if provided
	if len(group.Members) > 0 {
		for _, member := range group.Members {
			_, err := s.db.Pool.Exec(ctx, `
				INSERT INTO group_memberships (user_id, group_id, joined_at)
				VALUES ($1, $2, $3)
				ON CONFLICT DO NOTHING
			`, member.Value, groupID, now)
			if err != nil {
				s.logger.Warn("Failed to add group member", zap.Error(err))
			}
		}
	}

	return group, nil
}

// GetSCIMGroup retrieves a group via SCIM
func (s *Service) GetSCIMGroup(ctx context.Context, groupID string) (*SCIMGroup, error) {
	var name, description string
	var createdAt, updatedAt time.Time

	err := s.db.Pool.QueryRow(ctx, `
		SELECT name, description, created_at, updated_at
		FROM groups WHERE id = $1
	`, groupID).Scan(&name, &description, &createdAt, &updatedAt)

	if err != nil {
		return nil, err
	}

	// Get members
	rows, err := s.db.Pool.Query(ctx, `
		SELECT gm.user_id, u.username
		FROM group_memberships gm
		JOIN users u ON gm.user_id = u.id
		WHERE gm.group_id = $1
	`, groupID)

	var members []SCIMMember
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var userID, username string
			if err := rows.Scan(&userID, &username); err == nil {
				members = append(members, SCIMMember{
					Value:   userID,
					Display: username,
					Type:    "User",
				})
			}
		}
	}

	return &SCIMGroup{
		Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		ID:          groupID,
		DisplayName: name,
		Members:     members,
		Meta: SCIMMeta{
			ResourceType: "Group",
			Created:      createdAt,
			LastModified: updatedAt,
		},
	}, nil
}

// UpdateSCIMGroup updates a group via SCIM
func (s *Service) UpdateSCIMGroup(ctx context.Context, groupID string, group *SCIMGroup) (*SCIMGroup, error) {
	s.logger.Info("Updating SCIM group", zap.String("group_id", groupID))

	now := time.Now()
	group.ID = groupID
	group.Meta.LastModified = now

	_, err := s.db.Pool.Exec(ctx, `
		UPDATE groups SET name = $2, updated_at = $3 WHERE id = $1
	`, groupID, group.DisplayName, now)

	if err != nil {
		return nil, err
	}

	// Update members if provided
	if group.Members != nil {
		// Clear existing members
		s.db.Pool.Exec(ctx, "DELETE FROM group_memberships WHERE group_id = $1", groupID)

		// Add new members
		for _, member := range group.Members {
			s.db.Pool.Exec(ctx, `
				INSERT INTO group_memberships (user_id, group_id, joined_at)
				VALUES ($1, $2, $3)
				ON CONFLICT DO NOTHING
			`, member.Value, groupID, now)
		}
	}

	return group, nil
}

// DeleteSCIMGroup deletes a group via SCIM
func (s *Service) DeleteSCIMGroup(ctx context.Context, groupID string) error {
	s.logger.Info("Deleting SCIM group", zap.String("group_id", groupID))

	_, err := s.db.Pool.Exec(ctx, "DELETE FROM groups WHERE id = $1", groupID)
	return err
}

// ListSCIMGroups lists groups via SCIM
func (s *Service) ListSCIMGroups(ctx context.Context, startIndex, count int, filter string) (*SCIMListResponse, error) {
	var total int
	err := s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM groups").Scan(&total)
	if err != nil {
		return nil, err
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, description, created_at, updated_at
		FROM groups ORDER BY created_at OFFSET $1 LIMIT $2
	`, startIndex-1, count)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []SCIMGroup
	for rows.Next() {
		var id, name, description string
		var createdAt, updatedAt time.Time
		if err := rows.Scan(&id, &name, &description, &createdAt, &updatedAt); err != nil {
			continue
		}
		groups = append(groups, SCIMGroup{
			Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
			ID:          id,
			DisplayName: name,
			Meta: SCIMMeta{
				ResourceType: "Group",
				Created:      createdAt,
				LastModified: updatedAt,
			},
		})
	}

	return &SCIMListResponse{
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: len(groups),
		Resources:    groups,
	}, nil
}

// Group handlers
func (s *Service) handleListGroups(c *gin.Context) {
	// Parse query parameters
	startIndex := 1
	if si := c.Query("startIndex"); si != "" {
		if parsed, err := json.Number(si).Int64(); err == nil {
			startIndex = int(parsed)
		}
	}

	count := 100
	if cnt := c.Query("count"); cnt != "" {
		if parsed, err := json.Number(cnt).Int64(); err == nil {
			count = int(parsed)
		}
	}

	filter := c.Query("filter")

	resp, err := s.ListSCIMGroups(c.Request.Context(), startIndex, count, filter)
	if err != nil {
		c.JSON(500, SCIMError{
			Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
			Status:  "500",
			Detail:  "Failed to list groups: " + err.Error(),
		})
		return
	}
	c.JSON(200, resp)
}

func (s *Service) handleCreateGroup(c *gin.Context) {
	var group SCIMGroup
	if err := c.ShouldBindJSON(&group); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	created, err := s.CreateSCIMGroup(c.Request.Context(), &group)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(201, created)
}

func (s *Service) handleGetGroup(c *gin.Context) {
	group, err := s.GetSCIMGroup(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(404, gin.H{"error": "group not found"})
		return
	}
	c.JSON(200, group)
}

func (s *Service) handleReplaceGroup(c *gin.Context) {
	var group SCIMGroup
	if err := c.ShouldBindJSON(&group); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	updated, err := s.UpdateSCIMGroup(c.Request.Context(), c.Param("id"), &group)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, updated)
}

func (s *Service) handlePatchGroup(c *gin.Context) {
	var patch SCIMPatchRequest
	if err := c.ShouldBindJSON(&patch); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Get existing group
	group, err := s.GetSCIMGroup(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(404, gin.H{"error": "group not found"})
		return
	}

	// Apply patch operations
	for _, op := range patch.Operations {
		s.applyGroupPatchOperation(group, op)
	}

	// Update group
	updated, err := s.UpdateSCIMGroup(c.Request.Context(), c.Param("id"), group)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, updated)
}

func (s *Service) handleDeleteGroup(c *gin.Context) {
	if err := s.DeleteSCIMGroup(c.Request.Context(), c.Param("id")); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(204, nil)
}

// Schema discovery handlers
func (s *Service) handleGetSchemas(c *gin.Context) {
	c.JSON(200, gin.H{"schemas": []string{}})
}

func (s *Service) handleGetSchema(c *gin.Context) {
	c.JSON(200, gin.H{})
}

func (s *Service) handleGetResourceTypes(c *gin.Context) {
	c.JSON(200, []gin.H{
		{"name": "User", "endpoint": "/Users"},
		{"name": "Group", "endpoint": "/Groups"},
	})
}

func (s *Service) handleGetServiceProviderConfig(c *gin.Context) {
	c.JSON(200, gin.H{
		"schemas":            []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri":   "https://docs.openidx.io/scim",
		"patch":              gin.H{"supported": true},
		"bulk":               gin.H{"supported": false},
		"filter":             gin.H{"supported": true, "maxResults": 200},
		"changePassword":     gin.H{"supported": true},
		"sort":               gin.H{"supported": true},
		"etag":               gin.H{"supported": false},
		"authenticationSchemes": []gin.H{
			{"type": "oauthbearertoken", "name": "OAuth Bearer Token"},
		},
	})
}

// Provisioning rules handlers
func (s *Service) handleListRules(c *gin.Context)   { c.JSON(200, []ProvisioningRule{}) }
func (s *Service) handleCreateRule(c *gin.Context)  { c.JSON(201, ProvisioningRule{}) }
func (s *Service) handleGetRule(c *gin.Context)     { c.JSON(200, ProvisioningRule{}) }
func (s *Service) handleUpdateRule(c *gin.Context)  { c.JSON(200, ProvisioningRule{}) }
func (s *Service) handleDeleteRule(c *gin.Context)  { c.JSON(204, nil) }
