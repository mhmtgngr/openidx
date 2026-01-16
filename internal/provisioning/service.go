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
	
	// Store user
	data, _ := json.Marshal(user)
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO scim_users (id, external_id, username, data, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, user.ID, user.ExternalID, user.UserName, data, now, now)
	
	if err != nil {
		return nil, err
	}
	
	return user, nil
}

// GetSCIMUser retrieves a user via SCIM
func (s *Service) GetSCIMUser(ctx context.Context, userID string) (*SCIMUser, error) {
	var data []byte
	err := s.db.Pool.QueryRow(ctx, `
		SELECT data FROM scim_users WHERE id = $1
	`, userID).Scan(&data)
	
	if err != nil {
		return nil, err
	}
	
	var user SCIMUser
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, err
	}
	
	return &user, nil
}

// UpdateSCIMUser updates a user via SCIM
func (s *Service) UpdateSCIMUser(ctx context.Context, userID string, user *SCIMUser) (*SCIMUser, error) {
	s.logger.Info("Updating SCIM user", zap.String("user_id", userID))
	
	user.ID = userID
	user.Meta.LastModified = time.Now()
	
	data, _ := json.Marshal(user)
	_, err := s.db.Pool.Exec(ctx, `
		UPDATE scim_users SET data = $2, updated_at = $3 WHERE id = $1
	`, userID, data, time.Now())
	
	if err != nil {
		return nil, err
	}
	
	return user, nil
}

// DeleteSCIMUser deletes a user via SCIM
func (s *Service) DeleteSCIMUser(ctx context.Context, userID string) error {
	s.logger.Info("Deleting SCIM user", zap.String("user_id", userID))
	
	_, err := s.db.Pool.Exec(ctx, "DELETE FROM scim_users WHERE id = $1", userID)
	return err
}

// ListSCIMUsers lists users via SCIM
func (s *Service) ListSCIMUsers(ctx context.Context, startIndex, count int, filter string) (*SCIMListResponse, error) {
	var total int
	err := s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM scim_users").Scan(&total)
	if err != nil {
		return nil, err
	}
	
	rows, err := s.db.Pool.Query(ctx, `
		SELECT data FROM scim_users ORDER BY created_at OFFSET $1 LIMIT $2
	`, startIndex-1, count)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var users []SCIMUser
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var user SCIMUser
		json.Unmarshal(data, &user)
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
	startIndex := 1
	count := 100
	
	resp, err := s.ListSCIMUsers(c.Request.Context(), startIndex, count, "")
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
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
	// SCIM PATCH operation
	c.JSON(200, SCIMUser{})
}

func (s *Service) handleDeleteUser(c *gin.Context) {
	if err := s.DeleteSCIMUser(c.Request.Context(), c.Param("id")); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(204, nil)
}

// Group handlers
func (s *Service) handleListGroups(c *gin.Context) {
	c.JSON(200, SCIMListResponse{
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		TotalResults: 0,
		StartIndex:   1,
		ItemsPerPage: 0,
		Resources:    []SCIMGroup{},
	})
}

func (s *Service) handleCreateGroup(c *gin.Context)  { c.JSON(201, SCIMGroup{}) }
func (s *Service) handleGetGroup(c *gin.Context)     { c.JSON(200, SCIMGroup{}) }
func (s *Service) handleReplaceGroup(c *gin.Context) { c.JSON(200, SCIMGroup{}) }
func (s *Service) handlePatchGroup(c *gin.Context)   { c.JSON(200, SCIMGroup{}) }
func (s *Service) handleDeleteGroup(c *gin.Context)  { c.JSON(204, nil) }

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
