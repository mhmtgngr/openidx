// Package access provides the identity-aware reverse proxy (Zero Trust Access) for OpenIDX
package access

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
)

// ProxyRoute represents a configured proxy route
type ProxyRoute struct {
	ID                    string            `json:"id"`
	Name                  string            `json:"name"`
	Description           string            `json:"description,omitempty"`
	FromURL               string            `json:"from_url"`
	ToURL                 string            `json:"to_url"`
	PreserveHost          bool              `json:"preserve_host"`
	RequireAuth           bool              `json:"require_auth"`
	AllowedRoles          []string          `json:"allowed_roles,omitempty"`
	AllowedGroups         []string          `json:"allowed_groups,omitempty"`
	PolicyIDs             []string          `json:"policy_ids,omitempty"`
	IdleTimeout           int               `json:"idle_timeout"`
	AbsoluteTimeout       int               `json:"absolute_timeout"`
	CORSAllowedOrigins    []string          `json:"cors_allowed_origins,omitempty"`
	CustomHeaders         map[string]string `json:"custom_headers,omitempty"`
	Enabled               bool              `json:"enabled"`
	Priority              int               `json:"priority"`
	ZitiEnabled           bool              `json:"ziti_enabled"`
	ZitiServiceName       string            `json:"ziti_service_name,omitempty"`
	IDPId                 string            `json:"idp_id,omitempty"`
	RouteType             string            `json:"route_type"`
	RemoteHost            string            `json:"remote_host,omitempty"`
	RemotePort            int               `json:"remote_port,omitempty"`
	ReverifyInterval      int               `json:"reverify_interval"`
	PostureCheckIDs       []string          `json:"posture_check_ids,omitempty"`
	InlinePolicy          string            `json:"inline_policy,omitempty"`
	RequireDeviceTrust    bool              `json:"require_device_trust"`
	AllowedCountries      []string          `json:"allowed_countries,omitempty"`
	MaxRiskScore          int               `json:"max_risk_score"`
	GuacamoleConnectionID string            `json:"guacamole_connection_id,omitempty"`
	CreatedAt             time.Time         `json:"created_at"`
	UpdatedAt             time.Time         `json:"updated_at"`
}

// ProxySession represents an active proxy session
type ProxySession struct {
	ID                string    `json:"id"`
	UserID            string    `json:"user_id"`
	RouteID           string    `json:"route_id,omitempty"`
	SessionToken      string    `json:"-"`
	IPAddress         string    `json:"ip_address"`
	UserAgent         string    `json:"user_agent"`
	Email             string    `json:"email"`
	Name              string    `json:"name"`
	Roles             []string  `json:"roles"`
	StartedAt         time.Time `json:"started_at"`
	LastActiveAt      time.Time `json:"last_active_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	Revoked           bool      `json:"revoked"`
	DeviceFingerprint string    `json:"device_fingerprint,omitempty"`
	RiskScore         int       `json:"risk_score,omitempty"`
	AuthMethods       []string  `json:"auth_methods,omitempty"`
	Location          string    `json:"location,omitempty"`
	DeviceTrusted     bool      `json:"device_trusted,omitempty"`
}

// Service provides access proxy operations
type Service struct {
	db              *database.PostgresDB
	redis           *database.RedisClient
	config          *config.Config
	logger          *zap.Logger
	governanceURL   string
	auditURL        string
	sessionSecret   []byte
	oauthIssuer     string
	oauthJWKSURL    string
	zitiManager     *ZitiManager
	guacamoleClient *GuacamoleClient
}

// SetGuacamoleClient sets the Guacamole client for the service
func (s *Service) SetGuacamoleClient(gc *GuacamoleClient) {
	s.guacamoleClient = gc
}

// SetZitiManager sets the OpenZiti manager for the service
func (s *Service) SetZitiManager(zm *ZitiManager) {
	s.zitiManager = zm
}

// NewService creates a new access proxy service
func NewService(db *database.PostgresDB, redis *database.RedisClient, cfg *config.Config, logger *zap.Logger) *Service {
	secret := cfg.AccessSessionSecret
	if len(secret) < 32 {
		secret = secret + strings.Repeat("0", 32-len(secret))
	}

	return &Service{
		db:            db,
		redis:         redis,
		config:        cfg,
		logger:        logger.With(zap.String("service", "access")),
		governanceURL: cfg.GovernanceURL,
		auditURL:      cfg.AuditURL,
		sessionSecret: []byte(secret[:32]),
		oauthIssuer:   cfg.OAuthIssuer,
		oauthJWKSURL:  cfg.OAuthJWKSURL,
	}
}

// RegisterRoutes registers all access proxy routes
func RegisterRoutes(router *gin.Engine, svc *Service, authMiddleware ...gin.HandlerFunc) {
	// Auth flow endpoints (no auth required)
	auth := router.Group("/access/.auth")
	{
		auth.GET("/login", svc.handleLogin)
		auth.GET("/callback", svc.handleCallback)
		auth.GET("/logout", svc.handleLogout)
		auth.GET("/session", svc.handleSessionInfo)
		auth.GET("/idps", svc.handleIDPDiscovery)
	}

	// Admin API for route management (requires auth)
	api := router.Group("/api/v1/access")
	if len(authMiddleware) > 0 {
		api.Use(authMiddleware...)
	}
	{
		api.GET("/routes", svc.handleListRoutes)
		api.POST("/routes", svc.handleCreateRoute)
		api.GET("/routes/:id", svc.handleGetRoute)
		api.PUT("/routes/:id", svc.handleUpdateRoute)
		api.DELETE("/routes/:id", svc.handleDeleteRoute)
		api.GET("/sessions", svc.handleListSessions)
		api.DELETE("/sessions/:id", svc.handleRevokeSession)

		// OpenZiti management endpoints
		api.GET("/ziti/status", svc.handleZitiStatus)
		api.GET("/ziti/services", svc.handleListZitiServices)
		api.POST("/ziti/services", svc.handleCreateZitiService)
		api.DELETE("/ziti/services/:id", svc.handleDeleteZitiService)
		api.GET("/ziti/identities", svc.handleListZitiIdentities)
		api.POST("/ziti/identities", svc.handleCreateZitiIdentity)
		api.DELETE("/ziti/identities/:id", svc.handleDeleteZitiIdentity)
		api.GET("/ziti/identities/:id/enrollment-jwt", svc.handleGetEnrollmentJWT)
		api.POST("/ziti/routes/:id/enable", svc.handleEnableZitiOnRoute)
		api.POST("/ziti/routes/:id/disable", svc.handleDisableZitiOnRoute)

		// Phase 2: Fabric & Router management
		api.GET("/ziti/fabric/overview", svc.handleGetFabricOverview)
		api.GET("/ziti/fabric/routers", svc.handleListEdgeRouters)
		api.GET("/ziti/fabric/routers/:id", svc.handleGetEdgeRouter)
		api.GET("/ziti/fabric/health", svc.handleGetHealth)
		api.POST("/ziti/fabric/reconnect", svc.handleReconnect)
		api.GET("/ziti/fabric/metrics", svc.handleGetMetrics)
		api.GET("/ziti/fabric/service-policies", svc.handleListServicePolicies)

		// Phase 3: Posture checks
		api.GET("/ziti/posture/checks", svc.handleListPostureChecks)
		api.POST("/ziti/posture/checks", svc.handleCreatePostureCheck)
		api.PUT("/ziti/posture/checks/:id", svc.handleUpdatePostureCheck)
		api.DELETE("/ziti/posture/checks/:id", svc.handleDeletePostureCheck)
		api.GET("/ziti/posture/identities/:id", svc.handleGetIdentityPosture)
		api.POST("/ziti/posture/identities/:id/evaluate", svc.handleEvaluateIdentityPosture)
		api.GET("/ziti/posture/summary", svc.handleGetPostureSummary)

		// Phase 3: Policy sync
		api.GET("/ziti/policy-sync", svc.handleListPolicySyncStates)
		api.POST("/ziti/policy-sync", svc.handleSyncGovernancePolicy)
		api.POST("/ziti/policy-sync/:id/trigger", svc.handleTriggerPolicySync)
		api.DELETE("/ziti/policy-sync/:id", svc.handleDeletePolicySyncState)

		// Phase 5: Certificates
		api.GET("/ziti/certificates", svc.handleListCertificates)
		api.GET("/ziti/certificates/expiry-alerts", svc.handleGetCertExpiryAlerts)
		api.POST("/ziti/certificates/:id/rotate", svc.handleRotateCertificate)

		// Forward-auth endpoint for APISIX
		api.POST("/auth/decide", svc.handleAuthDecide)
		api.GET("/auth/decide", svc.handleAuthDecide)

		// Policy DSL validation
		api.POST("/routes/validate-policy", svc.handleValidatePolicy)

		// Guacamole remote access
		api.GET("/guacamole/connections", svc.handleListGuacamoleConnections)
		api.POST("/guacamole/connections/:routeId/connect", svc.handleGuacamoleConnect)
	}

	// Catch-all reverse proxy (must be last)
	router.NoRoute(svc.handleProxy)
}

// ---- Route CRUD ----

func (s *Service) handleListRoutes(c *gin.Context) {
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

	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, name, description, from_url, to_url, preserve_host, require_auth,
		        allowed_roles, allowed_groups, policy_ids, idle_timeout, absolute_timeout,
		        cors_allowed_origins, custom_headers, enabled, priority,
		        COALESCE(ziti_enabled, false), ziti_service_name,
		        idp_id, COALESCE(route_type, 'http'), remote_host, remote_port,
		        COALESCE(reverify_interval, 0), posture_check_ids, inline_policy,
		        COALESCE(require_device_trust, false), allowed_countries,
		        COALESCE(max_risk_score, 100), guacamole_connection_id,
		        created_at, updated_at
		 FROM proxy_routes ORDER BY priority DESC, name ASC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		s.logger.Error("Failed to list routes", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list routes"})
		return
	}
	defer rows.Close()

	routes := []ProxyRoute{}
	for rows.Next() {
		var r ProxyRoute
		var desc, zitiServiceName, idpID, remoteHost, inlinePolicy, guacConnID *string
		var remotePort *int
		var allowedRoles, allowedGroups, policyIDs, corsOrigins, customHeaders, postureCheckIDs, allowedCountries []byte
		err := rows.Scan(&r.ID, &r.Name, &desc, &r.FromURL, &r.ToURL, &r.PreserveHost,
			&r.RequireAuth, &allowedRoles, &allowedGroups, &policyIDs,
			&r.IdleTimeout, &r.AbsoluteTimeout, &corsOrigins, &customHeaders,
			&r.Enabled, &r.Priority, &r.ZitiEnabled, &zitiServiceName,
			&idpID, &r.RouteType, &remoteHost, &remotePort,
			&r.ReverifyInterval, &postureCheckIDs, &inlinePolicy,
			&r.RequireDeviceTrust, &allowedCountries,
			&r.MaxRiskScore, &guacConnID,
			&r.CreatedAt, &r.UpdatedAt)
		if err != nil {
			s.logger.Error("Failed to scan route", zap.Error(err))
			continue
		}
		if desc != nil {
			r.Description = *desc
		}
		if zitiServiceName != nil {
			r.ZitiServiceName = *zitiServiceName
		}
		if idpID != nil {
			r.IDPId = *idpID
		}
		if remoteHost != nil {
			r.RemoteHost = *remoteHost
		}
		if remotePort != nil {
			r.RemotePort = *remotePort
		}
		if inlinePolicy != nil {
			r.InlinePolicy = *inlinePolicy
		}
		if guacConnID != nil {
			r.GuacamoleConnectionID = *guacConnID
		}
		json.Unmarshal(allowedRoles, &r.AllowedRoles)
		json.Unmarshal(allowedGroups, &r.AllowedGroups)
		json.Unmarshal(policyIDs, &r.PolicyIDs)
		json.Unmarshal(corsOrigins, &r.CORSAllowedOrigins)
		json.Unmarshal(customHeaders, &r.CustomHeaders)
		json.Unmarshal(postureCheckIDs, &r.PostureCheckIDs)
		json.Unmarshal(allowedCountries, &r.AllowedCountries)
		routes = append(routes, r)
	}

	// Get total count
	var total int
	s.db.Pool.QueryRow(c.Request.Context(), "SELECT COUNT(*) FROM proxy_routes").Scan(&total)

	c.JSON(http.StatusOK, gin.H{
		"routes": routes,
		"total":  total,
		"offset": offset,
		"limit":  limit,
	})
}

func (s *Service) handleCreateRoute(c *gin.Context) {
	var req struct {
		Name               string            `json:"name" binding:"required"`
		Description        string            `json:"description"`
		FromURL            string            `json:"from_url" binding:"required"`
		ToURL              string            `json:"to_url" binding:"required"`
		PreserveHost       bool              `json:"preserve_host"`
		RequireAuth        *bool             `json:"require_auth"`
		AllowedRoles       []string          `json:"allowed_roles"`
		AllowedGroups      []string          `json:"allowed_groups"`
		PolicyIDs          []string          `json:"policy_ids"`
		IdleTimeout        int               `json:"idle_timeout"`
		AbsoluteTimeout    int               `json:"absolute_timeout"`
		CORSAllowedOrigins []string          `json:"cors_allowed_origins"`
		CustomHeaders      map[string]string `json:"custom_headers"`
		Enabled            *bool             `json:"enabled"`
		Priority           int               `json:"priority"`
		IDPId              string            `json:"idp_id"`
		RouteType          string            `json:"route_type"`
		RemoteHost         string            `json:"remote_host"`
		RemotePort         int               `json:"remote_port"`
		ReverifyInterval   int               `json:"reverify_interval"`
		PostureCheckIDs    []string          `json:"posture_check_ids"`
		InlinePolicy       string            `json:"inline_policy"`
		RequireDeviceTrust bool              `json:"require_device_trust"`
		AllowedCountries   []string          `json:"allowed_countries"`
		MaxRiskScore       int               `json:"max_risk_score"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	id := uuid.New().String()
	requireAuth := true
	if req.RequireAuth != nil {
		requireAuth = *req.RequireAuth
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	if req.IdleTimeout == 0 {
		req.IdleTimeout = 900
	}
	if req.AbsoluteTimeout == 0 {
		req.AbsoluteTimeout = 43200
	}
	if req.RouteType == "" {
		req.RouteType = "http"
	}
	if req.MaxRiskScore == 0 {
		req.MaxRiskScore = 100
	}

	// Validate inline policy if provided
	if req.InlinePolicy != "" {
		if err := ValidatePolicy(req.InlinePolicy); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid inline policy: %s", err.Error())})
			return
		}
	}

	rolesJSON, _ := json.Marshal(req.AllowedRoles)
	groupsJSON, _ := json.Marshal(req.AllowedGroups)
	policyJSON, _ := json.Marshal(req.PolicyIDs)
	corsJSON, _ := json.Marshal(req.CORSAllowedOrigins)
	headersJSON, _ := json.Marshal(req.CustomHeaders)
	postureJSON, _ := json.Marshal(req.PostureCheckIDs)
	countriesJSON, _ := json.Marshal(req.AllowedCountries)

	var idpID *string
	if req.IDPId != "" {
		idpID = &req.IDPId
	}

	_, err := s.db.Pool.Exec(c.Request.Context(),
		`INSERT INTO proxy_routes (id, name, description, from_url, to_url, preserve_host,
		  require_auth, allowed_roles, allowed_groups, policy_ids, idle_timeout, absolute_timeout,
		  cors_allowed_origins, custom_headers, enabled, priority,
		  idp_id, route_type, remote_host, remote_port,
		  reverify_interval, posture_check_ids, inline_policy,
		  require_device_trust, allowed_countries, max_risk_score)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
		         $17, $18, $19, $20, $21, $22, $23, $24, $25, $26)`,
		id, req.Name, req.Description, req.FromURL, req.ToURL, req.PreserveHost,
		requireAuth, rolesJSON, groupsJSON, policyJSON, req.IdleTimeout, req.AbsoluteTimeout,
		corsJSON, headersJSON, enabled, req.Priority,
		idpID, req.RouteType, req.RemoteHost, req.RemotePort,
		req.ReverifyInterval, postureJSON, req.InlinePolicy,
		req.RequireDeviceTrust, countriesJSON, req.MaxRiskScore)
	if err != nil {
		s.logger.Error("Failed to create route", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create route"})
		return
	}

	// Auto-provision Guacamole connection for remote access routes
	route := &ProxyRoute{
		ID: id, Name: req.Name, RouteType: req.RouteType,
		RemoteHost: req.RemoteHost, RemotePort: req.RemotePort,
	}
	if err := s.provisionGuacamoleForRoute(c.Request.Context(), route); err != nil {
		s.logger.Warn("Guacamole provisioning failed", zap.Error(err))
	}

	s.logAuditEvent(c, "proxy_route_created", id, "proxy_route", map[string]interface{}{
		"name":       req.Name,
		"from_url":   req.FromURL,
		"to_url":     req.ToURL,
		"route_type": req.RouteType,
	})

	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "route created"})
}

func (s *Service) handleGetRoute(c *gin.Context) {
	route, err := s.getRouteByID(c.Request.Context(), c.Param("id"))
	if err != nil {
		if err == pgx.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
			return
		}
		s.logger.Error("Failed to get route", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get route"})
		return
	}
	c.JSON(http.StatusOK, route)
}

func (s *Service) handleUpdateRoute(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Name               *string            `json:"name"`
		Description        *string            `json:"description"`
		FromURL            *string            `json:"from_url"`
		ToURL              *string            `json:"to_url"`
		PreserveHost       *bool              `json:"preserve_host"`
		RequireAuth        *bool              `json:"require_auth"`
		AllowedRoles       []string           `json:"allowed_roles"`
		AllowedGroups      []string           `json:"allowed_groups"`
		PolicyIDs          []string           `json:"policy_ids"`
		IdleTimeout        *int               `json:"idle_timeout"`
		AbsoluteTimeout    *int               `json:"absolute_timeout"`
		CORSAllowedOrigins []string           `json:"cors_allowed_origins"`
		CustomHeaders      map[string]string  `json:"custom_headers"`
		Enabled            *bool              `json:"enabled"`
		Priority           *int               `json:"priority"`
		IDPId              *string            `json:"idp_id"`
		RouteType          *string            `json:"route_type"`
		RemoteHost         *string            `json:"remote_host"`
		RemotePort         *int               `json:"remote_port"`
		ReverifyInterval   *int               `json:"reverify_interval"`
		PostureCheckIDs    []string           `json:"posture_check_ids"`
		InlinePolicy       *string            `json:"inline_policy"`
		RequireDeviceTrust *bool              `json:"require_device_trust"`
		AllowedCountries   []string           `json:"allowed_countries"`
		MaxRiskScore       *int               `json:"max_risk_score"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Build dynamic update
	existing, err := s.getRouteByID(c.Request.Context(), id)
	if err != nil {
		if err == pgx.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get route"})
		return
	}

	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.Description != nil {
		existing.Description = *req.Description
	}
	if req.FromURL != nil {
		existing.FromURL = *req.FromURL
	}
	if req.ToURL != nil {
		existing.ToURL = *req.ToURL
	}
	if req.PreserveHost != nil {
		existing.PreserveHost = *req.PreserveHost
	}
	if req.RequireAuth != nil {
		existing.RequireAuth = *req.RequireAuth
	}
	if req.AllowedRoles != nil {
		existing.AllowedRoles = req.AllowedRoles
	}
	if req.AllowedGroups != nil {
		existing.AllowedGroups = req.AllowedGroups
	}
	if req.PolicyIDs != nil {
		existing.PolicyIDs = req.PolicyIDs
	}
	if req.IdleTimeout != nil {
		existing.IdleTimeout = *req.IdleTimeout
	}
	if req.AbsoluteTimeout != nil {
		existing.AbsoluteTimeout = *req.AbsoluteTimeout
	}
	if req.CORSAllowedOrigins != nil {
		existing.CORSAllowedOrigins = req.CORSAllowedOrigins
	}
	if req.CustomHeaders != nil {
		existing.CustomHeaders = req.CustomHeaders
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	if req.Priority != nil {
		existing.Priority = *req.Priority
	}
	if req.IDPId != nil {
		existing.IDPId = *req.IDPId
	}
	if req.RouteType != nil {
		existing.RouteType = *req.RouteType
	}
	if req.RemoteHost != nil {
		existing.RemoteHost = *req.RemoteHost
	}
	if req.RemotePort != nil {
		existing.RemotePort = *req.RemotePort
	}
	if req.ReverifyInterval != nil {
		existing.ReverifyInterval = *req.ReverifyInterval
	}
	if req.PostureCheckIDs != nil {
		existing.PostureCheckIDs = req.PostureCheckIDs
	}
	if req.InlinePolicy != nil {
		existing.InlinePolicy = *req.InlinePolicy
		if existing.InlinePolicy != "" {
			if err := ValidatePolicy(existing.InlinePolicy); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid inline policy: %s", err.Error())})
				return
			}
		}
	}
	if req.RequireDeviceTrust != nil {
		existing.RequireDeviceTrust = *req.RequireDeviceTrust
	}
	if req.AllowedCountries != nil {
		existing.AllowedCountries = req.AllowedCountries
	}
	if req.MaxRiskScore != nil {
		existing.MaxRiskScore = *req.MaxRiskScore
	}

	rolesJSON, _ := json.Marshal(existing.AllowedRoles)
	groupsJSON, _ := json.Marshal(existing.AllowedGroups)
	policyJSON, _ := json.Marshal(existing.PolicyIDs)
	corsJSON, _ := json.Marshal(existing.CORSAllowedOrigins)
	headersJSON, _ := json.Marshal(existing.CustomHeaders)
	postureJSON, _ := json.Marshal(existing.PostureCheckIDs)
	countriesJSON, _ := json.Marshal(existing.AllowedCountries)

	var idpID *string
	if existing.IDPId != "" {
		idpID = &existing.IDPId
	}

	_, err = s.db.Pool.Exec(c.Request.Context(),
		`UPDATE proxy_routes SET name=$1, description=$2, from_url=$3, to_url=$4,
		  preserve_host=$5, require_auth=$6, allowed_roles=$7, allowed_groups=$8,
		  policy_ids=$9, idle_timeout=$10, absolute_timeout=$11, cors_allowed_origins=$12,
		  custom_headers=$13, enabled=$14, priority=$15,
		  idp_id=$16, route_type=$17, remote_host=$18, remote_port=$19,
		  reverify_interval=$20, posture_check_ids=$21, inline_policy=$22,
		  require_device_trust=$23, allowed_countries=$24, max_risk_score=$25,
		  updated_at=NOW()
		 WHERE id=$26`,
		existing.Name, existing.Description, existing.FromURL, existing.ToURL,
		existing.PreserveHost, existing.RequireAuth, rolesJSON, groupsJSON,
		policyJSON, existing.IdleTimeout, existing.AbsoluteTimeout, corsJSON,
		headersJSON, existing.Enabled, existing.Priority,
		idpID, existing.RouteType, existing.RemoteHost, existing.RemotePort,
		existing.ReverifyInterval, postureJSON, existing.InlinePolicy,
		existing.RequireDeviceTrust, countriesJSON, existing.MaxRiskScore, id)
	if err != nil {
		s.logger.Error("Failed to update route", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update route"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "route updated"})
}

func (s *Service) handleDeleteRoute(c *gin.Context) {
	id := c.Param("id")

	// Deprovision Guacamole connection before deleting route
	s.deprovisionGuacamoleForRoute(c.Request.Context(), id)

	result, err := s.db.Pool.Exec(c.Request.Context(), "DELETE FROM proxy_routes WHERE id=$1", id)
	if err != nil {
		s.logger.Error("Failed to delete route", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete route"})
		return
	}
	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
		return
	}

	s.logAuditEvent(c, "proxy_route_deleted", id, "proxy_route", nil)
	c.JSON(http.StatusOK, gin.H{"message": "route deleted"})
}

// ---- Session management ----

func (s *Service) handleListSessions(c *gin.Context) {
	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, user_id, route_id, ip_address, user_agent, started_at, last_active_at, expires_at, revoked
		 FROM proxy_sessions WHERE revoked=false AND expires_at > NOW()
		 ORDER BY last_active_at DESC LIMIT 100`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list sessions"})
		return
	}
	defer rows.Close()

	sessions := []ProxySession{}
	for rows.Next() {
		var sess ProxySession
		var routeID *string
		err := rows.Scan(&sess.ID, &sess.UserID, &routeID, &sess.IPAddress, &sess.UserAgent,
			&sess.StartedAt, &sess.LastActiveAt, &sess.ExpiresAt, &sess.Revoked)
		if err != nil {
			continue
		}
		if routeID != nil {
			sess.RouteID = *routeID
		}
		sessions = append(sessions, sess)
	}

	c.JSON(http.StatusOK, gin.H{"sessions": sessions})
}

func (s *Service) handleRevokeSession(c *gin.Context) {
	id := c.Param("id")
	_, err := s.db.Pool.Exec(c.Request.Context(),
		"UPDATE proxy_sessions SET revoked=true WHERE id=$1", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke session"})
		return
	}

	// Also remove from Redis
	s.redis.Client.Del(c.Request.Context(), "proxy_session:"+id)

	c.JSON(http.StatusOK, gin.H{"message": "session revoked"})
}

// ---- OAuth Login Flow ----

func (s *Service) handleLogin(c *gin.Context) {
	// Check if a specific IDP is requested
	if idpID := c.Query("idp"); idpID != "" && idpID != "default" {
		s.handleLoginWithIDP(c, idpID)
		return
	}

	// Generate PKCE code verifier and challenge
	verifier := generateCodeVerifier()
	challenge := generateCodeChallenge(verifier)
	state := generateState()

	// Store verifier and original URL in Redis
	redirectURL := c.Query("redirect_url")
	if redirectURL == "" {
		redirectURL = "/"
	}

	sessionData, _ := json.Marshal(map[string]string{
		"verifier":     verifier,
		"redirect_url": redirectURL,
	})
	s.redis.Client.Set(c.Request.Context(), "access_oauth_state:"+state, sessionData, 10*time.Minute)

	// Build OAuth authorization URL
	callbackURL := fmt.Sprintf("http://%s:%d/access/.auth/callback",
		s.config.AccessProxyDomain, s.config.Port)

	authURL := fmt.Sprintf("%s/oauth/authorize?client_id=access-proxy&response_type=code&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256&state=%s&scope=openid+profile+email",
		s.oauthIssuer,
		url.QueryEscape(callbackURL),
		url.QueryEscape(challenge),
		url.QueryEscape(state))

	c.Redirect(http.StatusFound, authURL)
}

func (s *Service) handleCallback(c *gin.Context) {
	code := c.Query("code")
	state := c.Query("state")

	if code == "" || state == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code or state"})
		return
	}

	// Retrieve stored state
	stateData, err := s.redis.Client.Get(c.Request.Context(), "access_oauth_state:"+state).Bytes()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired state"})
		return
	}
	s.redis.Client.Del(c.Request.Context(), "access_oauth_state:"+state)

	var storedState struct {
		Verifier    string `json:"verifier"`
		RedirectURL string `json:"redirect_url"`
		IDPID       string `json:"idp_id"`
		IDPIssuer   string `json:"idp_issuer"`
	}
	json.Unmarshal(stateData, &storedState)

	// If this callback is from an external IDP, delegate to multi-IDP handler
	if storedState.IDPID != "" && storedState.IDPID != "default" {
		s.handleCallbackWithIDP(c, storedState.IDPID, storedState.IDPIssuer, storedState.Verifier, storedState.RedirectURL)
		return
	}

	// Exchange code for tokens
	callbackURL := fmt.Sprintf("http://%s:%d/access/.auth/callback",
		s.config.AccessProxyDomain, s.config.Port)

	tokenResp, err := s.exchangeCode(c.Request.Context(), code, storedState.Verifier, callbackURL)
	if err != nil {
		s.logger.Error("Failed to exchange code", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "authentication failed"})
		return
	}

	// Parse the access token to extract user info
	claims, err := s.parseTokenClaims(tokenResp.AccessToken)
	if err != nil {
		s.logger.Error("Failed to parse token", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse token"})
		return
	}

	// Create proxy session
	session, err := s.createSession(c, claims, tokenResp.AccessToken)
	if err != nil {
		s.logger.Error("Failed to create session", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create session"})
		return
	}

	// Set session cookie
	c.SetCookie(
		"_openidx_proxy_session",
		session.SessionToken,
		session.AbsoluteTimeout(),
		"/",
		"",
		false, // secure (set true in production)
		true,  // httponly
	)

	s.logAuditEvent(c, "proxy_session_created", session.UserID, "session", map[string]interface{}{
		"session_id": session.ID,
		"email":      session.Email,
	})

	// Redirect to original URL
	redirectURL := storedState.RedirectURL
	if redirectURL == "" {
		redirectURL = "/"
	}
	c.Redirect(http.StatusFound, redirectURL)
}

func (s *Service) handleLogout(c *gin.Context) {
	cookie, err := c.Cookie("_openidx_proxy_session")
	if err == nil && cookie != "" {
		// Find and revoke session
		var sessionID string
		err := s.db.Pool.QueryRow(c.Request.Context(),
			"SELECT id FROM proxy_sessions WHERE session_token=$1", hashToken(cookie)).Scan(&sessionID)
		if err == nil {
			s.db.Pool.Exec(c.Request.Context(),
				"UPDATE proxy_sessions SET revoked=true WHERE id=$1", sessionID)
			s.redis.Client.Del(c.Request.Context(), "proxy_session:"+hashToken(cookie))
		}
	}

	c.SetCookie("_openidx_proxy_session", "", -1, "/", "", false, true)

	redirectURL := c.Query("redirect_url")
	if redirectURL == "" {
		redirectURL = "/access/.auth/login"
	}
	c.Redirect(http.StatusFound, redirectURL)
}

func (s *Service) handleSessionInfo(c *gin.Context) {
	session := s.getSessionFromRequest(c)
	if session == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "no active session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id":   session.UserID,
		"email":     session.Email,
		"name":      session.Name,
		"roles":     session.Roles,
		"expires_at": session.ExpiresAt,
	})
}

// ---- Reverse Proxy ----

func (s *Service) handleProxy(c *gin.Context) {
	// Find matching route by host header
	host := c.Request.Host
	route, err := s.findRouteByHost(c.Request.Context(), host)
	if err != nil || route == nil {
		// No matching route - return 404
		c.JSON(http.StatusNotFound, gin.H{"error": "no proxy route configured for this host"})
		return
	}

	if !route.Enabled {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "route is disabled"})
		return
	}

	// Check authentication
	var session *ProxySession
	if route.RequireAuth {
		session = s.getSessionFromRequest(c)
		if session == nil {
			// Also check for Bearer token
			session = s.getSessionFromBearer(c)
		}
		if session == nil {
			// Redirect to login
			loginURL := fmt.Sprintf("/access/.auth/login?redirect_url=%s",
				url.QueryEscape(c.Request.URL.String()))
			c.Redirect(http.StatusFound, loginURL)
			return
		}

		// Check roles
		if len(route.AllowedRoles) > 0 && !hasAnyRole(session.Roles, route.AllowedRoles) {
			s.logAuditEvent(c, "proxy_access_denied", route.ID, "proxy_route", map[string]interface{}{
				"reason":  "insufficient_roles",
				"user_id": session.UserID,
				"path":    c.Request.URL.Path,
			})
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			return
		}

		// Context-aware access evaluation
		accessCtx, ctxErr := s.buildAccessContext(c, route, session)
		if ctxErr != nil {
			s.logger.Error("Failed to build access context", zap.Error(ctxErr))
			c.JSON(http.StatusForbidden, gin.H{"error": "context evaluation failed"})
			return
		}
		decision := s.evaluateAccessContext(accessCtx)
		if !decision.Allowed {
			s.logAuditEvent(c, "proxy_access_denied", route.ID, "proxy_route", map[string]interface{}{
				"reason":  decision.Reason,
				"user_id": session.UserID,
				"path":    c.Request.URL.Path,
			})
			if decision.StepUpRequired {
				c.Header("X-Step-Up-Required", "true")
			}
			c.JSON(http.StatusForbidden, gin.H{"error": decision.Reason})
			return
		}
		session.RiskScore = decision.RiskScore

		// Evaluate governance policies
		if len(route.PolicyIDs) > 0 {
			allowed, err := s.evaluatePolicies(c, route, session)
			if err != nil {
				s.logger.Error("Policy evaluation failed", zap.Error(err))
				// Fail closed
				c.JSON(http.StatusForbidden, gin.H{"error": "policy evaluation failed"})
				return
			}
			if !allowed {
				s.logAuditEvent(c, "proxy_access_denied", route.ID, "proxy_route", map[string]interface{}{
					"reason":  "policy_denied",
					"user_id": session.UserID,
					"path":    c.Request.URL.Path,
				})
				c.JSON(http.StatusForbidden, gin.H{"error": "access denied by policy"})
				return
			}
		}

		// Update session activity
		s.updateSessionActivity(c.Request.Context(), session)
	}

	// Proxy the request
	target, err := url.Parse(route.ToURL)
	if err != nil {
		s.logger.Error("Invalid upstream URL", zap.String("to_url", route.ToURL), zap.Error(err))
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid upstream configuration"})
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	// Use Ziti transport if the route has Ziti enabled and ZitiManager is available
	if route.ZitiEnabled && route.ZitiServiceName != "" && s.zitiManager != nil && s.zitiManager.IsInitialized() {
		proxy.Transport = s.zitiManager.ZitiTransport(route.ZitiServiceName)
		s.logger.Debug("Proxying through Ziti overlay",
			zap.String("service", route.ZitiServiceName),
			zap.String("route", route.Name))
	}

	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, c.Request.URL.Path)
		req.URL.RawQuery = c.Request.URL.RawQuery

		if route.PreserveHost {
			req.Host = c.Request.Host
		} else {
			req.Host = target.Host
		}

		// Inject identity headers
		if session != nil {
			req.Header.Set("X-Forwarded-User", session.UserID)
			req.Header.Set("X-Forwarded-Email", session.Email)
			req.Header.Set("X-Forwarded-Name", session.Name)
			req.Header.Set("X-Forwarded-Roles", strings.Join(session.Roles, ","))
		}

		req.Header.Set("X-Forwarded-For", c.ClientIP())
		req.Header.Set("X-Forwarded-Proto", "http")
		req.Header.Set("X-Real-IP", c.ClientIP())

		// Custom headers
		for k, v := range route.CustomHeaders {
			req.Header.Set(k, v)
		}
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		s.logger.Error("Proxy error", zap.String("route", route.Name), zap.Error(err))
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(gin.H{"error": "upstream unavailable"})
	}

	// Log successful proxy
	if session != nil {
		s.logAuditEvent(c, "proxy_access_allowed", route.ID, "proxy_route", map[string]interface{}{
			"user_id": session.UserID,
			"path":    c.Request.URL.Path,
			"method":  c.Request.Method,
			"upstream": route.ToURL,
		})
	}

	proxy.ServeHTTP(c.Writer, c.Request)
}

// ---- Helper methods ----

func (s *Service) getRouteByID(ctx context.Context, id string) (*ProxyRoute, error) {
	var r ProxyRoute
	var desc, zitiServiceName, idpID, remoteHost, inlinePolicy, guacConnID *string
	var remotePort *int
	var allowedRoles, allowedGroups, policyIDs, corsOrigins, customHeaders, postureCheckIDs, allowedCountries []byte

	err := s.db.Pool.QueryRow(ctx,
		`SELECT id, name, description, from_url, to_url, preserve_host, require_auth,
		        allowed_roles, allowed_groups, policy_ids, idle_timeout, absolute_timeout,
		        cors_allowed_origins, custom_headers, enabled, priority,
		        COALESCE(ziti_enabled, false), ziti_service_name,
		        idp_id, COALESCE(route_type, 'http'), remote_host, remote_port,
		        COALESCE(reverify_interval, 0), posture_check_ids, inline_policy,
		        COALESCE(require_device_trust, false), allowed_countries,
		        COALESCE(max_risk_score, 100), guacamole_connection_id,
		        created_at, updated_at
		 FROM proxy_routes WHERE id=$1`, id).Scan(
		&r.ID, &r.Name, &desc, &r.FromURL, &r.ToURL, &r.PreserveHost,
		&r.RequireAuth, &allowedRoles, &allowedGroups, &policyIDs,
		&r.IdleTimeout, &r.AbsoluteTimeout, &corsOrigins, &customHeaders,
		&r.Enabled, &r.Priority, &r.ZitiEnabled, &zitiServiceName,
		&idpID, &r.RouteType, &remoteHost, &remotePort,
		&r.ReverifyInterval, &postureCheckIDs, &inlinePolicy,
		&r.RequireDeviceTrust, &allowedCountries,
		&r.MaxRiskScore, &guacConnID,
		&r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if desc != nil {
		r.Description = *desc
	}
	if zitiServiceName != nil {
		r.ZitiServiceName = *zitiServiceName
	}
	if idpID != nil {
		r.IDPId = *idpID
	}
	if remoteHost != nil {
		r.RemoteHost = *remoteHost
	}
	if remotePort != nil {
		r.RemotePort = *remotePort
	}
	if inlinePolicy != nil {
		r.InlinePolicy = *inlinePolicy
	}
	if guacConnID != nil {
		r.GuacamoleConnectionID = *guacConnID
	}
	json.Unmarshal(allowedRoles, &r.AllowedRoles)
	json.Unmarshal(allowedGroups, &r.AllowedGroups)
	json.Unmarshal(policyIDs, &r.PolicyIDs)
	json.Unmarshal(corsOrigins, &r.CORSAllowedOrigins)
	json.Unmarshal(customHeaders, &r.CustomHeaders)
	json.Unmarshal(postureCheckIDs, &r.PostureCheckIDs)
	json.Unmarshal(allowedCountries, &r.AllowedCountries)
	return &r, nil
}

func (s *Service) findRouteByHost(ctx context.Context, host string) (*ProxyRoute, error) {
	// Try exact match first, then wildcard
	var r ProxyRoute
	var desc, zitiServiceName, idpID, remoteHost, inlinePolicy, guacConnID *string
	var remotePort *int
	var allowedRoles, allowedGroups, policyIDs, corsOrigins, customHeaders, postureCheckIDs, allowedCountries []byte

	// Match from_url containing the host
	err := s.db.Pool.QueryRow(ctx,
		`SELECT id, name, description, from_url, to_url, preserve_host, require_auth,
		        allowed_roles, allowed_groups, policy_ids, idle_timeout, absolute_timeout,
		        cors_allowed_origins, custom_headers, enabled, priority,
		        COALESCE(ziti_enabled, false), ziti_service_name,
		        idp_id, COALESCE(route_type, 'http'), remote_host, remote_port,
		        COALESCE(reverify_interval, 0), posture_check_ids, inline_policy,
		        COALESCE(require_device_trust, false), allowed_countries,
		        COALESCE(max_risk_score, 100), guacamole_connection_id,
		        created_at, updated_at
		 FROM proxy_routes WHERE from_url LIKE '%' || $1 || '%' AND enabled=true
		 ORDER BY priority DESC LIMIT 1`, host).Scan(
		&r.ID, &r.Name, &desc, &r.FromURL, &r.ToURL, &r.PreserveHost,
		&r.RequireAuth, &allowedRoles, &allowedGroups, &policyIDs,
		&r.IdleTimeout, &r.AbsoluteTimeout, &corsOrigins, &customHeaders,
		&r.Enabled, &r.Priority, &r.ZitiEnabled, &zitiServiceName,
		&idpID, &r.RouteType, &remoteHost, &remotePort,
		&r.ReverifyInterval, &postureCheckIDs, &inlinePolicy,
		&r.RequireDeviceTrust, &allowedCountries,
		&r.MaxRiskScore, &guacConnID,
		&r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if desc != nil {
		r.Description = *desc
	}
	if zitiServiceName != nil {
		r.ZitiServiceName = *zitiServiceName
	}
	if idpID != nil {
		r.IDPId = *idpID
	}
	if remoteHost != nil {
		r.RemoteHost = *remoteHost
	}
	if remotePort != nil {
		r.RemotePort = *remotePort
	}
	if inlinePolicy != nil {
		r.InlinePolicy = *inlinePolicy
	}
	if guacConnID != nil {
		r.GuacamoleConnectionID = *guacConnID
	}
	json.Unmarshal(allowedRoles, &r.AllowedRoles)
	json.Unmarshal(allowedGroups, &r.AllowedGroups)
	json.Unmarshal(policyIDs, &r.PolicyIDs)
	json.Unmarshal(corsOrigins, &r.CORSAllowedOrigins)
	json.Unmarshal(customHeaders, &r.CustomHeaders)
	json.Unmarshal(postureCheckIDs, &r.PostureCheckIDs)
	json.Unmarshal(allowedCountries, &r.AllowedCountries)
	return &r, nil
}

func (s *Service) createSession(c *gin.Context, claims map[string]interface{}, accessToken string) (*ProxySession, error) {
	id := uuid.New().String()
	token := generateSessionToken()
	tokenHash := hashToken(token)

	userID, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	var roles []string
	if r, ok := claims["roles"].([]interface{}); ok {
		for _, role := range r {
			roles = append(roles, fmt.Sprint(role))
		}
	}

	expiresAt := time.Now().Add(12 * time.Hour)

	_, err := s.db.Pool.Exec(c.Request.Context(),
		`INSERT INTO proxy_sessions (id, user_id, session_token, ip_address, user_agent, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		id, userID, tokenHash, c.ClientIP(), c.Request.UserAgent(), expiresAt)
	if err != nil {
		return nil, err
	}

	// Store session data in Redis for fast access
	sessionData, _ := json.Marshal(map[string]interface{}{
		"id":       id,
		"user_id":  userID,
		"email":    email,
		"name":     name,
		"roles":    roles,
		"token":    accessToken,
		"expires":  expiresAt.Unix(),
	})
	s.redis.Client.Set(c.Request.Context(), "proxy_session:"+tokenHash, sessionData, 12*time.Hour)

	return &ProxySession{
		ID:           id,
		UserID:       userID,
		SessionToken: token,
		IPAddress:    c.ClientIP(),
		UserAgent:    c.Request.UserAgent(),
		Email:        email,
		Name:         name,
		Roles:        roles,
		StartedAt:    time.Now(),
		LastActiveAt: time.Now(),
		ExpiresAt:    expiresAt,
	}, nil
}

func (sess *ProxySession) AbsoluteTimeout() int {
	return int(time.Until(sess.ExpiresAt).Seconds())
}

func (s *Service) getSessionFromRequest(c *gin.Context) *ProxySession {
	cookie, err := c.Cookie("_openidx_proxy_session")
	if err != nil || cookie == "" {
		return nil
	}

	tokenHash := hashToken(cookie)
	data, err := s.redis.Client.Get(c.Request.Context(), "proxy_session:"+tokenHash).Bytes()
	if err != nil {
		return nil
	}

	var sessionData map[string]interface{}
	if err := json.Unmarshal(data, &sessionData); err != nil {
		return nil
	}

	// Check expiry
	expires, _ := sessionData["expires"].(float64)
	if time.Now().Unix() > int64(expires) {
		return nil
	}

	var roles []string
	if r, ok := sessionData["roles"].([]interface{}); ok {
		for _, role := range r {
			roles = append(roles, fmt.Sprint(role))
		}
	}

	return &ProxySession{
		ID:      fmt.Sprint(sessionData["id"]),
		UserID:  fmt.Sprint(sessionData["user_id"]),
		Email:   fmt.Sprint(sessionData["email"]),
		Name:    fmt.Sprint(sessionData["name"]),
		Roles:   roles,
	}
}

func (s *Service) getSessionFromBearer(c *gin.Context) *ProxySession {
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := s.parseTokenClaims(token)
	if err != nil {
		return nil
	}

	userID, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	var roles []string
	if r, ok := claims["roles"].([]interface{}); ok {
		for _, role := range r {
			roles = append(roles, fmt.Sprint(role))
		}
	}

	return &ProxySession{
		UserID: userID,
		Email:  email,
		Name:   name,
		Roles:  roles,
	}
}

func (s *Service) updateSessionActivity(ctx context.Context, session *ProxySession) {
	s.db.Pool.Exec(ctx,
		"UPDATE proxy_sessions SET last_active_at=NOW() WHERE id=$1", session.ID)
}

func (s *Service) evaluatePolicies(c *gin.Context, route *ProxyRoute, session *ProxySession) (bool, error) {
	for _, policyID := range route.PolicyIDs {
		reqBody, _ := json.Marshal(map[string]interface{}{
			"user_id":            session.UserID,
			"roles":              session.Roles,
			"ip":                 c.ClientIP(),
			"time":               time.Now().Format(time.RFC3339),
			"path":               c.Request.URL.Path,
			"method":             c.Request.Method,
			"route":              route.Name,
			"risk_score":         session.RiskScore,
			"device_trusted":     session.DeviceTrusted,
			"auth_methods":       session.AuthMethods,
			"location":           session.Location,
			"device_fingerprint": session.DeviceFingerprint,
		})

		resp, err := http.Post(
			fmt.Sprintf("%s/api/v1/governance/policies/%s/evaluate", s.governanceURL, policyID),
			"application/json",
			bytes.NewReader(reqBody))
		if err != nil {
			return false, fmt.Errorf("failed to evaluate policy %s: %w", policyID, err)
		}
		defer resp.Body.Close()

		var result struct {
			Allowed        bool `json:"allowed"`
			StepUpRequired bool `json:"step_up_required"`
		}
		body, _ := io.ReadAll(resp.Body)
		json.Unmarshal(body, &result)

		if !result.Allowed {
			if result.StepUpRequired {
				c.Header("X-Step-Up-Required", "true")
			}
			return false, nil
		}
	}
	return true, nil
}

// exchangeCode exchanges an authorization code for tokens
func (s *Service) exchangeCode(ctx context.Context, code, verifier, redirectURI string) (*tokenResponse, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {"access-proxy"},
		"code_verifier": {verifier},
	}

	resp, err := http.PostForm(s.oauthIssuer+"/oauth/token", data)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResp, nil
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

// parseTokenClaims decodes JWT claims without full validation (validation is done by session creation)
func (s *Service) parseTokenClaims(tokenString string) (map[string]interface{}, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode token payload: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse token claims: %w", err)
	}

	return claims, nil
}

func (s *Service) logAuditEvent(c *gin.Context, action, targetID, targetType string, details map[string]interface{}) {
	if s.auditURL == "" {
		return
	}

	event := map[string]interface{}{
		"event_type":  "authorization",
		"category":    "access_proxy",
		"action":      action,
		"outcome":     "success",
		"target_id":   targetID,
		"target_type": targetType,
		"actor_ip":    c.ClientIP(),
		"details":     details,
		"timestamp":   time.Now().Format(time.RFC3339),
	}

	if action == "proxy_access_denied" {
		event["outcome"] = "failure"
	}

	body, _ := json.Marshal(event)
	go func() {
		resp, err := http.Post(s.auditURL+"/api/v1/audit/events", "application/json", bytes.NewReader(body))
		if err != nil {
			s.logger.Warn("Failed to log audit event", zap.Error(err))
			return
		}
		resp.Body.Close()
	}()
}

// Utility functions

func generateCodeVerifier() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func generateCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func generateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateSessionToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func hasAnyRole(userRoles, requiredRoles []string) bool {
	roleSet := make(map[string]bool)
	for _, r := range userRoles {
		roleSet[r] = true
	}
	for _, r := range requiredRoles {
		if roleSet[r] {
			return true
		}
	}
	return false
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
