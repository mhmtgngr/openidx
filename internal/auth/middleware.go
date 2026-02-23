// Package auth provides RBAC middleware for OpenIDX Gin services
package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

var (
	// ErrMissingAuthHeader is returned when Authorization header is missing
	ErrMissingAuthHeader = errors.New("missing authorization header")

	// ErrInvalidAuthHeader is returned when Authorization header format is invalid
	ErrInvalidAuthHeader = errors.New("invalid authorization header format")

	// ErrInvalidToken is returned when token validation fails
	ErrInvalidToken = errors.New("invalid token")

	// ErrMissingRoles is returned when no roles are found in context
	ErrMissingRoles = errors.New("no roles found in context")

	// ErrInsufficientRole is returned when user doesn't have required role
	ErrInsufficientRole = errors.New("insufficient role privileges")

	// ErrInsufficientPermission is returned when user lacks required permission
	ErrInsufficientPermission = errors.New("insufficient permissions")
)

// TokenValidator defines the interface for validating JWT tokens
type TokenValidator interface {
	ValidateAccessToken(ctx context.Context, tokenString string) (*Claims, error)
}

// TokenServiceValidator adapts TokenService to TokenValidator interface
type TokenServiceValidator struct {
	tokenService *TokenService
}

// NewTokenServiceValidator creates a new TokenServiceValidator
func NewTokenServiceValidator(ts *TokenService) *TokenServiceValidator {
	return &TokenServiceValidator{tokenService: ts}
}

// ValidateAccessToken implements TokenValidator
func (v *TokenServiceValidator) ValidateAccessToken(ctx context.Context, tokenString string) (*Claims, error) {
	return v.tokenService.ValidateAccessToken(ctx, tokenString)
}

// RBACConfig holds configuration for RBAC middleware
type RBACConfig struct {
	TokenValidator TokenValidator
	Logger         *zap.Logger
}

// RBACMiddleware provides RBAC enforcement for Gin
type RBACMiddleware struct {
	config RBACConfig
}

// NewRBACMiddleware creates a new RBAC middleware
func NewRBACMiddleware(config RBACConfig) *RBACMiddleware {
	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}
	return &RBACMiddleware{config: config}
}

// Authenticate validates JWT tokens and sets user context
// It extracts the JWT from the Authorization Bearer header,
// validates it using the configured TokenValidator, and loads
// user roles from the claims into the Gin context.
func (m *RBACMiddleware) Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			m.config.Logger.Warn("authentication failed: missing authorization header",
				zap.String("path", c.Request.URL.Path),
				zap.String("method", c.Request.Method),
			)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": ErrMissingAuthHeader.Error(),
			})
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			m.config.Logger.Warn("authentication failed: invalid authorization header format",
				zap.String("header", authHeader),
			)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": ErrInvalidAuthHeader.Error(),
			})
			return
		}

		tokenString := parts[1]

		// Validate token using TokenValidator
		claims, err := m.config.TokenValidator.ValidateAccessToken(c.Request.Context(), tokenString)
		if err != nil {
			m.config.Logger.Warn("token validation failed",
				zap.Error(err),
				zap.String("path", c.Request.URL.Path),
			)

			statusCode := http.StatusUnauthorized
			errorMsg := ErrInvalidToken.Error()

			if errors.Is(err, ErrTokenExpired) {
				errorMsg = ErrTokenExpired.Error()
			}

			c.AbortWithStatusJSON(statusCode, gin.H{
				"error": errorMsg,
			})
			return
		}

		// Set user context from claims
		c.Set(ContextKeyUserID, claims.Subject)
		c.Set(ContextKeyTenantID, claims.TenantID)
		c.Set(ContextKeyRoles, claims.Roles)

		m.config.Logger.Debug("user authenticated",
			zap.String("user_id", claims.Subject),
			zap.Strings("roles", claims.Roles),
		)

		c.Next()
	}
}

// RequireRole ensures the user has at least one of the specified roles.
// It checks both directly assigned roles and inherited roles through the hierarchy.
// For example, if required is ["admin"], a super_admin will also pass.
func (m *RBACMiddleware) RequireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRoles, exists := c.Get(ContextKeyRoles)
		if !exists {
			m.config.Logger.Warn("authorization failed: no roles in context")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": ErrMissingRoles.Error(),
			})
			return
		}

		userRolesList, ok := userRoles.([]string)
		if !ok {
			m.config.Logger.Warn("authorization failed: invalid roles format")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "invalid roles format in context",
			})
			return
		}

		// Check if user has any of the required roles (including hierarchy)
		for _, userRoleStr := range userRolesList {
			userRole := Role(userRoleStr)

			for _, requiredRoleStr := range roles {
				requiredRole := Role(requiredRoleStr)

				// Direct match
				if userRole == requiredRole {
					m.config.Logger.Debug("role check passed",
						zap.String("user_role", string(userRole)),
						zap.String("required_role", string(requiredRole)),
					)
					c.Next()
					return
				}

				// Check hierarchy - if user's role is higher level than required
				if userRole.IsHigherOrEqual(requiredRole) {
					m.config.Logger.Debug("role check passed (hierarchy)",
						zap.String("user_role", string(userRole)),
						zap.String("required_role", string(requiredRole)),
					)
					c.Next()
					return
				}
			}
		}

		m.config.Logger.Warn("authorization failed: insufficient role",
			zap.Strings("user_roles", userRolesList),
			zap.Strings("required_roles", roles),
		)

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error":   ErrInsufficientRole.Error(),
			"required": roles,
		})
	}
}

// RequirePermission ensures the user has all of the specified permissions.
// It checks both direct permissions and inherited permissions through role hierarchy.
func (m *RBACMiddleware) RequirePermission(perms ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRoles, exists := c.Get(ContextKeyRoles)
		if !exists {
			m.config.Logger.Warn("authorization failed: no roles in context")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": ErrMissingRoles.Error(),
			})
			return
		}

		userRolesList, ok := userRoles.([]string)
		if !ok {
			m.config.Logger.Warn("authorization failed: invalid roles format")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "invalid roles format in context",
			})
			return
		}

		// Parse required permissions
		requiredPerms := make([]Permission, 0, len(perms))
		for _, permStr := range perms {
			perm, err := ParsePermission(permStr)
			if err != nil {
				m.config.Logger.Warn("authorization failed: invalid permission format",
					zap.String("permission", permStr),
				)
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": fmt.Sprintf("invalid permission format: %s", permStr),
				})
				return
			}
			requiredPerms = append(requiredPerms, perm)
		}

		// Check if user has all required permissions
		for _, userRoleStr := range userRolesList {
			userRole := Role(userRoleStr)

			// Check if this role has all required permissions
			allPermsGranted := true
			for _, reqPerm := range requiredPerms {
				if !userRole.HasPermission(reqPerm.Resource, reqPerm.Action) {
					allPermsGranted = false
					break
				}
			}

			if allPermsGranted {
				m.config.Logger.Debug("permission check passed",
					zap.String("user_role", string(userRole)),
					zap.Strings("permissions", perms),
				)
				c.Next()
				return
			}
		}

		m.config.Logger.Warn("authorization failed: insufficient permissions",
			zap.Strings("user_roles", userRolesList),
			zap.Strings("required_permissions", perms),
		)

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error":      ErrInsufficientPermission.Error(),
			"required":   perms,
		})
	}
}

// RequireAny ensures the user has at least one of the specified roles (OR logic).
// This is useful for endpoints that can be accessed by multiple different roles.
func (m *RBACMiddleware) RequireAny(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRoles, exists := c.Get(ContextKeyRoles)
		if !exists {
			m.config.Logger.Warn("authorization failed: no roles in context")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": ErrMissingRoles.Error(),
			})
			return
		}

		userRolesList, ok := userRoles.([]string)
		if !ok {
			m.config.Logger.Warn("authorization failed: invalid roles format")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "invalid roles format in context",
			})
			return
		}

		// Check if user has any of the required roles (including hierarchy)
		for _, userRoleStr := range userRolesList {
			userRole := Role(userRoleStr)

			for _, requiredRoleStr := range roles {
				requiredRole := Role(requiredRoleStr)

				// Direct match
				if userRole == requiredRole {
					m.config.Logger.Debug("role check passed (any)",
						zap.String("user_role", string(userRole)),
						zap.String("required_role", string(requiredRole)),
					)
					c.Next()
					return
				}

				// Check hierarchy
				if userRole.IsHigherOrEqual(requiredRole) {
					m.config.Logger.Debug("role check passed (any, hierarchy)",
						zap.String("user_role", string(userRole)),
						zap.String("required_role", string(requiredRole)),
					)
					c.Next()
					return
				}
			}
		}

		m.config.Logger.Warn("authorization failed: no matching role",
			zap.Strings("user_roles", userRolesList),
			zap.Strings("any_of_roles", roles),
		)

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error":   ErrInsufficientRole.Error(),
			"any_of": roles,
		})
	}
}

// RequireAnyPermission ensures the user has at least one of the specified permissions.
func (m *RBACMiddleware) RequireAnyPermission(perms ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRoles, exists := c.Get(ContextKeyRoles)
		if !exists {
			m.config.Logger.Warn("authorization failed: no roles in context")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": ErrMissingRoles.Error(),
			})
			return
		}

		userRolesList, ok := userRoles.([]string)
		if !ok {
			m.config.Logger.Warn("authorization failed: invalid roles format")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "invalid roles format in context",
			})
			return
		}

		// Parse required permissions
		requiredPerms := make([]Permission, 0, len(perms))
		for _, permStr := range perms {
			perm, err := ParsePermission(permStr)
			if err != nil {
				m.config.Logger.Warn("authorization failed: invalid permission format",
					zap.String("permission", permStr),
				)
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": fmt.Sprintf("invalid permission format: %s", permStr),
				})
				return
			}
			requiredPerms = append(requiredPerms, perm)
		}

		// Check if user has at least one of the required permissions
		for _, userRoleStr := range userRolesList {
			userRole := Role(userRoleStr)

			for _, reqPerm := range requiredPerms {
				if userRole.HasPermission(reqPerm.Resource, reqPerm.Action) {
					m.config.Logger.Debug("permission check passed (any)",
						zap.String("user_role", string(userRole)),
						zap.String("permission", reqPerm.String()),
					)
					c.Next()
					return
				}
			}
		}

		m.config.Logger.Warn("authorization failed: insufficient permissions",
			zap.Strings("user_roles", userRolesList),
			zap.Strings("any_of_permissions", perms),
		)

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error":   ErrInsufficientPermission.Error(),
			"any_of": perms,
		})
	}
}

// RequireAllRoles ensures the user has all of the specified roles.
// This is rarely needed but can be useful for multi-role requirements.
func (m *RBACMiddleware) RequireAllRoles(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRoles, exists := c.Get(ContextKeyRoles)
		if !exists {
			m.config.Logger.Warn("authorization failed: no roles in context")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": ErrMissingRoles.Error(),
			})
			return
		}

		userRolesList, ok := userRoles.([]string)
		if !ok {
			m.config.Logger.Warn("authorization failed: invalid roles format")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "invalid roles format in context",
			})
			return
		}

		// Check if user has all required roles (including hierarchy)
		userRoleMap := make(map[Role]bool)
		for _, userRoleStr := range userRolesList {
			userRole := Role(userRoleStr)
			userRoleMap[userRole] = true

			// Also include inherited roles in the map
			for _, inherited := range RoleHierarchy[userRole] {
				userRoleMap[inherited] = true
			}
		}

		// Verify all required roles are present
		for _, requiredRoleStr := range roles {
			requiredRole := Role(requiredRoleStr)
			if !userRoleMap[requiredRole] {
				m.config.Logger.Warn("authorization failed: missing required role",
					zap.Strings("user_roles", userRolesList),
					zap.String("missing_role", string(requiredRole)),
					zap.Strings("required_roles", roles),
				)
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error":   ErrInsufficientRole.Error(),
					"required": roles,
				})
				return
			}
		}

		m.config.Logger.Debug("all roles check passed",
			zap.Strings("user_roles", userRolesList),
			zap.Strings("required_roles", roles),
		)
		c.Next()
	}
}
