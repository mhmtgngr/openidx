// Package provisioning provides user lifecycle and SCIM 2.0 provisioning
package provisioning

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/secretcrypt"
	"github.com/openidx/openidx/internal/common/sessionend"
	"github.com/openidx/openidx/internal/common/ssfsignal"
	"github.com/openidx/openidx/internal/revocation"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/middleware"
)

// ctxKey is an unexported type for context keys in this package.
type ctxKey int

const (
	// ctxKeyActorID is the context key for the actor (authenticated user) performing the operation.
	ctxKeyActorID ctxKey = iota
)

// ContextWithActorID returns a new context that carries the given actor ID.
func ContextWithActorID(ctx context.Context, actorID string) context.Context {
	return context.WithValue(ctx, ctxKeyActorID, actorID)
}

// actorIDFromContext extracts the actor ID from context, returning "system" if not set.
func actorIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyActorID).(string); ok && v != "" {
		return v
	}
	return "system"
}

// writeSCIMError writes a SCIM-formatted error response
func writeSCIMError(c *gin.Context, status int, detail string) {
	c.JSON(status, SCIMError{
		Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		Status:  strconv.Itoa(status),
		Detail:  detail,
	})
}

// SCIMUser represents a user in SCIM 2.0 format
type SCIMUser struct {
	Schemas     []string       `json:"schemas"`
	ID          string         `json:"id,omitempty"`
	ExternalID  string         `json:"externalId,omitempty"`
	UserName    string         `json:"userName"`
	Name        SCIMName       `json:"name,omitempty"`
	DisplayName string         `json:"displayName,omitempty"`
	Emails      []SCIMEmail    `json:"emails,omitempty"`
	Active      bool           `json:"active"`
	Groups      []SCIMGroupRef `json:"groups,omitempty"`
	Meta        SCIMMeta       `json:"meta,omitempty"`
	// Enterprise carries the SCIM 2.0 enterprise user extension. The JSON key
	// is the full schema URN, which encoding/json maps verbatim.
	Enterprise *SCIMEnterpriseUser `json:"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User,omitempty"`
}

// scimEnterpriseUserSchema is the URN of the SCIM 2.0 enterprise user extension.
const scimEnterpriseUserSchema = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"

// SCIMEnterpriseUser is the SCIM 2.0 enterprise user extension. Only the
// attributes OpenIDX consumes are modeled; unknown attributes are ignored.
type SCIMEnterpriseUser struct {
	EmployeeNumber string       `json:"employeeNumber,omitempty"`
	Department     string       `json:"department,omitempty"`
	Manager        *SCIMManager `json:"manager,omitempty"`
}

// SCIMManager is the enterprise-extension manager reference. Per RFC 7643 §4.3,
// Value is the SCIM id of the User's manager resource (our users.id).
type SCIMManager struct {
	Value       string `json:"value,omitempty"`
	Ref         string `json:"$ref,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
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
	Schemas     []string     `json:"schemas"`
	ID          string       `json:"id,omitempty"`
	ExternalID  string       `json:"externalId,omitempty"`
	DisplayName string       `json:"displayName"`
	Members     []SCIMMember `json:"members,omitempty"`
	Meta        SCIMMeta     `json:"meta,omitempty"`
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
	Schemas    []string             `json:"schemas"`
	Operations []SCIMPatchOperation `json:"Operations"`
}

// SCIMPatchOperation represents a SCIM PATCH operation
type SCIMPatchOperation struct {
	Op    string      `json:"op"` // add, remove, replace
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
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Trigger     RuleTrigger     `json:"trigger"`
	Conditions  []RuleCondition `json:"conditions"`
	Actions     []RuleAction    `json:"actions"`
	Enabled     bool            `json:"enabled"`
	Priority    int             `json:"priority"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// RuleTrigger defines what triggers a provisioning rule
type RuleTrigger string

const (
	TriggerUserCreated     RuleTrigger = "user_created"
	TriggerUserUpdated     RuleTrigger = "user_updated"
	TriggerUserDeleted     RuleTrigger = "user_deleted"
	TriggerGroupMembership RuleTrigger = "group_membership"
	TriggerAttributeChange RuleTrigger = "attribute_change"
	TriggerScheduled       RuleTrigger = "scheduled"
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

	jwksCacheMu     sync.RWMutex
	jwksCachedKey   *rsa.PublicKey
	jwksCacheExpiry time.Time

	// cipher encrypts/decrypts outbound-SCIM target secrets at rest.
	cipher *secretcrypt.Cipher
}

// NewService creates a new provisioning service
func NewService(db *database.PostgresDB, redis *database.RedisClient, cfg *config.Config, logger *zap.Logger) *Service {
	log := logger.With(zap.String("service", "provisioning"))
	// Build the secret cipher for outbound-SCIM target credentials. Fall back to
	// a no-op cipher (plaintext passthrough) when no key is configured, matching
	// the rest of the tree's rollout behavior.
	cipher, err := secretcrypt.New(cfg.EncryptionKey)
	if err != nil {
		log.Warn("provisioning: encryption key unusable; outbound-SCIM secrets will not be encrypted at rest", zap.Error(err))
		cipher = secretcrypt.NewNoop()
	}
	return &Service{
		db:     db,
		redis:  redis,
		config: cfg,
		logger: log,
		cipher: cipher,
	}
}

// encryptSecret seals a plaintext secret for storage. Empty input returns "".
func (s *Service) encryptSecret(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	if s.cipher == nil {
		return plaintext, nil
	}
	return s.cipher.Encrypt(plaintext)
}

// decryptSecret opens a stored secret. Empty input returns "".
func (s *Service) decryptSecret(stored string) (string, error) {
	if stored == "" {
		return "", nil
	}
	if s.cipher == nil {
		return stored, nil
	}
	return s.cipher.Decrypt(stored)
}

// openIDXAuthMiddleware validates OpenIDX OAuth JWT tokens for provisioning service
func (s *Service) openIDXAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing authorization header",
			})
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid authorization header format",
			})
			return
		}

		tokenString := parts[1]

		// Parse JWT token with signature validation
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validate signing method
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				s.logger.Warn("Unexpected signing method", zap.Any("method", token.Header["alg"]))
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			// Fetch the public key from OAuth service
			key, err := s.getOAuthPublicKey()
			if err != nil {
				s.logger.Error("Failed to get OAuth public key", zap.Error(err))
				return nil, err
			}
			return key, nil
		})

		if err != nil {
			s.logger.Warn("JWT parsing failed", zap.Error(err), zap.String("token_prefix", tokenString[:min(50, len(tokenString))]))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid token",
			})
			return
		}

		// Validate token
		if token == nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid token",
			})
			return
		}

		// Extract claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid token claims",
			})
			return
		}

		// Validate expiration
		if exp, ok := claims["exp"].(float64); ok {
			if time.Now().Unix() > int64(exp) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "token expired",
				})
				return
			}
		}

		// Validate issuer
		if iss, ok := claims["iss"].(string); ok {
			expectedIssuer := s.config.OAuthIssuer
			if expectedIssuer == "" {
				expectedIssuer = "http://localhost:8006"
			}
			if iss != expectedIssuer {
				s.logger.Warn("Invalid token issuer", zap.String("expected", expectedIssuer), zap.String("actual", iss))
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "invalid token issuer",
				})
				return
			}
		}

		// Set user context
		if sub, ok := claims["sub"].(string); ok {
			c.Set("user_id", sub)
		}
		if email, ok := claims["email"].(string); ok {
			c.Set("email", email)
		}
		if name, ok := claims["name"].(string); ok {
			c.Set("name", name)
		}
		// Roles and groups, which this middleware never bound. OPAAuthz is
		// mounted on this service's routes and builds its authorization input
		// from these two keys, so without them every role- and group-based rule
		// in authz.rego was evaluated against an empty list -- and that policy
		// opens with `default allow := false`. See BindSubjectClaims.
		middleware.BindSubjectClaims(c, claims)

		c.Next()
	}
}

// getOAuthPublicKey fetches the OAuth service's public key for token validation
// with caching using a 5-minute TTL to avoid fetching on every request
func (s *Service) getOAuthPublicKey() (*rsa.PublicKey, error) {
	// Check cache with read lock
	s.jwksCacheMu.RLock()
	if s.jwksCachedKey != nil && time.Now().Before(s.jwksCacheExpiry) {
		key := s.jwksCachedKey
		s.jwksCacheMu.RUnlock()
		return key, nil
	}
	s.jwksCacheMu.RUnlock()

	// Cache miss: acquire write lock
	s.jwksCacheMu.Lock()
	defer s.jwksCacheMu.Unlock()

	// Double-check: another goroutine may have populated the cache
	if s.jwksCachedKey != nil && time.Now().Before(s.jwksCacheExpiry) {
		return s.jwksCachedKey, nil
	}

	jwksURL := s.config.OAuthJWKSURL
	if jwksURL == "" {
		jwksURL = "http://oauth-service:8006/.well-known/jwks.json"
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	if len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("no keys found in JWKS")
	}

	// Use the first RSA key
	for _, key := range jwks.Keys {
		if key.Kty == "RSA" && key.Use == "sig" {
			pubKey, err := parseRSAPublicKey(key.N, key.E)
			if err != nil {
				return nil, err
			}
			s.jwksCachedKey = pubKey
			s.jwksCacheExpiry = time.Now().Add(5 * time.Minute)
			return pubKey, nil
		}
	}

	return nil, fmt.Errorf("no valid RSA signing keys found in JWKS")
}

// parseRSAPublicKey parses RSA public key from base64url encoded n and e
func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	// Decode n (modulus)
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode n: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)

	// Decode e (exponent)
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode e: %w", err)
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

// SCIM 2.0 User Operations

// resolveManagerID maps a SCIM enterprise-extension manager reference to a
// local users.id, scoped to the caller's org. Per RFC 7643 §4.3, manager.value
// is the SCIM id of the manager (our users.id). Returns nil when no manager is
// supplied or the reference does not resolve to a user in this org: a dangling
// reference must not fail the whole provisioning call, and the users.manager_id
// self-FK would otherwise reject an unknown id with a 500. The id::text compare
// avoids a uuid-cast error on a malformed value (it yields no rows instead).
func (s *Service) resolveManagerID(ctx context.Context, orgID string, user *SCIMUser) *string {
	if user.Enterprise == nil || user.Enterprise.Manager == nil {
		return nil
	}
	ref := strings.TrimSpace(user.Enterprise.Manager.Value)
	if ref == "" {
		return nil
	}
	var managerID string
	err := s.db.Pool.QueryRow(ctx,
		`SELECT id FROM users WHERE id::text = $1 AND org_id = $2`, ref, orgID).Scan(&managerID)
	if err != nil {
		s.logger.Warn("SCIM manager reference did not resolve to an in-org user; leaving manager unset",
			zap.String("manager_ref", logsafe.Clean(ref)))
		return nil
	}
	return &managerID
}

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
	if user.Enterprise != nil {
		user.Schemas = append(user.Schemas, scimEnterpriseUserSchema)
	}

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	// Extract email
	email := ""
	if len(user.Emails) > 0 {
		email = user.Emails[0].Value
	}

	// Resolve the optional enterprise-extension manager to a local user id
	// (nil -> stored NULL); an unknown reference is dropped, not fatal.
	managerID := s.resolveManagerID(ctx, org.ID, user)

	// Create user in users table
	var userID string
	err = s.db.Pool.QueryRow(ctx, `
		INSERT INTO users (username, email, first_name, last_name, enabled, email_verified, created_at, updated_at, org_id, manager_id, external_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULLIF($11, ''))
		RETURNING id
	`, user.UserName, email, user.Name.GivenName, user.Name.FamilyName, user.Active, false, now, now, org.ID, managerID, user.ExternalID).Scan(&userID)

	if err != nil {
		s.logger.Error("Failed to create user in users table", zap.Error(err))
		return nil, err
	}

	user.ID = userID

	// Store SCIM representation
	data, _ := json.Marshal(user)
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO scim_users (id, external_id, username, data, created_at, updated_at, org_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (id) DO UPDATE SET data = $4, updated_at = $6
	`, userID, user.ExternalID, user.UserName, data, now, now, org.ID)

	if err != nil {
		s.logger.Error("Failed to store SCIM user data", zap.Error(err))
		// Don't return error, user is already created
	}

	// Audit log: SCIM user created
	actorID := actorIDFromContext(ctx)
	s.logAuditEvent(ctx, "provisioning", "scim", "scim.user_created", "success",
		actorID, userID, "user", map[string]interface{}{
			"username": user.UserName,
		})

	// Apply the org's enabled user_created provisioning rules (best-effort:
	// rule evaluation never fails the SCIM create).
	s.applyProvisioningRules(ctx, TriggerUserCreated, user)

	// Fan out to downstream SCIM targets: an upstream create provisions the
	// user into every enabled SaaS target.
	s.fanOutUserChange(ctx, org.ID, userID, OpCreate, user)

	return user, nil
}

// GetSCIMUser retrieves a user via SCIM
func (s *Service) GetSCIMUser(ctx context.Context, userID string) (*SCIMUser, error) {
	var username, email, firstName, lastName, externalID string
	var enabled bool
	var createdAt, updatedAt time.Time

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	// COALESCE because the name and email columns are nullable and the scan
	// targets are not: a user created without a name used to answer 404.
	err = s.db.Pool.QueryRow(ctx, `
		SELECT username, COALESCE(email, ''), COALESCE(first_name, ''), COALESCE(last_name, ''),
		       COALESCE(enabled, false), COALESCE(external_id, ''), created_at, updated_at
		FROM users WHERE id::text = $1 AND org_id = $2
	`, userID, org.ID).Scan(&username, &email, &firstName, &lastName, &enabled, &externalID, &createdAt, &updatedAt)

	if err != nil {
		return nil, err
	}

	user := scimUserFromRow(userID, username, email, firstName, lastName, externalID, enabled, createdAt, updatedAt)
	return &user, nil
}

// scimUserFromRow is the one mapping from a users row to a SCIM User, shared
// by the resource and the list endpoints so the two cannot disagree.
func scimUserFromRow(id, username, email, firstName, lastName, externalID string, enabled bool, createdAt, updatedAt time.Time) SCIMUser {
	user := SCIMUser{
		Schemas:    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		ID:         id,
		ExternalID: externalID,
		UserName:   username,
		Name: SCIMName{
			GivenName:  firstName,
			FamilyName: lastName,
		},
		DisplayName: strings.TrimSpace(firstName + " " + lastName),
		Active:      enabled,
		Meta: SCIMMeta{
			ResourceType: "User",
			Created:      createdAt,
			LastModified: updatedAt,
		},
	}
	if email != "" {
		user.Emails = []SCIMEmail{{Value: email, Type: "work", Primary: true}}
	}
	return user
}

// UpdateSCIMUser updates a user via SCIM
func (s *Service) UpdateSCIMUser(ctx context.Context, userID string, user *SCIMUser) (*SCIMUser, error) {
	s.logger.Info("Updating SCIM user", zap.String("user_id", userID))

	now := time.Now()
	user.ID = userID
	user.Meta.LastModified = now

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	// Extract email
	email := ""
	if len(user.Emails) > 0 {
		email = user.Emails[0].Value
	}

	// Resolve the optional enterprise-extension manager. COALESCE preserves the
	// existing manager when this update carries no (or an unresolvable) manager
	// reference — so a plain PUT or an `active:false` deprovision PATCH routed
	// through here can't silently wipe an already-set manager.
	managerID := s.resolveManagerID(ctx, org.ID, user)

	// The users row and its SCIM representation move together.
	//
	// They used not to: the users UPDATE was checked and the scim_users one
	// discarded its error. scim_users is what a GET on this resource answers
	// with, so a failure there left the IdP reading back the values it had just
	// replaced -- and an IdP that reconciles against what it reads either sends
	// the change again for ever or concludes it never applied. One transaction
	// makes the two agree or leaves both alone.
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err = tx.Exec(ctx, `
		UPDATE users
		SET username = $2, email = $3, first_name = $4, last_name = $5, enabled = $6, updated_at = $7,
		    manager_id = COALESCE($9::uuid, manager_id), external_id = NULLIF($10, '')
		WHERE id = $1 AND org_id = $8
	`, userID, user.UserName, email, user.Name.GivenName, user.Name.FamilyName, user.Active, now, org.ID, managerID, user.ExternalID); err != nil {
		return nil, err
	}

	data, _ := json.Marshal(user)
	if _, err = tx.Exec(ctx, `
		UPDATE scim_users SET data = $2, updated_at = $3 WHERE id = $1 AND org_id = $4
	`, userID, data, now, org.ID); err != nil {
		return nil, fmt.Errorf("update the SCIM representation the provider reads back: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	// SCIM `active:false` is the standard IdP deprovisioning signal. Flipping the
	// flag alone left live sessions and tokens valid; revoke them so an upstream
	// IdP deprovision actually cuts off access. UpdateSCIMUser is the single
	// choke point for both PUT and PATCH(active), so this covers both.
	if !user.Active {
		s.deprovisionUser(ctx, userID, org.ID, false)
	}

	// Apply the org's enabled user_updated provisioning rules (best-effort;
	// supported actions are additive and idempotent).
	s.applyProvisioningRules(ctx, TriggerUserUpdated, user)

	// Fan out to downstream SCIM targets. An `active:false` update is the
	// standard IdP deprovision signal, so route it as a deactivate op (the
	// worker PATCHes active=false or DELETEs per the target's policy); anything
	// else is a normal update.
	op := OpUpdate
	if !user.Active {
		op = OpDeactivate
	}
	s.fanOutUserChange(ctx, org.ID, userID, op, user)

	return user, nil
}

// revokedSessionTTL matches the identity service's marker lifetime — it must
// outlast the longest refresh-token lifetime so a deprovisioned user's in-flight
// refresh tokens keep failing the oauth-service's revoked-session check.
const revokedSessionTTL = 30 * 24 * time.Hour

// deprovisionUser revokes a user's live sessions (marking them revoked and
// publishing the `revoked_session:<id>` markers the oauth-service honors) and
// active API keys. hardDelete removes the child rows outright. Best-effort and
// idempotent; OAuth tokens are additionally neutralized by the oauth-service's
// user-active check on the refresh grant. Mirrors identity.Service.deprovisionUser
// so a SCIM-driven deprovision has the same effect as an admin-console one.
func (s *Service) deprovisionUser(ctx context.Context, userID, orgID string, hardDelete bool) {
	// One scoped logger with the (scrubbed) user id, so the per-step warnings
	// below never re-embed caller-supplied input directly.
	log := s.logger.With(zap.String("user_id", logsafe.Clean(userID)))

	rows, err := s.db.Pool.Query(ctx,
		`SELECT id FROM sessions WHERE user_id = $1 AND org_id = $2`, userID, orgID)
	if err != nil {
		log.Warn("deprovision: list sessions failed", zap.Error(err))
	} else {
		var sessionIDs []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err == nil {
				sessionIDs = append(sessionIDs, id)
			}
		}
		rows.Close()
		if s.redis != nil {
			for _, id := range sessionIDs {
				if err := s.redis.RevocationDB().Set(ctx, "revoked_session:"+id, "1", revokedSessionTTL).Err(); err != nil {
					log.Warn("deprovision: publish revoked-session marker failed", zap.Error(err))
				}
			}
		}
	}

	// The session markers above are honoured by the REFRESH grant. They are not
	// read by /oauth/userinfo or /oauth/introspect, which consult the per-user
	// cutoff and the per-token blacklist and nothing else -- so without this
	// line the access token already in a leaver's browser keeps answering for
	// the rest of its hour after the account is disabled.
	if s.redis != nil {
		if err := revocation.RevokeUserTokens(ctx, s.redis.RevocationDB(), userID); err != nil {
			log.Warn("deprovision: revoke outstanding access tokens failed", zap.Error(err))
		}
	}

	// Whichever branch below ends the sessions, the relying parties they
	// reached are told through backchannel_logout_pending
	// (internal/common/sessionend); the capture reads the rows, so it comes
	// first.
	if err := sessionend.ForUser(ctx, s.db.Pool, orgID, userID); err != nil {
		log.Warn("deprovision: the sessions' relying parties will not be told", zap.Error(err))
	}
	if hardDelete {
		if _, err := s.db.Pool.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1 AND org_id = $2`, userID, orgID); err != nil {
			log.Warn("deprovision: delete sessions failed", zap.Error(err))
		}
		//orgscope:ignore user_sessions is keyed by globally-unique user_id (no org_id column)
		if _, err := s.db.Pool.Exec(ctx, `DELETE FROM user_sessions WHERE user_id = $1`, userID); err != nil {
			log.Warn("deprovision: delete user_sessions failed", zap.Error(err))
		}
		if _, err := s.db.Pool.Exec(ctx, `DELETE FROM api_keys WHERE user_id = $1 AND org_id = $2`, userID, orgID); err != nil {
			log.Warn("deprovision: delete api_keys failed", zap.Error(err))
		}
		return
	}

	if _, err := s.db.Pool.Exec(ctx,
		`UPDATE sessions SET revoked = true, revoked_at = NOW()
		 WHERE user_id = $1 AND org_id = $2 AND (revoked IS NULL OR revoked = false)`,
		userID, orgID); err != nil {
		log.Warn("deprovision: revoke sessions failed", zap.Error(err))
	}
	if _, err := s.db.Pool.Exec(ctx,
		`UPDATE api_keys SET status = 'revoked' WHERE user_id = $1 AND org_id = $2 AND status = 'active'`,
		userID, orgID); err != nil {
		log.Warn("deprovision: revoke api_keys failed", zap.Error(err))
	}
}

// scrubLogValue strips CR/LF from a value before it goes into a log field, so a
// caller-supplied identifier can't forge extra log lines (clears CodeQL's
// log-injection sink; defense in depth on top of the JSON encoder).

// DeleteSCIMUser deletes a user via SCIM
func (s *Service) DeleteSCIMUser(ctx context.Context, userID string) error {
	s.logger.Info("Deleting SCIM user", zap.String("user_id", userID))

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	// Audit log before deletion so the record exists even if delete succeeds
	actorID := actorIDFromContext(ctx)
	s.logAuditEvent(ctx, "provisioning", "scim", "scim.user_deleted", "success",
		actorID, userID, "user", nil)

	// Revoke sessions + API keys before removing the user row.
	s.deprovisionUser(ctx, userID, org.ID, true)

	// Fan out a delete to downstream SCIM targets BEFORE removing the local row,
	// so the outbox snapshot still identifies the user. The worker deactivates
	// or deletes the remote resource per each target's policy. Enqueued with a
	// minimal snapshot (identity is all the worker needs to find the mapping).
	s.fanOutUserChange(ctx, org.ID, userID, OpDelete, &SCIMUser{ID: userID})

	// Delete from users table (CASCADE will delete from scim_users)
	_, err = s.db.Pool.Exec(ctx, "DELETE FROM users WHERE id = $1 AND org_id = $2", userID, org.ID)
	if err != nil {
		return err
	}
	// An inbound SCIM delete is an upstream IdP saying "this person is gone";
	// the SSF receivers downstream of this product have to hear it too.
	if serr := ssfsignal.Enqueue(ctx, s.db.Pool, ssfsignal.Signal{
		OrgID: org.ID, SubjectID: userID, Claims: map[string]any{"reason": "scim_deleted"},
	}); serr != nil {
		s.logger.Error("SCIM deleted the user, but the account-disabled signal was not enqueued",
			logsafe.String("user_id", userID), zap.Error(serr))
	}
	return nil
}

// ListSCIMUsers lists users via SCIM
func (s *Service) ListSCIMUsers(ctx context.Context, startIndex, count int, filter string) (*SCIMListResponse, error) {
	// Translate the SCIM filter (e.g. userName eq "x") into a parameterized
	// predicate. A nil predicate means no filter; errUnsupportedFilter is
	// surfaced to the handler as 400 invalidFilter rather than silently
	// returning an unfiltered page (which would break IdP dedup/existence).
	pred, err := parseSCIMFilter(filter, scimUserFilterAttrs)
	if err != nil {
		return nil, err
	}
	return s.listSCIMUsers(ctx, startIndex, count, pred)
}

// listSCIMUsers is ListSCIMUsers with the filter already parsed. The handler
// parses it itself and answers a bad one with 400, so the errors this returns
// -- the ones that reach the log -- never carry the caller's filter text.
func (s *Service) listSCIMUsers(ctx context.Context, startIndex, count int, pred *scimFilterPredicate) (*SCIMListResponse, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	// COUNT: $1 = org.ID, the filter value (if any) binds at $2. The predicate
	// must be applied here too so totalResults reflects the filter.
	countSQL := "SELECT COUNT(*) FROM users WHERE org_id = $1"
	countArgs := []interface{}{org.ID}
	if pred != nil {
		countSQL += pred.clause(2)
		countArgs = append(countArgs, pred.value)
	}
	var total int
	if err = s.db.Pool.QueryRow(ctx, countSQL, countArgs...).Scan(&total); err != nil {
		return nil, err
	}

	// Build query with optional filter. NOTE: this SELECT is assigned to
	// a variable before being passed to Query, so orgscope does not flag
	// it — the org_id filter here is still required for correctness.
	// $1 = offset, $2 = limit, $3 = org.ID, the filter value (if any) = $4.
	// COALESCE because these columns are nullable and the scan targets are not.
	// Without it rows.Scan fails on every user who has no name or no address,
	// and the loop below used to answer that by skipping the row -- so the
	// response carried totalResults = N and none of the N users, with nothing
	// logged. A SCIM client reads that as "these accounts do not exist".
	query := `
		SELECT id, username, COALESCE(email, ''), COALESCE(first_name, ''),
		       COALESCE(last_name, ''), COALESCE(enabled, false), COALESCE(external_id, ''), created_at, updated_at
		FROM users
		WHERE org_id = $3`
	listArgs := []interface{}{startIndex - 1, count, org.ID}
	if pred != nil {
		query += pred.clause(4)
		listArgs = append(listArgs, pred.value)
	}
	// One place for the ordering, and it carries id: created_at alone is not a
	// total order and the ties are guaranteed, not rare. See scim_ordering.go.
	query += "\n\t\t" + scimUserOrdering + "\n\t\tOFFSET $1 LIMIT $2"

	rows, err := s.db.Pool.Query(ctx, query, listArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Never nil: an empty page is "Resources": [], not null.
	users := []SCIMUser{}
	for rows.Next() {
		var id, username, email, firstName, lastName, externalID string
		var enabled bool
		var createdAt, updatedAt time.Time

		// Not `continue`: a row this endpoint cannot read is not a row that
		// does not exist. Skipping it hands the caller a short page and calls
		// it complete, which on a provisioning API is an account that never
		// reaches a downstream application.
		if err := rows.Scan(&id, &username, &email, &firstName, &lastName, &enabled, &externalID, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("scan SCIM user: %w", err)
		}
		users = append(users, scimUserFromRow(id, username, email, firstName, lastName, externalID, enabled, createdAt, updatedAt))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list SCIM users: %w", err)
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
func RegisterRoutes(router *gin.Engine, svc *Service, extraMiddleware ...gin.HandlerFunc) {
	// SCIM 2.0 endpoints
	scim := router.Group("/scim/v2")
	scim.Use(scimContentType())
	scim.Use(svc.openIDXAuthMiddleware())
	for _, mw := range extraMiddleware {
		scim.Use(mw)
	}
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
		scim.GET("/ResourceTypes/:id", svc.handleGetResourceType)
		scim.GET("/ServiceProviderConfig", svc.handleGetServiceProviderConfig)
	}

	// Internal provisioning API
	prov := router.Group("/api/v1/provisioning")
	prov.Use(svc.openIDXAuthMiddleware())
	for _, mw := range extraMiddleware {
		prov.Use(mw)
	}
	{
		prov.GET("/rules", svc.handleListRules)
		prov.POST("/rules", svc.handleCreateRule)
		prov.GET("/rules/:id", svc.handleGetRule)
		prov.PUT("/rules/:id", svc.handleUpdateRule)
		prov.DELETE("/rules/:id", svc.handleDeleteRule)

		// Outbound SCIM: downstream target apps (provision OUT to SaaS).
		svc.registerOutboundRoutes(prov)
	}
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

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	// Create group in groups table
	var groupID string
	err = s.db.Pool.QueryRow(ctx, `
		INSERT INTO groups (name, description, created_at, updated_at, org_id, external_id)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''))
		RETURNING id
	`, group.DisplayName, "", now, now, org.ID, group.ExternalID).Scan(&groupID)

	if err != nil {
		s.logger.Error("Failed to create group", zap.Error(err))
		return nil, err
	}

	group.ID = groupID

	// Add members if provided
	if len(group.Members) > 0 {
		for _, member := range group.Members {
			_, err := s.db.Pool.Exec(ctx, `
				INSERT INTO group_memberships (user_id, group_id, joined_at, org_id)
				VALUES ($1, $2, $3, $4)
				ON CONFLICT DO NOTHING
			`, member.Value, groupID, now, org.ID)
			if err != nil {
				s.logger.Warn("Failed to add group member", zap.Error(err))
			}
		}
	}

	// Fan out what was stored, not what was asked for: a member that could
	// not be added is not a member downstream either.
	if members, err := s.groupMembers(ctx, groupID, org.ID); err != nil {
		s.logger.Warn("could not read the members of a new SCIM group; its outbound fan-out is skipped",
			zap.Error(err))
	} else {
		s.fanOutGroupChange(ctx, org.ID, groupID, OpCreate, group.DisplayName, members)
	}

	return group, nil
}

// GetSCIMGroup retrieves a group via SCIM
func (s *Service) GetSCIMGroup(ctx context.Context, groupID string) (*SCIMGroup, error) {
	var name, externalID string
	var createdAt, updatedAt time.Time

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	err = s.db.Pool.QueryRow(ctx, `
		SELECT name, COALESCE(external_id, ''), created_at, updated_at
		FROM groups WHERE id::text = $1 AND org_id = $2
	`, groupID, org.ID).Scan(&name, &externalID, &createdAt, &updatedAt)

	if err != nil {
		return nil, err
	}

	// A member list that could not be read is an error, not an empty group:
	// a SCIM client that reads "no members" removes them downstream.
	members, err := s.scimGroupMembers(ctx, groupID, org.ID)
	if err != nil {
		return nil, err
	}

	return &SCIMGroup{
		Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		ID:          groupID,
		ExternalID:  externalID,
		DisplayName: name,
		Members:     members,
		Meta: SCIMMeta{
			ResourceType: "Group",
			Created:      createdAt,
			LastModified: updatedAt,
		},
	}, nil
}

// scimGroupMembers lists a group's members as SCIM member references.
func (s *Service) scimGroupMembers(ctx context.Context, groupID, orgID string) ([]SCIMMember, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT gm.user_id::text, u.username
		FROM group_memberships gm
		JOIN users u ON gm.user_id = u.id
		WHERE gm.group_id::text = $1 AND gm.org_id = $2
		ORDER BY u.username, gm.user_id
	`, groupID, orgID)
	if err != nil {
		return nil, fmt.Errorf("list group members: %w", err)
	}
	defer rows.Close()
	var members []SCIMMember
	for rows.Next() {
		var userID, username string
		if err := rows.Scan(&userID, &username); err != nil {
			return nil, fmt.Errorf("scan group member: %w", err)
		}
		members = append(members, SCIMMember{Value: userID, Display: username, Type: "User"})
	}
	return members, rows.Err()
}

// UpdateSCIMGroup updates a group via SCIM
func (s *Service) UpdateSCIMGroup(ctx context.Context, groupID string, group *SCIMGroup) (*SCIMGroup, error) {
	s.logger.Info("Updating SCIM group", zap.String("group_id", groupID))

	now := time.Now()
	group.ID = groupID
	group.Meta.LastModified = now

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	_, err = s.db.Pool.Exec(ctx, `
		UPDATE groups SET name = $2, updated_at = $3, external_id = NULLIF($5, '') WHERE id = $1 AND org_id = $4
	`, groupID, group.DisplayName, now, org.ID, group.ExternalID)

	if err != nil {
		return nil, err
	}

	// Update members if provided — use a transaction to ensure atomicity
	if group.Members != nil {
		tx, err := s.db.Pool.Begin(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer tx.Rollback(ctx)

		// Clear existing members. RETURNING, because the users this drops for
		// good have to have their tokens cut and a row count cannot be revoked.
		rows, err := tx.Query(ctx,
			"DELETE FROM group_memberships WHERE group_id = $1 AND org_id = $2 RETURNING user_id::text", groupID, org.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to clear group members: %w", err)
		}
		var removed []string
		for rows.Next() {
			var uid string
			if serr := rows.Scan(&uid); serr != nil {
				rows.Close()
				return nil, fmt.Errorf("failed to read the members being replaced: %w", serr)
			}
			removed = append(removed, uid)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("failed to clear group members: %w", err)
		}

		// Add new members
		kept := make([]string, 0, len(group.Members))
		for _, member := range group.Members {
			if _, err := tx.Exec(ctx, `
				INSERT INTO group_memberships (user_id, group_id, joined_at, org_id)
				VALUES ($1, $2, $3, $4)
				ON CONFLICT DO NOTHING
			`, member.Value, groupID, now, org.ID); err != nil {
				return nil, fmt.Errorf("failed to add group member: %w", err)
			}
			kept = append(kept, member.Value)
		}

		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("failed to commit transaction: %w", err)
		}

		// A REPLACEMENT IS BOTH A GRANT AND A REVOCATION. This clears every
		// membership and re-inserts the ones the IdP still sends, so most of
		// the rows it removed it also put back; cutting on the delete would log
		// out every member of every SCIM-managed group on every push, for
		// nothing -- a grant that has not reached the token permits nothing it
		// should not. Only the DIFFERENCE is a revocation.
		//
		// After the commit, because Redis cannot join a Postgres transaction
		// and a marker written inside one that rolls back logs somebody out of
		// a membership they still have. An IdP pushing a group update is the
		// commonest way a membership is taken away in this product, and
		// "groups" is a claim on the access token.
		s.revokeAfterMembershipLoss(ctx, "scim.UpdateSCIMGroup", membershipsLost(removed, kept)...)
	}

	if members, err := s.groupMembers(ctx, groupID, org.ID); err != nil {
		s.logger.Warn("could not read the members of an updated SCIM group; its outbound fan-out is skipped",
			zap.Error(err))
	} else {
		s.fanOutGroupChange(ctx, org.ID, groupID, OpUpdate, group.DisplayName, members)
	}

	return group, nil
}

// membershipsLost returns the ids in removed that are not in kept, each once.
// It is the group counterpart of identity's lostRoles and directory's function
// of the same name: a wholesale replacement is a grant and a revocation at
// once, and treating the two alike would end live sessions on every sync.
func membershipsLost(removed, kept []string) []string {
	still := make(map[string]struct{}, len(kept))
	for _, id := range kept {
		still[id] = struct{}{}
	}
	var lost []string
	seen := make(map[string]struct{}, len(removed))
	for _, id := range removed {
		if id == "" {
			continue
		}
		if _, back := still[id]; back {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		lost = append(lost, id)
	}
	return lost
}

// revokeAfterMembershipLoss cuts the outstanding access tokens of users who
// have just lost a group. Best-effort and loud, the contract every sever path
// in this product shares: the membership is already gone when this runs, so a
// Redis hiccup must not fail the SCIM request -- but "the membership was
// removed and the token carrying it was not cut" is what an operator needs in
// the record.
func (s *Service) revokeAfterMembershipLoss(ctx context.Context, why string, userIDs ...string) {
	if s.redis == nil {
		return
	}
	for _, userID := range userIDs {
		if userID == "" {
			continue
		}
		if err := revocation.RevokeUserTokens(ctx, s.redis.RevocationDB(), userID); err != nil {
			s.logger.Error("a group membership was removed, but the tokens still asserting it were not revoked",
				zap.String("path", why), zap.String("user_id", logsafe.Clean(userID)), zap.Error(err))
		}
	}
}

// DeleteSCIMGroup deletes a group via SCIM
func (s *Service) DeleteSCIMGroup(ctx context.Context, groupID string) error {
	s.logger.Info("Deleting SCIM group", zap.String("group_id", groupID))

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	// Audit log before deletion so the record exists even if delete succeeds
	actorID := actorIDFromContext(ctx)
	s.logAuditEvent(ctx, "provisioning", "scim", "scim.group_deleted", "success",
		actorID, groupID, "group", nil)

	// THE CASCADE IS THE PART THAT HIDES. group_memberships.group_id carries
	// ON DELETE CASCADE, so this statement takes every membership with it
	// without ever naming group_memberships -- which is why the sever census
	// could not see this path. The members are read BEFORE the delete because a
	// cascade returns nothing, and cut after it, because "groups" is a claim
	// and a member of a group that has stopped existing keeps asserting it.
	members, mErr := s.groupMembers(ctx, groupID, org.ID)
	if mErr != nil {
		// The group goes either way: leaving it in place is worse than removing
		// it without cutting. Loud, because this is the case where a live token
		// keeps a membership the IdP has dropped.
		s.logger.Warn("could not read the members of a SCIM group being deleted; their tokens will not be cut",
			logsafe.String("group_id", groupID), zap.Error(mErr))
		members = nil
	}
	if _, err = s.db.Pool.Exec(ctx, "DELETE FROM groups WHERE id = $1 AND org_id = $2", groupID, org.ID); err != nil {
		return err
	}
	s.revokeAfterMembershipLoss(ctx, "scim.DeleteSCIMGroup", members...)
	s.fanOutGroupChange(ctx, org.ID, groupID, OpDelete, "", nil)
	return nil
}

// groupMembers lists the users in a group, for the paths that must cut tokens
// after a delete the database performs by cascade.
func (s *Service) groupMembers(ctx context.Context, groupID, orgID string) ([]string, error) {
	rows, err := s.db.Pool.Query(ctx,
		`SELECT user_id::text FROM group_memberships WHERE group_id = $1 AND org_id = $2`, groupID, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var uid string
		if err := rows.Scan(&uid); err != nil {
			return nil, err
		}
		out = append(out, uid)
	}
	return out, rows.Err()
}

// ListSCIMGroups lists groups via SCIM, with their members.
func (s *Service) ListSCIMGroups(ctx context.Context, startIndex, count int, filter string) (*SCIMListResponse, error) {
	pred, err := parseSCIMFilter(filter, scimGroupFilterAttrs)
	if err != nil {
		return nil, err
	}
	return s.listSCIMGroups(ctx, startIndex, count, pred, true)
}

// listSCIMGroups lists groups; withMembers false is excludedAttributes=members,
// which Microsoft Entra sends so a large group's membership is not paged
// through the list endpoint. The filter arrives parsed, for the reason
// listSCIMUsers gives.
func (s *Service) listSCIMGroups(ctx context.Context, startIndex, count int, pred *scimFilterPredicate, withMembers bool) (*SCIMListResponse, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	// COUNT: $1 = org.ID, the filter value (if any) binds at $2.
	countSQL := "SELECT COUNT(*) FROM groups WHERE org_id = $1"
	countArgs := []interface{}{org.ID}
	if pred != nil {
		countSQL += pred.clause(2)
		countArgs = append(countArgs, pred.value)
	}
	var total int
	if err = s.db.Pool.QueryRow(ctx, countSQL, countArgs...).Scan(&total); err != nil {
		return nil, err
	}

	// $1 = offset, $2 = limit, $3 = org.ID, the filter value (if any) = $4.
	// COALESCE for the same reason as the user list: description is nullable.
	query := `
		SELECT id, name, COALESCE(external_id, ''), created_at, updated_at
		FROM groups WHERE org_id = $3`
	listArgs := []interface{}{startIndex - 1, count, org.ID}
	if pred != nil {
		query += pred.clause(4)
		listArgs = append(listArgs, pred.value)
	}
	query += " " + scimGroupOrdering + " OFFSET $1 LIMIT $2"

	rows, err := s.db.Pool.Query(ctx, query, listArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Never nil: an empty page is "Resources": [], not null.
	groups := []SCIMGroup{}
	for rows.Next() {
		var id, name, externalID string
		var createdAt, updatedAt time.Time
		if err := rows.Scan(&id, &name, &externalID, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("scan SCIM group: %w", err)
		}
		groups = append(groups, SCIMGroup{
			Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
			ID:          id,
			ExternalID:  externalID,
			DisplayName: name,
			Meta: SCIMMeta{
				ResourceType: "Group",
				Created:      createdAt,
				LastModified: updatedAt,
			},
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list SCIM groups: %w", err)
	}
	rows.Close()
	if withMembers {
		for i := range groups {
			members, err := s.scimGroupMembers(ctx, groups[i].ID, org.ID)
			if err != nil {
				return nil, err
			}
			groups[i].Members = members
		}
	}

	return &SCIMListResponse{
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: len(groups),
		Resources:    groups,
	}, nil
}

// Provisioning Rules CRUD

// CreateRule creates a new provisioning rule
func (s *Service) CreateRule(ctx context.Context, rule *ProvisioningRule) (*ProvisioningRule, error) {
	s.logger.Info("Creating provisioning rule", zap.String("name", rule.Name))

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	conditionsJSON, err := json.Marshal(rule.Conditions)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal conditions: %w", err)
	}
	actionsJSON, err := json.Marshal(rule.Actions)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal actions: %w", err)
	}

	var id string
	err = s.db.Pool.QueryRow(ctx, `
		INSERT INTO provisioning_rules (name, description, trigger, conditions, actions, enabled, priority, created_at, updated_at, org_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id
	`, rule.Name, rule.Description, string(rule.Trigger), conditionsJSON, actionsJSON, rule.Enabled, rule.Priority, now, now, org.ID).Scan(&id)
	if err != nil {
		return nil, fmt.Errorf("failed to create rule: %w", err)
	}

	rule.ID = id
	rule.CreatedAt = now
	rule.UpdatedAt = now
	return rule, nil
}

// GetRule retrieves a provisioning rule by ID
func (s *Service) GetRule(ctx context.Context, id string) (*ProvisioningRule, error) {
	var rule ProvisioningRule
	var conditionsJSON, actionsJSON []byte
	var trigger string

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	err = s.db.Pool.QueryRow(ctx, `
		SELECT id, name, description, trigger, conditions, actions, enabled, priority, created_at, updated_at
		FROM provisioning_rules WHERE id = $1 AND org_id = $2
	`, id, org.ID).Scan(&rule.ID, &rule.Name, &rule.Description, &trigger, &conditionsJSON, &actionsJSON, &rule.Enabled, &rule.Priority, &rule.CreatedAt, &rule.UpdatedAt)
	if err != nil {
		return nil, err
	}

	rule.Trigger = RuleTrigger(trigger)
	json.Unmarshal(conditionsJSON, &rule.Conditions)
	json.Unmarshal(actionsJSON, &rule.Actions)
	return &rule, nil
}

// ListRules lists provisioning rules with pagination support
func (s *Service) ListRules(ctx context.Context, offset, limit int) ([]ProvisioningRule, int, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, 0, err
	}

	var total int
	err = s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM provisioning_rules WHERE org_id = $1", org.ID).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, description, trigger, conditions, actions, enabled, priority, created_at, updated_at
		FROM provisioning_rules WHERE org_id = $3 ORDER BY priority ASC, created_at DESC
		OFFSET $1 LIMIT $2
	`, offset, limit, org.ID)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var rules []ProvisioningRule
	for rows.Next() {
		var rule ProvisioningRule
		var conditionsJSON, actionsJSON []byte
		var trigger string

		if err := rows.Scan(&rule.ID, &rule.Name, &rule.Description, &trigger, &conditionsJSON, &actionsJSON, &rule.Enabled, &rule.Priority, &rule.CreatedAt, &rule.UpdatedAt); err != nil {
			continue
		}
		rule.Trigger = RuleTrigger(trigger)
		json.Unmarshal(conditionsJSON, &rule.Conditions)
		json.Unmarshal(actionsJSON, &rule.Actions)
		rules = append(rules, rule)
	}

	if rules == nil {
		rules = []ProvisioningRule{}
	}
	return rules, total, nil
}

// UpdateRule updates an existing provisioning rule
func (s *Service) UpdateRule(ctx context.Context, id string, rule *ProvisioningRule) (*ProvisioningRule, error) {
	s.logger.Info("Updating provisioning rule", zap.String("id", id))

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	conditionsJSON, err := json.Marshal(rule.Conditions)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal conditions: %w", err)
	}
	actionsJSON, err := json.Marshal(rule.Actions)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal actions: %w", err)
	}

	result, err := s.db.Pool.Exec(ctx, `
		UPDATE provisioning_rules
		SET name = $2, description = $3, trigger = $4, conditions = $5, actions = $6, enabled = $7, priority = $8, updated_at = $9
		WHERE id = $1 AND org_id = $10
	`, id, rule.Name, rule.Description, string(rule.Trigger), conditionsJSON, actionsJSON, rule.Enabled, rule.Priority, now, org.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to update rule: %w", err)
	}
	if result.RowsAffected() == 0 {
		return nil, fmt.Errorf("rule not found")
	}

	rule.ID = id
	rule.UpdatedAt = now
	return rule, nil
}

// DeleteRule deletes a provisioning rule
func (s *Service) DeleteRule(ctx context.Context, id string) error {
	s.logger.Info("Deleting provisioning rule", zap.String("id", id))

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	result, err := s.db.Pool.Exec(ctx, "DELETE FROM provisioning_rules WHERE id = $1 AND org_id = $2", id, org.ID)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("rule not found")
	}
	return nil
}

// Provisioning rules handlers

func (s *Service) handleListRules(c *gin.Context) {
	offset := 0
	if v := c.Query("offset"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
			offset = parsed
		}
	}
	limit := 20
	if v := c.Query("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	rules, total, err := s.ListRules(c.Request.Context(), offset, limit)
	if err != nil {
		s.logger.Error("failed to list provisioning rules", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.Header("X-Total-Count", strconv.Itoa(total))
	c.JSON(200, rules)
}

func (s *Service) handleCreateRule(c *gin.Context) {
	var rule ProvisioningRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if rule.Name == "" {
		c.JSON(400, gin.H{"error": "name is required"})
		return
	}
	if rule.Trigger == "" {
		c.JSON(400, gin.H{"error": "trigger is required"})
		return
	}

	created, err := s.CreateRule(c.Request.Context(), &rule)
	if err != nil {
		s.logger.Error("failed to create provisioning rule", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(201, created)
}

func (s *Service) handleGetRule(c *gin.Context) {
	rule, err := s.GetRule(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(404, gin.H{"error": "rule not found"})
		return
	}
	c.JSON(200, rule)
}

func (s *Service) handleUpdateRule(c *gin.Context) {
	var rule ProvisioningRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	updated, err := s.UpdateRule(c.Request.Context(), c.Param("id"), &rule)
	if err != nil {
		if err.Error() == "rule not found" {
			c.JSON(404, gin.H{"error": "rule not found"})
			return
		}
		s.logger.Error("failed to update provisioning rule", zap.String("id", c.Param("id")), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, updated)
}

func (s *Service) handleDeleteRule(c *gin.Context) {
	err := s.DeleteRule(c.Request.Context(), c.Param("id"))
	if err != nil {
		if err.Error() == "rule not found" {
			c.JSON(404, gin.H{"error": "rule not found"})
			return
		}
		s.logger.Error("failed to delete provisioning rule", zap.String("id", c.Param("id")), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(204, nil)
}

// logAuditEvent writes an audit event to the audit_events table (best-effort, non-blocking).
// It mirrors the pattern used in the OAuth service.
func (s *Service) logAuditEvent(ctx context.Context, eventType, category, action, outcome, actorID, targetID, targetType string, details map[string]interface{}) {
	// Capture org synchronously before the detached goroutine (the write
	// runs on context.Background()). Falls back to the default org UUID
	// when unresolved, matching the milestone's DefaultOrgFallback.
	orgID := "00000000-0000-0000-0000-000000000010"
	if org, err := orgctx.From(ctx); err == nil && org.ID != "" {
		orgID = org.ID
	}
	go func() {
		// The org has to travel on the CONTEXT, not just in the row.
		// audit_events is behind the FORCE-RLS belt, and the pool sets
		// app.org_id at checkout from orgctx -- so on a bare
		// context.Background the setting is empty, the policy's WITH CHECK
		// evaluates to NULL, and Postgres refuses the insert. Every one of
		// these writes was being rejected and the only trace was a WARN.
		detailsJSON, _ := json.Marshal(details)
		_, err := s.db.Pool.Exec(orgctx.With(context.Background(), orgctx.Org{ID: orgID}), `
			INSERT INTO audit_events (id, timestamp, event_type, category, action, outcome,
			                          actor_id, actor_type, actor_ip, target_id, target_type,
			                          resource_id, details, org_id)
			VALUES (gen_random_uuid(), NOW(), $1, $2, $3, $4, $5, 'service', '', $6, $7, $6, $8, $9)
		`, eventType, category, action, outcome, actorID, targetID, targetType, detailsJSON, orgID)
		if err != nil {
			s.logger.Warn("failed to record audit event",
				zap.String("event_type", eventType),
				zap.String("action", action),
				zap.Error(err))
		}
	}()
}
