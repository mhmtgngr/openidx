// Package identity - Biometric Authentication (Face ID / Touch ID via WebAuthn)
package identity

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// BiometricPreferences represents user's biometric authentication preferences
type BiometricPreferences struct {
	ID                           string    `json:"id"`
	UserID                       string    `json:"user_id"`
	PlatformAuthenticatorPreferred bool    `json:"platform_authenticator_preferred"`
	AllowCrossPlatform           bool      `json:"allow_cross_platform"`
	RequireUserVerification      bool      `json:"require_user_verification"`
	BiometricOnlyEnabled         bool      `json:"biometric_only_enabled"`
	ResidentKeyRequired          bool      `json:"resident_key_required"`
	CreatedAt                    time.Time `json:"created_at"`
	UpdatedAt                    time.Time `json:"updated_at"`
}

// BiometricPolicy defines organization-wide biometric authentication requirements
type BiometricPolicy struct {
	ID                           string   `json:"id"`
	Name                         string   `json:"name"`
	Description                  string   `json:"description,omitempty"`
	Enabled                      bool     `json:"enabled"`
	AppliesToGroups              []string `json:"applies_to_groups,omitempty"`
	AppliesToRoles               []string `json:"applies_to_roles,omitempty"`
	RequirePlatformAuthenticator bool     `json:"require_platform_authenticator"`
	AllowedAuthenticatorTypes    []string `json:"allowed_authenticator_types"` // platform, cross-platform
	MinAuthenticatorLevel        string   `json:"min_authenticator_level"`     // any, single, multi
	CreatedAt                    time.Time `json:"created_at"`
}

// GetBiometricPreferences returns user's biometric preferences
func (s *Service) GetBiometricPreferences(ctx context.Context, userID string) (*BiometricPreferences, error) {
	query := `
		SELECT id, user_id, platform_authenticator_preferred, allow_cross_platform,
			require_user_verification, biometric_only_enabled, resident_key_required,
			created_at, updated_at
		FROM biometric_preferences
		WHERE user_id = $1
	`

	var prefs BiometricPreferences
	err := s.db.Pool.QueryRow(ctx, query, userID).Scan(
		&prefs.ID, &prefs.UserID, &prefs.PlatformAuthenticatorPreferred,
		&prefs.AllowCrossPlatform, &prefs.RequireUserVerification,
		&prefs.BiometricOnlyEnabled, &prefs.ResidentKeyRequired,
		&prefs.CreatedAt, &prefs.UpdatedAt,
	)
	if err != nil {
		// Return defaults
		return &BiometricPreferences{
			UserID:                       userID,
			PlatformAuthenticatorPreferred: true,
			AllowCrossPlatform:           true,
			RequireUserVerification:      true,
			BiometricOnlyEnabled:         false,
			ResidentKeyRequired:          false,
		}, nil
	}

	return &prefs, nil
}

// UpdateBiometricPreferences updates user's biometric preferences
func (s *Service) UpdateBiometricPreferences(ctx context.Context, userID string, prefs *BiometricPreferences) error {
	// Check if exists
	var existing string
	err := s.db.Pool.QueryRow(ctx,
		"SELECT id FROM biometric_preferences WHERE user_id = $1",
		userID,
	).Scan(&existing)

	if err == nil {
		// Update
		_, err = s.db.Pool.Exec(ctx,
			`UPDATE biometric_preferences
			SET platform_authenticator_preferred = $1, allow_cross_platform = $2,
				require_user_verification = $3, biometric_only_enabled = $4,
				resident_key_required = $5, updated_at = NOW()
			WHERE user_id = $6`,
			prefs.PlatformAuthenticatorPreferred, prefs.AllowCrossPlatform,
			prefs.RequireUserVerification, prefs.BiometricOnlyEnabled,
			prefs.ResidentKeyRequired, userID,
		)
	} else {
		// Insert
		_, err = s.db.Pool.Exec(ctx,
			`INSERT INTO biometric_preferences (
				id, user_id, platform_authenticator_preferred, allow_cross_platform,
				require_user_verification, biometric_only_enabled, resident_key_required,
				created_at, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())`,
			uuid.New().String(), userID, prefs.PlatformAuthenticatorPreferred,
			prefs.AllowCrossPlatform, prefs.RequireUserVerification,
			prefs.BiometricOnlyEnabled, prefs.ResidentKeyRequired,
		)
	}

	return err
}

// EnableBiometricOnly enables biometric-only login for a user
func (s *Service) EnableBiometricOnly(ctx context.Context, userID string) error {
	// Verify user has platform authenticator registered
	var credCount int
	err := s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM webauthn_credentials
		WHERE user_id = $1 AND authenticator_type = 'platform'`,
		userID,
	).Scan(&credCount)
	if err != nil || credCount == 0 {
		// Check for any WebAuthn credential as fallback
		s.db.Pool.QueryRow(ctx,
			"SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = $1",
			userID,
		).Scan(&credCount)
		if credCount == 0 {
			return &AuthError{Message: "user must have at least one WebAuthn credential registered"}
		}
	}

	prefs, _ := s.GetBiometricPreferences(ctx, userID)
	prefs.BiometricOnlyEnabled = true
	return s.UpdateBiometricPreferences(ctx, userID, prefs)
}

// DisableBiometricOnly disables biometric-only login
func (s *Service) DisableBiometricOnly(ctx context.Context, userID string) error {
	prefs, _ := s.GetBiometricPreferences(ctx, userID)
	prefs.BiometricOnlyEnabled = false
	return s.UpdateBiometricPreferences(ctx, userID, prefs)
}

// GetWebAuthnOptions returns WebAuthn registration/authentication options based on biometric preferences
func (s *Service) GetWebAuthnOptionsForUser(ctx context.Context, userID string) (map[string]interface{}, error) {
	prefs, _ := s.GetBiometricPreferences(ctx, userID)

	options := map[string]interface{}{
		"authenticatorSelection": map[string]interface{}{
			"userVerification": "preferred",
		},
	}

	if prefs.PlatformAuthenticatorPreferred {
		options["authenticatorSelection"].(map[string]interface{})["authenticatorAttachment"] = "platform"
	}

	if prefs.RequireUserVerification {
		options["authenticatorSelection"].(map[string]interface{})["userVerification"] = "required"
	}

	if prefs.ResidentKeyRequired {
		options["authenticatorSelection"].(map[string]interface{})["residentKey"] = "required"
		options["authenticatorSelection"].(map[string]interface{})["requireResidentKey"] = true
	}

	return options, nil
}

// ListBiometricPolicies returns all biometric policies
func (s *Service) ListBiometricPolicies(ctx context.Context) ([]BiometricPolicy, error) {
	query := `
		SELECT id, name, description, enabled, applies_to_groups, applies_to_roles,
			require_platform_authenticator, allowed_authenticator_types,
			min_authenticator_level, created_at
		FROM biometric_policies
		ORDER BY name
	`

	rows, err := s.db.Pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []BiometricPolicy
	for rows.Next() {
		var p BiometricPolicy
		err := rows.Scan(
			&p.ID, &p.Name, &p.Description, &p.Enabled, &p.AppliesToGroups,
			&p.AppliesToRoles, &p.RequirePlatformAuthenticator,
			&p.AllowedAuthenticatorTypes, &p.MinAuthenticatorLevel, &p.CreatedAt,
		)
		if err != nil {
			continue
		}
		policies = append(policies, p)
	}

	return policies, nil
}

// CreateBiometricPolicy creates a new biometric policy
func (s *Service) CreateBiometricPolicy(ctx context.Context, policy *BiometricPolicy) (*BiometricPolicy, error) {
	policy.ID = uuid.New().String()

	if len(policy.AllowedAuthenticatorTypes) == 0 {
		policy.AllowedAuthenticatorTypes = []string{"platform", "cross-platform"}
	}
	if policy.MinAuthenticatorLevel == "" {
		policy.MinAuthenticatorLevel = "any"
	}

	query := `
		INSERT INTO biometric_policies (
			id, name, description, enabled, applies_to_groups, applies_to_roles,
			require_platform_authenticator, allowed_authenticator_types,
			min_authenticator_level, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
		RETURNING created_at
	`

	err := s.db.Pool.QueryRow(ctx, query,
		policy.ID, policy.Name, policy.Description, policy.Enabled,
		policy.AppliesToGroups, policy.AppliesToRoles,
		policy.RequirePlatformAuthenticator, policy.AllowedAuthenticatorTypes,
		policy.MinAuthenticatorLevel,
	).Scan(&policy.CreatedAt)

	if err != nil {
		return nil, err
	}

	return policy, nil
}

// UpdateBiometricPolicy updates a biometric policy
func (s *Service) UpdateBiometricPolicy(ctx context.Context, policy *BiometricPolicy) error {
	query := `
		UPDATE biometric_policies
		SET name = $1, description = $2, enabled = $3, applies_to_groups = $4,
			applies_to_roles = $5, require_platform_authenticator = $6,
			allowed_authenticator_types = $7, min_authenticator_level = $8
		WHERE id = $9
	`

	_, err := s.db.Pool.Exec(ctx, query,
		policy.Name, policy.Description, policy.Enabled,
		policy.AppliesToGroups, policy.AppliesToRoles,
		policy.RequirePlatformAuthenticator, policy.AllowedAuthenticatorTypes,
		policy.MinAuthenticatorLevel, policy.ID,
	)

	return err
}

// DeleteBiometricPolicy deletes a biometric policy
func (s *Service) DeleteBiometricPolicy(ctx context.Context, policyID string) error {
	_, err := s.db.Pool.Exec(ctx, "DELETE FROM biometric_policies WHERE id = $1", policyID)
	return err
}

// GetApplicableBiometricPolicy returns the policy applicable to a user
func (s *Service) GetApplicableBiometricPolicy(ctx context.Context, userID string) (*BiometricPolicy, error) {
	// Get user's groups and roles
	var userGroups []string
	var userRoles []string

	rows, _ := s.db.Pool.Query(ctx,
		"SELECT group_id FROM user_groups WHERE user_id = $1",
		userID,
	)
	for rows.Next() {
		var groupID string
		rows.Scan(&groupID)
		userGroups = append(userGroups, groupID)
	}
	rows.Close()

	s.db.Pool.QueryRow(ctx,
		"SELECT roles FROM users WHERE id = $1",
		userID,
	).Scan(&userRoles)

	// Find applicable policy
	policies, _ := s.ListBiometricPolicies(ctx)
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}

		// Check if policy applies to user
		applies := false

		// Check groups
		if len(policy.AppliesToGroups) == 0 && len(policy.AppliesToRoles) == 0 {
			applies = true // Applies to all
		} else {
			for _, pg := range policy.AppliesToGroups {
				for _, ug := range userGroups {
					if pg == ug {
						applies = true
						break
					}
				}
			}
			for _, pr := range policy.AppliesToRoles {
				for _, ur := range userRoles {
					if pr == ur {
						applies = true
						break
					}
				}
			}
		}

		if applies {
			return &policy, nil
		}
	}

	return nil, nil
}

// ValidateAuthenticatorForPolicy checks if an authenticator meets policy requirements
func (s *Service) ValidateAuthenticatorForPolicy(ctx context.Context, userID, authenticatorType string) (bool, string, error) {
	policy, err := s.GetApplicableBiometricPolicy(ctx, userID)
	if err != nil {
		return false, "", err
	}

	if policy == nil {
		return true, "", nil // No policy, allow all
	}

	// Check if authenticator type is allowed
	allowed := false
	for _, at := range policy.AllowedAuthenticatorTypes {
		if at == authenticatorType {
			allowed = true
			break
		}
	}

	if !allowed {
		return false, "authenticator type not allowed by policy", nil
	}

	// Check if platform authenticator is required
	if policy.RequirePlatformAuthenticator && authenticatorType != "platform" {
		return false, "platform authenticator (Face ID/Touch ID) required", nil
	}

	return true, "", nil
}

// GetUserPlatformAuthenticators returns user's platform authenticators (Face ID/Touch ID)
func (s *Service) GetUserPlatformAuthenticators(ctx context.Context, userID string) ([]map[string]interface{}, error) {
	query := `
		SELECT id, name, authenticator_type, created_at, last_used_at
		FROM webauthn_credentials
		WHERE user_id = $1 AND authenticator_type = 'platform'
		ORDER BY created_at DESC
	`

	rows, err := s.db.Pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var authenticators []map[string]interface{}
	for rows.Next() {
		var id, name, authType string
		var createdAt time.Time
		var lastUsedAt *time.Time

		if err := rows.Scan(&id, &name, &authType, &createdAt, &lastUsedAt); err != nil {
			continue
		}

		authenticators = append(authenticators, map[string]interface{}{
			"id":                 id,
			"name":               name,
			"authenticator_type": authType,
			"created_at":         createdAt,
			"last_used_at":       lastUsedAt,
		})
	}

	return authenticators, nil
}

// AuthError represents an authentication error
type AuthError struct {
	Message string
}

func (e *AuthError) Error() string {
	return e.Message
}
