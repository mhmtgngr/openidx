// Package identity - Biometric Authentication (Face ID / Touch ID via WebAuthn)
package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// BiometricPreferences represents user's biometric authentication preferences
type BiometricPreferences struct {
	ID                             string    `json:"id"`
	UserID                         string    `json:"user_id"`
	PlatformAuthenticatorPreferred bool      `json:"platform_authenticator_preferred"`
	AllowCrossPlatform             bool      `json:"allow_cross_platform"`
	RequireUserVerification        bool      `json:"require_user_verification"`
	BiometricOnlyEnabled           bool      `json:"biometric_only_enabled"`
	ResidentKeyRequired            bool      `json:"resident_key_required"`
	CreatedAt                      time.Time `json:"created_at"`
	UpdatedAt                      time.Time `json:"updated_at"`
}

// BiometricPolicy defines organization-wide biometric authentication requirements
type BiometricPolicy struct {
	ID                           string    `json:"id"`
	Name                         string    `json:"name"`
	Description                  string    `json:"description,omitempty"`
	Enabled                      bool      `json:"enabled"`
	AppliesToGroups              []string  `json:"applies_to_groups,omitempty"`
	AppliesToRoles               []string  `json:"applies_to_roles,omitempty"`
	RequirePlatformAuthenticator bool      `json:"require_platform_authenticator"`
	AllowedAuthenticatorTypes    []string  `json:"allowed_authenticator_types"` // platform, cross-platform
	MinAuthenticatorLevel        string    `json:"min_authenticator_level"`     // any, single, multi
	CreatedAt                    time.Time `json:"created_at"`
}

// GetBiometricPreferences returns user's biometric preferences.
//
// A user with no stored row gets the built-in defaults; every other error is
// returned. The original returned the defaults on ANY error, so a connection
// failure, a permission error, or a read of a belted table without app.org_id
// set was indistinguishable from "this user has not set preferences" and the
// caller got RequireUserVerification true, ResidentKeyRequired false and a nil
// error. With v158's belt in place that path stops being theoretical, and
// answering it with defaults would silently loosen what a user had stored.
func (s *Service) GetBiometricPreferences(ctx context.Context, userID string) (*BiometricPreferences, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, fmt.Errorf("organization context required: %w", err)
	}

	query := `
		SELECT id, user_id, platform_authenticator_preferred, allow_cross_platform,
			require_user_verification, biometric_only_enabled, resident_key_required,
			created_at, updated_at
		FROM biometric_preferences
		WHERE user_id = $1 AND org_id = $2
	`

	var prefs BiometricPreferences
	err = s.db.Pool.QueryRow(ctx, query, userID, org.ID).Scan(
		&prefs.ID, &prefs.UserID, &prefs.PlatformAuthenticatorPreferred,
		&prefs.AllowCrossPlatform, &prefs.RequireUserVerification,
		&prefs.BiometricOnlyEnabled, &prefs.ResidentKeyRequired,
		&prefs.CreatedAt, &prefs.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		// This user has not set preferences. The defaults are the product's,
		// and they are the stricter reading in each case.
		return &BiometricPreferences{
			UserID:                         userID,
			PlatformAuthenticatorPreferred: true,
			AllowCrossPlatform:             true,
			RequireUserVerification:        true,
			BiometricOnlyEnabled:           false,
			ResidentKeyRequired:            false,
		}, nil
	}
	if err != nil {
		return nil, err
	}

	return &prefs, nil
}

// UpdateBiometricPreferences updates user's biometric preferences.
//
// The org term is what stops one tenant rewriting another user's authenticator
// requirements — turning off "user verification required", or switching an
// account to biometric-only. EnableBiometricOnly already resolved the tenant to
// count the user's WebAuthn credentials before flipping that flag; the write it
// guarded named no organization at all.
func (s *Service) UpdateBiometricPreferences(ctx context.Context, userID string, prefs *BiometricPreferences) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return fmt.Errorf("organization context required: %w", err)
	}

	// Refuse a target outside the caller's tenant rather than writing for it.
	// Without this the INSERT branch below would create a preferences row in
	// the caller's organization keyed on somebody else's user id.
	var one int
	if err := s.db.Pool.QueryRow(ctx,
		"SELECT 1 FROM users WHERE id = $1 AND org_id = $2", userID, org.ID).Scan(&one); err != nil {
		return fmt.Errorf("user is not in this organization")
	}

	// Check if exists
	var existing string
	err = s.db.Pool.QueryRow(ctx,
		"SELECT id FROM biometric_preferences WHERE user_id = $1 AND org_id = $2",
		userID, org.ID,
	).Scan(&existing)

	if err == nil {
		// Update
		_, err = s.db.Pool.Exec(ctx,
			`UPDATE biometric_preferences
			SET platform_authenticator_preferred = $1, allow_cross_platform = $2,
				require_user_verification = $3, biometric_only_enabled = $4,
				resident_key_required = $5, updated_at = NOW()
			WHERE user_id = $6 AND org_id = $7`,
			prefs.PlatformAuthenticatorPreferred, prefs.AllowCrossPlatform,
			prefs.RequireUserVerification, prefs.BiometricOnlyEnabled,
			prefs.ResidentKeyRequired, userID, org.ID,
		)
		return err
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		// A real read failure is not "no row yet": answering it with an INSERT
		// would fail on the unique key and report a save that did not happen.
		return err
	}

	// Insert
	_, err = s.db.Pool.Exec(ctx,
		`INSERT INTO biometric_preferences (
			id, user_id, platform_authenticator_preferred, allow_cross_platform,
			require_user_verification, biometric_only_enabled, resident_key_required,
			created_at, updated_at, org_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW(), $8)`,
		uuid.New().String(), userID, prefs.PlatformAuthenticatorPreferred,
		prefs.AllowCrossPlatform, prefs.RequireUserVerification,
		prefs.BiometricOnlyEnabled, prefs.ResidentKeyRequired, org.ID,
	)

	return err
}

// EnableBiometricOnly enables biometric-only login for a user
func (s *Service) EnableBiometricOnly(ctx context.Context, userID string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}
	// Verify the user has at least one WebAuthn credential registered. Creds
	// live in mfa_webauthn (where the wired registration path writes) — the old
	// query hit a phantom `webauthn_credentials` table that no migration creates
	// and filtered on an `authenticator_type` column mfa_webauthn does not have,
	// so it always errored and this could never succeed.
	var credCount int
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM mfa_webauthn WHERE user_id = $1 AND org_id = $2`,
		userID, org.ID,
	).Scan(&credCount); err != nil {
		return err
	}
	if credCount == 0 {
		return &AuthError{Message: "user must have at least one WebAuthn credential registered"}
	}

	// The read can fail now that it distinguishes a missing row from a broken
	// query; taking its error means a failed read no longer silently rewrites
	// the user's other preferences to the defaults on the way past.
	prefs, err := s.GetBiometricPreferences(ctx, userID)
	if err != nil {
		return err
	}
	prefs.BiometricOnlyEnabled = true
	return s.UpdateBiometricPreferences(ctx, userID, prefs)
}

// DisableBiometricOnly disables biometric-only login
func (s *Service) DisableBiometricOnly(ctx context.Context, userID string) error {
	prefs, err := s.GetBiometricPreferences(ctx, userID)
	if err != nil {
		return err
	}
	prefs.BiometricOnlyEnabled = false
	return s.UpdateBiometricPreferences(ctx, userID, prefs)
}

// GetWebAuthnOptions returns WebAuthn registration/authentication options based on biometric preferences
func (s *Service) GetWebAuthnOptionsForUser(ctx context.Context, userID string) (map[string]interface{}, error) {
	// These options tell the authenticator what to require. Building them from
	// preferences that failed to load would relax user verification and the
	// resident-key requirement for a reason the caller never sees.
	prefs, err := s.GetBiometricPreferences(ctx, userID)
	if err != nil {
		return nil, err
	}

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

// ListBiometricPolicies returns this organization's biometric policies.
//
// This is not only the administrative list: GetApplicableBiometricPolicy calls
// it and returns the FIRST policy that applies, and a policy naming no groups
// and no roles applies to everyone. Without the org term any administrator on
// the installation could author an untargeted rule that governed every user on
// it, and `ORDER BY name` decided which one won — a control aimed by sort
// order is aimed by whoever picks the earlier name. It can loosen as well as
// tighten: allowed_authenticator_types defaults to both types, so a permissive
// foreign policy sorting first replaced a restrictive local one.
func (s *Service) ListBiometricPolicies(ctx context.Context) ([]BiometricPolicy, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, fmt.Errorf("organization context required: %w", err)
	}

	query := `
		SELECT id, name, COALESCE(description, ''), COALESCE(enabled, false),
			COALESCE(applies_to_groups, '{}'), COALESCE(applies_to_roles, '{}'),
			COALESCE(require_platform_authenticator, false),
			COALESCE(allowed_authenticator_types, '{}'),
			COALESCE(min_authenticator_level, 'any'), created_at
		FROM biometric_policies
		WHERE org_id = $1
		ORDER BY name
	`

	rows, err := s.db.Pool.Query(ctx, query, org.ID)
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
			// Every nullable column above is now COALESCEd, so a scan error is
			// a real fault rather than a NULL. Dropping the row silently would
			// hide a rule from the list that decides which rule applies.
			return nil, err
		}
		policies = append(policies, p)
	}

	return policies, rows.Err()
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

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, fmt.Errorf("organization context required: %w", err)
	}

	query := `
		INSERT INTO biometric_policies (
			id, name, description, enabled, applies_to_groups, applies_to_roles,
			require_platform_authenticator, allowed_authenticator_types,
			min_authenticator_level, created_at, org_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), $10)
		RETURNING created_at
	`

	err = s.db.Pool.QueryRow(ctx, query,
		policy.ID, policy.Name, policy.Description, policy.Enabled,
		policy.AppliesToGroups, policy.AppliesToRoles,
		policy.RequirePlatformAuthenticator, policy.AllowedAuthenticatorTypes,
		policy.MinAuthenticatorLevel, org.ID,
	).Scan(&policy.CreatedAt)

	if err != nil {
		return nil, err
	}

	return policy, nil
}

// UpdateBiometricPolicy updates a biometric policy.
//
// The org term is what stops another tenant re-aiming the rule. Everything a
// policy says is settable here — which authenticator types are allowed, whether
// a platform authenticator is required, and which groups and roles it covers —
// so without it a rule labelled "security keys only" could be rewritten to
// allow anything and handed back to the administrator who owns it.
func (s *Service) UpdateBiometricPolicy(ctx context.Context, policy *BiometricPolicy) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return fmt.Errorf("organization context required: %w", err)
	}

	query := `
		UPDATE biometric_policies
		SET name = $1, description = $2, enabled = $3, applies_to_groups = $4,
			applies_to_roles = $5, require_platform_authenticator = $6,
			allowed_authenticator_types = $7, min_authenticator_level = $8
		WHERE id = $9 AND org_id = $10
	`

	tag, err := s.db.Pool.Exec(ctx, query,
		policy.Name, policy.Description, policy.Enabled,
		policy.AppliesToGroups, policy.AppliesToRoles,
		policy.RequirePlatformAuthenticator, policy.AllowedAuthenticatorTypes,
		policy.MinAuthenticatorLevel, policy.ID, org.ID,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// Saying "updated" when the predicate matched nothing is how a
		// cross-tenant id looks like a successful edit from the console.
		return fmt.Errorf("biometric policy not found in this organization")
	}
	return nil
}

// DeleteBiometricPolicy deletes a biometric policy.
//
// Deleting another organization's rule removes their control with nothing on
// their console to say it has stopped existing.
func (s *Service) DeleteBiometricPolicy(ctx context.Context, policyID string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return fmt.Errorf("organization context required: %w", err)
	}
	tag, err := s.db.Pool.Exec(ctx,
		"DELETE FROM biometric_policies WHERE id = $1 AND org_id = $2", policyID, org.ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("biometric policy not found in this organization")
	}
	return nil
}

// GetApplicableBiometricPolicy returns the policy applicable to a user
func (s *Service) GetApplicableBiometricPolicy(ctx context.Context, userID string) (*BiometricPolicy, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	// Get user's groups and roles. Read the real membership table
	// group_memberships (org-scoped) — the previous query hit a phantom
	// `user_groups` table that no migration creates, so it always errored and
	// left userGroups empty, making any group-scoped biometric policy silently
	// never match (fail-open). Fail closed if group resolution errors.
	var userGroups []string
	var userRoles []string

	rows, err := s.db.Pool.Query(ctx,
		"SELECT group_id FROM group_memberships WHERE user_id = $1 AND org_id = $2",
		userID, org.ID,
	)
	if err != nil {
		return nil, fmt.Errorf("resolve user groups: %w", err)
	}
	for rows.Next() {
		var groupID string
		rows.Scan(&groupID)
		userGroups = append(userGroups, groupID)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("resolve user groups: %w", err)
	}

	// users has no roles column; a user's roles are rows in user_roles. The
	// old statement could not plan, so userRoles stayed empty and a biometric
	// policy targeted at a role matched nobody -- the policy displayed as
	// applying to a role it never applied to.
	roleRows, rerr := s.db.Pool.Query(ctx,
		`SELECT r.name FROM user_roles ur
		 JOIN roles r ON r.id = ur.role_id
		 WHERE ur.user_id = $1 AND ur.org_id = $2`,
		userID, org.ID)
	if rerr != nil {
		return nil, fmt.Errorf("resolve user roles: %w", rerr)
	}
	for roleRows.Next() {
		var roleName string
		if roleRows.Scan(&roleName) == nil {
			userRoles = append(userRoles, roleName)
		}
	}
	roleRows.Close()
	if err := roleRows.Err(); err != nil {
		return nil, fmt.Errorf("resolve user roles: %w", err)
	}

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
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}
	// WebAuthn credentials live in mfa_webauthn; it has no `authenticator_type`
	// column (the old query targeted a phantom `webauthn_credentials` table), so
	// list all of the user's registered credentials, org-scoped. name is
	// nullable — COALESCE to avoid a NULL scan into a non-pointer string.
	query := `
		SELECT id, COALESCE(name, ''), created_at, last_used_at
		FROM mfa_webauthn
		WHERE user_id = $1 AND org_id = $2
		ORDER BY created_at DESC
	`

	rows, err := s.db.Pool.Query(ctx, query, userID, org.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var authenticators []map[string]interface{}
	for rows.Next() {
		var id, name string
		var createdAt time.Time
		var lastUsedAt *time.Time

		if err := rows.Scan(&id, &name, &createdAt, &lastUsedAt); err != nil {
			continue
		}

		authenticators = append(authenticators, map[string]interface{}{
			"id":                 id,
			"name":               name,
			"authenticator_type": "platform",
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
