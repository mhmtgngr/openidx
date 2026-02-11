package risk

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// RiskPolicy represents an adaptive MFA policy
type RiskPolicy struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Enabled     bool            `json:"enabled"`
	Priority    int             `json:"priority"`
	Conditions  PolicyCondition `json:"conditions"`
	Actions     PolicyAction    `json:"actions"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// PolicyCondition defines when a policy applies
type PolicyCondition struct {
	RiskScoreMin      *int     `json:"risk_score_min,omitempty"`
	RiskScoreMax      *int     `json:"risk_score_max,omitempty"`
	NewDevice         *bool    `json:"new_device,omitempty"`
	NewLocation       *bool    `json:"new_location,omitempty"`
	ImpossibleTravel  *bool    `json:"impossible_travel,omitempty"`
	OffHours          *bool    `json:"off_hours,omitempty"`
	FailedAttempts    *int     `json:"failed_attempts,omitempty"`
	UntrustedDevice   *bool    `json:"untrusted_device,omitempty"`
	Countries         []string `json:"countries,omitempty"`          // Block/allow specific countries
	ExcludeCountries  []string `json:"exclude_countries,omitempty"`  // Exclude from policy
	IPRanges          []string `json:"ip_ranges,omitempty"`          // CIDR ranges
	UserGroups        []string `json:"user_groups,omitempty"`        // Apply to specific groups
	Applications      []string `json:"applications,omitempty"`       // Apply to specific apps
}

// PolicyAction defines what happens when policy matches
type PolicyAction struct {
	RequireMFA      bool     `json:"require_mfa"`
	MFAMethods      []string `json:"mfa_methods,omitempty"`      // ["push", "webauthn", "totp", "any"]
	StepUp          bool     `json:"step_up,omitempty"`          // Require additional verification
	Deny            bool     `json:"deny,omitempty"`             // Block access completely
	NotifyUser      bool     `json:"notify_user,omitempty"`      // Send email/push notification
	NotifyAdmin     bool     `json:"notify_admin,omitempty"`     // Alert security team
	LogLevel        string   `json:"log_level,omitempty"`        // "info", "warning", "critical"
	SessionDuration *int     `json:"session_duration,omitempty"` // Override session length (minutes)
	RequireReason   bool     `json:"require_reason,omitempty"`   // User must provide access reason
}

// PolicyEvaluationResult contains the outcome of policy evaluation
type PolicyEvaluationResult struct {
	PolicyID        string       `json:"policy_id,omitempty"`
	PolicyName      string       `json:"policy_name,omitempty"`
	RiskScore       int          `json:"risk_score"`
	RiskFactors     []string     `json:"risk_factors"`
	Action          PolicyAction `json:"action"`
	MatchedPolicies []string     `json:"matched_policies"`
	Decision        string       `json:"decision"` // "allow", "mfa_required", "step_up", "deny"
}

// CreateRiskPolicyRequest is the request to create a risk policy
type CreateRiskPolicyRequest struct {
	Name        string          `json:"name" binding:"required"`
	Description string          `json:"description"`
	Enabled     bool            `json:"enabled"`
	Priority    int             `json:"priority"`
	Conditions  PolicyCondition `json:"conditions" binding:"required"`
	Actions     PolicyAction    `json:"actions" binding:"required"`
}

// CreateRiskPolicy creates a new risk policy
func (s *Service) CreateRiskPolicy(ctx context.Context, req CreateRiskPolicyRequest) (*RiskPolicy, error) {
	conditionsJSON, err := json.Marshal(req.Conditions)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal conditions: %w", err)
	}

	actionsJSON, err := json.Marshal(req.Actions)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal actions: %w", err)
	}

	var policy RiskPolicy
	err = s.db.Pool.QueryRow(ctx,
		`INSERT INTO risk_policies (name, description, enabled, priority, conditions, actions)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, name, description, enabled, priority, conditions, actions, created_at, updated_at`,
		req.Name, req.Description, req.Enabled, req.Priority, conditionsJSON, actionsJSON,
	).Scan(&policy.ID, &policy.Name, &policy.Description, &policy.Enabled, &policy.Priority,
		&conditionsJSON, &actionsJSON, &policy.CreatedAt, &policy.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create policy: %w", err)
	}

	json.Unmarshal(conditionsJSON, &policy.Conditions)
	json.Unmarshal(actionsJSON, &policy.Actions)

	s.logger.Info("Created risk policy",
		zap.String("policy_id", policy.ID),
		zap.String("name", policy.Name))

	return &policy, nil
}

// GetRiskPolicy retrieves a risk policy by ID
func (s *Service) GetRiskPolicy(ctx context.Context, policyID string) (*RiskPolicy, error) {
	var policy RiskPolicy
	var conditionsJSON, actionsJSON []byte

	err := s.db.Pool.QueryRow(ctx,
		`SELECT id, name, description, enabled, priority, conditions, actions, created_at, updated_at
		 FROM risk_policies WHERE id = $1`,
		policyID,
	).Scan(&policy.ID, &policy.Name, &policy.Description, &policy.Enabled, &policy.Priority,
		&conditionsJSON, &actionsJSON, &policy.CreatedAt, &policy.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("policy not found: %w", err)
	}

	json.Unmarshal(conditionsJSON, &policy.Conditions)
	json.Unmarshal(actionsJSON, &policy.Actions)

	return &policy, nil
}

// ListRiskPolicies returns all risk policies
func (s *Service) ListRiskPolicies(ctx context.Context, enabledOnly bool) ([]RiskPolicy, error) {
	query := `SELECT id, name, description, enabled, priority, conditions, actions, created_at, updated_at
			  FROM risk_policies`
	if enabledOnly {
		query += ` WHERE enabled = true`
	}
	query += ` ORDER BY priority ASC, created_at ASC`

	rows, err := s.db.Pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []RiskPolicy
	for rows.Next() {
		var p RiskPolicy
		var conditionsJSON, actionsJSON []byte
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Enabled, &p.Priority,
			&conditionsJSON, &actionsJSON, &p.CreatedAt, &p.UpdatedAt); err != nil {
			continue
		}
		json.Unmarshal(conditionsJSON, &p.Conditions)
		json.Unmarshal(actionsJSON, &p.Actions)
		policies = append(policies, p)
	}

	return policies, nil
}

// UpdateRiskPolicy updates an existing risk policy
func (s *Service) UpdateRiskPolicy(ctx context.Context, policyID string, req CreateRiskPolicyRequest) (*RiskPolicy, error) {
	conditionsJSON, err := json.Marshal(req.Conditions)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal conditions: %w", err)
	}

	actionsJSON, err := json.Marshal(req.Actions)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal actions: %w", err)
	}

	var policy RiskPolicy
	err = s.db.Pool.QueryRow(ctx,
		`UPDATE risk_policies
		 SET name = $2, description = $3, enabled = $4, priority = $5, conditions = $6, actions = $7, updated_at = NOW()
		 WHERE id = $1
		 RETURNING id, name, description, enabled, priority, conditions, actions, created_at, updated_at`,
		policyID, req.Name, req.Description, req.Enabled, req.Priority, conditionsJSON, actionsJSON,
	).Scan(&policy.ID, &policy.Name, &policy.Description, &policy.Enabled, &policy.Priority,
		&conditionsJSON, &actionsJSON, &policy.CreatedAt, &policy.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to update policy: %w", err)
	}

	json.Unmarshal(conditionsJSON, &policy.Conditions)
	json.Unmarshal(actionsJSON, &policy.Actions)

	return &policy, nil
}

// DeleteRiskPolicy deletes a risk policy
func (s *Service) DeleteRiskPolicy(ctx context.Context, policyID string) error {
	result, err := s.db.Pool.Exec(ctx, `DELETE FROM risk_policies WHERE id = $1`, policyID)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("policy not found")
	}
	return nil
}

// ToggleRiskPolicy enables or disables a policy
func (s *Service) ToggleRiskPolicy(ctx context.Context, policyID string, enabled bool) error {
	_, err := s.db.Pool.Exec(ctx,
		`UPDATE risk_policies SET enabled = $2, updated_at = NOW() WHERE id = $1`,
		policyID, enabled)
	return err
}

// EvaluateLoginContext holds all context for risk evaluation
type EvaluateLoginContext struct {
	UserID            string
	IPAddress         string
	UserAgent         string
	DeviceFingerprint string
	Location          string
	Latitude          float64
	Longitude         float64
	Country           string
	IsNewDevice       bool
	IsDeviceTrusted   bool
	FailedAttempts    int
	UserGroups        []string
	ApplicationID     string
}

// EvaluateRiskPolicies evaluates all policies against a login context
func (s *Service) EvaluateRiskPolicies(ctx context.Context, loginCtx EvaluateLoginContext) (*PolicyEvaluationResult, error) {
	// First, calculate the risk score
	riskScore, riskFactors := s.CalculateRiskScore(ctx, loginCtx.UserID, loginCtx.IPAddress,
		loginCtx.UserAgent, loginCtx.DeviceFingerprint, loginCtx.Location, loginCtx.Latitude, loginCtx.Longitude)

	result := &PolicyEvaluationResult{
		RiskScore:       riskScore,
		RiskFactors:     riskFactors,
		MatchedPolicies: []string{},
		Decision:        "allow",
		Action: PolicyAction{
			RequireMFA: false,
		},
	}

	// Get all enabled policies ordered by priority
	policies, err := s.ListRiskPolicies(ctx, true)
	if err != nil {
		s.logger.Warn("Failed to load risk policies", zap.Error(err))
		return result, nil
	}

	// Check for impossible travel in factors
	hasImpossibleTravel := false
	hasNewDevice := false
	hasNewLocation := false
	hasOffHours := false
	for _, factor := range riskFactors {
		switch {
		case factor == "impossible_travel":
			hasImpossibleTravel = true
		case factor == "new_device":
			hasNewDevice = true
		case factor == "unusual_location" || factor == "first_country_login":
			hasNewLocation = true
		case factor == "off_hours":
			hasOffHours = true
		}
	}

	// Evaluate each policy
	for _, policy := range policies {
		if s.policyMatches(policy.Conditions, riskScore, hasNewDevice, hasNewLocation,
			hasImpossibleTravel, hasOffHours, loginCtx) {

			result.MatchedPolicies = append(result.MatchedPolicies, policy.Name)

			// Apply actions (most restrictive wins)
			if policy.Actions.Deny {
				result.Decision = "deny"
				result.Action = policy.Actions
				result.PolicyID = policy.ID
				result.PolicyName = policy.Name
				break // Deny is final
			}

			if policy.Actions.StepUp && result.Decision != "deny" {
				result.Decision = "step_up"
				result.Action = mergeActions(result.Action, policy.Actions)
				result.PolicyID = policy.ID
				result.PolicyName = policy.Name
			} else if policy.Actions.RequireMFA && result.Decision == "allow" {
				result.Decision = "mfa_required"
				result.Action = mergeActions(result.Action, policy.Actions)
				if result.PolicyID == "" {
					result.PolicyID = policy.ID
					result.PolicyName = policy.Name
				}
			}

			// Accumulate notification flags
			if policy.Actions.NotifyUser {
				result.Action.NotifyUser = true
			}
			if policy.Actions.NotifyAdmin {
				result.Action.NotifyAdmin = true
			}
		}
	}

	s.logger.Info("Risk evaluation completed",
		zap.String("user_id", loginCtx.UserID),
		zap.Int("risk_score", riskScore),
		zap.Strings("factors", riskFactors),
		zap.String("decision", result.Decision),
		zap.Strings("matched_policies", result.MatchedPolicies))

	return result, nil
}

// policyMatches checks if policy conditions match the login context
func (s *Service) policyMatches(cond PolicyCondition, riskScore int, newDevice, newLocation, impossibleTravel, offHours bool, ctx EvaluateLoginContext) bool {
	// Check risk score range
	if cond.RiskScoreMin != nil && riskScore < *cond.RiskScoreMin {
		return false
	}
	if cond.RiskScoreMax != nil && riskScore > *cond.RiskScoreMax {
		return false
	}

	// Check boolean conditions
	if cond.NewDevice != nil && *cond.NewDevice != newDevice {
		return false
	}
	if cond.NewLocation != nil && *cond.NewLocation != newLocation {
		return false
	}
	if cond.ImpossibleTravel != nil && *cond.ImpossibleTravel != impossibleTravel {
		return false
	}
	if cond.OffHours != nil && *cond.OffHours != offHours {
		return false
	}
	if cond.UntrustedDevice != nil && *cond.UntrustedDevice != !ctx.IsDeviceTrusted {
		return false
	}

	// Check failed attempts threshold
	if cond.FailedAttempts != nil && ctx.FailedAttempts < *cond.FailedAttempts {
		return false
	}

	// Check country restrictions
	if len(cond.Countries) > 0 {
		found := false
		for _, c := range cond.Countries {
			if c == ctx.Country {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check country exclusions
	if len(cond.ExcludeCountries) > 0 {
		for _, c := range cond.ExcludeCountries {
			if c == ctx.Country {
				return false
			}
		}
	}

	// Check user groups
	if len(cond.UserGroups) > 0 {
		found := false
		for _, reqGroup := range cond.UserGroups {
			for _, userGroup := range ctx.UserGroups {
				if reqGroup == userGroup {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check applications
	if len(cond.Applications) > 0 && ctx.ApplicationID != "" {
		found := false
		for _, app := range cond.Applications {
			if app == ctx.ApplicationID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// mergeActions combines two action sets (most restrictive wins)
func mergeActions(existing, new PolicyAction) PolicyAction {
	result := existing

	if new.RequireMFA {
		result.RequireMFA = true
	}
	if new.StepUp {
		result.StepUp = true
	}
	if new.NotifyUser {
		result.NotifyUser = true
	}
	if new.NotifyAdmin {
		result.NotifyAdmin = true
	}
	if new.RequireReason {
		result.RequireReason = true
	}

	// Merge MFA methods
	if len(new.MFAMethods) > 0 {
		methodSet := make(map[string]bool)
		for _, m := range result.MFAMethods {
			methodSet[m] = true
		}
		for _, m := range new.MFAMethods {
			methodSet[m] = true
		}
		result.MFAMethods = nil
		for m := range methodSet {
			result.MFAMethods = append(result.MFAMethods, m)
		}
	}

	// Use shorter session duration if specified
	if new.SessionDuration != nil {
		if result.SessionDuration == nil || *new.SessionDuration < *result.SessionDuration {
			result.SessionDuration = new.SessionDuration
		}
	}

	// Use higher log level
	if new.LogLevel == "critical" || (new.LogLevel == "warning" && result.LogLevel != "critical") {
		result.LogLevel = new.LogLevel
	}

	return result
}

// GetRecentFailedAttempts returns count of failed login attempts in the last hour
func (s *Service) GetRecentFailedAttempts(ctx context.Context, userID string) int {
	var count int
	s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM login_history
		 WHERE user_id = $1 AND success = false AND created_at > NOW() - INTERVAL '1 hour'`,
		userID).Scan(&count)
	return count
}
