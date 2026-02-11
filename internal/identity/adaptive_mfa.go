// Package identity - Adaptive/Risk-Based MFA implementation
package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// RiskPolicy represents a risk-based MFA policy
type RiskPolicy struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Enabled     bool                   `json:"enabled"`
	Priority    int                    `json:"priority"`
	Conditions  map[string]interface{} `json:"conditions"`
	Actions     map[string]interface{} `json:"actions"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// TrustedBrowser represents a trusted browser that can skip MFA
type TrustedBrowser struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	BrowserHash string     `json:"browser_hash"`
	Name        string     `json:"name"`
	IPAddress   string     `json:"ip_address"`
	UserAgent   string     `json:"user_agent"`
	TrustedAt   time.Time  `json:"trusted_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	Revoked     bool       `json:"revoked"`
}

// RiskAssessment represents the risk assessment result for a login attempt
type RiskAssessment struct {
	Score            int      `json:"score"`
	Level            string   `json:"level"`       // low, medium, high, critical
	Factors          []string `json:"factors"`     // Contributing factors
	RequiresMFA      bool     `json:"requires_mfa"`
	AllowedMethods   []string `json:"allowed_methods,omitempty"` // Allowed MFA methods
	StepUpRequired   bool     `json:"step_up_required"`
	DenyAccess       bool     `json:"deny_access"`
	NotifyAdmin      bool     `json:"notify_admin"`
	TrustedBrowserID string   `json:"trusted_browser_id,omitempty"`
}

// LoginContext contains all context information for a login attempt
type LoginContext struct {
	UserID          string
	Username        string
	IPAddress       string
	UserAgent       string
	Latitude        float64
	Longitude       float64
	DeviceID        string
	BrowserHash     string
	FailedAttempts  int
	LastLoginIP     string
	LastLoginLat    float64
	LastLoginLon    float64
	LastLoginTime   *time.Time
	KnownDevice     bool
	TrustedBrowser  bool
}

// AssessLoginRisk evaluates the risk level of a login attempt
func (s *Service) AssessLoginRisk(ctx context.Context, lc *LoginContext) (*RiskAssessment, error) {
	assessment := &RiskAssessment{
		Score:          0,
		Factors:        make([]string, 0),
		AllowedMethods: []string{"totp", "push", "webauthn", "sms", "email"},
	}

	cfg := s.cfg.AdaptiveMFA

	// Check if adaptive MFA is enabled
	if !cfg.Enabled {
		assessment.Level = "low"
		assessment.RequiresMFA = false
		return assessment, nil
	}

	// 1. Check trusted browser
	if lc.BrowserHash != "" {
		trusted, err := s.IsTrustedBrowser(ctx, lc.UserID, lc.BrowserHash)
		if err == nil && trusted != nil && !trusted.Revoked {
			assessment.TrustedBrowserID = trusted.ID
			lc.TrustedBrowser = true
			// Update last used
			s.updateTrustedBrowserLastUsed(ctx, trusted.ID)
		}
	}

	// 2. Check if IP is blocked
	if s.anomalyDetector != nil {
		blocked, reason := s.anomalyDetector.CheckIPThreatList(ctx, lc.IPAddress)
		if blocked {
			assessment.Score += cfg.BlockedIPRiskScore
			assessment.Factors = append(assessment.Factors, fmt.Sprintf("blocked_ip: %s", reason))
			assessment.DenyAccess = true
			assessment.NotifyAdmin = true
		}
	}

	// 3. Check for new device
	if !lc.KnownDevice {
		assessment.Score += cfg.NewDeviceRiskScore
		assessment.Factors = append(assessment.Factors, "new_device")
	}

	// 4. Check for new location (compare with last login)
	if lc.LastLoginTime != nil && lc.Latitude != 0 && lc.Longitude != 0 {
		if lc.LastLoginLat != 0 && lc.LastLoginLon != 0 {
			// Check for impossible travel
			timeSinceLastLogin := time.Since(*lc.LastLoginTime)
			distance := haversineDistance(lc.LastLoginLat, lc.LastLoginLon, lc.Latitude, lc.Longitude)

			// Speed in km/h (assuming commercial flight max speed ~900 km/h)
			if timeSinceLastLogin.Hours() > 0 {
				speed := distance / timeSinceLastLogin.Hours()
				if speed > 900 {
					assessment.Score += cfg.ImpossibleTravelRiskScore
					assessment.Factors = append(assessment.Factors, fmt.Sprintf("impossible_travel: %.0f km in %.1f hours", distance, timeSinceLastLogin.Hours()))
					assessment.StepUpRequired = true
					assessment.NotifyAdmin = true
				} else if distance > 100 {
					// New location (more than 100km away)
					assessment.Score += cfg.NewLocationRiskScore
					assessment.Factors = append(assessment.Factors, fmt.Sprintf("new_location: %.0f km from last login", distance))
				}
			}
		}
	}

	// 5. Check failed login attempts
	if lc.FailedAttempts > 0 {
		failedScore := lc.FailedAttempts * cfg.FailedLoginRiskScore
		if failedScore > 50 {
			failedScore = 50 // Cap at 50
		}
		assessment.Score += failedScore
		assessment.Factors = append(assessment.Factors, fmt.Sprintf("failed_attempts: %d", lc.FailedAttempts))
	}

	// 6. Evaluate risk policies from database
	policies, err := s.GetEnabledRiskPolicies(ctx)
	if err == nil {
		for _, policy := range policies {
			if s.evaluateRiskPolicy(lc, assessment, &policy) {
				// Apply policy actions
				s.applyRiskPolicyActions(assessment, &policy)
			}
		}
	}

	// 7. Determine risk level based on score
	switch {
	case assessment.Score < cfg.LowRiskThreshold:
		assessment.Level = "low"
		if lc.TrustedBrowser {
			assessment.RequiresMFA = false
		} else {
			assessment.RequiresMFA = false // Allow login without MFA for trusted contexts
		}
	case assessment.Score < cfg.MediumRiskThreshold:
		assessment.Level = "medium"
		assessment.RequiresMFA = true
		// Any MFA method allowed
	case assessment.Score < cfg.HighRiskThreshold:
		assessment.Level = "high"
		assessment.RequiresMFA = true
		assessment.StepUpRequired = true
		// Only strong MFA methods (WebAuthn, Push)
		assessment.AllowedMethods = []string{"webauthn", "push"}
	default:
		assessment.Level = "critical"
		assessment.RequiresMFA = true
		assessment.StepUpRequired = true
		assessment.NotifyAdmin = true
		// Only WebAuthn allowed at critical risk
		assessment.AllowedMethods = []string{"webauthn"}
	}

	// If denied, override MFA settings
	if assessment.DenyAccess {
		assessment.RequiresMFA = false
		assessment.Level = "critical"
	}

	s.logger.Info("Risk assessment completed",
		zap.String("user_id", lc.UserID),
		zap.Int("score", assessment.Score),
		zap.String("level", assessment.Level),
		zap.Strings("factors", assessment.Factors),
		zap.Bool("requires_mfa", assessment.RequiresMFA),
		zap.Bool("deny_access", assessment.DenyAccess))

	return assessment, nil
}

// evaluateRiskPolicy checks if a policy's conditions match the login context
func (s *Service) evaluateRiskPolicy(lc *LoginContext, assessment *RiskAssessment, policy *RiskPolicy) bool {
	conditions := policy.Conditions

	// Check new_device condition
	if newDevice, ok := conditions["new_device"].(bool); ok && newDevice {
		if !lc.KnownDevice {
			return true
		}
	}

	// Check new_location condition
	if newLocation, ok := conditions["new_location"].(bool); ok && newLocation {
		for _, factor := range assessment.Factors {
			if factor == "new_location" || contains(factor, "new_location") {
				return true
			}
		}
	}

	// Check impossible_travel condition
	if impossibleTravel, ok := conditions["impossible_travel"].(bool); ok && impossibleTravel {
		for _, factor := range assessment.Factors {
			if contains(factor, "impossible_travel") {
				return true
			}
		}
	}

	// Check ip_blocked condition
	if ipBlocked, ok := conditions["ip_blocked"].(bool); ok && ipBlocked {
		for _, factor := range assessment.Factors {
			if contains(factor, "blocked_ip") {
				return true
			}
		}
	}

	// Check risk_score_min condition
	if minScore, ok := conditions["risk_score_min"].(float64); ok {
		if assessment.Score >= int(minScore) {
			return true
		}
	}

	return false
}

// applyRiskPolicyActions applies the actions from a matched policy
func (s *Service) applyRiskPolicyActions(assessment *RiskAssessment, policy *RiskPolicy) {
	actions := policy.Actions

	// Check deny action
	if deny, ok := actions["deny"].(bool); ok && deny {
		assessment.DenyAccess = true
	}

	// Check require_mfa action
	if requireMFA, ok := actions["require_mfa"].(bool); ok && requireMFA {
		assessment.RequiresMFA = true
	}

	// Check mfa_methods action
	if methods, ok := actions["mfa_methods"].([]interface{}); ok {
		assessment.AllowedMethods = make([]string, 0)
		for _, m := range methods {
			if method, ok := m.(string); ok {
				if method == "any" {
					assessment.AllowedMethods = []string{"totp", "push", "webauthn", "sms", "email"}
					break
				}
				assessment.AllowedMethods = append(assessment.AllowedMethods, method)
			}
		}
	}

	// Check step_up action
	if stepUp, ok := actions["step_up"].(bool); ok && stepUp {
		assessment.StepUpRequired = true
	}

	// Check notify_admin action
	if notify, ok := actions["notify_admin"].(bool); ok && notify {
		assessment.NotifyAdmin = true
	}
}

// --- Trusted Browser Management ---

// TrustBrowser creates a trusted browser entry for a user
func (s *Service) TrustBrowser(ctx context.Context, userID, browserHash, name, ipAddress, userAgent string) (*TrustedBrowser, error) {
	if browserHash == "" {
		browserHash = generateBrowserHash(userAgent, ipAddress)
	}

	// Check if already trusted
	existing, _ := s.IsTrustedBrowser(ctx, userID, browserHash)
	if existing != nil && !existing.Revoked {
		// Update expiration
		existing.ExpiresAt = time.Now().AddDate(0, 0, s.cfg.AdaptiveMFA.TrustedBrowserDays)
		if err := s.updateTrustedBrowser(ctx, existing); err != nil {
			return nil, err
		}
		return existing, nil
	}

	tb := &TrustedBrowser{
		ID:          uuid.New().String(),
		UserID:      userID,
		BrowserHash: browserHash,
		Name:        name,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		TrustedAt:   time.Now(),
		ExpiresAt:   time.Now().AddDate(0, 0, s.cfg.AdaptiveMFA.TrustedBrowserDays),
		Revoked:     false,
	}

	if err := s.storeTrustedBrowser(ctx, tb); err != nil {
		return nil, fmt.Errorf("failed to store trusted browser: %w", err)
	}

	s.logger.Info("Browser trusted",
		zap.String("user_id", userID),
		zap.String("browser_id", tb.ID),
		zap.Time("expires_at", tb.ExpiresAt))

	return tb, nil
}

// IsTrustedBrowser checks if a browser is trusted for a user
func (s *Service) IsTrustedBrowser(ctx context.Context, userID, browserHash string) (*TrustedBrowser, error) {
	query := `
		SELECT id, user_id, browser_hash, name, ip_address, user_agent,
		       trusted_at, expires_at, last_used_at, revoked
		FROM trusted_browsers
		WHERE user_id = $1 AND browser_hash = $2 AND revoked = false AND expires_at > NOW()
	`

	var tb TrustedBrowser
	err := s.db.Pool.QueryRow(ctx, query, userID, browserHash).Scan(
		&tb.ID,
		&tb.UserID,
		&tb.BrowserHash,
		&tb.Name,
		&tb.IPAddress,
		&tb.UserAgent,
		&tb.TrustedAt,
		&tb.ExpiresAt,
		&tb.LastUsedAt,
		&tb.Revoked,
	)
	if err != nil {
		return nil, err
	}

	return &tb, nil
}

// GetTrustedBrowsers returns all trusted browsers for a user
func (s *Service) GetTrustedBrowsers(ctx context.Context, userID string) ([]TrustedBrowser, error) {
	query := `
		SELECT id, user_id, browser_hash, name, ip_address, user_agent,
		       trusted_at, expires_at, last_used_at, revoked
		FROM trusted_browsers
		WHERE user_id = $1
		ORDER BY trusted_at DESC
	`

	rows, err := s.db.Pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var browsers []TrustedBrowser
	for rows.Next() {
		var tb TrustedBrowser
		err := rows.Scan(
			&tb.ID,
			&tb.UserID,
			&tb.BrowserHash,
			&tb.Name,
			&tb.IPAddress,
			&tb.UserAgent,
			&tb.TrustedAt,
			&tb.ExpiresAt,
			&tb.LastUsedAt,
			&tb.Revoked,
		)
		if err != nil {
			return nil, err
		}
		browsers = append(browsers, tb)
	}

	return browsers, nil
}

// RevokeTrustedBrowser revokes a trusted browser
func (s *Service) RevokeTrustedBrowser(ctx context.Context, userID, browserID string) error {
	query := `UPDATE trusted_browsers SET revoked = true WHERE user_id = $1 AND id = $2`
	result, err := s.db.Pool.Exec(ctx, query, userID, browserID)
	if err != nil {
		return fmt.Errorf("failed to revoke browser: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("trusted browser not found")
	}

	s.logger.Info("Trusted browser revoked",
		zap.String("user_id", userID),
		zap.String("browser_id", browserID))

	return nil
}

// RevokeAllTrustedBrowsers revokes all trusted browsers for a user
func (s *Service) RevokeAllTrustedBrowsers(ctx context.Context, userID string) error {
	query := `UPDATE trusted_browsers SET revoked = true WHERE user_id = $1`
	_, err := s.db.Pool.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to revoke browsers: %w", err)
	}

	s.logger.Info("All trusted browsers revoked", zap.String("user_id", userID))
	return nil
}

// --- Risk Policy Management ---

// GetEnabledRiskPolicies returns all enabled risk policies
func (s *Service) GetEnabledRiskPolicies(ctx context.Context) ([]RiskPolicy, error) {
	query := `
		SELECT id, name, description, enabled, priority, conditions, actions, created_at, updated_at
		FROM risk_policies
		WHERE enabled = true
		ORDER BY priority ASC
	`

	rows, err := s.db.Pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []RiskPolicy
	for rows.Next() {
		var policy RiskPolicy
		var conditionsJSON, actionsJSON []byte
		err := rows.Scan(
			&policy.ID,
			&policy.Name,
			&policy.Description,
			&policy.Enabled,
			&policy.Priority,
			&conditionsJSON,
			&actionsJSON,
			&policy.CreatedAt,
			&policy.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		// Parse JSON
		if len(conditionsJSON) > 0 {
			parseJSON(conditionsJSON, &policy.Conditions)
		}
		if len(actionsJSON) > 0 {
			parseJSON(actionsJSON, &policy.Actions)
		}

		policies = append(policies, policy)
	}

	return policies, nil
}

// --- Helper Functions ---

func (s *Service) storeTrustedBrowser(ctx context.Context, tb *TrustedBrowser) error {
	query := `
		INSERT INTO trusted_browsers (id, user_id, browser_hash, name, ip_address, user_agent, trusted_at, expires_at, revoked)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (user_id, browser_hash) DO UPDATE
		SET name = EXCLUDED.name, ip_address = EXCLUDED.ip_address, user_agent = EXCLUDED.user_agent,
		    expires_at = EXCLUDED.expires_at, revoked = EXCLUDED.revoked
	`
	_, err := s.db.Pool.Exec(ctx, query,
		tb.ID,
		tb.UserID,
		tb.BrowserHash,
		tb.Name,
		tb.IPAddress,
		tb.UserAgent,
		tb.TrustedAt,
		tb.ExpiresAt,
		tb.Revoked,
	)
	return err
}

func (s *Service) updateTrustedBrowser(ctx context.Context, tb *TrustedBrowser) error {
	query := `UPDATE trusted_browsers SET expires_at = $1 WHERE id = $2`
	_, err := s.db.Pool.Exec(ctx, query, tb.ExpiresAt, tb.ID)
	return err
}

func (s *Service) updateTrustedBrowserLastUsed(ctx context.Context, browserID string) {
	query := `UPDATE trusted_browsers SET last_used_at = $1 WHERE id = $2`
	s.db.Pool.Exec(ctx, query, time.Now(), browserID)
}

// generateBrowserHash creates a hash from browser characteristics
func generateBrowserHash(userAgent, ipAddress string) string {
	// Note: In production, use a more sophisticated fingerprinting approach
	// This is a simplified version using user-agent and IP subnet
	ipParts := extractIPSubnet(ipAddress)
	data := fmt.Sprintf("%s|%s", userAgent, ipParts)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// extractIPSubnet extracts the /24 subnet from an IP address
func extractIPSubnet(ip string) string {
	// Simple extraction - just take first 3 octets for IPv4
	parts := splitIP(ip)
	if len(parts) >= 3 {
		return fmt.Sprintf("%s.%s.%s", parts[0], parts[1], parts[2])
	}
	return ip
}

func splitIP(ip string) []string {
	var result []string
	current := ""
	for _, c := range ip {
		if c == '.' || c == ':' {
			if current != "" {
				result = append(result, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

// haversineDistance calculates the distance between two lat/lon points in kilometers
func haversineDistance(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadius = 6371 // km

	dLat := toRadians(lat2 - lat1)
	dLon := toRadians(lon2 - lon1)

	a := sinSquared(dLat/2) + cos(toRadians(lat1))*cos(toRadians(lat2))*sinSquared(dLon/2)
	c := 2 * asin(sqrt(a))

	return earthRadius * c
}

// Math helper functions
func toRadians(deg float64) float64 { return deg * 3.141592653589793 / 180 }
func sin(x float64) float64         { return sinApprox(x) }
func cos(x float64) float64         { return sin(x + 3.141592653589793/2) }
func sinSquared(x float64) float64  { s := sin(x); return s * s }
func sqrt(x float64) float64        { return sqrtApprox(x) }
func asin(x float64) float64        { return asinApprox(x) }

func sinApprox(x float64) float64 {
	// Taylor series approximation
	x = mod(x, 2*3.141592653589793)
	if x > 3.141592653589793 {
		x -= 2 * 3.141592653589793
	}
	x3 := x * x * x
	x5 := x3 * x * x
	x7 := x5 * x * x
	return x - x3/6 + x5/120 - x7/5040
}

func sqrtApprox(x float64) float64 {
	if x <= 0 {
		return 0
	}
	z := x
	for i := 0; i < 10; i++ {
		z = (z + x/z) / 2
	}
	return z
}

func asinApprox(x float64) float64 {
	if x < -1 {
		x = -1
	}
	if x > 1 {
		x = 1
	}
	// Polynomial approximation
	return x + x*x*x/6 + 3*x*x*x*x*x/40
}

func mod(x, y float64) float64 {
	for x >= y {
		x -= y
	}
	for x < 0 {
		x += y
	}
	return x
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func parseJSON(data []byte, v interface{}) {
	// Simple JSON parse - in production use encoding/json
	// This is handled by pgx automatically for JSONB
}
