// Package risk provides risk-based authentication policies
package risk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// Redis key prefixes for policy storage
const (
	policyKeyPrefix = "policy:tenant:"
)

// RiskLevel represents the risk category
type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "low"
	RiskLevelMedium   RiskLevel = "medium"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelCritical RiskLevel = "critical"
)

// AuthAction represents the authentication action to take
type AuthAction string

const (
	AuthActionAllow            AuthAction = "allow"
	AuthActionRequireMFA       AuthAction = "require_mfa"
	AuthActionRequireStrongMFA AuthAction = "require_strong_mfa"
	AuthActionRequireApproval  AuthAction = "require_approval"
	AuthActionBlock            AuthAction = "block"
	AuthActionBlockAndAlert    AuthAction = "block_and_alert"
)

// TenantPolicy represents per-tenant risk policy thresholds
type TenantPolicy struct {
	TenantID         string     `json:"tenant_id"`
	LowThreshold     int        `json:"low_threshold"`      // Default: 30
	MediumThreshold  int        `json:"medium_threshold"`   // Default: 50
	HighThreshold    int        `json:"high_threshold"`     // Default: 70
	CriticalThreshold int       `json:"critical_threshold"` // Default: 90
	Enabled          bool       `json:"enabled"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// EvaluateRequest represents a risk evaluation request
type EvaluateRequest struct {
	TenantID      string  `json:"tenant_id" binding:"required"`
	UserID        string  `json:"user_id" binding:"required"`
	IPAddress     string  `json:"ip_address"`
	UserAgent     string  `json:"user_agent"`
	DeviceFingerprint string `json:"device_fingerprint"`
	Latitude      float64 `json:"latitude"`
	Longitude     float64 `json:"longitude"`
	LoginHour     int     `json:"login_hour"`
	Resource      string  `json:"resource,omitempty"`
}

// EvaluateResponse represents the risk evaluation result
type EvaluateResponse struct {
	RequestID      string     `json:"request_id"`
	RiskScore      int        `json:"risk_score"`
	RiskLevel      RiskLevel  `json:"risk_level"`
	Action         AuthAction `json:"action"`
	Reasons        []string   `json:"reasons"`
	Anomalies      []string   `json:"anomalies"`
	SessionDuration *int      `json:"session_duration_minutes,omitempty"`
	RequireMFA     bool       `json:"require_mfa"`
	MFAMethods     []string   `json:"mfa_methods,omitempty"`
	RequireApproval bool      `json:"require_approval"`
	Allowed        bool       `json:"allowed"`
	EvaluatedAt    time.Time  `json:"evaluated_at"`
}

// PolicyConfig holds configuration for risk policies
type PolicyConfig struct {
	// Default thresholds (0-100)
	DefaultLowThreshold      int
	DefaultMediumThreshold   int
	DefaultHighThreshold     int
	DefaultCriticalThreshold int

	// Session duration overrides based on risk (minutes)
	LowRiskSessionDuration     int
	MediumRiskSessionDuration  int
	HighRiskSessionDuration    int
	CriticalRiskSessionDuration int

	// MFA requirements
	DefaultMFAMethods []string
	StrongMFAMethods  []string

	// Evaluation cache TTL
	CacheTTL time.Duration
}

// DefaultPolicyConfig returns default policy configuration
func DefaultPolicyConfig() PolicyConfig {
	return PolicyConfig{
		DefaultLowThreshold:       30,
		DefaultMediumThreshold:    50,
		DefaultHighThreshold:      70,
		DefaultCriticalThreshold:  90,
		LowRiskSessionDuration:    480,      // 8 hours
		MediumRiskSessionDuration: 240,     // 4 hours
		HighRiskSessionDuration:   60,      // 1 hour
		CriticalRiskSessionDuration: 15,    // 15 minutes
		DefaultMFAMethods:         []string{"totp", "webauthn"},
		StrongMFAMethods:          []string{"webauthn", "push"},
		CacheTTL:                  5 * time.Minute,
	}
}

// PolicyEngine evaluates risk against tenant policies
type PolicyEngine struct {
	db         *database.PostgresDB
	redis      *database.RedisClient
	config     PolicyConfig
	httpClient *http.Client
	logger     *zap.Logger
	behavior   *BehaviorTracker
}

// NewPolicyEngine creates a new policy engine
func NewPolicyEngine(db *database.PostgresDB, redis *database.RedisClient, config PolicyConfig, logger *zap.Logger) *PolicyEngine {
	if logger == nil {
		logger = zap.NewNop()
	}
	if config.DefaultLowThreshold == 0 {
		config = DefaultPolicyConfig()
	}

	return &PolicyEngine{
		db:         db,
		redis:      redis,
		config:     config,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		logger:     logger.With(zap.String("component", "policy_engine")),
		behavior:   NewBehaviorTracker(db, redis, DefaultBehaviorConfig(), logger),
	}
}

// SetBehaviorTracker sets the behavior tracker
func (p *PolicyEngine) SetBehaviorTracker(bt *BehaviorTracker) {
	p.behavior = bt
}

// GetTenantPolicy retrieves a tenant's risk policy, returning defaults if not set
func (p *PolicyEngine) GetTenantPolicy(ctx context.Context, tenantID string) (*TenantPolicy, error) {
	// Try Redis cache first
	cacheKey := fmt.Sprintf("%s%s", policyKeyPrefix, tenantID)
	cached, err := p.redis.Client.Get(ctx, cacheKey).Result()
	if err == nil {
		var policy TenantPolicy
		if json.Unmarshal([]byte(cached), &policy) == nil {
			return &policy, nil
		}
	}

	// Query database
	var policy TenantPolicy
	dbErr := p.db.Pool.QueryRow(ctx,
		`SELECT tenant_id, low_threshold, medium_threshold, high_threshold, critical_threshold,
		         enabled, created_at, updated_at
		 FROM tenant_risk_policies
		 WHERE tenant_id = $1`,
		tenantID).Scan(&policy.TenantID, &policy.LowThreshold, &policy.MediumThreshold,
		&policy.HighThreshold, &policy.CriticalThreshold, &policy.Enabled,
		&policy.CreatedAt, &policy.UpdatedAt)

	if dbErr != nil {
		// Return default policy
		policy = TenantPolicy{
			TenantID:           tenantID,
			LowThreshold:       p.config.DefaultLowThreshold,
			MediumThreshold:    p.config.DefaultMediumThreshold,
			HighThreshold:      p.config.DefaultHighThreshold,
			CriticalThreshold:  p.config.DefaultCriticalThreshold,
			Enabled:            true,
			CreatedAt:          time.Now(),
			UpdatedAt:          time.Now(),
		}
	}

	// Cache the result
	data, _ := json.Marshal(policy)
	p.redis.Client.Set(ctx, cacheKey, data, p.config.CacheTTL)

	return &policy, nil
}

// SetTenantPolicy creates or updates a tenant's risk policy
func (p *PolicyEngine) SetTenantPolicy(ctx context.Context, policy *TenantPolicy) error {
	now := time.Now()
	policy.UpdatedAt = now

	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = now
	}

	// Set defaults if not provided
	if policy.LowThreshold == 0 {
		policy.LowThreshold = p.config.DefaultLowThreshold
	}
	if policy.MediumThreshold == 0 {
		policy.MediumThreshold = p.config.DefaultMediumThreshold
	}
	if policy.HighThreshold == 0 {
		policy.HighThreshold = p.config.DefaultHighThreshold
	}
	if policy.CriticalThreshold == 0 {
		policy.CriticalThreshold = p.config.DefaultCriticalThreshold
	}

	// Upsert into database
	_, err := p.db.Pool.Exec(ctx,
		`INSERT INTO tenant_risk_policies
		 (tenant_id, low_threshold, medium_threshold, high_threshold, critical_threshold, enabled, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (tenant_id) DO UPDATE
		 SET low_threshold = EXCLUDED.low_threshold,
		     medium_threshold = EXCLUDED.medium_threshold,
		     high_threshold = EXCLUDED.high_threshold,
		     critical_threshold = EXCLUDED.critical_threshold,
		     enabled = EXCLUDED.enabled,
		     updated_at = EXCLUDED.updated_at`,
		policy.TenantID, policy.LowThreshold, policy.MediumThreshold,
		policy.HighThreshold, policy.CriticalThreshold, policy.Enabled,
		policy.CreatedAt, policy.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to set tenant policy: %w", err)
	}

	// Invalidate cache
	cacheKey := fmt.Sprintf("%s%s", policyKeyPrefix, policy.TenantID)
	p.redis.Client.Del(ctx, cacheKey)

	p.logger.Info("Tenant risk policy updated",
		zap.String("tenant_id", policy.TenantID),
		zap.Int("low_threshold", policy.LowThreshold),
		zap.Int("medium_threshold", policy.MediumThreshold),
		zap.Int("high_threshold", policy.HighThreshold),
		zap.Int("critical_threshold", policy.CriticalThreshold),
	)

	return nil
}

// Evaluate performs risk evaluation based on the request
func (p *PolicyEngine) Evaluate(ctx context.Context, req EvaluateRequest) (*EvaluateResponse, error) {
	requestID := uuid.New().String()
	startTime := time.Now()

	// Get tenant policy
	policy, err := p.GetTenantPolicy(ctx, req.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant policy: %w", err)
	}

	if !policy.Enabled {
		// Policy disabled - allow all
		return &EvaluateResponse{
			RequestID:   requestID,
			RiskScore:   0,
			RiskLevel:   RiskLevelLow,
			Action:      AuthActionAllow,
			Reasons:     []string{"policy_disabled"},
			RequireMFA:  false,
			Allowed:     true,
			EvaluatedAt: startTime,
		}, nil
	}

	response := &EvaluateResponse{
		RequestID:   requestID,
		EvaluatedAt: startTime,
		Reasons:     []string{},
		Anomalies:   []string{},
	}

	// Detect behavioral anomalies
	anomalies, behaviorScore := p.behavior.DetectAnomalies(
		ctx,
		req.UserID,
		req.IPAddress,
		req.UserAgent,
		req.Latitude,
		req.Longitude,
		time.Now(),
	)

	response.Anomalies = anomalies
	baseScore := behaviorScore

	// Additional risk factors
	reasons := []string{}

	// Check for known malicious IP
	ipRisk := p.checkIPRisk(ctx, req.IPAddress)
	baseScore += ipRisk.Score
	if ipRisk.Score > 0 {
		reasons = append(reasons, ipRisk.Reason...)
	}

	// Check device trust
	if req.DeviceFingerprint != "" {
		deviceRisk := p.checkDeviceRisk(ctx, req.UserID, req.DeviceFingerprint)
		baseScore += deviceRisk
		if deviceRisk > 0 {
			reasons = append(reasons, fmt.Sprintf("untrusted_device:%d", deviceRisk))
		}
	}

	// Check for recent failed attempts
	failedRisk := p.checkFailedAttempts(ctx, req.UserID, req.IPAddress)
	baseScore += failedRisk
	if failedRisk > 0 {
		reasons = append(reasons, fmt.Sprintf("recent_failures:%d", failedRisk))
	}

	// Calculate final risk score (cap at 100)
	if baseScore > 100 {
		baseScore = 100
	}
	response.RiskScore = baseScore
	response.Reasons = reasons

	// Determine risk level and action based on tenant thresholds
	response.RiskLevel = p.determineRiskLevel(baseScore, policy)
	response.Action = p.determineAction(baseScore, policy)

	// Set additional response fields based on action
	switch response.Action {
	case AuthActionAllow:
		response.Allowed = true
		response.RequireMFA = false
		duration := p.config.LowRiskSessionDuration
		response.SessionDuration = &duration

	case AuthActionRequireMFA:
		response.Allowed = true
		response.RequireMFA = true
		response.MFAMethods = p.config.DefaultMFAMethods
		duration := p.config.MediumRiskSessionDuration
		response.SessionDuration = &duration

	case AuthActionRequireStrongMFA:
		response.Allowed = true
		response.RequireMFA = true
		response.MFAMethods = p.config.StrongMFAMethods
		duration := p.config.HighRiskSessionDuration
		response.SessionDuration = &duration

	case AuthActionRequireApproval:
		response.Allowed = false
		response.RequireApproval = true
		duration := p.config.HighRiskSessionDuration
		response.SessionDuration = &duration

	case AuthActionBlock:
		response.Allowed = false
		response.Reasons = append(response.Reasons, "risk_threshold_exceeded")

	case AuthActionBlockAndAlert:
		response.Allowed = false
		response.Reasons = append(response.Reasons, "risk_threshold_exceeded_alert")
		// Trigger alert
		p.triggerHighRiskAlert(ctx, req, baseScore, anomalies)
	}

	// Log the evaluation
	p.logger.Info("Risk evaluation completed",
		zap.String("request_id", requestID),
		zap.String("tenant_id", req.TenantID),
		zap.String("user_id", req.UserID),
		zap.Int("risk_score", baseScore),
		zap.String("risk_level", string(response.RiskLevel)),
		zap.String("action", string(response.Action)),
		zap.Bool("allowed", response.Allowed),
	)

	return response, nil
}

// determineRiskLevel determines the risk level based on score and thresholds
func (p *PolicyEngine) determineRiskLevel(score int, policy *TenantPolicy) RiskLevel {
	switch {
	case score < policy.LowThreshold:
		return RiskLevelLow
	case score < policy.MediumThreshold:
		return RiskLevelMedium
	case score < policy.HighThreshold:
		return RiskLevelHigh
	default:
		return RiskLevelCritical
	}
}

// determineAction determines the auth action based on score and thresholds
func (p *PolicyEngine) determineAction(score int, policy *TenantPolicy) AuthAction {
	switch {
	case score < policy.LowThreshold:
		return AuthActionAllow
	case score < policy.MediumThreshold:
		return AuthActionRequireMFA
	case score < policy.HighThreshold:
		return AuthActionRequireStrongMFA
	case score < policy.CriticalThreshold:
		return AuthActionRequireApproval
	default:
		return AuthActionBlockAndAlert
	}
}

// IPRiskResult represents IP risk assessment result
type IPRiskResult struct {
	Score  int      `json:"score"`
	Reason []string `json:"reason"`
}

// checkIPRisk checks IP-based risk factors
func (p *PolicyEngine) checkIPRisk(ctx context.Context, ip string) IPRiskResult {
	result := IPRiskResult{}

	// Check if IP is on blocklist
	var blocked bool
	var reason string
	err := p.db.Pool.QueryRow(ctx,
		`SELECT blocked FROM ip_blocklist WHERE ip_address = $1 AND (permanent = true OR blocked_until > NOW())`,
		ip).Scan(&blocked)

	if err == nil && blocked {
		result.Score = 100
		result.Reason = append(result.Reason, "ip_blocklisted")
		return result
	}

	// Check for known Tor exit node
	var isTor bool
	p.db.Pool.QueryRow(ctx,
		`SELECT is_tor FROM ip_threat_list WHERE ip_address = $1 AND (permanent = true OR blocked_until > NOW())`,
		ip).Scan(&isTor)

	if isTor {
		result.Score = 40
		result.Reason = append(result.Reason, "tor_exit_node")
	}

	// Check for VPN
	var isVPN bool
	p.db.Pool.QueryRow(ctx,
		`SELECT is_vpn FROM ip_threat_list WHERE ip_address = $1 AND (permanent = true OR blocked_until > NOW())`,
		ip).Scan(&isVPN)

	if isVPN {
		result.Score += 20
		result.Reason = append(result.Reason, "vpn_detected")
	}

	return result
}

// checkDeviceRisk checks device-based risk factors
func (p *PolicyEngine) checkDeviceRisk(ctx context.Context, userID, fingerprint string) int {
	var trusted bool
	err := p.db.Pool.QueryRow(ctx,
		`SELECT trusted FROM known_devices WHERE user_id = $1 AND fingerprint = $2`,
		userID, fingerprint).Scan(&trusted)

	if err != nil {
		// Device not found - new device risk
		return 30
	}

	if !trusted {
		return 15
	}

	return 0
}

// checkFailedAttempts checks for recent failed login attempts
func (p *PolicyEngine) checkFailedAttempts(ctx context.Context, userID, ip string) int {
	var count int

	// Check user-specific failures
	err := p.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM login_history
		 WHERE user_id = $1 AND success = false AND created_at > NOW() - INTERVAL '1 hour'`,
		userID).Scan(&count)

	if err == nil && count > 0 {
		// 10 points per failure, max 50
		score := count * 10
		if score > 50 {
			score = 50
		}
		return score
	}

	// Check IP-based failures
	err = p.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM login_history
		 WHERE ip_address = $1 AND success = false AND created_at > NOW() - INTERVAL '15 minutes'`,
		ip).Scan(&count)

	if err == nil && count > 5 {
		return 30
	}

	return 0
}

// triggerHighRiskAlert creates a security alert for high-risk events
func (p *PolicyEngine) triggerHighRiskAlert(ctx context.Context, req EvaluateRequest, score int, anomalies []string) {
	alert := &SecurityAlert{
		ID:        uuid.New().String(),
		UserID:    &req.UserID,
		AlertType: "high_risk_login_blocked",
		Severity:  "critical",
		Status:    "open",
		Title:     "High Risk Login Blocked",
		Description: fmt.Sprintf(
			"Login attempt blocked due to high risk score (%d). User: %s, IP: %s",
			score, req.UserID, req.IPAddress,
		),
		Details: map[string]interface{}{
			"tenant_id":     req.TenantID,
			"user_id":       req.UserID,
			"ip_address":    req.IPAddress,
			"user_agent":    req.UserAgent,
			"risk_score":    score,
			"anomalies":     anomalies,
			"latitude":      req.Latitude,
			"longitude":     req.Longitude,
		},
		SourceIP:           req.IPAddress,
		RemediationActions: []string{"verify_identity", "require_mfa", "notify_admin"},
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}

	// Store in database (will be picked up by alert delivery system)
	err := p.CreateSecurityAlert(ctx, alert)
	if err != nil {
		p.logger.Error("Failed to create security alert", zap.Error(err))
	}
}

// CreateSecurityAlert creates a security alert in the database
func (p *PolicyEngine) CreateSecurityAlert(ctx context.Context, alert *SecurityAlert) error {
	detailsJSON, _ := json.Marshal(alert.Details)
	remediationJSON, _ := json.Marshal(alert.RemediationActions)

	_, err := p.db.Pool.Exec(ctx,
		`INSERT INTO security_alerts
		 (id, user_id, alert_type, severity, status, title, description, details, source_ip, remediation_actions, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		alert.ID, alert.UserID, alert.AlertType, alert.Severity, alert.Status,
		alert.Title, alert.Description, detailsJSON, alert.SourceIP,
		remediationJSON, alert.CreatedAt, alert.UpdatedAt)

	return err
}

// GetRiskStatistics returns risk statistics for a tenant
func (p *PolicyEngine) GetRiskStatistics(ctx context.Context, tenantID string, days int) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Get risk score distribution from login_history
	rows, err := p.db.Pool.Query(ctx,
		`SELECT
				COUNT(*) FILTER (WHERE risk_score < 30) as low_count,
				COUNT(*) FILTER (WHERE risk_score >= 30 AND risk_score < 50) as medium_count,
				COUNT(*) FILTER (WHERE risk_score >= 50 AND risk_score < 70) as high_count,
				COUNT(*) FILTER (WHERE risk_score >= 70) as critical_count,
				AVG(risk_score) as avg_score,
				MAX(risk_score) as max_score
		 FROM login_history
		 WHERE created_at > NOW() - ($1::int || ' days')::interval`)
	if err == nil {
		var lowCount, mediumCount, highCount, criticalCount int
		var avgScore float64
		var maxScore int

		rows.Next()
		rows.Scan(&lowCount, &mediumCount, &highCount, &criticalCount, &avgScore, &maxScore)
		rows.Close()

		stats["low_risk_count"] = lowCount
		stats["medium_risk_count"] = mediumCount
		stats["high_risk_count"] = highCount
		stats["critical_risk_count"] = criticalCount
		stats["average_score"] = avgScore
		stats["max_score"] = maxScore
	}

	// Get blocked login count
	var blockedCount int
	p.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM login_history
		 WHERE success = false AND created_at > NOW() - ($1::int || ' days')::interval`,
		days).Scan(&blockedCount)
	stats["blocked_count"] = blockedCount

	// Get MFA required count
	var mfaRequiredCount int
	p.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM login_history
		 WHERE risk_score >= 30 AND risk_score < 70 AND success = true
		 AND created_at > NOW() - ($1::int || ' days')::interval`,
		days).Scan(&mfaRequiredCount)
	stats["mfa_required_count"] = mfaRequiredCount

	return stats, nil
}

// DeleteTenantPolicy deletes a tenant's risk policy
func (p *PolicyEngine) DeleteTenantPolicy(ctx context.Context, tenantID string) error {
	_, err := p.db.Pool.Exec(ctx,
		`DELETE FROM tenant_risk_policies WHERE tenant_id = $1`, tenantID)

	if err != nil {
		return fmt.Errorf("failed to delete tenant policy: %w", err)
	}

	// Invalidate cache
	cacheKey := fmt.Sprintf("%s%s", policyKeyPrefix, tenantID)
	p.redis.Client.Del(ctx, cacheKey)

	p.logger.Info("Tenant risk policy deleted", zap.String("tenant_id", tenantID))

	return nil
}
