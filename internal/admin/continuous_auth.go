// Package admin provides a continuous authentication engine with risk scoring
// This module implements continuous authentication that evaluates user sessions
// for anomalies and requires reauthentication based on risk signals.
package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// AuthContext represents the current authentication context of a session
type AuthContext struct {
	SessionID         string                 `json:"session_id"`
	UserID            string                 `json:"user_id"`
	AuthTime          time.Time              `json:"auth_time"`
	AuthMethod        string                 `json:"auth_method"`
	AuthStrength      string                 `json:"auth_strength"` // low, medium, high
	CurrentRiskScore  float64                `json:"current_risk_score"`
	DeviceFingerprint string                 `json:"device_fingerprint"`
	IPAddress         string                 `json:"ip_address"`
	Location          *GeoLocation           `json:"location,omitempty"`
	UserAgent         string                 `json:"user_agent"`
	Metadata          map[string]interface{} `json:"metadata"`
	UpdatedAt         time.Time              `json:"updated_at"`
}

// RiskFactor represents a specific risk factor in the authentication context
type RiskFactor struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Severity    float64   `json:"severity"` // 0-1
	Description string    `json:"description"`
	DetectedAt  time.Time `json:"detected_at"`
	Resolved    bool      `json:"resolved"`
	ResolvedAt  *time.Time `json:"resolved_at,omitempty"`
}

// SessionRisk represents the calculated risk for a session
type SessionRisk struct {
	SessionID        string                 `json:"session_id"`
	OverallRisk      float64                `json:"overall_risk"`      // 0-100
	RiskLevel        string                 `json:"risk_level"`        // low, medium, high, critical
	RiskFactors      []RiskFactor           `json:"risk_factors"`
	ActionRequired   string                 `json:"action_required"`   // none, monitor, step_up, terminate
	RecommendedAuth  string                 `json:"recommended_auth"`  // mfa, reauth, password
	CalculatedAt     time.Time              `json:"calculated_at"`
	PreviousRisk     float64                `json:"previous_risk"`
	RiskDelta        float64                `json:"risk_delta"`        // change in risk
	Context          map[string]interface{} `json:"context"`
}

// ContinuousAuthConfig represents configuration for continuous auth
type ContinuousAuthConfig struct {
	Enabled                   bool              `json:"enabled"`
	RiskEvaluationInterval    time.Duration     `json:"risk_evaluation_interval"`
	HighRiskThreshold         float64           `json:"high_risk_threshold"`          // default 70
	MediumRiskThreshold       float64           `json:"medium_risk_threshold"`        // default 40
	CriticalRiskThreshold     float64           `json:"critical_risk_threshold"`       // default 90
	SessionMaxLifetime        time.Duration     `json:"session_max_lifetime"`
	IdleTimeout              time.Duration     `json:"idle_timeout"`
	StepUpAuthRequired       bool              `json:"step_up_auth_required"`
	DeviceFingerprintEnabled bool              `json:"device_fingerprint_enabled"`
	GeoAnomalyEnabled        bool              `json:"geo_anomaly_enabled"`
	BehavioralAnalysis       bool              `json:"behavioral_analysis"`
	RiskFactors              map[string]float64 `json:"risk_factors"` // weight for each factor
}

// continuousAuthService handles continuous authentication
type continuousAuthService struct {
	db     *database.PostgresDB
	logger *zap.Logger
	config *ContinuousAuthConfig
}

// CalculateSessionRisk calculates the current risk score for a session
func (s *continuousAuthService) CalculateSessionRisk(ctx context.Context, sessionID string) (*SessionRisk, error) {
	// Get current session context
	authCtx, err := s.GetAuthContext(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth context: %w", err)
	}

	// Get previous risk score for delta calculation
	var previousRisk float64
	s.db.Pool.QueryRow(ctx, `
		SELECT overall_risk FROM session_risks WHERE session_id = $1 ORDER BY calculated_at DESC LIMIT 1
	`, sessionID).Scan(&previousRisk)

	risk := &SessionRisk{
		SessionID:    sessionID,
		RiskFactors:  []RiskFactor{},
		CalculatedAt: time.Now(),
		PreviousRisk: previousRisk,
		Context:      make(map[string]interface{}),
	}

	// Calculate individual risk factors
	totalRisk := 0.0

	// 1. Time-based risk (session age)
	timeRisk := s.calculateTimeRisk(ctx, authCtx)
	totalRisk += timeRisk * s.config.RiskFactors["session_age"]

	// 2. Location/IP risk
	geoRisk := s.calculateGeoRisk(ctx, authCtx)
	totalRisk += geoRisk * s.config.RiskFactors["geo_anomaly"]

	// 3. Device fingerprint risk
	deviceRisk := s.calculateDeviceRisk(ctx, authCtx)
	totalRisk += deviceRisk * s.config.RiskFactors["device_anomaly"]

	// 4. Behavioral risk
	behaviorRisk := s.calculateBehaviorRisk(ctx, authCtx)
	totalRisk += behaviorRisk * s.config.RiskFactors["behavioral_anomaly"]

	// 5. Velocity risk (rapid actions)
	velocityRisk := s.calculateVelocityRisk(ctx, authCtx)
	totalRisk += velocityRisk * s.config.RiskFactors["velocity"]

	// Normalize to 0-100
	risk.OverallRisk = math.Min(totalRisk, 100)

	// Determine risk level
	risk.RiskLevel = s.determineRiskLevel(risk.OverallRisk)

	// Determine required action
	risk.ActionRequired = s.determineActionRequired(risk.RiskLevel)
	risk.RecommendedAuth = s.getRecommendedAuth(risk.RiskLevel)

	// Calculate delta
	risk.RiskDelta = risk.OverallRisk - previousRisk

	// Store risk calculation
	_, _ = s.db.Pool.Exec(ctx, `
		INSERT INTO session_risks (session_id, overall_risk, risk_level, action_required, risk_factors, calculated_at, previous_risk, risk_delta)
		VALUES ($1, $2, $3, $4, $5, NOW(), $6, $7)
	`, sessionID, risk.OverallRisk, risk.RiskLevel, risk.ActionRequired,
		[]byte("{}"), previousRisk, risk.RiskDelta)

	return risk, nil
}

// GetAuthContext retrieves the current authentication context for a session
func (s *continuousAuthService) GetAuthContext(ctx context.Context, sessionID string) (*AuthContext, error) {
	var authCtx AuthContext
	var metadata []byte

	err := s.db.Pool.QueryRow(ctx, `
		SELECT session_id, user_id, auth_time, auth_method, auth_strength, current_risk_score,
			device_fingerprint, ip_address, location, user_agent, metadata, updated_at
		FROM auth_contexts WHERE session_id = $1
	`, sessionID).Scan(
		&authCtx.SessionID, &authCtx.UserID, &authCtx.AuthTime, &authCtx.AuthMethod,
		&authCtx.AuthStrength, &authCtx.CurrentRiskScore, &authCtx.DeviceFingerprint,
		&authCtx.IPAddress, &authCtx.Location, &authCtx.UserAgent, &metadata, &authCtx.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	json.Unmarshal(metadata, &authCtx.Metadata)
	return &authCtx, nil
}

// UpdateAuthScore updates the authentication score based on new events
func (s *continuousAuthService) UpdateAuthScore(ctx context.Context, sessionID string, event string, metadata map[string]interface{}) error {
	// Get current context
	authCtx, err := s.GetAuthContext(ctx, sessionID)
	if err != nil {
		return err
	}

	// Update based on event type
	scoreAdjustment := 0.0

	switch event {
	case "sensitive_access":
		scoreAdjustment = -5 // Decrease risk (positive signal)
	case "failed_auth":
		scoreAdjustment = 20
	case "new_location":
		scoreAdjustment = 30
	case "new_device":
		scoreAdjustment = 25
	case "impossible_travel":
		scoreAdjustment = 50
	case "mass_download":
		scoreAdjustment = 40
	}

	authCtx.CurrentRiskScore = math.Max(0, math.Min(100, authCtx.CurrentRiskScore+scoreAdjustment))
	authCtx.UpdatedAt = time.Now()

	// Store updated context
	metadataJSON, _ := json.Marshal(authCtx.Metadata)
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE auth_contexts
		SET current_risk_score = $1, updated_at = NOW(), metadata = $2
		WHERE session_id = $3
	`, authCtx.CurrentRiskScore, metadataJSON, sessionID)

	return err
}

// RequireReauthentication checks if reauthentication is required
func (s *continuousAuthService) RequireReauthentication(ctx context.Context, sessionID string) (bool, string, error) {
	risk, err := s.CalculateSessionRisk(ctx, sessionID)
	if err != nil {
		return false, "", err
	}

	if risk.ActionRequired == "terminate" {
		return true, "session_terminated", nil
	}

	if risk.ActionRequired == "step_up" {
		return true, risk.RecommendedAuth, nil
	}

	// Check session age
	authCtx, _ := s.GetAuthContext(ctx, sessionID)
	if authCtx != nil && time.Since(authCtx.AuthTime) > s.config.SessionMaxLifetime {
		return true, "session_expired", nil
	}

	return false, "", nil
}

// GetRiskFactors returns detailed risk factors for a session
func (s *continuousAuthService) GetRiskFactors(ctx context.Context, sessionID string) ([]RiskFactor, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, type, severity, description, detected_at, resolved, resolved_at
		FROM risk_factors
		WHERE session_id = $1 AND resolved = false
		ORDER BY severity DESC, detected_at DESC
	`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	factors := []RiskFactor{}
	for rows.Next() {
		var f RiskFactor
		rows.Scan(&f.ID, &f.Type, &f.Severity, &f.Description, &f.DetectedAt, &f.Resolved, &f.ResolvedAt)
		factors = append(factors, f)
	}

	return factors, nil
}

// Risk calculation helpers

func (s *continuousAuthService) calculateTimeRisk(ctx context.Context, authCtx *AuthContext) float64 {
	sessionAge := time.Since(authCtx.AuthTime)

	// Risk increases with session age
	if sessionAge > 8*time.Hour {
		return 30
	} else if sessionAge > 4*time.Hour {
		return 20
	} else if sessionAge > 2*time.Hour {
		return 10
	} else if sessionAge > 1*time.Hour {
		return 5
	}

	return 0
}

func (s *continuousAuthService) calculateGeoRisk(ctx context.Context, authCtx *AuthContext) float64 {
	// Check for impossible travel
	var previousIP string
	var previousTime time.Time
	s.db.Pool.QueryRow(ctx, `
		SELECT ip_address, auth_time FROM auth_contexts
		WHERE user_id = $1 AND session_id != $2
		ORDER BY auth_time DESC LIMIT 1
	`, authCtx.UserID, authCtx.SessionID).Scan(&previousIP, &previousTime)

	if previousIP != "" && authCtx.IPAddress != previousIP {
		// Calculate distance and speed
		// This would integrate with a GeoIP service
		// For now, return moderate risk for IP change
		return 15
	}

	return 0
}

func (s *continuousAuthService) calculateDeviceRisk(ctx context.Context, authCtx *AuthContext) float64 {
	// Check if this is a known device
	var isKnown bool
	s.db.Pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM user_devices
			WHERE user_id = $1 AND device_fingerprint = $2 AND trusted = true)
	`, authCtx.UserID, authCtx.DeviceFingerprint).Scan(&isKnown)

	if !isKnown {
		return 25
	}

	return 0
}

func (s *continuousAuthService) calculateBehaviorRisk(ctx context.Context, authCtx *AuthContext) float64 {
	// Analyze behavioral patterns
	// Check for rapid actions, unusual access times, etc.

	// Check for actions outside normal hours
	hour := time.Now().Hour()
	if hour < 6 || hour > 22 {
		// Outside business hours - slightly elevated risk
		return 5
	}

	return 0
}

func (s *continuousAuthService) calculateVelocityRisk(ctx context.Context, authCtx *AuthContext) float64 {
	// Check for rapid successive actions
	var actionCount int
	s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_logs
		WHERE user_id = $1 AND created_at > NOW() - INTERVAL '1 minute'
	`, authCtx.UserID).Scan(&actionCount)

	if actionCount > 100 {
		return 40 // Very high velocity
	} else if actionCount > 50 {
		return 30
	} else if actionCount > 20 {
		return 15
	}

	return 0
}

func (s *continuousAuthService) determineRiskLevel(score float64) string {
	if score >= s.config.CriticalRiskThreshold {
		return "critical"
	} else if score >= s.config.HighRiskThreshold {
		return "high"
	} else if score >= s.config.MediumRiskThreshold {
		return "medium"
	}
	return "low"
}

func (s *continuousAuthService) determineActionRequired(level string) string {
	switch level {
	case "critical":
		return "terminate"
	case "high":
		return "step_up"
	case "medium":
		return "monitor"
	default:
		return "none"
	}
}

func (s *continuousAuthService) getRecommendedAuth(level string) string {
	switch level {
	case "critical", "high":
		return "mfa"
	case "medium":
		return "reauth"
	default:
		return ""
	}
}

// Handlers

func (s *Service) handleContinuousAuthGetRisk(c *gin.Context) {
	ctx := c.Request.Context()
	sessionID := c.Query("session_id")

	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session_id required"})
		return
	}

	config := &ContinuousAuthConfig{
		Enabled:                true,
		RiskEvaluationInterval:  5 * time.Minute,
		HighRiskThreshold:       70,
		MediumRiskThreshold:     40,
		CriticalRiskThreshold:   90,
		SessionMaxLifetime:      8 * time.Hour,
		IdleTimeout:             30 * time.Minute,
		RiskFactors: map[string]float64{
			"session_age":       0.3,
			"geo_anomaly":       0.25,
			"device_anomaly":    0.2,
			"behavioral_anomaly": 0.15,
			"velocity":          0.1,
		},
	}

	authService := &continuousAuthService{db: s.db, logger: s.logger, config: config}

	risk, err := authService.CalculateSessionRisk(ctx, sessionID)
	if err != nil {
		s.logger.Error("failed to calculate session risk", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to calculate risk"})
		return
	}

	c.JSON(http.StatusOK, risk)
}

func (s *Service) handleContinuousAuthCheck(c *gin.Context) {
	ctx := c.Request.Context()

	var req struct {
		SessionID string `json:"session_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	config := &ContinuousAuthConfig{SessionMaxLifetime: 8 * time.Hour}
	authService := &continuousAuthService{db: s.db, logger: s.logger, config: config}

	required, reason, err := authService.RequireReauthentication(ctx, req.SessionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check auth status"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"reauth_required": required,
		"reason":         reason,
	})
}

func (s *Service) handleContinuousAuthUpdate(c *gin.Context) {
	ctx := c.Request.Context()

	var req struct {
		SessionID string                 `json:"session_id" binding:"required"`
		Event     string                 `json:"event" binding:"required"`
		Metadata  map[string]interface{} `json:"metadata"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	authService := &continuousAuthService{db: s.db, logger: s.logger, config: &ContinuousAuthConfig{}}
	err := authService.UpdateAuthScore(ctx, req.SessionID, req.Event, req.Metadata)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update auth score"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "auth score updated"})
}

// GeoLocation represents geographical location data
type GeoLocation struct {
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ASN         int     `json:"asn"`
}
