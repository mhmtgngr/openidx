// Package admin provides a continuous authentication engine with risk scoring
// This module implements continuous authentication that evaluates user sessions
// for anomalies and requires reauthentication based on risk signals.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"

	"github.com/openidx/openidx/internal/common/logsafe"
)

// AuthContext represents the current authentication context of a session
type AuthContext struct {
	SessionID         string    `json:"session_id"`
	UserID            string    `json:"user_id"`
	AuthTime          time.Time `json:"auth_time"`
	AuthMethod        string    `json:"auth_method"`
	AuthStrength      string    `json:"auth_strength"` // low, medium, high
	CurrentRiskScore  float64   `json:"current_risk_score"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	IPAddress         string    `json:"ip_address"`
	// Location is the label sessions.location carries ("Istanbul, TR"), not a
	// coordinate. It was typed *GeoLocation -- a struct with latitude,
	// longitude and ASN -- and read from a TEXT column, which is the clearest
	// single proof that the query below it never ran against a row: the scan
	// destination was a **GeoLocation and would have failed on type every time.
	// GeoLocation described a shape nothing in the product ever produced and
	// has been removed with it.
	Location  string                 `json:"location,omitempty"`
	UserAgent string                 `json:"user_agent"`
	Metadata  map[string]interface{} `json:"metadata"`
	UpdatedAt time.Time              `json:"updated_at"`
}

// RiskFactor represents a specific risk factor in the authentication context
type RiskFactor struct {
	ID          string     `json:"id"`
	Type        string     `json:"type"`
	Severity    float64    `json:"severity"` // 0-1
	Description string     `json:"description"`
	DetectedAt  time.Time  `json:"detected_at"`
	Resolved    bool       `json:"resolved"`
	ResolvedAt  *time.Time `json:"resolved_at,omitempty"`
}

// SessionRisk represents the calculated risk for a session
type SessionRisk struct {
	SessionID       string                 `json:"session_id"`
	OverallRisk     float64                `json:"overall_risk"` // 0-100
	RiskLevel       string                 `json:"risk_level"`   // low, medium, high, critical
	RiskFactors     []RiskFactor           `json:"risk_factors"`
	ActionRequired  string                 `json:"action_required"`  // none, monitor, step_up, terminate
	RecommendedAuth string                 `json:"recommended_auth"` // mfa, reauth, password
	CalculatedAt    time.Time              `json:"calculated_at"`
	PreviousRisk    float64                `json:"previous_risk"`
	RiskDelta       float64                `json:"risk_delta"` // change in risk
	Context         map[string]interface{} `json:"context"`
}

// ContinuousAuthConfig represents configuration for continuous auth
type ContinuousAuthConfig struct {
	Enabled                  bool               `json:"enabled"`
	RiskEvaluationInterval   time.Duration      `json:"risk_evaluation_interval"`
	HighRiskThreshold        float64            `json:"high_risk_threshold"`     // default 70
	MediumRiskThreshold      float64            `json:"medium_risk_threshold"`   // default 40
	CriticalRiskThreshold    float64            `json:"critical_risk_threshold"` // default 90
	SessionMaxLifetime       time.Duration      `json:"session_max_lifetime"`
	IdleTimeout              time.Duration      `json:"idle_timeout"`
	StepUpAuthRequired       bool               `json:"step_up_auth_required"`
	DeviceFingerprintEnabled bool               `json:"device_fingerprint_enabled"`
	GeoAnomalyEnabled        bool               `json:"geo_anomaly_enabled"`
	BehavioralAnalysis       bool               `json:"behavioral_analysis"`
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

	org, orgErr := orgctx.From(ctx)
	if orgErr != nil {
		return nil, fmt.Errorf("organization context required: %w", orgErr)
	}

	// Get previous risk score for delta calculation
	var previousRisk float64
	s.db.Pool.QueryRow(ctx, `
		SELECT overall_risk FROM session_risks WHERE session_id = $1 AND org_id = $2 ORDER BY calculated_at DESC LIMIT 1
	`, sessionID, org.ID).Scan(&previousRisk)

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

	// 2. Source-address change. The RiskFactors key stays "geo_anomaly" so a
	// deployment's tuned weights keep working, but what is measured is an
	// address change, not geography — see calculateIPChangeRisk.
	ipChangeRisk := s.calculateIPChangeRisk(ctx, authCtx)
	totalRisk += ipChangeRisk * s.config.RiskFactors["geo_anomaly"]

	// 3. Device fingerprint risk. It reports whether it could measure at all;
	// an unmeasured factor contributes nothing and says so in Context, rather
	// than contributing a constant that reads like a finding.
	deviceRisk, deviceMeasured := s.calculateDeviceRisk(ctx, authCtx)
	totalRisk += deviceRisk * s.config.RiskFactors["device_anomaly"]

	// 4. Behavioral risk
	behaviorRisk := s.calculateBehaviorRisk(ctx, authCtx)
	totalRisk += behaviorRisk * s.config.RiskFactors["behavioral_anomaly"]

	// 5. Velocity risk (rapid actions)
	velocityRisk := s.calculateVelocityRisk(ctx, authCtx)
	totalRisk += velocityRisk * s.config.RiskFactors["velocity"]

	// Normalize to 0-100
	risk.OverallRisk = math.Min(totalRisk, 100)

	// Say which factors were actually measured. A score of 12 built from four
	// live factors and one that could not run is a different number from a 12
	// built from five, and the caller acting on it -- step up, terminate --
	// deserves to know which it has.
	risk.Context["factors_measured"] = map[string]bool{
		"session_age":        true,
		"ip_change":          true,
		"device_anomaly":     deviceMeasured,
		"behavioral_anomaly": true,
		"velocity":           true,
	}
	risk.Context["auth_strength"] = authCtx.AuthStrength

	// Determine risk level
	risk.RiskLevel = s.determineRiskLevel(risk.OverallRisk)

	// Determine required action
	risk.ActionRequired = s.determineActionRequired(risk.RiskLevel)
	risk.RecommendedAuth = s.getRecommendedAuth(risk.RiskLevel)

	// Calculate delta - ensure non-negative and clamp to valid range
	risk.RiskDelta = risk.OverallRisk - previousRisk
	// Prevent negative riskDelta values and clamp to 0-100 range
	risk.RiskDelta = math.Max(0, math.Min(100, risk.RiskDelta))
	// Also clamp overall risk to 0-100 range
	risk.OverallRisk = math.Max(0, math.Min(100, risk.OverallRisk))

	// Store risk calculation (v77 created session_risks; failures are logged,
	// not swallowed — the risk score is still returned either way)
	if _, err := s.db.Pool.Exec(ctx, `
		INSERT INTO session_risks (session_id, overall_risk, risk_level, action_required, risk_factors, calculated_at, previous_risk, risk_delta, org_id)
		VALUES ($1, $2, $3, $4, $5, NOW(), $6, $7, $8)
	`, sessionID, risk.OverallRisk, risk.RiskLevel, risk.ActionRequired,
		[]byte("{}"), previousRisk, risk.RiskDelta, org.ID); err != nil {
		s.logger.Warn("failed to store session risk history",
			zap.String("session_id", logsafe.Clean(sessionID)), zap.Error(err))
	}

	return risk, nil
}

// GetAuthContext retrieves the current authentication context for a session.
//
// It reads `sessions` -- the table the product actually writes on login, which
// carries org_id and has been behind the v37 FORCE-RLS belt since v37 -- plus
// the most recent score this engine itself stored in `session_risks` (v77,
// org_id NOT NULL).
//
// It used to read `auth_contexts`, a table v62 created to stop these endpoints
// 500ing and that no code path has ever written a row to: not a handler, not
// the login path, not a seed, not a migration. So this function returned "no
// rows in result set" for every session that has ever existed, and with it the
// three routes that depend on it. v157 drops the table. The tenant term was
// missing at exactly one place in this engine -- the input -- because every
// other factor below already resolves orgctx and scopes its own query.
func (s *continuousAuthService) GetAuthContext(ctx context.Context, sessionID string) (*AuthContext, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, fmt.Errorf("organization context required: %w", err)
	}

	var authCtx AuthContext
	var authMethods []string
	var startedAt, lastSeenAt *time.Time

	// The org term is what stops one tenant scoring, and with
	// RequireReauthentication terminating, another tenant's session by id.
	err = s.db.Pool.QueryRow(ctx, `
		SELECT s.id::text, s.user_id::text, s.started_at, s.last_seen_at,
		       COALESCE(s.auth_methods, '{}'), COALESCE(s.ip_address, ''),
		       COALESCE(s.user_agent, ''), COALESCE(s.location, ''),
		       COALESCE((SELECT r.overall_risk FROM session_risks r
		                  WHERE r.session_id = s.id AND r.org_id = $2
		                  ORDER BY r.calculated_at DESC LIMIT 1), 0)
		FROM sessions s
		WHERE s.id = $1 AND s.org_id = $2
	`, sessionID, org.ID).Scan(
		&authCtx.SessionID, &authCtx.UserID, &startedAt, &lastSeenAt,
		&authMethods, &authCtx.IPAddress, &authCtx.UserAgent, &authCtx.Location,
		&authCtx.CurrentRiskScore,
	)
	if err != nil {
		return nil, err
	}

	if startedAt != nil {
		authCtx.AuthTime = *startedAt
	}
	if lastSeenAt != nil {
		authCtx.UpdatedAt = *lastSeenAt
	}
	authCtx.AuthMethod = strings.Join(authMethods, ",")
	authCtx.AuthStrength = authStrength(authMethods)
	// sessions carries no device fingerprint; see calculateDeviceRisk.
	authCtx.Metadata = map[string]interface{}{}

	return &authCtx, nil
}

// authStrength grades a session by what was actually presented at login. v133
// added sessions.auth_methods for exactly this and nothing has read it since.
// A second factor is the line that matters: "high" means something beyond a
// password was proven.
func authStrength(methods []string) string {
	if len(methods) == 0 {
		return "unknown"
	}
	for _, m := range methods {
		switch strings.ToLower(m) {
		case "webauthn", "passkey", "totp", "mfa", "push", "sms", "hardware_token", "backup_code":
			return "high"
		}
	}
	if len(methods) > 1 {
		return "medium"
	}
	return "low"
}

// authScoreEventAdjustments is the risk delta each reportable event carries.
// An event outside this set is rejected rather than scored as zero: the handler
// used to accept any string, adjust by nothing and answer "auth score updated",
// so a caller mis-spelling "failed_auth" was told their report had been
// recorded.
var authScoreEventAdjustments = map[string]float64{
	"sensitive_access":  -5, // a positive signal: the user re-proved themselves
	"failed_auth":       20,
	"new_location":      30,
	"new_device":        25,
	"impossible_travel": 50,
	"mass_download":     40,
}

// errUnknownRiskEvent is returned for an event name outside the set above, so
// the handler can answer 400 rather than 500.
var errUnknownRiskEvent = errors.New("unknown risk event")

// UpdateAuthScore records a risk event against a session and stores the
// adjusted score.
//
// It used to UPDATE auth_contexts, which no row has ever existed in, so it
// matched nothing, returned nil, and POST /continuous-auth/update answered
// {"message":"auth score updated"} having updated nothing at all. The score now
// lands in session_risks -- the append-only ledger CalculateSessionRisk already
// writes to and reads previous_risk from -- under the caller's organization.
//
// The caller's metadata is recorded too. The old body marshalled
// authCtx.Metadata, the context's own map, and dropped the metadata argument on
// the floor, so whatever a reporter sent to explain the event was discarded.
func (s *continuousAuthService) UpdateAuthScore(ctx context.Context, sessionID string, event string, metadata map[string]interface{}) error {
	adjustment, known := authScoreEventAdjustments[event]
	if !known {
		return fmt.Errorf("%w: %q", errUnknownRiskEvent, event)
	}

	org, err := orgctx.From(ctx)
	if err != nil {
		return fmt.Errorf("organization context required: %w", err)
	}

	// Resolves the session under this organization: another tenant's session is
	// not found rather than scored.
	authCtx, err := s.GetAuthContext(ctx, sessionID)
	if err != nil {
		return err
	}

	previous := authCtx.CurrentRiskScore
	updated := math.Max(0, math.Min(100, previous+adjustment))
	level := s.determineRiskLevel(updated)

	payload, mErr := json.Marshal(map[string]interface{}{
		"event":      event,
		"adjustment": adjustment,
		"metadata":   metadata,
	})
	if mErr != nil {
		payload = []byte(`{}`)
	}

	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO session_risks (session_id, overall_risk, risk_level, action_required,
		                           risk_factors, calculated_at, previous_risk, risk_delta, org_id)
		VALUES ($1, $2, $3, $4, $5, NOW(), $6, $7, $8)
	`, sessionID, updated, level, s.determineActionRequired(level),
		payload, previous, updated-previous, org.ID)

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
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, fmt.Errorf("organization context required: %w", err)
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, type, severity, COALESCE(description, ''), detected_at, resolved, resolved_at
		FROM risk_factors
		WHERE session_id = $1 AND org_id = $2 AND resolved = false
		ORDER BY severity DESC, detected_at DESC
	`, sessionID, org.ID)
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

// calculateIPChangeRisk scores a change of source address between sessions.
// It was called calculateGeoRisk and documented as impossible-travel
// detection, which it has never been — see the comment at its return.
func (s *continuousAuthService) calculateIPChangeRisk(ctx context.Context, authCtx *AuthContext) float64 {
	org, err := orgctx.From(ctx)
	if err != nil {
		return 0
	}

	// Most recent session from this user, other than this one. Read from
	// sessions, which is written on every login and carries org_id; the
	// auth_contexts this used to read has never held a row, so this factor
	// could only ever have contributed 0 -- and it never ran at all, because
	// the caller failed on the same table one step earlier.
	var previousIP string
	s.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(ip_address, '') FROM sessions
		WHERE user_id = $1::uuid AND id != $2::uuid AND org_id = $3
		ORDER BY started_at DESC LIMIT 1
	`, authCtx.UserID, authCtx.SessionID, org.ID).Scan(&previousIP)

	if previousIP != "" && authCtx.IPAddress != previousIP {
		// A changed source address between two sessions, which is a real
		// signal and is what this function measures.
		//
		// It is NOT impossible-travel detection, and the name and comment used
		// to say it was ("Check for impossible travel" / "Calculate distance
		// and speed"). Distance and speed need coordinates for both addresses,
		// which needs a GeoIP lookup: GEOIP_SERVICE_URL exists in config
		// (config.go GeoIPServiceURL) and no client consults it, so the
		// factor scored a flat 15 for any address change and was labelled as
		// geography. Until a GeoIP client exists, this contributes the
		// address-change signal under its own name and claims nothing about
		// travel.
		return ipChangeRiskScore
	}

	return 0
}

// ipChangeRiskScore is the weight of "this session started from a different
// address than the last one". Modest on purpose: a phone moving between wifi
// and cellular changes address constantly, so on its own it must not push a
// session over a gate.
const ipChangeRiskScore = 15

// calculateDeviceRisk scores the session's device against the tenant's trusted
// devices, and reports whether it could measure anything at all.
//
// It checks known_devices — the table device trust actually lives in. The
// original EXISTS read a nonexistent user_devices table and swallowed the
// error, so this factor always contributed 0 and continuous auth under-scored
// every session on an unrecognized device.
//
// The lookup needs a fingerprint, and there is currently no way to get one for
// a session: sessions carries device_name and device_type but no fingerprint,
// and login_history — which does record device_fingerprint — has no session_id
// to join on. So for now this reports "not measured" rather than asserting the
// 25 of an unknown device on every session, which would be a constant dressed
// as a measurement, the same shape as the flat 15 this file's IP factor used to
// return under the name of impossible travel. Giving sessions a fingerprint at
// login is a feature; it is named in the readiness guide rather than guessed at
// here. The returned flag is reported in the response so a caller can see which
// factors are live.
func (s *continuousAuthService) calculateDeviceRisk(ctx context.Context, authCtx *AuthContext) (float64, bool) {
	if authCtx.DeviceFingerprint == "" {
		return 0, false
	}
	org, err := orgctx.From(ctx)
	if err != nil {
		return 25, true // org context is required upstream; unknown device is the safe read
	}
	var isKnown bool
	s.db.Pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM known_devices
			WHERE user_id = $1 AND fingerprint = $2 AND trusted = true AND org_id = $3)
	`, authCtx.UserID, authCtx.DeviceFingerprint, org.ID).Scan(&isKnown)

	if !isKnown {
		return 25, true
	}

	return 0, true
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
	// Check for rapid successive actions in audit_events (the old query read a
	// nonexistent audit_logs table, so velocity risk was always 0)
	org, err := orgctx.From(ctx)
	if err != nil {
		return 0
	}
	var actionCount int
	s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_events
		WHERE actor_id = $1 AND org_id = $2 AND created_at > NOW() - INTERVAL '1 minute'
	`, authCtx.UserID, org.ID).Scan(&actionCount)

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

// defaultContinuousAuthConfig is the one set of thresholds and weights all
// three routes evaluate against.
//
// It exists because they did not share one. Only the risk route built a full
// config; the check route built &ContinuousAuthConfig{SessionMaxLifetime: 8h}
// and the update route built an empty one, so their thresholds were all zero --
// and determineRiskLevel compares `score >= CriticalRiskThreshold` first, so
// with a critical threshold of zero every session on those two routes graded
// "critical", which determineActionRequired turns into "terminate". The bug was
// invisible only because both routes failed on auth_contexts before reaching
// it; making the engine work is what makes it reachable, so it is fixed in the
// same commit.
func defaultContinuousAuthConfig() *ContinuousAuthConfig {
	return &ContinuousAuthConfig{
		Enabled:                true,
		RiskEvaluationInterval: 5 * time.Minute,
		HighRiskThreshold:      70,
		MediumRiskThreshold:    40,
		CriticalRiskThreshold:  90,
		SessionMaxLifetime:     8 * time.Hour,
		IdleTimeout:            30 * time.Minute,
		RiskFactors: map[string]float64{
			"session_age":        0.3,
			"geo_anomaly":        0.25,
			"device_anomaly":     0.2,
			"behavioral_anomaly": 0.15,
			"velocity":           0.1,
		},
	}
}

func (s *Service) handleContinuousAuthGetRisk(c *gin.Context) {
	ctx := c.Request.Context()
	sessionID := c.Query("session_id")

	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session_id required"})
		return
	}

	authService := &continuousAuthService{db: s.db, logger: s.logger, config: defaultContinuousAuthConfig()}

	risk, err := authService.CalculateSessionRisk(ctx, sessionID)
	if err != nil {
		// A session this organization does not have is a 404, not a server
		// fault. Before v157 every call landed here, because the table the
		// score was read from has never held a row.
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "session not found in this organization"})
			return
		}
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

	authService := &continuousAuthService{db: s.db, logger: s.logger, config: defaultContinuousAuthConfig()}

	required, reason, err := authService.RequireReauthentication(ctx, req.SessionID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "session not found in this organization"})
			return
		}
		s.logger.Error("failed to check auth status", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check auth status"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"reauth_required": required,
		"reason":          reason,
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

	authService := &continuousAuthService{db: s.db, logger: s.logger, config: defaultContinuousAuthConfig()}
	err := authService.UpdateAuthScore(ctx, req.SessionID, req.Event, req.Metadata)
	if err != nil {
		switch {
		case errors.Is(err, errUnknownRiskEvent):
			c.JSON(http.StatusBadRequest, gin.H{
				"error":           err.Error(),
				"accepted_events": sortedRiskEvents(),
			})
		case errors.Is(err, pgx.ErrNoRows):
			c.JSON(http.StatusNotFound, gin.H{"error": "session not found in this organization"})
		default:
			s.logger.Error("failed to update auth score", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update auth score"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "auth score updated"})
}

// sortedRiskEvents lists the events UpdateAuthScore accepts, so a 400 tells the
// caller what to send instead of only that they were wrong.
func sortedRiskEvents() []string {
	events := make([]string, 0, len(authScoreEventAdjustments))
	for e := range authScoreEventAdjustments {
		events = append(events, e)
	}
	sort.Strings(events)
	return events
}
