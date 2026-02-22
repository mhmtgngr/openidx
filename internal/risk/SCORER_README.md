# Risk Scorer Module

The `scorer.go` module provides comprehensive risk assessment capabilities for authentication and access events in OpenIDX. It implements a weighted scoring system that analyzes multiple risk factors to produce a 0-100 risk score with corresponding risk level classification.

## Overview

The `RiskScorer` evaluates login attempts and access requests using multiple dimensions:

- **IP Reputation** (25% default weight): Threat intelligence assessment of IP addresses
- **Device Score** (20% default weight): Known/trusted device verification
- **Geolocation** (15% default weight): Geographic location analysis
- **Login Velocity** (20% default weight): Frequency and timing pattern analysis
- **Impossible Travel** (20% default weight): Physical travel plausibility detection

## Risk Levels

| Score Range | Risk Level  | Action Required |
|-------------|-------------|-----------------|
| 0-29        | Low         | Allow normal authentication |
| 30-49       | Medium      | Require additional verification, notify user |
| 50-69       | High        | Require step-up MFA, limit session, alert user |
| 70-100      | Critical    | Block attempt, require admin approval, lock account |

## Usage

### Basic Example

```go
import (
    "context"
    "github.com/openidx/openidx/internal/risk"
    "go.uber.org/zap"
)

// Create scorer
scorer := risk.NewRiskScorer(db, redis, logger)

// Create request from login attempt
req := risk.ScoreRequest{
    UserID:            "user-123",
    IPAddress:         "203.0.113.42",
    UserAgent:         "Mozilla/5.0...",
    DeviceFingerprint: "abc123",
    Latitude:          37.7749,
    Longitude:         -122.4194,
    Timestamp:         time.Now(),
}

// Calculate risk
result, err := scorer.Score(ctx, req)

// Handle based on risk level
switch result.RiskLevel {
case risk.RiskLevelLow:
    // Allow normal authentication
case risk.RiskLevelMedium:
    // Require additional verification
case risk.RiskLevelHigh:
    // Require step-up MFA
case risk.RiskLevelCritical:
    // Block and escalate
}
```

### Individual Factor Scoring

```go
// IP Reputation Score (0-100, higher = worse)
ipScore := scorer.CalculateIPReputationScore("192.168.1.1")

// Device Score (0-100, higher = worse)
deviceScore := scorer.CalculateDeviceScore(ctx, fingerprint, userID)

// Geolocation Score (0-100, higher = worse)
geoScore := scorer.CalculateGeolocationScore(ctx, lat, lng, userID)

// Login Velocity Score (0-100, higher = worse)
velocityScore := scorer.CalculateLoginVelocityScore(ctx, userID, timestamp)

// Impossible Travel Detection
impossible, timeDiff := scorer.DetectImpossibleTravel(login1, login2)
```

## Customization

### Adjust Weights

```go
scorer.SetWeights(
    0.30, // IP reputation weight
    0.20, // Device score weight
    0.15, // Geolocation weight
    0.20, // Login velocity weight
    0.15, // Impossible travel weight
)
```

### Adjust Thresholds

```go
scorer.SetThresholds(
    20, // Low risk (0-19)
    40, // Medium risk (20-39)
    60, // High risk (40-59)
    // Critical risk (60+)
)
```

### Adjust Travel Speed

```go
// Set maximum plausible travel speed (km/h)
// Default: 900 km/h (aircraft speed)
scorer.SetMaxTravelSpeed(800) // More conservative
```

## Data Structures

### ScoreRequest

```go
type ScoreRequest struct {
    UserID            string    // User identifier
    IPAddress         string    // IP address
    UserAgent         string    // HTTP User-Agent header
    DeviceFingerprint string    // Device fingerprint hash
    Latitude          float64   // Geographic latitude
    Longitude         float64   // Geographic longitude
    Timestamp         time.Time // Event timestamp
    SessionID         string    // Session identifier (optional)
    AuthMethod        string    // Authentication method (optional)
    RequestedResource string    // Resource being accessed (optional)
}
```

### ScoreResult

```go
type ScoreResult struct {
    TotalScore       int              // 0-100
    RiskLevel        RiskLevel        // low/medium/high/critical
    Factors          []RiskFactor     // Individual risk factors
    Details          map[string]float64 // Detailed scores
    RecommendActions []string         // Suggested actions
    Timestamp        time.Time        // When score was calculated
}
```

## Integration Points

### During Authentication

```go
func handleLogin(c *gin.Context) {
    // Get login data
    req := extractScoreRequest(c)

    // Calculate risk
    result, _ := scorer.Score(c.Request.Context(), req)

    // Apply security controls
    switch result.RiskLevel {
    case risk.RiskLevelLow:
        completeLogin(c)
    case risk.RiskLevelMedium:
        requireEmailVerification(c)
    case risk.RiskLevelHigh:
        requireStepUpMFA(c)
    case risk.RiskLevelCritical:
        blockLogin(c)
        alertSecurityTeam(result)
    }
}
```

### Session Management

```go
func createSession(userID string, riskResult *risk.ScoreResult) {
    sessionDuration := 24 * time.Hour

    // Reduce session duration for elevated risk
    if riskResult.RiskLevel == risk.RiskLevelHigh {
        sessionDuration = 30 * time.Minute
    }

    session := createSessionWithTTL(userID, sessionDuration)
    logRiskScore(session.ID, riskResult)
}
```

## Testing

Run unit tests:

```bash
go test -v ./internal/risk/... -run TestRiskScorer
```

Run specific tests:

```bash
go test -v ./internal/risk/... -run TestDetectImpossibleTravel
go test -v ./internal/risk/... -run TestCalculateIPReputationScore
```

View examples:

```bash
go test ./internal/risk/... -run Example
```

## Configuration

The scorer integrates with OpenIDX's `AdaptiveMFA` configuration:

```yaml
adaptive_mfa:
  enabled: true
  new_device_risk_score: 30
  new_location_risk_score: 20
  impossible_travel_risk_score: 50
  blocked_ip_risk_score: 40
  failed_login_risk_score: 10
  trusted_browser_days: 30
  low_risk_threshold: 30
  medium_risk_threshold: 50
  high_risk_threshold: 70
```

## Database Tables

The scorer relies on these database tables:

- `known_devices` - Trusted device registry
- `login_history` - Historical login records for velocity/travel analysis

## Performance Considerations

- IP reputation scores are cached in Redis for 1 hour
- Device lookups use indexed database queries
- Impossible travel calculations use efficient Haversine formula
- All scoring operations are designed to complete in < 100ms

## Security Considerations

- Risk scores should never be the sole authentication factor
- Always combine with other security controls (MFA, device trust, etc.)
- Log all high and critical risk events for audit
- Regularly review and tune weights and thresholds based on threat intelligence
- Consider integrating with commercial threat intelligence feeds for production

## Future Enhancements

- Integration with commercial threat intelligence APIs (AbuseIPDB, VirusTotal)
- Machine learning-based anomaly detection
- User behavior analytics baseline establishment
- Real-time risk score updates during active sessions
- Peer group comparison scoring
- Time-based risk factor adjustments (business hours vs off-hours)
