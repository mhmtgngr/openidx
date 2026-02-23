// Package mfa provides Multi-Factor Authentication functionality for OpenIDX
package mfa

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// mockAdaptiveRedisClient is a mock implementation of RedisClient for testing
type mockAdaptiveRedisClient struct {
	data      map[string]string
	ttl       map[string]time.Duration
	getError  error
	setError  error
	delError  error
}

func newMockAdaptiveRedisClient() *mockAdaptiveRedisClient {
	return &mockAdaptiveRedisClient{
		data: make(map[string]string),
		ttl:  make(map[string]time.Duration),
	}
}

func (m *mockAdaptiveRedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	if m.setError != nil {
		cmd := redis.NewStatusCmd(ctx)
		cmd.SetErr(m.setError)
		return cmd
	}
	m.data[key] = fmt.Sprintf("%v", value)
	m.ttl[key] = expiration
	return redis.NewStatusCmd(ctx)
}

func (m *mockAdaptiveRedisClient) Get(ctx context.Context, key string) *redis.StringCmd {
	if m.getError != nil {
		cmd := redis.NewStringCmd(ctx)
		cmd.SetErr(m.getError)
		return cmd
	}
	if val, ok := m.data[key]; ok {
		cmd := redis.NewStringCmd(ctx)
		cmd.SetVal(val)
		return cmd
	}
	cmd := redis.NewStringCmd(ctx)
	cmd.SetErr(redis.Nil)
	return cmd
}

func (m *mockAdaptiveRedisClient) Del(ctx context.Context, keys ...string) *redis.IntCmd {
	if m.delError != nil {
		cmd := redis.NewIntCmd(ctx)
		cmd.SetErr(m.delError)
		return cmd
	}
	for _, key := range keys {
		delete(m.data, key)
		delete(m.ttl, key)
	}
	cmd := redis.NewIntCmd(ctx)
	cmd.SetVal(int64(len(keys)))
	return cmd
}

func (m *mockAdaptiveRedisClient) TTL(_ context.Context, key string) *redis.DurationCmd {
	if ttl, ok := m.ttl[key]; ok {
		cmd := redis.NewDurationCmd(context.Background(), ttl)
		cmd.SetVal(ttl)
		return cmd
	}
	cmd := redis.NewDurationCmd(context.Background(), time.Duration(-2))
	cmd.SetVal(time.Duration(-2))
	return cmd
}

func (m *mockAdaptiveRedisClient) Exists(_ context.Context, keys ...string) *redis.IntCmd {
	count := int64(0)
	for _, key := range keys {
		if _, ok := m.data[key]; ok {
			count++
		}
	}
	cmd := redis.NewIntCmd(context.Background())
	cmd.SetVal(count)
	return cmd
}

func (m *mockAdaptiveRedisClient) Incr(_ context.Context, key string) *redis.IntCmd {
	if _, ok := m.data[key]; !ok {
		m.data[key] = "0"
	}
	var val int
	fmt.Sscanf(m.data[key], "%d", &val)
	val++
	m.data[key] = fmt.Sprintf("%d", val)
	cmd := redis.NewIntCmd(context.Background())
	cmd.SetVal(int64(val))
	return cmd
}

func (m *mockAdaptiveRedisClient) Expire(_ context.Context, key string, expiration time.Duration) *redis.BoolCmd {
	if _, ok := m.data[key]; ok {
		m.ttl[key] = expiration
		cmd := redis.NewBoolCmd(context.Background())
		cmd.SetVal(true)
		return cmd
	}
	cmd := redis.NewBoolCmd(context.Background())
	cmd.SetVal(false)
	return cmd
}

// Test DefaultAdaptivePolicyConfig
func TestDefaultAdaptivePolicyConfig(t *testing.T) {
	config := DefaultAdaptivePolicyConfig()

	assert.Equal(t, 30, config.LowRiskThreshold, "LowRiskThreshold should be 30")
	assert.Equal(t, 70, config.MediumRiskThreshold, "MediumRiskThreshold should be 70")
	assert.Equal(t, 90, config.HighRiskThreshold, "HighRiskThreshold should be 90")
	assert.Equal(t, 30, config.NewDeviceRiskScore, "NewDeviceRiskScore should be 30")
	assert.Equal(t, 20, config.NewLocationRiskScore, "NewLocationRiskScore should be 20")
	assert.Equal(t, 15, config.NewIPRiskScore, "NewIPRiskScore should be 15")
	assert.Equal(t, 10, config.FailedLoginRiskScore, "FailedLoginRiskScore should be 10")
	assert.Equal(t, 50, config.ImpossibleTravelScore, "ImpossibleTravelScore should be 50")
	assert.Equal(t, 100, config.BlockedIPRiskScore, "BlockedIPRiskScore should be 100")
	assert.Equal(t, 15, config.AbnormalTimeRiskScore, "AbnormalTimeRiskScore should be 15")
	assert.Equal(t, 3, config.MaxFailedLogins, "MaxFailedLogins should be 3")
}

// Test NewAdaptiveService
func TestNewAdaptiveService(t *testing.T) {
	logger := zap.NewNop()
	redis := newMockAdaptiveRedisClient()
	config := DefaultAdaptivePolicyConfig()

	service := NewAdaptiveService(logger, redis, config)

	assert.NotNil(t, service)
	assert.Equal(t, config, service.config)
	assert.Equal(t, redis, service.redis)
	assert.NotNil(t, service.blockedIPs)
}

// Test low risk scenario - all trusted signals
func TestAdaptiveService_LowRiskScenario(t *testing.T) {
	logger := zap.NewNop()
	redis := newMockAdaptiveRedisClient()
	config := DefaultAdaptivePolicyConfig()
	service := NewAdaptiveService(logger, redis, config)

	userID := uuid.New()

	// Pre-populate known data (simulate previous successful logins)
	userIDStr := userID.String()
	redis.Set(context.Background(), fmt.Sprintf("%s%s:device123", redisKnownDevicePrefix, userIDStr), "1", knownDeviceTTL)
	redis.Set(context.Background(), fmt.Sprintf("%s%s:192.168.1.1", redisKnownIPPrefix, userIDStr), "1", knownIPTTL)
	redis.Set(context.Background(), fmt.Sprintf("%s%s:US-NY", redisKnownLocationPrefix, userIDStr), "1", knownLocationTTL)

	// Create signal with all trusted indicators
	signal := &AuthSignal{
		UserID:          userID,
		IPAddress:       "192.168.1.1",
		DeviceID:        "device123",
		Location:        "US-NY",
		Timestamp:       time.Date(2026, 2, 23, 14, 0, 0, 0, time.UTC), // 2 PM (normal hours)
		LoginTimeNormal: true,
		IsNewDevice:     false,
		IsNewIP:         false,
		IsNewLocation:   false,
	}

	// Evaluate risk
	ctx := context.Background()
	risk, err := service.EvaluateRisk(ctx, signal)

	require.NoError(t, err)
	assert.Equal(t, 0, risk.Score, "Low risk scenario should have score of 0")
	assert.Equal(t, RiskLevelLow, risk.Level)
	assert.Equal(t, MFANone, risk.RequiredMFA)
	assert.Empty(t, risk.Reasons)
}

// Test medium risk scenario - new device
func TestAdaptiveService_MediumRiskScenario_NewDevice(t *testing.T) {
	logger := zap.NewNop()
	redis := newMockAdaptiveRedisClient()
	config := DefaultAdaptivePolicyConfig()
	service := NewAdaptiveService(logger, redis, config)

	userID := uuid.New()
	userIDStr := userID.String()

	// Pre-populate known IP and location
	redis.Set(context.Background(), fmt.Sprintf("%s%s:192.168.1.1", redisKnownIPPrefix, userIDStr), "1", knownIPTTL)
	redis.Set(context.Background(), fmt.Sprintf("%s%s:US-NY", redisKnownLocationPrefix, userIDStr), "1", knownLocationTTL)

	// Create signal with new device only
	signal := &AuthSignal{
		UserID:          userID,
		IPAddress:       "192.168.1.1",
		DeviceID:        "new-device-456",
		Location:        "US-NY",
		Timestamp:       time.Date(2026, 2, 23, 14, 0, 0, 0, time.UTC),
		LoginTimeNormal: true,
		IsNewDevice:     true,
		IsNewIP:         false,
		IsNewLocation:   false,
	}

	ctx := context.Background()
	risk, err := service.EvaluateRisk(ctx, signal)

	require.NoError(t, err)
	assert.Equal(t, 30, risk.Score, "New device should add 30 points")
	assert.Equal(t, RiskLevelMedium, risk.Level)
	assert.Equal(t, MFATOTP, risk.RequiredMFA)
	assert.Contains(t, risk.Reasons, "New device detected")
}

// Test high risk scenario - multiple new signals
func TestAdaptiveService_HighRiskScenario_MultipleNewSignals(t *testing.T) {
	logger := zap.NewNop()
	redis := newMockAdaptiveRedisClient()
	config := DefaultAdaptivePolicyConfig()
	service := NewAdaptiveService(logger, redis, config)

	userID := uuid.New()

	// All signals are new
	signal := &AuthSignal{
		UserID:          userID,
		IPAddress:       "203.0.113.1",
		DeviceID:        "new-device",
		Location:        "CN-BJ",
		Timestamp:       time.Date(2026, 2, 23, 3, 0, 0, 0, time.UTC), // 3 AM (abnormal)
		LoginTimeNormal: false,
		IsNewDevice:     true,
		IsNewIP:         true,
		IsNewLocation:   true,
	}

	ctx := context.Background()
	risk, err := service.EvaluateRisk(ctx, signal)

	require.NoError(t, err)
	// Score = 30 (new device) + 15 (new IP) + 20 (new location) + 15 (abnormal time) = 80
	assert.Equal(t, 80, risk.Score)
	assert.Equal(t, RiskLevelHigh, risk.Level)
	assert.Equal(t, MFAWebAuthn, risk.RequiredMFA)
	assert.Len(t, risk.Reasons, 4)
}

// Test critical risk scenario - blocked IP
func TestAdaptiveService_CriticalRiskScenario_BlockedIP(t *testing.T) {
	logger := zap.NewNop()
	redis := newMockAdaptiveRedisClient()
	config := DefaultAdaptivePolicyConfig()
	service := NewAdaptiveService(logger, redis, config)

	// Block the IP
	blockedIP := "198.51.100.1"
	service.AddBlockedIP(blockedIP)

	userID := uuid.New()
	signal := &AuthSignal{
		UserID:          userID,
		IPAddress:       blockedIP,
		DeviceID:        "device123",
		Location:        "US-NY",
		Timestamp:       time.Date(2026, 2, 23, 14, 0, 0, 0, time.UTC),
		LoginTimeNormal: true,
		IsNewDevice:     false,
		IsNewIP:         false,
		IsNewLocation:   false,
	}

	ctx := context.Background()
	risk, err := service.EvaluateRisk(ctx, signal)

	require.NoError(t, err)
	assert.GreaterOrEqual(t, risk.Score, 90, "Blocked IP should result in critical risk")
	assert.Equal(t, RiskLevelCritical, risk.Level)
	assert.Equal(t, MFABlock, risk.RequiredMFA)
	assert.Contains(t, risk.Reasons, "IP address "+blockedIP+" is blocked")
}

// Test risk level thresholds
func TestAdaptiveService_RiskLevelThresholds(t *testing.T) {
	tests := []struct {
		name        string
		score       int
		expectedLevel RiskLevel
		expectedMFA  MFAType
	}{
		{"Score 0 - Low", 0, RiskLevelLow, MFANone},
		{"Score 20 - Low", 20, RiskLevelLow, MFANone},
		{"Score 29 - Low", 29, RiskLevelLow, MFANone},
		{"Score 30 - Medium", 30, RiskLevelMedium, MFATOTP},
		{"Score 50 - Medium", 50, RiskLevelMedium, MFATOTP},
		{"Score 69 - Medium", 69, RiskLevelMedium, MFATOTP},
		{"Score 70 - High", 70, RiskLevelHigh, MFAWebAuthn},
		{"Score 85 - High", 85, RiskLevelHigh, MFAWebAuthn},
		{"Score 89 - High", 89, RiskLevelHigh, MFAWebAuthn},
		{"Score 90 - Critical", 90, RiskLevelCritical, MFABlock},
		{"Score 100 - Critical", 100, RiskLevelCritical, MFABlock},
	}

	logger := zap.NewNop()
	redis := newMockAdaptiveRedisClient()
	config := DefaultAdaptivePolicyConfig()
	service := NewAdaptiveService(logger, redis, config)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level, mfaType := service.determineRiskLevel(tt.score)
			assert.Equal(t, tt.expectedLevel, level)
			assert.Equal(t, tt.expectedMFA, mfaType)
		})
	}
}

// Test failed login tracking
func TestAdaptiveService_FailedLoginTracking(t *testing.T) {
	logger := zap.NewNop()
	redis := newMockAdaptiveRedisClient()
	config := DefaultAdaptivePolicyConfig()
	service := NewAdaptiveService(logger, redis, config)

	userID := uuid.New()
	ctx := context.Background()

	// Record 5 failed logins
	for i := 0; i < 5; i++ {
		err := service.RecordFailedLogin(ctx, userID, "192.168.1.1")
		require.NoError(t, err)
	}

	// Create signal to evaluate
	signal := &AuthSignal{
		UserID:          userID,
		IPAddress:       "192.168.1.1",
		DeviceID:        "device123",
		Location:        "US-NY",
		Timestamp:       time.Date(2026, 2, 23, 14, 0, 0, 0, time.UTC),
		LoginTimeNormal: true,
		IsNewDevice:     false,
		IsNewIP:         false,
		IsNewLocation:   false,
	}

	risk, err := service.EvaluateRisk(ctx, signal)
	require.NoError(t, err)

	// 5 failed logins - 3 max = 2 additional * 10 = 20 points
	assert.Equal(t, 20, risk.Score)
	assert.Contains(t, risk.Reasons, "5 recent failed login attempts")
}

// Test recording successful login
func TestAdaptiveService_RecordSuccessfulLogin(t *testing.T) {
	logger := zap.NewNop()
	redis := newMockAdaptiveRedisClient()
	config := DefaultAdaptivePolicyConfig()
	service := NewAdaptiveService(logger, redis, config)

	userID := uuid.New()
	ctx := context.Background()

	signal := &AuthSignal{
		UserID:    userID,
		IPAddress: "192.168.1.100",
		DeviceID:  "device-abc-123",
		Location:  "US-CA",
		Timestamp: time.Date(2026, 2, 23, 15, 30, 0, 0, time.UTC),
	}

	err := service.RecordSuccessfulLogin(ctx, signal)
	require.NoError(t, err)

	// Verify that the data was stored
	userIDStr := userID.String()

	// Check device
	deviceKey := service.buildDeviceKey(userIDStr, "device-abc-123")
	deviceVal := redis.data[deviceKey]
	assert.Equal(t, "1", deviceVal)

	// Check IP
	ipKey := service.buildIPKey(userIDStr, "192.168.1.100")
	ipVal := redis.data[ipKey]
	assert.Equal(t, "1", ipVal)

	// Check location
	locationKey := service.buildLocationKey(userIDStr, "US-CA")
	locationVal := redis.data[locationKey]
	assert.Equal(t, "1", locationVal)
}

// Test GetSignalInfo with known and unknown signals
func TestAdaptiveService_GetSignalInfo(t *testing.T) {
	logger := zap.NewNop()
	redis := newMockAdaptiveRedisClient()
	config := DefaultAdaptivePolicyConfig()
	service := NewAdaptiveService(logger, redis, config)

	userID := uuid.New()
	ctx := context.Background()
	userIDStr := userID.String()

	// Pre-populate some known data
	redis.Set(context.Background(), service.buildDeviceKey(userIDStr, "known-device"), "1", knownDeviceTTL)
	redis.Set(context.Background(), service.buildIPKey(userIDStr, "10.0.0.1"), "1", knownIPTTL)

	tests := []struct {
		name           string
		deviceID       string
		ip             string
		location       string
		expectNewDevice bool
		expectNewIP    bool
		expectNewLocation bool
	}{
		{
			name:           "All known",
			deviceID:       "known-device",
			ip:             "10.0.0.1",
			location:       "",
			expectNewDevice: false,
			expectNewIP:    false,
			expectNewLocation: true, // No location data stored yet
		},
		{
			name:           "New device",
			deviceID:       "unknown-device",
			ip:             "10.0.0.1",
			location:       "",
			expectNewDevice: true,
			expectNewIP:    false,
			expectNewLocation: true,
		},
		{
			name:           "New IP",
			deviceID:       "known-device",
			ip:             "10.0.0.99",
			location:       "",
			expectNewDevice: false,
			expectNewIP:    true,
			expectNewLocation: true,
		},
		{
			name:           "Empty device ID",
			deviceID:       "",
			ip:             "10.0.0.1",
			location:       "",
			expectNewDevice: true, // Empty device ID is treated as new
			expectNewIP:    false,
			expectNewLocation: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signal, err := service.GetSignalInfo(ctx, userID, tt.ip, tt.deviceID, tt.location, time.Now())
			require.NoError(t, err)
			assert.Equal(t, tt.expectNewDevice, signal.IsNewDevice)
			assert.Equal(t, tt.expectNewIP, signal.IsNewIP)
			assert.Equal(t, tt.expectNewLocation, signal.IsNewLocation)
		})
	}
}

// Test normal login time detection
func TestAdaptiveService_IsNormalLoginTime(t *testing.T) {
	tests := []struct {
		name     string
		hour     int
		expected bool
	}{
		{"Midnight", 0, false},
		{"3 AM", 3, false},
		{"6 AM - start", 6, true},
		{"10 AM", 10, true},
		{"2 PM", 14, true},
		{"10 PM - end", 22, true},
		{"11 PM", 23, false},
	}

	config := DefaultAdaptivePolicyConfig()
	service := &AdaptiveService{config: config}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := time.Date(2026, 2, 23, tt.hour, 0, 0, 0, time.UTC)
			result := service.isNormalLoginTime(ts)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test ShouldSkipMFA
func TestAdaptiveService_ShouldSkipMFA(t *testing.T) {
	logger := zap.NewNop()
	redis := newMockAdaptiveRedisClient()
	config := DefaultAdaptivePolicyConfig()
	service := NewAdaptiveService(logger, redis, config)

	userID := uuid.New()
	ctx := context.Background()

	// Low risk - should skip
	lowRiskSignal := &AuthSignal{
		UserID:          userID,
		IPAddress:       "192.168.1.1",
		DeviceID:        "device123",
		Location:        "US-NY",
		Timestamp:       time.Date(2026, 2, 23, 14, 0, 0, 0, time.UTC),
		LoginTimeNormal: true,
		IsNewDevice:     false,
		IsNewIP:         false,
		IsNewLocation:   false,
	}

	skip, risk, err := service.ShouldSkipMFA(ctx, lowRiskSignal)
	require.NoError(t, err)
	assert.True(t, skip)
	assert.Equal(t, MFANone, risk.RequiredMFA)

	// High risk - should not skip
	highRiskSignal := &AuthSignal{
		UserID:          userID,
		IPAddress:       "203.0.113.1",
		DeviceID:        "new-device",
		Location:        "CN-BJ",
		Timestamp:       time.Date(2026, 2, 23, 3, 0, 0, 0, time.UTC),
		LoginTimeNormal: false,
		IsNewDevice:     true,
		IsNewIP:         true,
		IsNewLocation:   true,
	}

	skip, risk, err = service.ShouldSkipMFA(ctx, highRiskSignal)
	require.NoError(t, err)
	assert.False(t, skip)
	assert.NotEqual(t, MFANone, risk.RequiredMFA)
}

// Test blocked IP management
func TestAdaptiveService_BlockedIPManagement(t *testing.T) {
	logger := zap.NewNop()
	redis := newMockAdaptiveRedisClient()
	config := DefaultAdaptivePolicyConfig()
	service := NewAdaptiveService(logger, redis, config)

	ip := "10.20.30.40"

	// Initially not blocked
	assert.False(t, service.isIPBlocked(ip))

	// Add to blocked list
	service.AddBlockedIP(ip)
	assert.True(t, service.isIPBlocked(ip))

	// Remove from blocked list
	service.RemoveBlockedIP(ip)
	assert.False(t, service.isIPBlocked(ip))
}

// Test GetRequiredMFA
func TestAdaptiveService_GetRequiredMFA(t *testing.T) {
	logger := zap.NewNop()
	redis := newMockAdaptiveRedisClient()
	config := DefaultAdaptivePolicyConfig()
	service := NewAdaptiveService(logger, redis, config)

	userID := uuid.New()
	ctx := context.Background()

	signal := &AuthSignal{
		UserID:          userID,
		IPAddress:       "192.168.1.1",
		DeviceID:        "device123",
		Location:        "US-NY",
		Timestamp:       time.Date(2026, 2, 23, 14, 0, 0, 0, time.UTC),
		LoginTimeNormal: true,
		IsNewDevice:     false,
		IsNewIP:         false,
		IsNewLocation:   false,
	}

	mfaType, risk, err := service.GetRequiredMFA(ctx, signal)
	require.NoError(t, err)
	assert.Equal(t, MFANone, mfaType)
	assert.NotNil(t, risk)
}

// Test with real miniredis for more realistic testing
func TestAdaptiveService_WithMiniRedis(t *testing.T) {
	s := miniredis.RunT(t)
	defer s.Close()

	client := redis.NewClient(&redis.Options{
		Addr: s.Addr(),
	})

	logger := zap.NewNop()
	config := DefaultAdaptivePolicyConfig()
	service := NewAdaptiveService(logger, client, config)

	userID := uuid.New()
	ctx := context.Background()

	// Record successful login
	signal := &AuthSignal{
		UserID:    userID,
		IPAddress: "192.168.1.50",
		DeviceID:  "test-device",
		Location:  "US-TX",
		Timestamp: time.Now(),
	}

	err := service.RecordSuccessfulLogin(ctx, signal)
	require.NoError(t, err)

	// Now evaluate with same signals - should be low risk
	evalSignal := &AuthSignal{
		UserID:          userID,
		IPAddress:       "192.168.1.50",
		DeviceID:        "test-device",
		Location:        "US-TX",
		Timestamp:       time.Now(),
		LoginTimeNormal: true,
		IsNewDevice:     false,
		IsNewIP:         false,
		IsNewLocation:   false,
	}

	risk, err := service.EvaluateRisk(ctx, evalSignal)
	require.NoError(t, err)
	assert.Equal(t, 0, risk.Score)
	assert.Equal(t, RiskLevelLow, risk.Level)
}
