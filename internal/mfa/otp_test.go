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

// mockOTPRedisClient is a mock implementation of OTPRedisClient for testing
type mockOTPRedisClient struct {
	data map[string]string
	ttl  map[string]time.Duration
}

func newMockOTPRedisClient() *mockOTPRedisClient {
	return &mockOTPRedisClient{
		data: make(map[string]string),
		ttl:  make(map[string]time.Duration),
	}
}

func (m *mockOTPRedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	m.data[key] = fmt.Sprintf("%v", value)
	m.ttl[key] = expiration
	return redis.NewStatusCmd(ctx)
}

func (m *mockOTPRedisClient) Get(ctx context.Context, key string) *redis.StringCmd {
	if val, ok := m.data[key]; ok {
		cmd := redis.NewStringCmd(ctx)
		cmd.SetVal(val)
		return cmd
	}
	cmd := redis.NewStringCmd(ctx)
	cmd.SetErr(redis.Nil)
	return cmd
}

func (m *mockOTPRedisClient) Del(ctx context.Context, keys ...string) *redis.IntCmd {
	for _, key := range keys {
		delete(m.data, key)
		delete(m.ttl, key)
	}
	cmd := redis.NewIntCmd(ctx)
	cmd.SetVal(int64(len(keys)))
	return cmd
}

func (m *mockOTPRedisClient) TTL(ctx context.Context, key string) *redis.DurationCmd {
	if ttl, ok := m.ttl[key]; ok {
		cmd := redis.NewDurationCmd(ctx, ttl)
		cmd.SetVal(ttl)
		return cmd
	}
	cmd := redis.NewDurationCmd(ctx, time.Duration(-2))
	cmd.SetVal(time.Duration(-2))
	return cmd
}

// Test DefaultOTPConfig
func TestDefaultOTPConfig(t *testing.T) {
	config := DefaultOTPConfig()

	assert.Equal(t, 6, config.Length, "Default length should be 6")
	assert.Equal(t, 5*time.Minute, config.Expiry, "Default expiry should be 5 minutes")
	assert.Equal(t, 3, config.MaxAttempts, "Default max attempts should be 3")
	assert.Equal(t, 60*time.Second, config.RateLimit, "Default rate limit should be 60 seconds")
}

// Test NewOTPService
func TestNewOTPService(t *testing.T) {
	logger := zap.NewNop()
	redis := newMockOTPRedisClient()
	config := DefaultOTPConfig()
	provider := NewMockProvider(logger)

	service := NewOTPService(logger, redis, provider, config)

	assert.NotNil(t, service)
	assert.Equal(t, config, service.config)
	assert.Equal(t, redis, service.redis)
	assert.Equal(t, provider, service.provider)
	assert.Equal(t, "OpenIDX", service.messagePrefix)
}

// Test NewOTPServiceWithPrefix
func TestNewOTPServiceWithPrefix(t *testing.T) {
	logger := zap.NewNop()
	redis := newMockOTPRedisClient()
	config := DefaultOTPConfig()
	provider := NewMockProvider(logger)

	service := NewOTPServiceWithPrefix(logger, redis, provider, config, "TestApp")

	assert.NotNil(t, service)
	assert.Equal(t, "TestApp", service.messagePrefix)
}

// Test OTP generation
func TestOTPService_GenerateOTP(t *testing.T) {
	logger := zap.NewNop()
	redis := newMockOTPRedisClient()
	config := DefaultOTPConfig()
	mockProvider := NewMockProvider(logger)
	service := NewOTPService(logger, redis, mockProvider, config)

	userID := uuid.New()
	ctx := context.Background()

	otp, err := service.GenerateOTP(ctx, userID, OTPTypeEmail, "user@example.com")

	require.NoError(t, err)
	assert.NotNil(t, otp)
	assert.Equal(t, userID, otp.UserID)
	assert.Equal(t, OTPTypeEmail, otp.Type)
	assert.Equal(t, "user@example.com", otp.Destination)
	assert.Equal(t, 6, len(otp.Code), "OTP should be 6 digits")
	assert.Equal(t, "use***@example.com", maskDestination("user@example.com", OTPTypeEmail))

	// Verify code is numeric
	for _, c := range otp.Code {
		assert.GreaterOrEqual(t, c, '0')
		assert.LessOrEqual(t, c, '9')
	}

	// Verify it was stored in Redis
	otpKey := service.buildOTPKey(userID, OTPTypeEmail)
	storedCode := redis.data[otpKey]
	assert.Equal(t, otp.Code, storedCode)
}

// Test OTP generation for SMS
func TestOTPService_GenerateOTP_SMS(t *testing.T) {
	logger := zap.NewNop()
	redis := newMockOTPRedisClient()
	config := DefaultOTPConfig()
	mockProvider := NewMockProvider(logger)
	service := NewOTPService(logger, redis, mockProvider, config)

	userID := uuid.New()
	ctx := context.Background()

	otp, err := service.GenerateOTP(ctx, userID, OTPTypeSMS, "+1234567890")

	require.NoError(t, err)
	assert.Equal(t, OTPTypeSMS, otp.Type)
	assert.Equal(t, "+1234567890", otp.Destination)

	// Verify masking
	masked := maskDestination("+1234567890", OTPTypeSMS)
	assert.Equal(t, "+1***7890", masked)
}

// Test OTP verification
func TestOTPService_VerifyOTP(t *testing.T) {
	logger := zap.NewNop()
	redis := newMockOTPRedisClient()
	config := DefaultOTPConfig()
	mockProvider := NewMockProvider(logger)
	service := NewOTPService(logger, redis, mockProvider, config)

	userID := uuid.New()
	ctx := context.Background()

	// Generate OTP
	otp, err := service.GenerateOTP(ctx, userID, OTPTypeEmail, "user@example.com")
	require.NoError(t, err)

	// Verify correct OTP
	valid, err := service.VerifyOTP(ctx, userID, OTPTypeEmail, otp.Code)
	require.NoError(t, err)
	assert.True(t, valid)

	// Verify OTP was deleted after successful verification
	otpKey := service.buildOTPKey(userID, OTPTypeEmail)
	_, exists := redis.data[otpKey]
	assert.False(t, exists, "OTP should be deleted after successful verification")
}

// Test OTP verification with wrong code
func TestOTPService_VerifyOTP_WrongCode(t *testing.T) {
	logger := zap.NewNop()
	redis := newMockOTPRedisClient()
	config := DefaultOTPConfig()
	mockProvider := NewMockProvider(logger)
	service := NewOTPService(logger, redis, mockProvider, config)

	userID := uuid.New()
	ctx := context.Background()

	// Generate OTP
	_, err := service.GenerateOTP(ctx, userID, OTPTypeEmail, "user@example.com")
	require.NoError(t, err)

	// Verify wrong OTP
	valid, err := service.VerifyOTP(ctx, userID, OTPTypeEmail, "000000")
	require.NoError(t, err)
	assert.False(t, valid)

	// Verify OTP still exists after failed verification
	otpKey := service.buildOTPKey(userID, OTPTypeEmail)
	_, exists := redis.data[otpKey]
	assert.True(t, exists, "OTP should still exist after failed verification")
}

// Test OTP verification with expired code
func TestOTPService_VerifyOTP_Expired(t *testing.T) {
	logger := zap.NewNop()
	redis := newMockOTPRedisClient()
	config := DefaultOTPConfig()
	mockProvider := NewMockProvider(logger)
	service := NewOTPService(logger, redis, mockProvider, config)

	userID := uuid.New()
	ctx := context.Background()

	// Generate OTP
	otp, err := service.GenerateOTP(ctx, userID, OTPTypeEmail, "user@example.com")
	require.NoError(t, err)

	// Manually delete from Redis to simulate expiry
	otpKey := service.buildOTPKey(userID, OTPTypeEmail)
	delete(redis.data, otpKey)

	// Try to verify
	valid, err := service.VerifyOTP(ctx, userID, OTPTypeEmail, otp.Code)
	require.Error(t, err)
	assert.False(t, valid)
	assert.Contains(t, err.Error(), "not found or expired")
}

// Test max attempts
func TestOTPService_VerifyOTP_MaxAttempts(t *testing.T) {
	logger := zap.NewNop()
	redis := newMockOTPRedisClient()
	config := DefaultOTPConfig()
	mockProvider := NewMockProvider(logger)
	service := NewOTPService(logger, redis, mockProvider, config)

	userID := uuid.New()
	ctx := context.Background()

	// Generate OTP
	otp, err := service.GenerateOTP(ctx, userID, OTPTypeEmail, "user@example.com")
	require.NoError(t, err)

	// Try wrong codes up to max attempts
	for i := 0; i < config.MaxAttempts; i++ {
		valid, err := service.VerifyOTP(ctx, userID, OTPTypeEmail, fmt.Sprintf("%06d", i))
		require.NoError(t, err)
		assert.False(t, valid)
	}

	// Next attempt should fail with max attempts exceeded
	valid, err := service.VerifyOTP(ctx, userID, OTPTypeEmail, "999999")
	require.Error(t, err)
	assert.False(t, valid)
	assert.Contains(t, err.Error(), "max verification attempts exceeded")

	// Even the correct code should now fail
	valid, err = service.VerifyOTP(ctx, userID, OTPTypeEmail, otp.Code)
	require.Error(t, err)
	assert.False(t, valid)
}

// Test rate limiting
func TestOTPService_GenerateOTP_RateLimit(t *testing.T) {
	logger := zap.NewNop()
	redis := newMockOTPRedisClient()
	config := DefaultOTPConfig()
	mockProvider := NewMockProvider(logger)
	service := NewOTPService(logger, redis, mockProvider, config)

	userID := uuid.New()
	ctx := context.Background()

	// Generate first OTP
	_, err := service.GenerateOTP(ctx, userID, OTPTypeEmail, "user@example.com")
	require.NoError(t, err)

	// Try to generate second OTP immediately - should be rate limited
	_, err = service.GenerateOTP(ctx, userID, OTPTypeEmail, "user@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rate limit")
}

// Test SendOTP for email
func TestOTPService_SendOTP_Email(t *testing.T) {
	logger := zap.NewNop()
	redis := newMockOTPRedisClient()
	config := DefaultOTPConfig()
	mockProvider := NewMockProvider(logger)
	service := NewOTPService(logger, redis, mockProvider, config)

	userID := uuid.New()
	ctx := context.Background()

	otp := &OTPCode{
		Code:        "123456",
		UserID:      userID,
		Type:        OTPTypeEmail,
		Destination: "user@example.com",
		ExpiresAt:   time.Now().Add(5 * time.Minute),
		CreatedAt:   time.Now(),
	}

	err := service.SendOTP(ctx, otp)
	require.NoError(t, err)

	// Verify the mock provider received the email
	assert.Len(t, mockProvider.Emails, 1)
	sentEmail := mockProvider.Emails[0]
	assert.Equal(t, "user@example.com", sentEmail.To)
	assert.Contains(t, sentEmail.Subject, "Verification Code")
	assert.Contains(t, sentEmail.Body, "123456")
}

// Test SendOTP for SMS
func TestOTPService_SendOTP_SMS(t *testing.T) {
	logger := zap.NewNop()
	redis := newMockOTPRedisClient()
	config := DefaultOTPConfig()
	mockProvider := NewMockProvider(logger)
	service := NewOTPService(logger, redis, mockProvider, config)

	userID := uuid.New()
	ctx := context.Background()

	otp := &OTPCode{
		Code:        "654321",
		UserID:      userID,
		Type:        OTPTypeSMS,
		Destination: "+1234567890",
		ExpiresAt:   time.Now().Add(5 * time.Minute),
		CreatedAt:   time.Now(),
	}

	err := service.SendOTP(ctx, otp)
	require.NoError(t, err)

	// Verify the mock provider received the SMS
	assert.Len(t, mockProvider.SMSs, 1)
	sentSMS := mockProvider.SMSs[0]
	assert.Equal(t, "+1234567890", sentSMS.To)
	assert.Contains(t, sentSMS.Body, "654321")
}

// Test GenerateAndSendOTP
func TestOTPService_GenerateAndSendOTP(t *testing.T) {
	logger := zap.NewNop()
	redis := newMockOTPRedisClient()
	config := DefaultOTPConfig()
	mockProvider := NewMockProvider(logger)
	service := NewOTPService(logger, redis, mockProvider, config)

	userID := uuid.New()
	ctx := context.Background()

	err := service.GenerateAndSendOTP(ctx, userID, OTPTypeEmail, "user@example.com")
	require.NoError(t, err)

	// Verify email was sent
	assert.Len(t, mockProvider.Emails, 1)
	sentEmail := mockProvider.Emails[0]
	assert.Equal(t, "user@example.com", sentEmail.To)
}

// Test DeleteOTP
func TestOTPService_DeleteOTP(t *testing.T) {
	logger := zap.NewNop()
	redis := newMockOTPRedisClient()
	config := DefaultOTPConfig()
	mockProvider := NewMockProvider(logger)
	service := NewOTPService(logger, redis, mockProvider, config)

	userID := uuid.New()
	ctx := context.Background()

	// Generate OTP
	_, err := service.GenerateOTP(ctx, userID, OTPTypeEmail, "user@example.com")
	require.NoError(t, err)

	// Verify it exists
	otpKey := service.buildOTPKey(userID, OTPTypeEmail)
	_, exists := redis.data[otpKey]
	assert.True(t, exists)

	// Delete OTP
	err = service.DeleteOTP(ctx, userID, OTPTypeEmail)
	require.NoError(t, err)

	// Verify it's gone
	_, exists = redis.data[otpKey]
	assert.False(t, exists)
}

// Test GetRemainingTime
func TestOTPService_GetRemainingTime(t *testing.T) {
	logger := zap.NewNop()
	redis := newMockOTPRedisClient()
	config := DefaultOTPConfig()
	mockProvider := NewMockProvider(logger)
	service := NewOTPService(logger, redis, mockProvider, config)

	userID := uuid.New()
	ctx := context.Background()

	// Generate OTP
	_, err := service.GenerateOTP(ctx, userID, OTPTypeEmail, "user@example.com")
	require.NoError(t, err)

	// Get remaining time
	remaining, err := service.GetRemainingTime(ctx, userID, OTPTypeEmail)
	require.NoError(t, err)
	assert.Greater(t, remaining, 4*time.Minute)
	assert.LessOrEqual(t, remaining, 5*time.Minute)
}

// Test GetRemainingAttempts
func TestOTPService_GetRemainingAttempts(t *testing.T) {
	logger := zap.NewNop()
	redis := newMockOTPRedisClient()
	config := DefaultOTPConfig()
	mockProvider := NewMockProvider(logger)
	service := NewOTPService(logger, redis, mockProvider, config)

	userID := uuid.New()
	ctx := context.Background()

	// Generate OTP
	_, err := service.GenerateOTP(ctx, userID, OTPTypeEmail, "user@example.com")
	require.NoError(t, err)

	// Should have max attempts remaining
	remaining, err := service.GetRemainingAttempts(ctx, userID, OTPTypeEmail)
	require.NoError(t, err)
	assert.Equal(t, 3, remaining)

	// Fail one attempt
	_, _ = service.VerifyOTP(ctx, userID, OTPTypeEmail, "000000")

	// Should have 2 remaining
	remaining, err = service.GetRemainingAttempts(ctx, userID, OTPTypeEmail)
	require.NoError(t, err)
	assert.Equal(t, 2, remaining)
}

// Test maskDestination for various inputs
func TestMaskDestination(t *testing.T) {
	tests := []struct {
		input      string
		otpType    OTPType
		expected   string
	}{
		{"user@example.com", OTPTypeEmail, "use***@example.com"},
		{"a@b.co", OTPTypeEmail, "***@b.co"},
		{"verylongusername@domain.com", OTPTypeEmail, "ver***@domain.com"},
		{"+1234567890", OTPTypeSMS, "+1***7890"},
		{"+441234567890", OTPTypeSMS, "+4***7890"},
		{"", OTPTypeEmail, ""},
		{"", OTPTypeSMS, ""},
		{"invalid", OTPTypeEmail, "***"},
		{"123", OTPTypeSMS, "***"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := maskDestination(tt.input, tt.otpType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test code generation is cryptographically random
func TestOTPService_GenerateCode_Randomness(t *testing.T) {
	logger := zap.NewNop()
	redis := newMockOTPRedisClient()
	config := DefaultOTPConfig()
	mockProvider := NewMockProvider(logger)
	service := NewOTPService(logger, redis, mockProvider, config)

	// Generate multiple codes
	codes := make(map[string]bool)
	for i := 0; i < 100; i++ {
		code, err := service.generateCode()
		require.NoError(t, err)
		codes[code] = true
	}

	// With 100 codes, we should have close to 100 unique codes
	// (some collisions possible but unlikely)
	assert.Greater(t, len(codes), 90, "Should generate mostly unique codes")
}

// Test formatEmailMessage
func TestOTPService_FormatEmailMessage(t *testing.T) {
	service := NewOTPServiceWithPrefix(zap.NewNop(), newMockOTPRedisClient(), NewMockProvider(zap.NewNop()), DefaultOTPConfig(), "TestApp")

	otp := &OTPCode{
		Code:        "123456",
		Type:        OTPTypeEmail,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	message := service.formatEmailMessage(otp)
	assert.Contains(t, message, "123456")
	assert.Contains(t, message, "TestApp")
	assert.Contains(t, message, "5 minutes")
}

// Test formatSMSMessage
func TestOTPService_FormatSMSMessage(t *testing.T) {
	service := NewOTPServiceWithPrefix(zap.NewNop(), newMockOTPRedisClient(), NewMockProvider(zap.NewNop()), DefaultOTPConfig(), "TestApp")

	otp := &OTPCode{
		Code:        "654321",
		Type:        OTPTypeSMS,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	message := service.formatSMSMessage(otp)
	assert.Contains(t, message, "654321")
	assert.Contains(t, message, "TestApp")
	assert.Contains(t, message, "5 minutes")
}

// Test with real miniredis
func TestOTPService_WithMiniRedis(t *testing.T) {
	s := miniredis.RunT(t)
	defer s.Close()

	client := redis.NewClient(&redis.Options{
		Addr: s.Addr(),
	})

	logger := zap.NewNop()
	config := DefaultOTPConfig()
	mockProvider := NewMockProvider(logger)
	service := NewOTPService(logger, client, mockProvider, config)

	userID := uuid.New()
	ctx := context.Background()

	// Generate OTP
	otp, err := service.GenerateOTP(ctx, userID, OTPTypeEmail, "user@example.com")
	require.NoError(t, err)
	assert.Equal(t, 6, len(otp.Code))

	// Verify correct OTP
	valid, err := service.VerifyOTP(ctx, userID, OTPTypeEmail, otp.Code)
	require.NoError(t, err)
	assert.True(t, valid)

	// Can't verify again (code deleted)
	valid, err = service.VerifyOTP(ctx, userID, OTPTypeEmail, otp.Code)
	require.Error(t, err)
	assert.False(t, valid)
}

// Test rate limit expiry with real miniredis
func TestOTPService_RateLimitExpiry_WithMiniRedis(t *testing.T) {
	s := miniredis.RunT(t)
	defer s.Close()

	client := redis.NewClient(&redis.Options{
		Addr: s.Addr(),
	})

	logger := zap.NewNop()
	config := DefaultOTPConfig()
	mockProvider := NewMockProvider(logger)
	service := NewOTPService(logger, client, mockProvider, config)

	userID := uuid.New()
	ctx := context.Background()

	// Generate first OTP
	_, err := service.GenerateOTP(ctx, userID, OTPTypeEmail, "user@example.com")
	require.NoError(t, err)

	// Should be rate limited
	_, err = service.GenerateOTP(ctx, userID, OTPTypeEmail, "user@example.com")
	require.Error(t, err)

	// Fast forward past rate limit
	s.FastForward(config.RateLimit + time.Second)

	// Should work now
	otp2, err := service.GenerateOTP(ctx, userID, OTPTypeEmail, "user@example.com")
	require.NoError(t, err)
	assert.NotEmpty(t, otp2.Code)
}

// Test OTP expiry with real miniredis
func TestOTPService_Expiry_WithMiniRedis(t *testing.T) {
	s := miniredis.RunT(t)
	defer s.Close()

	client := redis.NewClient(&redis.Options{
		Addr: s.Addr(),
	})

	logger := zap.NewNop()
	config := DefaultOTPConfig()
	mockProvider := NewMockProvider(logger)
	service := NewOTPService(logger, client, mockProvider, config)

	userID := uuid.New()
	ctx := context.Background()

	// Generate OTP
	otp, err := service.GenerateOTP(ctx, userID, OTPTypeEmail, "user@example.com")
	require.NoError(t, err)

	// Fast forward past expiry
	s.FastForward(config.Expiry + time.Second)

	// Should be expired
	valid, err := service.VerifyOTP(ctx, userID, OTPTypeEmail, otp.Code)
	require.Error(t, err)
	assert.False(t, valid)
	assert.Contains(t, err.Error(), "not found or expired")
}

// Test GetRemainingTime_WithMiniRedis
func TestOTPService_GetRemainingTime_WithMiniRedis(t *testing.T) {
	s := miniredis.RunT(t)
	defer s.Close()

	client := redis.NewClient(&redis.Options{
		Addr: s.Addr(),
	})

	logger := zap.NewNop()
	config := DefaultOTPConfig()
	mockProvider := NewMockProvider(logger)
	service := NewOTPService(logger, client, mockProvider, config)

	userID := uuid.New()
	ctx := context.Background()

	// Generate OTP
	_, err := service.GenerateOTP(ctx, userID, OTPTypeEmail, "user@example.com")
	require.NoError(t, err)

	// Get remaining time
	remaining, err := service.GetRemainingTime(ctx, userID, OTPTypeEmail)
	require.NoError(t, err)
	assert.Greater(t, remaining, 4*time.Minute)

	// Fast forward 1 minute
	s.FastForward(time.Minute)

	// Get remaining time again
	remaining, err = service.GetRemainingTime(ctx, userID, OTPTypeEmail)
	require.NoError(t, err)
	assert.Greater(t, remaining, 3*time.Minute)
	assert.LessOrEqual(t, remaining, 4*time.Minute)
}
