// Package mfa provides Multi-Factor Authentication enrollment tests
package mfa

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// MockTOTPRepository is a mock implementation of Repository for testing
type MockTOTPRepository struct {
	enrollments map[uuid.UUID]*TOTPEnrollment
}

func NewMockTOTPRepository() *MockTOTPRepository {
	return &MockTOTPRepository{
		enrollments: make(map[uuid.UUID]*TOTPEnrollment),
	}
}

func (m *MockTOTPRepository) CreateTOTP(ctx context.Context, enrollment *TOTPEnrollment) error {
	m.enrollments[enrollment.UserID] = enrollment
	return nil
}

func (m *MockTOTPRepository) GetTOTPByUserID(ctx context.Context, userID uuid.UUID) (*TOTPEnrollment, error) {
	enrollment, exists := m.enrollments[userID]
	if !exists {
		return nil, nil
	}
	return enrollment, nil
}

func (m *MockTOTPRepository) UpdateTOTP(ctx context.Context, enrollment *TOTPEnrollment) error {
	m.enrollments[enrollment.UserID] = enrollment
	return nil
}

func (m *MockTOTPRepository) DeleteTOTP(ctx context.Context, userID uuid.UUID) error {
	delete(m.enrollments, userID)
	return nil
}

func (m *MockTOTPRepository) VerifyTOTP(ctx context.Context, userID uuid.UUID) error {
	if enrollment, exists := m.enrollments[userID]; exists {
		now := time.Now()
		enrollment.Verified = true
		enrollment.VerifiedAt = &now
	}
	return nil
}

func (m *MockTOTPRepository) MarkTOTPUsed(ctx context.Context, userID uuid.UUID) error {
	if enrollment, exists := m.enrollments[userID]; exists {
		now := time.Now()
		enrollment.LastUsedAt = &now
	}
	return nil
}

func (m *MockTOTPRepository) Ping(ctx context.Context) error {
	return nil
}

// Test TOTP Enrollment Flow

func TestEnrollmentFlow_Complete(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Setup services
	logger := zap.NewNop()
	redisClient := newMockRedisClient(t)
	encrypter := NewNoopEncrypter()

	totpRepo := NewMockTOTPRepository()
	recoveryRepo := NewMockRecoveryCodeRepository()

	totpService := NewService(logger, redisClient, encrypter)
	recoveryService := NewRecoveryService(recoveryRepo, redisClient, logger, encrypter)

	enrollmentService := NewEnrollmentService(totpService, recoveryService, totpRepo, recoveryRepo, logger)
	handlers := NewHandlers(enrollmentService, logger)

	// Setup router
	router := gin.New()
	handlers.RegisterRoutes(router)

	userID := uuid.New()

	// Step 1: Initiate TOTP enrollment
	t.Run("Step1_EnrollTOTP", func(t *testing.T) {
		reqBody := TOTPEnrollRequest{
			UserID:      userID.String(),
			AccountName: "test@example.com",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/mfa/enroll/totp", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp TOTPEnrollResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotEmpty(t, resp.Secret)
		assert.NotEmpty(t, resp.QRCodeURL)
		assert.Contains(t, resp.QRCodeURL, "otpauth://totp")
		assert.Contains(t, resp.QRCodeURL, "OpenIDX")
	})

	// Step 2: Verify the TOTP enrollment with a valid code
	t.Run("Step2_VerifyTOTP", func(t *testing.T) {
		// Get the enrollment to extract the secret
		enrollment, err := totpRepo.GetTOTPByUserID(context.Background(), userID)
		require.NoError(t, err)
		require.NotNil(t, enrollment)

		// Decrypt the secret to generate a valid code
		secret, err := totpService.encrypter.Decrypt(enrollment.Secret)
		require.NoError(t, err)

		// Generate a valid code for the current time
		validCode, err := totpService.GenerateCode(secret)
		require.NoError(t, err)

		reqBody := TOTPVerifyRequest{
			UserID: userID.String(),
			Code:   validCode,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/mfa/enroll/totp/verify", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp TOTPVerifyResponse
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.True(t, resp.Success)
		assert.Contains(t, resp.Message, "enabled")

		// Verify the enrollment is now enabled
		enrollment, _ = totpRepo.GetTOTPByUserID(context.Background(), userID)
		assert.True(t, enrollment.Verified)
		assert.True(t, enrollment.Enabled)
	})

	// Step 3: Use MFA verification at login time
	t.Run("Step3_MFAVerify", func(t *testing.T) {
		enrollment, err := totpRepo.GetTOTPByUserID(context.Background(), userID)
		require.NoError(t, err)

		// Decrypt the secret to generate a valid code
		secret, err := totpService.encrypter.Decrypt(enrollment.Secret)
		require.NoError(t, err)

		// Generate a code for the next time window (30 seconds from now)
		// This ensures we get a different code than Step 2 to avoid replay attack detection
		validCode, err := totpService.GenerateCodeCustom(secret, time.Now().Add(30*time.Second))
		require.NoError(t, err)

		reqBody := MFAVerifyRequest{
			UserID: userID.String(),
			Code:   validCode,
			Method: "totp",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/mfa/verify", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp MFAVerifyResponse
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.True(t, resp.Success)
		assert.Contains(t, resp.Message, "verified")
	})
}

func TestEnrollmentFlow_RecoveryCodes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Setup services
	logger := zap.NewNop()
	redisClient := newMockRedisClient(t)
	encrypter := NewNoopEncrypter()

	totpRepo := NewMockTOTPRepository()
	recoveryRepo := NewMockRecoveryCodeRepository()

	totpService := NewService(logger, redisClient, encrypter)
	recoveryService := NewRecoveryService(recoveryRepo, redisClient, logger, encrypter)

	enrollmentService := NewEnrollmentService(totpService, recoveryService, totpRepo, recoveryRepo, logger)
	handlers := NewHandlers(enrollmentService, logger)

	// Setup router
	router := gin.New()
	handlers.RegisterRoutes(router)

	userID := uuid.New()

	// Generate recovery codes
	t.Run("GenerateRecoveryCodes", func(t *testing.T) {
		reqBody := struct {
			UserID string `json:"user_id"`
		}{
			UserID: userID.String(),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/mfa/recovery/generate", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp RecoveryGenerateResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotEmpty(t, resp.Codes)
		assert.Equal(t, RecoveryCodeCount, resp.Remaining)
		assert.NotEmpty(t, resp.Warning)
	})

	// Check recovery code status
	t.Run("RecoveryCodeStatus", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/mfa/recovery/status?user_id="+userID.String(), nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp RecoveryStatusResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.True(t, resp.Enabled)
		assert.Equal(t, RecoveryCodeCount, resp.Remaining)
	})
}

func TestEnrollmentFlow_InvalidRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Setup services
	logger := zap.NewNop()
	redisClient := newMockRedisClient(t)
	encrypter := NewNoopEncrypter()

	totpRepo := NewMockTOTPRepository()
	recoveryRepo := NewMockRecoveryCodeRepository()

	totpService := NewService(logger, redisClient, encrypter)
	recoveryService := NewRecoveryService(recoveryRepo, redisClient, logger, encrypter)

	enrollmentService := NewEnrollmentService(totpService, recoveryService, totpRepo, recoveryRepo, logger)
	handlers := NewHandlers(enrollmentService, logger)

	// Setup router
	router := gin.New()
	handlers.RegisterRoutes(router)

	t.Run("InvalidUserID", func(t *testing.T) {
		reqBody := TOTPEnrollRequest{
			UserID: "not-a-uuid",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/mfa/enroll/totp", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("MissingUserID", func(t *testing.T) {
		reqBody := TOTPEnrollRequest{}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/mfa/enroll/totp", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("InvalidTOTPCode", func(t *testing.T) {
		userID := uuid.New()

		// First enroll
		enrollReq := TOTPEnrollRequest{
			UserID: userID.String(),
		}
		body, _ := json.Marshal(enrollReq)

		req := httptest.NewRequest("POST", "/mfa/enroll/totp", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(httptest.NewRecorder(), req)

		// Now try to verify with invalid code
		verifyReq := TOTPVerifyRequest{
			UserID: userID.String(),
			Code:   "000000",
		}
		body, _ = json.Marshal(verifyReq)

		req = httptest.NewRequest("POST", "/mfa/enroll/totp/verify", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp TOTPVerifyResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.False(t, resp.Success)
	})
}

func TestEnrollmentFlow_RateLimiting(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Setup services
	logger := zap.NewNop()
	s := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: s.Addr()})
	encrypter := NewNoopEncrypter()

	totpRepo := NewMockTOTPRepository()
	recoveryRepo := NewMockRecoveryCodeRepository()

	totpService := NewService(logger, redisClient, encrypter)
	recoveryService := NewRecoveryService(recoveryRepo, redisClient, logger, encrypter)

	enrollmentService := NewEnrollmentService(totpService, recoveryService, totpRepo, recoveryRepo, logger)
	handlers := NewHandlers(enrollmentService, logger)

	// Setup router
	router := gin.New()
	handlers.RegisterRoutes(router)

	userID := uuid.New()

	// First enroll
	enrollReq := TOTPEnrollRequest{
		UserID: userID.String(),
	}
	body, _ := json.Marshal(enrollReq)

	req := httptest.NewRequest("POST", "/mfa/enroll/totp", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(httptest.NewRecorder(), req)

	// Try to verify with invalid codes up to rate limit
	for i := 0; i < rateLimitMaxAttempts; i++ {
		verifyReq := TOTPVerifyRequest{
			UserID: userID.String(),
			Code:   "111111",
		}
		body, _ = json.Marshal(verifyReq)

		req := httptest.NewRequest("POST", "/mfa/enroll/totp/verify", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		var resp TOTPVerifyResponse
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		assert.False(t, resp.Success, "Invalid code should fail")
	}

	// Get a valid code
	enrollment, _ := totpRepo.GetTOTPByUserID(context.Background(), userID)
	validCode, _ := totpService.GenerateCode(enrollment.Secret)

	// Even the valid code should fail due to rate limit
	verifyReq := TOTPVerifyRequest{
		UserID: userID.String(),
		Code:   validCode,
	}
	body, _ = json.Marshal(verifyReq)

	req = httptest.NewRequest("POST", "/mfa/enroll/totp/verify", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Response should indicate failure
	var resp TOTPVerifyResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.False(t, resp.Success, "Should be rate limited")
}

// TestTOTPDriftTolerance tests the drift tolerance during enrollment verification
func TestTOTP_DriftTolerance_Enrollment(t *testing.T) {
	logger := zap.NewNop()
	redisClient := newMockRedisClient(t)
	encrypter := NewNoopEncrypter()

	totpService := NewService(logger, redisClient, encrypter)

	userID := uuid.New().String()

	// Generate a secret
	secret, encryptedSecret, err := totpService.EnrollTOTP(context.Background(), userID, "test@example.com")
	require.NoError(t, err)
	require.NotNil(t, secret)

	// Generate code for current time
	currentCode, err := totpService.GenerateCode(secret.Secret)
	require.NoError(t, err)

	// Verify current time code works
	valid, err := totpService.VerifyTOTP(context.Background(), userID, secret.Secret, currentCode)
	require.NoError(t, err)
	assert.True(t, valid)

	// Generate code from 30 seconds ago
	pastCode, err := totpService.GenerateCodeCustom(secret.Secret, time.Now().Add(-30*time.Second))
	require.NoError(t, err)

	// Should verify with drift tolerance
	valid, err = totpService.VerifyTOTP(context.Background(), userID, secret.Secret, pastCode)
	require.NoError(t, err)
	assert.True(t, valid, "Code from -30s should validate with drift tolerance")

	// Generate code from 30 seconds in the future
	futureCode, err := totpService.GenerateCodeCustom(secret.Secret, time.Now().Add(30*time.Second))
	require.NoError(t, err)

	// Should verify with drift tolerance
	valid, err = totpService.VerifyTOTP(context.Background(), userID, secret.Secret, futureCode)
	require.NoError(t, err)
	assert.True(t, valid, "Code from +30s should validate with drift tolerance")

	// Code from 60 seconds ago should not validate
	oldCode, err := totpService.GenerateCodeCustom(secret.Secret, time.Now().Add(-60*time.Second))
	require.NoError(t, err)

	valid, err = totpService.VerifyTOTP(context.Background(), userID, secret.Secret, oldCode)
	require.NoError(t, err)
	assert.False(t, valid, "Code from -60s should not validate with drift tolerance of 1")

	// Verify the encrypted secret can be decrypted
	decryptedSecret, err := encrypter.Decrypt(encryptedSecret)
	require.NoError(t, err)
	assert.Equal(t, secret.Secret, decryptedSecret)
}

// TestRecoveryCode_SingleUse verifies single-use behavior
func TestRecoveryCode_SingleUse_Detailed(t *testing.T) {
	repo := NewMockRecoveryCodeRepository()
	redisClient := newMockRedisClient(t)
	logger := zap.NewNop()
	encrypter := NewNoopEncrypter()

	service := NewRecoveryService(repo, redisClient, logger, encrypter)
	ctx := context.Background()
	userID := uuid.New()

	// We can't verify codes directly since we only have bcrypt hashes
	// But we can test the single-use behavior with a known code
	plainCode := "SINGLE01"
	hashedCode, err := bcryptHash(plainCode)
	require.NoError(t, err)

	testCode := RecoveryCode{
		ID:       uuid.New(),
		UserID:   userID,
		CodeHash: hashedCode,
		Used:     false,
	}
	err = repo.CreateCodes(ctx, []RecoveryCode{testCode})
	require.NoError(t, err)

	// First use should succeed
	usedCode, err := service.VerifyCode(ctx, userID, plainCode)
	require.NoError(t, err)
	require.NotNil(t, usedCode)
	assert.True(t, usedCode.Used)

	// Get remaining codes - should be 0 since the only code is now used
	remaining, err := service.GetRemainingCount(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, 0, remaining)

	// Second use should fail
	_, err = service.VerifyCode(ctx, userID, plainCode)
	assert.Error(t, err)

	// Remaining should still be 0 (code already used)
	remaining, err = service.GetRemainingCount(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, 0, remaining)
}

// TestTOTPSecretFormat verifies the TOTP secret format
func TestTOTPSecret_Format(t *testing.T) {
	logger := zap.NewNop()
	redisClient := newMockRedisClient(t)
	encrypter := NewNoopEncrypter()

	service := NewService(logger, redisClient, encrypter)

	// Test secret generation
	secret, err := service.GenerateSecret("testuser", "test@example.com")
	require.NoError(t, err)

	// Verify secret is Base32 encoded (only contains A-Z, 2-7, and padding =)
	for _, c := range secret.Secret {
		isValid := (c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7') || c == '='
		assert.True(t, isValid, "Secret should be valid Base32: %c", c)
	}

	// Verify secret length (20 bytes = 32 Base32 chars with padding)
	assert.LessOrEqual(t, len(secret.Secret), 32)

	// Verify QR code URL format
	assert.Contains(t, secret.QRCodeURL, "otpauth://totp")
	assert.Contains(t, secret.QRCodeURL, "OpenIDX")
	assert.Contains(t, secret.QRCodeURL, "test@example.com")
	assert.Contains(t, secret.QRCodeURL, "secret=")

	// Verify issuer
	assert.Equal(t, "OpenIDX", secret.Issuer)

	// Verify account name
	assert.Equal(t, "test@example.com", secret.AccountName)
}

// Benchmark enrollment flow
func BenchmarkEnrollmentFlow(b *testing.B) {
	gin.SetMode(gin.TestMode)

	logger := zap.NewNop()
	redisClient := newMockRedisClient(b)
	encrypter := NewNoopEncrypter()

	totpRepo := NewMockTOTPRepository()
	recoveryRepo := NewMockRecoveryCodeRepository()

	totpService := NewService(logger, redisClient, encrypter)
	recoveryService := NewRecoveryService(recoveryRepo, redisClient, logger, encrypter)

	enrollmentService := NewEnrollmentService(totpService, recoveryService, totpRepo, recoveryRepo, logger)
	handlers := NewHandlers(enrollmentService, logger)

	router := gin.New()
	handlers.RegisterRoutes(router)

	ctx := context.Background()
	userID := uuid.New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Generate secret
		_, _, _ = totpService.EnrollTOTP(ctx, userID.String(), "test@example.com")
		_ = totpRepo.DeleteTOTP(ctx, userID)
	}
}
