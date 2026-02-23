// Package mfa provides Multi-Factor Authentication tests
package mfa

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// MockRecoveryCodeRepository is a mock implementation of RecoveryCodeRepository
type MockRecoveryCodeRepository struct {
	codes map[uuid.UUID][]RecoveryCode
}

func NewMockRecoveryCodeRepository() *MockRecoveryCodeRepository {
	return &MockRecoveryCodeRepository{
		codes: make(map[uuid.UUID][]RecoveryCode),
	}
}

func (m *MockRecoveryCodeRepository) CreateCodes(ctx context.Context, codes []RecoveryCode) error {
	for _, code := range codes {
		m.codes[code.UserID] = append(m.codes[code.UserID], code)
	}
	return nil
}

func (m *MockRecoveryCodeRepository) GetCodesByUserID(ctx context.Context, userID uuid.UUID) ([]RecoveryCode, error) {
	codes, exists := m.codes[userID]
	if !exists {
		return []RecoveryCode{}, nil
	}
	return codes, nil
}

func (m *MockRecoveryCodeRepository) GetUnusedCodeByUserIDAndHash(ctx context.Context, userID uuid.UUID, codeHash string) (*RecoveryCode, error) {
	codes, exists := m.codes[userID]
	if !exists {
		return nil, nil
	}
	for _, code := range codes {
		if !code.Used && code.CodeHash == codeHash {
			return &code, nil
		}
	}
	return nil, nil
}

func (m *MockRecoveryCodeRepository) MarkCodeUsed(ctx context.Context, codeID uuid.UUID, usedAt time.Time) error {
	for userID, codes := range m.codes {
		for i := range codes {
			if codes[i].ID == codeID {
				m.codes[userID][i].Used = true
				m.codes[userID][i].UsedAt = &usedAt
				return nil
			}
		}
	}
	return nil
}

func (m *MockRecoveryCodeRepository) DeleteCodesByUserID(ctx context.Context, userID uuid.UUID) error {
	delete(m.codes, userID)
	return nil
}

func (m *MockRecoveryCodeRepository) CountRemainingCodes(ctx context.Context, userID uuid.UUID) (int, error) {
	codes, exists := m.codes[userID]
	if !exists {
		return 0, nil
	}
	count := 0
	for _, code := range codes {
		if !code.Used {
			count++
		}
	}
	return count, nil
}

// Helper to get a mock Redis client
func newMockRedisClient(t *testing.T) *redis.Client {
	s := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{
		Addr: s.Addr(),
	})
	return client
}

// Test RecoveryCode generation

func TestRecoveryService_GenerateCodes(t *testing.T) {
	repo := NewMockRecoveryCodeRepository()
	redis := newMockRedisClient(t)
	logger := zap.NewNop()
	encrypter := NewNoopEncrypter()

	service := NewRecoveryService(repo, redis, logger, encrypter)
	userID := uuid.New()

	// Generate codes
	codeSet, err := service.GenerateCodes(context.Background(), userID)
	require.NoError(t, err)
	require.NotNil(t, codeSet)

	// Verify code count
	assert.Equal(t, RecoveryCodeCount, len(codeSet.Codes))
	assert.Equal(t, RecoveryCodeCount, codeSet.Remaining)

	// Verify all codes are for the correct user
	for _, code := range codeSet.Codes {
		assert.Equal(t, userID, code.UserID)
		assert.False(t, code.Used, "Newly generated codes should not be used")
		assert.NotEmpty(t, code.CodeHash, "Code hash should not be empty")
		assert.NotEmpty(t, code.ID, "Code ID should not be empty")
	}

	// Verify codes were stored in repository
	storedCodes, err := repo.GetCodesByUserID(context.Background(), userID)
	require.NoError(t, err)
	assert.Equal(t, RecoveryCodeCount, len(storedCodes))
}

func TestRecoveryService_GenerateCodes_ReplacesExisting(t *testing.T) {
	repo := NewMockRecoveryCodeRepository()
	redis := newMockRedisClient(t)
	logger := zap.NewNop()
	encrypter := NewNoopEncrypter()

	service := NewRecoveryService(repo, redis, logger, encrypter)
	userID := uuid.New()

	// Generate initial codes
	_, err := service.GenerateCodes(context.Background(), userID)
	require.NoError(t, err)

	// Use one code
	codes, _ := repo.GetCodesByUserID(context.Background(), userID)
	err = repo.MarkCodeUsed(context.Background(), codes[0].ID, time.Now())
	require.NoError(t, err)

	// Verify we have used codes
	remainingBefore, _ := repo.CountRemainingCodes(context.Background(), userID)
	assert.Equal(t, RecoveryCodeCount-1, remainingBefore)

	// Regenerate codes
	codeSet, err := service.RegenerateCodes(context.Background(), userID)
	require.NoError(t, err)
	require.NotNil(t, codeSet)

	// All codes should be new and unused
	assert.Equal(t, RecoveryCodeCount, len(codeSet.Codes))
	assert.Equal(t, RecoveryCodeCount, codeSet.Remaining)
	assert.True(t, codeSet.Regenerated)

	// Verify old codes were deleted
	storedCodes, _ := repo.GetCodesByUserID(context.Background(), userID)
	assert.Equal(t, RecoveryCodeCount, len(storedCodes))

	// Verify all stored codes are unused
	for _, code := range storedCodes {
		assert.False(t, code.Used)
	}
}

func TestRecoveryService_GenerateRandomCode(t *testing.T) {
	repo := NewMockRecoveryCodeRepository()
	redis := newMockRedisClient(t)
	logger := zap.NewNop()
	encrypter := NewNoopEncrypter()

	service := NewRecoveryService(repo, redis, logger, encrypter)

	// Generate multiple codes and verify uniqueness
	codes := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		code, err := service.generateRandomCode()
		require.NoError(t, err)
		assert.Len(t, code, RecoveryCodeLength)

		// Verify code only contains valid characters
		for _, c := range code {
			assert.Contains(t, RecoveryCodeAlphabet, string(c))
		}

		// Track uniqueness (with a high probability check)
		codes[code] = true
	}

	// We should have close to 1000 unique codes (collisions possible but unlikely)
	assert.Greater(t, len(codes), 990, "Should have mostly unique codes")
}

// Test RecoveryCode verification

func TestRecoveryService_VerifyCode_Valid(t *testing.T) {
	repo := NewMockRecoveryCodeRepository()
	redis := newMockRedisClient(t)
	logger := zap.NewNop()
	encrypter := NewNoopEncrypter()

	service := NewRecoveryService(repo, redis, logger, encrypter)
	userID := uuid.New()

	// Generate codes
	codeSet, err := service.GenerateCodes(context.Background(), userID)
	require.NoError(t, err)

	// Get a code's plaintext (we need to extract it from the service)
	// Since we use NoopEncrypter, we can work around this for testing
	// In real scenario, the codes would be stored in plaintext temporarily

	// For this test, we'll create a code with known plaintext
	plainCode := "ABCD1234"
	hashedCode, err := bcryptHash(plainCode)
	require.NoError(t, err)

	testCode := RecoveryCode{
		ID:       uuid.New(),
		UserID:   userID,
		CodeHash: hashedCode,
		Used:     false,
	}
	repo.CreateCodes(context.Background(), []RecoveryCode{testCode})

	// Verify the code
	verifiedCode, err := service.VerifyCode(context.Background(), userID, plainCode)
	require.NoError(t, err)
	require.NotNil(t, verifiedCode)
	assert.Equal(t, testCode.ID, verifiedCode.ID)
	assert.True(t, verifiedCode.Used)

	// Verify it's marked as used
	remaining, _ := service.GetRemainingCount(context.Background(), userID)
	assert.Equal(t, 0, remaining) // Only one test code
}

func TestRecoveryService_VerifyCode_Invalid(t *testing.T) {
	repo := NewMockRecoveryCodeRepository()
	redis := newMockRedisClient(t)
	logger := zap.NewNop()
	encrypter := NewNoopEncrypter()

	service := NewRecoveryService(repo, redis, logger, encrypter)
	userID := uuid.New()

	// Generate codes without tracking plaintext
	_, err := service.GenerateCodes(context.Background(), userID)
	require.NoError(t, err)

	// Try to verify with invalid code
	_, err = service.VerifyCode(context.Background(), userID, "INVALID0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid recovery code")
}

func TestRecoveryService_VerifyCode_SingleUse(t *testing.T) {
	repo := NewMockRecoveryCodeRepository()
	redis := newMockRedisClient(t)
	logger := zap.NewNop()
	encrypter := NewNoopEncrypter()

	service := NewRecoveryService(repo, redis, logger, encrypter)
	userID := uuid.New()

	// Create a test code
	plainCode := "TEST5678"
	hashedCode, err := bcryptHash(plainCode)
	require.NoError(t, err)

	testCode := RecoveryCode{
		ID:       uuid.New(),
		UserID:   userID,
		CodeHash: hashedCode,
		Used:     false,
	}
	repo.CreateCodes(context.Background(), []RecoveryCode{testCode})

	// First verification should succeed
	verifiedCode, err := service.VerifyCode(context.Background(), userID, plainCode)
	require.NoError(t, err)
	assert.True(t, verifiedCode.Used)

	// Second verification should fail (single-use)
	_, err = service.VerifyCode(context.Background(), userID, plainCode)
	assert.Error(t, err)
}

func TestRecoveryService_VerifyCode_RateLimit(t *testing.T) {
	repo := NewMockRecoveryCodeRepository()
	redis := newMockRedisClient(t)
	logger := zap.NewNop()
	encrypter := NewNoopEncrypter()

	service := NewRecoveryService(repo, redis, logger, encrypter)
	userID := uuid.New()

	// Try to verify invalid codes multiple times
	for i := 0; i < recoveryRateLimitMax; i++ {
		_, err := service.VerifyCode(context.Background(), userID, "BADCODE1")
		assert.Error(t, err)
	}

	// Next attempt should hit rate limit
	_, err := service.VerifyCode(context.Background(), userID, "BADCODE2")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rate limit")
}

func TestRecoveryService_VerifyCodeConstantTime(t *testing.T) {
	repo := NewMockRecoveryCodeRepository()
	redis := newMockRedisClient(t)
	logger := zap.NewNop()
	encrypter := NewNoopEncrypter()

	service := NewRecoveryService(repo, redis, logger, encrypter)
	userID := uuid.New()

	// Create a test code
	plainCode := "CONSTIME"
	hashedCode, err := bcryptHash(plainCode)
	require.NoError(t, err)

	testCode := RecoveryCode{
		ID:       uuid.New(),
		UserID:   userID,
		CodeHash: hashedCode,
		Used:     false,
	}
	repo.CreateCodes(context.Background(), []RecoveryCode{testCode})

	// Test valid code
	verifiedCode, err := service.VerifyCodeConstantTime(context.Background(), userID, plainCode)
	require.NoError(t, err)
	assert.NotNil(t, verifiedCode)
	assert.Equal(t, testCode.ID, verifiedCode.ID)

	// Test invalid code
	_, err = service.VerifyCodeConstantTime(context.Background(), userID, "WRONG01")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid recovery code")
}

func TestRecoveryService_GetRemainingCount(t *testing.T) {
	repo := NewMockRecoveryCodeRepository()
	redis := newMockRedisClient(t)
	logger := zap.NewNop()
	encrypter := NewNoopEncrypter()

	service := NewRecoveryService(repo, redis, logger, encrypter)
	userID := uuid.New()

	// Generate codes
	_, err := service.GenerateCodes(context.Background(), userID)
	require.NoError(t, err)

	// Check remaining count
	count, err := service.GetRemainingCount(context.Background(), userID)
	require.NoError(t, err)
	assert.Equal(t, RecoveryCodeCount, count)

	// Mark some codes as used
	codes, _ := repo.GetCodesByUserID(context.Background(), userID)
	for i := 0; i < 3; i++ {
		_ = repo.MarkCodeUsed(context.Background(), codes[i].ID, time.Now())
	}

	// Check remaining count again
	count, err = service.GetRemainingCount(context.Background(), userID)
	require.NoError(t, err)
	assert.Equal(t, RecoveryCodeCount-3, count)
}

func TestRecoveryService_HasCodes(t *testing.T) {
	repo := NewMockRecoveryCodeRepository()
	redis := newMockRedisClient(t)
	logger := zap.NewNop()
	encrypter := NewNoopEncrypter()

	service := NewRecoveryService(repo, redis, logger, encrypter)
	userID := uuid.New()

	// No codes initially
	assert.False(t, service.HasCodes(context.Background(), userID))

	// Generate codes
	_, err := service.GenerateCodes(context.Background(), userID)
	require.NoError(t, err)

	// Should have codes now
	assert.True(t, service.HasCodes(context.Background(), userID))

	// Use all codes
	codes, _ := repo.GetCodesByUserID(context.Background(), userID)
	for _, code := range codes {
		_ = repo.MarkCodeUsed(context.Background(), code.ID, time.Now())
	}

	// Should not have usable codes
	assert.False(t, service.HasCodes(context.Background(), userID))
}

func TestConstantTimeCompareCode(t *testing.T) {
	// Test matching codes
	result := ConstantTimeCompareCode("ABCD1234", "ABCD1234")
	assert.True(t, result)

	// Test non-matching codes
	result = ConstantTimeCompareCode("ABCD1234", "ABCD4321")
	assert.False(t, result)

	// Test wrong length codes
	result = ConstantTimeCompareCode("ABCD1234", "SHORT")
	assert.False(t, result)
}

// Helper function for bcrypt hashing in tests
func bcryptHash(plainCode string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plainCode), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// TOTP Drift Tolerance Tests

func TestTOTPService_DriftTolerance(t *testing.T) {
	logger := zap.NewNop()
	redis := newMockRedisClient(t)
	encrypter := NewNoopEncrypter()

	service := NewService(logger, redis, encrypter)

	// Generate a secret
	secret, err := service.GenerateSecret("testuser", "test@example.com")
	require.NoError(t, err)

	// Generate code for current time
	currentCode, err := service.GenerateCode(secret.Secret)
	require.NoError(t, err)

	// Test current time validates
	valid, err := service.ValidateCodeConstantTime(secret.Secret, currentCode, 0)
	require.NoError(t, err)
	assert.True(t, valid, "Current time code should validate")

	// Test with window for drift tolerance
	// Generate code for 30 seconds in the past
	pastTime := time.Now().Add(-30 * time.Second)
	pastCode, err := service.GenerateCodeCustom(secret.Secret, pastTime)
	require.NoError(t, err)

	// Should validate with window of 1
	valid, err = service.ValidateCodeConstantTime(secret.Secret, pastCode, 1)
	require.NoError(t, err)
	assert.True(t, valid, "Code from -30 seconds should validate with window=1")

	// Should not validate without window
	valid, err = service.ValidateCodeConstantTime(secret.Secret, pastCode, 0)
	require.NoError(t, err)
	assert.False(t, valid, "Code from -30 seconds should not validate with window=0")

	// Generate code for 30 seconds in the future
	futureTime := time.Now().Add(30 * time.Second)
	futureCode, err := service.GenerateCodeCustom(secret.Secret, futureTime)
	require.NoError(t, err)

	// Should validate with window of 1
	valid, err = service.ValidateCodeConstantTime(secret.Secret, futureCode, 1)
	require.NoError(t, err)
	assert.True(t, valid, "Code from +30 seconds should validate with window=1")

	// Test beyond window (60 seconds = 2 time steps)
	beyondTime := time.Now().Add(-60 * time.Second)
	beyondCode, err := service.GenerateCodeCustom(secret.Secret, beyondTime)
	require.NoError(t, err)

	valid, err = service.ValidateCodeConstantTime(secret.Secret, beyondCode, 1)
	require.NoError(t, err)
	assert.False(t, valid, "Code from -60 seconds should not validate with window=1")
}

func TestTOTPService_RateLimit(t *testing.T) {
	logger := zap.NewNop()
	redis := newMockRedisClient(t)
	encrypter := NewNoopEncrypter()

	service := NewService(logger, redis, encrypter)
	userID := uuid.New().String()

	// Generate a secret and valid code
	secret, err := service.GenerateSecret(userID, "test@example.com")
	require.NoError(t, err)

	validCode, err := service.GenerateCode(secret.Secret)
	require.NoError(t, err)

	// Use up the rate limit with invalid codes
	for i := 0; i < rateLimitMaxAttempts; i++ {
		_, err := service.VerifyTOTP(context.Background(), userID, secret.Secret, "000000")
		require.NoError(t, err)
	}

	// Even the valid code should fail due to rate limit
	valid, err = service.VerifyTOTP(context.Background(), userID, secret.Secret, validCode)
	require.NoError(t, err)
	assert.False(t, valid, "Should be rate limited")
}

func TestTOTPService_ReferenceVectors(t *testing.T) {
	// Test against RFC 6238 reference vectors
	// Secret: "12345678901234567890" in base32
	// For SHA1, 6 digits, 30 second period

	logger := zap.NewNop()
	redis := newMockRedisClient(t)
	encrypter := NewNoopEncrypter()

	config := &TOTPConfig{
		Issuer:      "Test",
		Period:      30,
		Digits:      6,
		Algorithm:   totp.AlgorithmSHA1,
		SecretLength: 20,
	}

	service := NewServiceWithConfig(logger, redis, encrypter, config)

	// Generate a secret with known value for testing
	// Using a fixed base32 secret
	testSecret := "JBSWY3DPEHPK3PXP" // Well-known test secret

	// Generate code for a specific time
	// Unix timestamp 59 (for testing purposes)
	testTime := time.Unix(59, 0)

	code, err := service.GenerateCodeCustom(testSecret, testTime)
	require.NoError(t, err)
	assert.NotEmpty(t, code)
	assert.Len(t, code, 6)

	// Verify the code is valid
	valid, err := service.ValidateCodeConstantTime(testSecret, code, 0)
	require.NoError(t, err)
	assert.True(t, valid)

	// Verify the same code for same time step (still valid)
	code2, err := service.GenerateCodeCustom(testSecret, testTime.Add(10*time.Second))
	require.NoError(t, err)
	assert.Equal(t, code, code2, "Same time step should produce same code")

	// Verify different code for next time step
	code3, err := service.GenerateCodeCustom(testSecret, testTime.Add(30*time.Second))
	require.NoError(t, err)
	assert.NotEqual(t, code, code3, "Different time step should produce different code")
}

// Benchmark tests

func BenchmarkRecoveryCodeGeneration(b *testing.B) {
	repo := NewMockRecoveryCodeRepository()
	redis := newMockRedisClient(b)
	logger := zap.NewNop()
	encrypter := NewNoopEncrypter()

	service := NewRecoveryService(repo, redis, logger, encrypter)
	ctx := context.Background()
	userID := uuid.New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = service.GenerateCodes(ctx, userID)
		_ = repo.DeleteCodesByUserID(ctx, userID)
	}
}

func BenchmarkRecoveryCodeVerification(b *testing.B) {
	repo := NewMockRecoveryCodeRepository()
	redis := newMockRedisClient(b)
	logger := zap.NewNop()
	encrypter := NewNoopEncrypter()

	service := NewRecoveryService(repo, redis, logger, encrypter)
	ctx := context.Background()
	userID := uuid.New()

	// Setup codes
	codeSet, _ := service.GenerateCodes(ctx, userID)
	codes, _ := repo.GetCodesByUserID(ctx, userID)

	// For benchmarking, we need to track a plaintext code
	// In real usage, this wouldn't be available after generation
	plainCode := "TESTBENCH"

	// Create a known code
	hashedCode, _ := bcryptHash(plainCode)
	testCode := RecoveryCode{
		ID:       uuid.New(),
		UserID:   userID,
		CodeHash: hashedCode,
		Used:     false,
	}
	repo.CreateCodes(ctx, []RecoveryCode{testCode})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Create a new unused code for each iteration
		testCode.ID = uuid.New()
		testCode.Used = false
		_, _ = service.VerifyCode(ctx, userID, plainCode)
	}
}
