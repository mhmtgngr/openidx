// Package mfa provides Multi-Factor Authentication functionality
package mfa

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestTOTPService_GenerateSecret(t *testing.T) {
	logger := zap.NewNop()
	redisClient := newMockRedisClient(t)
	encrypter := NewNoopEncrypter()

	service := NewService(logger, redisClient, encrypter)

	tests := []struct {
		name        string
		userID      string
		accountName string
		wantErr     bool
	}{
		{
			name:        "generate secret with account name",
			userID:      "user123",
			accountName: "test@example.com",
			wantErr:     false,
		},
		{
			name:        "generate secret without account name",
			userID:      "user456",
			accountName: "",
			wantErr:     false,
		},
		{
			name:        "generate secret with empty user ID",
			userID:      "",
			accountName: "test@example.com",
			wantErr:     false, // TOTP generation doesn't validate userID
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret, err := service.GenerateSecret(tt.userID, tt.accountName)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, secret)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, secret)
				assert.NotEmpty(t, secret.Secret, "Secret should not be empty")
				assert.NotEmpty(t, secret.QRCodeURL, "QR Code URL should not be empty")
				assert.Equal(t, DefaultTOTPIssuer, secret.Issuer)

				// Account name should default to userID if not provided
				expectedAccountName := tt.accountName
				if expectedAccountName == "" {
					expectedAccountName = tt.userID
				}
				assert.Equal(t, expectedAccountName, secret.AccountName)

				// Verify QR Code URL format
				assert.Contains(t, secret.QRCodeURL, "otpauth://totp")
				assert.Contains(t, secret.QRCodeURL, secret.AccountName)
			}
		})
	}
}

func TestTOTPService_ValidateCode(t *testing.T) {
	logger := zap.NewNop()
	redisClient := newMockRedisClient(t)
	encrypter := NewNoopEncrypter()

	service := NewService(logger, redisClient, encrypter)

	// Generate a valid secret
	secret, err := service.GenerateSecret("testuser", "test@example.com")
	require.NoError(t, err)

	// Generate a valid code for current time
	validCode, err := service.GenerateCode(secret.Secret)
	require.NoError(t, err)

	tests := []struct {
		name    string
		secret  string
		code    string
		window  int
		wantErr bool
		wantVal bool
	}{
		{
			name:    "valid code with no window",
			secret:  secret.Secret,
			code:    validCode,
			window:  0,
			wantErr: false,
			wantVal: true,
		},
		{
			name:    "valid code with window",
			secret:  secret.Secret,
			code:    validCode,
			window:  1,
			wantErr: false,
			wantVal: true,
		},
		{
			name:    "invalid code",
			secret:  secret.Secret,
			code:    "000000",
			window:  0,
			wantErr: false,
			wantVal: false,
		},
		{
			name:    "empty code",
			secret:  secret.Secret,
			code:    "",
			window:  0,
			wantErr: true,
			wantVal: false,
		},
		{
			name:    "empty secret",
			secret:  "",
			code:    validCode,
			window:  0,
			wantErr: true,
			wantVal: false,
		},
		{
			name:    "code too short",
			secret:  secret.Secret,
			code:    "123",
			window:  0,
			wantErr: true,  // TOTP validation returns error for invalid length codes
			wantVal: false,
		},
		{
			name:    "code too long",
			secret:  secret.Secret,
			code:    "123456789",
			window:  0,
			wantErr: true,  // TOTP validation returns error for invalid length codes
			wantVal: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := service.ValidateCode(tt.secret, tt.code, tt.window)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantVal, valid)
			}
		})
	}
}

func TestTOTPService_ValidateCodeConstantTime(t *testing.T) {
	logger := zap.NewNop()
	redisClient := newMockRedisClient(t)
	encrypter := NewNoopEncrypter()

	service := NewService(logger, redisClient, encrypter)

	// Generate a valid secret
	secret, err := service.GenerateSecret("testuser", "test@example.com")
	require.NoError(t, err)

	// Generate a valid code for current time
	validCode, err := service.GenerateCode(secret.Secret)
	require.NoError(t, err)

	// Test that validation works
	valid, err := service.ValidateCodeConstantTime(secret.Secret, validCode, 0)
	require.NoError(t, err)
	assert.True(t, valid, "Valid code should pass validation")

	// Test that invalid code fails
	invalidCode := "000000"
	valid, err = service.ValidateCodeConstantTime(secret.Secret, invalidCode, 0)
	require.NoError(t, err)
	assert.False(t, valid, "Invalid code should fail validation")
}

func TestTOTPService_EnrollTOTP(t *testing.T) {
	logger := zap.NewNop()
	redisClient := newMockRedisClient(t)
	encrypter := NewNoopEncrypter()

	service := NewService(logger, redisClient, encrypter)

	tests := []struct {
		name        string
		userID      string
		accountName string
		wantErr     bool
	}{
		{
			name:        "successful enrollment",
			userID:      uuid.New().String(),
			accountName: "test@example.com",
			wantErr:     false,
		},
		{
			name:        "enrollment with empty account name",
			userID:      uuid.New().String(),
			accountName: "",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret, encryptedSecret, err := service.EnrollTOTP(context.Background(), tt.userID, tt.accountName)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, secret)
				assert.Empty(t, encryptedSecret)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, secret)
				assert.NotEmpty(t, secret.Secret)
				assert.NotEmpty(t, secret.QRCodeURL)
				assert.NotEmpty(t, encryptedSecret)

				// With NoopEncrypter, encrypted secret should match original
				assert.Equal(t, secret.Secret, encryptedSecret)
			}
		})
	}
}

func TestTOTPService_VerifyTOTP(t *testing.T) {
	logger := zap.NewNop()
	redisClient := newMockRedisClient(t)
	encrypter := NewNoopEncrypter()

	service := NewService(logger, redisClient, encrypter)

	userID := uuid.New().String()

	// Generate a secret and valid code
	secret, err := service.GenerateSecret(userID, "test@example.com")
	require.NoError(t, err)

	validCode, err := service.GenerateCode(secret.Secret)
	require.NoError(t, err)

	tests := []struct {
		name    string
		userID  string
		secret  string
		code    string
		wantErr bool
		wantVal bool
	}{
		{
			name:    "valid code",
			userID:  userID,
			secret:  secret.Secret,
			code:    validCode,
			wantErr: false,
			wantVal: true,
		},
		{
			name:    "invalid code",
			userID:  userID,
			secret:  secret.Secret,
			code:    "000000",
			wantErr: false,
			wantVal: false,
		},
		{
			name:    "empty code",
			userID:  userID,
			secret:  secret.Secret,
			code:    "",
			wantErr: true,
			wantVal: false,
		},
		{
			name:    "empty secret",
			userID:  userID,
			secret:  "",
			code:    validCode,
			wantErr: true,
			wantVal: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := service.VerifyTOTP(context.Background(), tt.userID, tt.secret, tt.code)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantVal, valid)
			}
		})
	}
}

func TestTOTPService_GenerateCode(t *testing.T) {
	logger := zap.NewNop()
	redisClient := newMockRedisClient(t)
	encrypter := NewNoopEncrypter()

	service := NewService(logger, redisClient, encrypter)

	secret, err := service.GenerateSecret("testuser", "test@example.com")
	require.NoError(t, err)

	// Generate code for current time
	code, err := service.GenerateCode(secret.Secret)
	assert.NoError(t, err)
	assert.NotEmpty(t, code)
	assert.Len(t, code, 6) // Default is 6 digits

	// Verify the code is valid
	valid, err := service.ValidateCode(secret.Secret, code, 0)
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestTOTPService_GenerateCodeCustom(t *testing.T) {
	logger := zap.NewNop()
	redisClient := newMockRedisClient(t)
	encrypter := NewNoopEncrypter()

	service := NewService(logger, redisClient, encrypter)

	secret, err := service.GenerateSecret("testuser", "test@example.com")
	require.NoError(t, err)

	// Generate code for a specific time
	testTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	code, err := service.GenerateCodeCustom(secret.Secret, testTime)
	assert.NoError(t, err)
	assert.NotEmpty(t, code)
	assert.Len(t, code, 6)

	// Generate code for the same time again - should be the same
	code2, err := service.GenerateCodeCustom(secret.Secret, testTime)
	assert.NoError(t, err)
	assert.Equal(t, code, code2, "Code should be the same for the same time")

	// Generate code for different time (30 seconds later)
	differentTime := testTime.Add(30 * time.Second)
	code3, err := service.GenerateCodeCustom(secret.Secret, differentTime)
	assert.NoError(t, err)
	assert.NotEqual(t, code, code3, "Code should be different for different time steps")
}

func TestAES256GCMEncrypter(t *testing.T) {
	tests := []struct {
		name      string
		keySize   int
		plaintext string
		wantErr   bool
	}{
		{
			name:      "valid encryption and decryption",
			keySize:   32,
			plaintext: "JBSWY3DPEHPK3PXP", // Base32 TOTP secret
			wantErr:   false,
		},
		{
			name:      "invalid key size",
			keySize:   16,
			plaintext: "test",
			wantErr:   true,
		},
		{
			name:      "empty plaintext",
			keySize:   32,
			plaintext: "",
			wantErr:   false, // Empty string is valid
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a key of the specified size
			key := make([]byte, tt.keySize)
			for i := range key {
				key[i] = byte(i % 256)
			}

			encrypter, err := NewAES256GCMEncrypter(string(key))
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Test encryption
			ciphertext, err := encrypter.Encrypt(tt.plaintext)
			assert.NoError(t, err)
			assert.NotEmpty(t, ciphertext)
			assert.NotEqual(t, tt.plaintext, ciphertext, "Ciphertext should differ from plaintext")

			// Test decryption
			decrypted, err := encrypter.Decrypt(ciphertext)
			assert.NoError(t, err)
			assert.Equal(t, tt.plaintext, decrypted, "Decrypted text should match original")

			// Test that invalid ciphertext fails
			_, err = encrypter.Decrypt("invalid-base64!@#")
			assert.Error(t, err, "Invalid ciphertext should return error")
		})
	}
}

func TestTOTPConfig_Defaults(t *testing.T) {
	config := DefaultTOTPConfig()

	assert.Equal(t, DefaultTOTPIssuer, config.Issuer)
	assert.Equal(t, uint(DefaultTOTPPeriod), config.Period)
	assert.Equal(t, otp.Digits(DefaultTOTPDigits), config.Digits)
	assert.Equal(t, DefaultTOTPAlgorithm, config.Algorithm)
	assert.Equal(t, DefaultSecretLength, config.SecretLength)
}

// Benchmark tests

func BenchmarkValidateCode(b *testing.B) {
	logger := zap.NewNop()
	redisClient := newMockRedisClient(b)
	encrypter := NewNoopEncrypter()

	service := NewService(logger, redisClient, encrypter)

	secret, _ := service.GenerateSecret("testuser", "test@example.com")
	validCode, _ := service.GenerateCode(secret.Secret)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = service.ValidateCode(secret.Secret, validCode, 0)
	}
}

func BenchmarkValidateCodeConstantTime(b *testing.B) {
	logger := zap.NewNop()
	redisClient := newMockRedisClient(b)
	encrypter := NewNoopEncrypter()

	service := NewService(logger, redisClient, encrypter)

	secret, _ := service.GenerateSecret("testuser", "test@example.com")
	validCode, _ := service.GenerateCode(secret.Secret)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = service.ValidateCodeConstantTime(secret.Secret, validCode, 0)
	}
}

func BenchmarkGenerateCode(b *testing.B) {
	logger := zap.NewNop()
	redisClient := newMockRedisClient(b)
	encrypter := NewNoopEncrypter()

	service := NewService(logger, redisClient, encrypter)

	secret, _ := service.GenerateSecret("testuser", "test@example.com")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = service.GenerateCode(secret.Secret)
	}
}
