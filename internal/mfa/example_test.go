// Package mfa provides Multi-Factor Authentication functionality
package mfa_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/openidx/openidx/internal/mfa"
	"go.uber.org/zap"
	"github.com/redis/go-redis/v9"
)

// ExampleTOTPEnrollment demonstrates how to enroll a user in TOTP
func ExampleTOTPEnrollment() {
	// Initialize logger
	logger := zap.NewExample()

	// Initialize Redis client (for replay attack prevention)
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	// Initialize encrypter - USE A SECURE 32-BYTE KEY IN PRODUCTION
	// For this example, we use a 32-byte key
	encryptionKey := "12345678901234567890123456789012" // 32 bytes
	encrypter, err := mfa.NewAES256GCMEncrypter(encryptionKey)
	if err != nil {
		log.Fatal(err)
	}

	// Create TOTP service
	totpService := mfa.NewTOTPService(logger, redisClient, encrypter)

	// Generate TOTP secret for user
	userID := "user-123"
	accountName := "alice@example.com"

	secret, encryptedSecret, err := totpService.EnrollTOTP(context.Background(), userID, accountName)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Account Name: %s\n", secret.AccountName)
	fmt.Printf("Secret (for QR code): %s\n", secret.Secret)
	fmt.Printf("QR Code URL: %s\n", secret.QRCodeURL)
	fmt.Printf("Encrypted Secret (store in DB): %s\n", encryptedSecret)

	// User would scan the QR code URL with their authenticator app
	// Output:
	// Account Name: alice@example.com
	// Secret (for QR code): JBSWY3DPEHPK3PXP
	// QR Code URL: otpauth://totp/OpenIDX%3Aalice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=OpenIDX
	// Encrypted Secret (store in DB): ...
}

// ExampleTOTPValidation demonstrates how to validate a TOTP code
func ExampleTOTPValidation() {
	logger := zap.NewExample()
	redisClient := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	encrypter, _ := mfa.NewAES256GCMEncrypter("12345678901234567890123456789012")

	totpService := mfa.NewTOTPService(logger, redisClient, encrypter)

	// Generate a secret (normally stored in database)
	secret, _, _ := totpService.EnrollTOTP(context.Background(), "user-123", "alice@example.com")

	// Generate current valid code (user would get this from their authenticator app)
	currentCode, _ := totpService.GenerateCode(secret.Secret)

	// Validate the code using constant-time comparison (recommended)
	valid, err := totpService.ValidateCodeConstantTime(
		secret.Secret,
		currentCode,
		1, // Allow ±1 time step window for clock drift
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Code valid: %v\n", valid)
	// Output: Code valid: true

	// Test with invalid code
	invalidCode := "000000"
	valid, _ = totpService.ValidateCodeConstantTime(secret.Secret, invalidCode, 1)
	fmt.Printf("Invalid code valid: %v\n", valid)
	// Output: Invalid code valid: false
}

// ExampleTOTPWithReplayPrevention demonstrates replay attack prevention
func ExampleTOTPWithReplayPrevention() {
	ctx := context.Background()
	logger := zap.NewExample()
	redisClient := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	encrypter, _ := mfa.NewAES256GCMEncrypter("12345678901234567890123456789012")

	totpService := mfa.NewTOTPService(logger, redisClient, encrypter)

	userID := uuid.New().String()
	secret, _, _ := totpService.EnrollTOTP(ctx, userID, "alice@example.com")
	currentCode, _ := totpService.GenerateCode(secret.Secret)

	// First use - should succeed
	valid, err := totpService.VerifyTOTP(ctx, userID, secret.Secret, currentCode)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("First use valid: %v\n", valid)
	// Output: First use valid: true

	// Second use (replay attack) - should fail
	valid, err = totpService.VerifyTOTP(ctx, userID, secret.Secret, currentCode)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Replay attack valid: %v\n", valid)
	// Output: Replay attack valid: false
}

// ExampleTOTPService demonstrates the high-level service API
func ExampleTOTPService() {
	ctx := context.Background()
	logger := zap.NewExample()
	redisClient := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	encrypter, _ := mfa.NewAES256GCMEncrypter("12345678901234567890123456789012")

	// Note: In real usage, you would provide a pgxpool.Pool
	// pool, _ := pgxpool.New(ctx, databaseURL)
	// service := mfa.NewService(logger, pool, redisClient, encrypter)

	// For this example, we show the API usage
	userID := uuid.New()

	// Step 1: Enroll user in TOTP
	// secret, err := service.EnrollTOTP(ctx, userID, "alice@example.com")
	_ = userID
	_ = encrypter
	_ = redisClient
	_ = logger
	_ = ctx
	_ = time.Now()

	// Step 2: User scans QR code and enters verification code
	// verificationCode := "123456"
	// err = service.VerifyAndEnableTOTP(ctx, userID, verificationCode)

	// Step 3: Authenticate user during login
	// loginCode := "654321"
	// valid, err := service.AuthenticateTOTP(ctx, userID, loginCode)

	// Step 4: Check TOTP status
	// status, err := service.GetTOTPStatus(ctx, userID)

	// Step 5: Disable TOTP if needed
	// err = service.DisableTOTP(ctx, userID)

	fmt.Println("See code comments for usage examples")
	// Output: See code comments for usage examples
}

// ExampleTOTPCustomConfig demonstrates custom TOTP configuration
func ExampleTOTPCustomConfig() {
	logger := zap.NewExample()
	redisClient := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	encrypter, _ := mfa.NewAES256GCMEncrypter("12345678901234567890123456789012")

	// Create custom configuration
	config := &mfa.TOTPConfig{
		Issuer:       "MyApp",
		Period:       30,  // 30-second time step
		Digits:       8,   // 8-digit codes (more secure)
		Algorithm:    mfa.DefaultTOTPAlgorithm,
		SecretLength: 32,  // 256-bit secret (more secure)
	}

	// Create service with custom config
	totpService := mfa.NewTOTPServiceWithConfig(logger, redisClient, encrypter, config)

	secret, _, _ := totpService.EnrollTOTP(context.Background(), "user-123", "bob@example.com")

	// Generate code (will be 8 digits with this config)
	code, _ := totpService.GenerateCode(secret.Secret)

	fmt.Printf("Code length: %d\n", len(code))
	fmt.Printf("Issuer: %s\n", secret.Issuer)

	// Output:
	// Code length: 8
	// Issuer: MyApp
}

// ExampleTOTPTimeTravel demonstrates TOTP validation across time steps
func ExampleTOTPTimeTravel() {
	logger := zap.NewExample()
	redisClient := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	encrypter, _ := mfa.NewAES256GCMEncrypter("12345678901234567890123456789012")

	totpService := mfa.NewTOTPService(logger, redisClient, encrypter)

	secret, _, _ := totpService.EnrollTOTP(context.Background(), "user-123", "alice@example.com")

	// Generate code for current time
	now := time.Now()
	currentCode, _ := totpService.GenerateCodeCustom(secret.Secret, now)

	// Validate with time window
	valid, _ := totpService.ValidateCodeConstantTime(secret.Secret, currentCode, 1)
	fmt.Printf("Current time code valid: %v\n", valid)

	// Generate code for 30 seconds in the past
	pastCode, _ := totpService.GenerateCodeCustom(secret.Secret, now.Add(-30*time.Second))
	valid, _ = totpService.ValidateCodeConstantTime(secret.Secret, pastCode, 1)
	fmt.Printf("Past code valid (with window=1): %v\n", valid)

	// Generate code for 60 seconds in the past (outside window)
	oldCode, _ := totpService.GenerateCodeCustom(secret.Secret, now.Add(-60*time.Second))
	valid, _ = totpService.ValidateCodeConstantTime(secret.Secret, oldCode, 1)
	fmt.Printf("Old code valid (outside window): %v\n", valid)

	// Output:
	// Current time code valid: true
	// Past code valid (with window=1): true
	// Old code valid (outside window): false
}

// ExampleTOTPEncryption demonstrates secret encryption and decryption
func ExampleTOTPEncryption() {
	// Create encrypter with 32-byte key
	key := "12345678901234567890123456789012" // 32 bytes
	encrypter, err := mfa.NewAES256GCMEncrypter(key)
	if err != nil {
		log.Fatal(err)
	}

	// Original TOTP secret (base32)
	originalSecret := "JBSWY3DPEHPK3PXP"

	// Encrypt for storage
	encrypted, err := encrypter.Encrypt(originalSecret)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Original: %s\n", originalSecret)
	fmt.Printf("Encrypted: %s\n", encrypted)

	// Decrypt for use
	decrypted, err := encrypter.Decrypt(encrypted)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Decrypted: %s\n", decrypted)
	fmt.Printf("Match: %v\n", originalSecret == decrypted)

	// Output:
	// Original: JBSWY3DPEHPK3PXP
	// Encrypted: (base64 string, varies each time)
	// Decrypted: JBSWY3DPEHPK3PXP
	// Match: true
}
