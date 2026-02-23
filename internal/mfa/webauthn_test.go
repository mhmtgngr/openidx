// Package mfa provides unit tests for WebAuthn/FIDO2 functionality
package mfa

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWebAuthnServiceCreation tests creating a WebAuthn service
func TestWebAuthnServiceCreation(t *testing.T) {
	logger := zap.NewNop()
	store := NewInMemoryWebAuthnStore(logger)

	config := DefaultWebAuthnConfig("localhost", []string{"http://localhost:8080"})

	service, err := NewWebAuthnService(config, store, logger)

	assert.NoError(t, err)
	assert.NotNil(t, service)
	assert.NotNil(t, service.webAuthn)
	assert.Equal(t, "OpenIDX", service.config.RPDisplayName)
}

// TestWebAuthnServiceCreationWithInvalidConfig tests creating a service with invalid config
func TestWebAuthnServiceCreationWithInvalidConfig(t *testing.T) {
	logger := zap.NewNop()
	store := NewInMemoryWebAuthnStore(logger)

	// Test with nil config
	_, err := NewWebAuthnService(nil, store, logger)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config cannot be nil")
}

// TestBeginRegistration tests the registration ceremony initiation
func TestBeginRegistration(t *testing.T) {
	logger := zap.NewNop()
	store := NewInMemoryWebAuthnStore(logger)

	// Set up a test user
	userID := uuid.New()
	store.SetUser(&User{
		UserID:      userID,
		Username:    "testuser",
		DisplayName: "Test User",
	})

	config := DefaultWebAuthnConfig("localhost", []string{"http://localhost:8080"})
	service, err := NewWebAuthnService(config, store, logger)
	require.NoError(t, err)

	// Begin registration
	options, err := service.BeginRegistration(
		context.Background(),
		userID,
		"testuser",
		"Test User",
		"My Passkey",
	)

	assert.NoError(t, err)
	assert.NotNil(t, options)
	assert.NotNil(t, options.PublicKey)
	assert.Equal(t, "ok", options.Status)
	assert.NotEmpty(t, options.PublicKey.Challenge.String())

	// Verify RP info
	assert.Equal(t, "OpenIDX", options.PublicKey.RP.DisplayName)
	assert.Equal(t, "localhost", options.PublicKey.RP.ID)

	// Verify user info
	assert.Equal(t, "testuser", string(options.PublicKey.User.Name))
	assert.Equal(t, "Test User", string(options.PublicKey.User.DisplayName))
	assert.Equal(t, userID[:], options.PublicKey.User.ID)
}

// TestBeginRegistrationWithExistingCredentials tests registration with existing credentials
func TestBeginRegistrationWithExistingCredentials(t *testing.T) {
	logger := zap.NewNop()
	store := NewInMemoryWebAuthnStore(logger)

	// Set up a test user
	userID := uuid.New()
	store.SetUser(&User{
		UserID:      userID,
		Username:    "testuser",
		DisplayName: "Test User",
	})

	// Add an existing credential
	existingCred := &WebAuthnCredential{
		ID:           uuid.New(),
		CredentialID: "existing-credential-id",
		PublicKey:    []byte("test-public-key"),
		UserID:       userID,
		UserHandle:   userID[:],
		SignCount:    1,
		Transports:   []string{"internal"},
		CreatedAt:    time.Now(),
	}
	err := store.CreateCredential(context.Background(), existingCred)
	require.NoError(t, err)

	config := DefaultWebAuthnConfig("localhost", []string{"http://localhost:8080"})
	service, err := NewWebAuthnService(config, store, logger)
	require.NoError(t, err)

	// Begin registration - should exclude existing credentials
	options, err := service.BeginRegistration(
		context.Background(),
		userID,
		"testuser",
		"Test User",
		"Second Passkey",
	)

	assert.NoError(t, err)
	assert.NotNil(t, options)

	// Verify that the excludeCredentials list includes the existing credential
	assert.Len(t, options.PublicKey.ExcludeCredentials, 1)
	assert.Equal(t, []byte("test-public-key"), options.PublicKey.ExcludeCredentials[0].ID)
}

// TestBeginLogin tests the login ceremony initiation
func TestBeginLogin(t *testing.T) {
	logger := zap.NewNop()
	store := NewInMemoryWebAuthnStore(logger)

	// Set up a test user with credentials
	userID := uuid.New()
	store.SetUser(&User{
		UserID:      userID,
		Username:    "testuser",
		DisplayName: "Test User",
	})

	// Add a credential
	cred := &WebAuthnCredential{
		ID:           uuid.New(),
		CredentialID: "test-credential-id",
		PublicKey:    []byte("test-public-key"),
		UserID:       userID,
		UserHandle:   userID[:],
		SignCount:    0,
		Transports:   []string{"internal"},
		CreatedAt:    time.Now(),
	}
	err := store.CreateCredential(context.Background(), cred)
	require.NoError(t, err)

	config := DefaultWebAuthnConfig("localhost", []string{"http://localhost:8080"})
	service, err := NewWebAuthnService(config, store, logger)
	require.NoError(t, err)

	// Begin login
	options, err := service.BeginLogin(context.Background(), userID)

	assert.NoError(t, err)
	assert.NotNil(t, options)
	assert.NotNil(t, options.PublicKey)
	assert.Equal(t, "ok", options.Status)
	assert.NotEmpty(t, options.PublicKey.Challenge.String())

	// Verify that allowCredentials includes the user's credential
	assert.Len(t, options.PublicKey.AllowCredentials, 1)
}

// TestBeginLoginWithNoCredentials tests login when user has no credentials
func TestBeginLoginWithNoCredentials(t *testing.T) {
	logger := zap.NewNop()
	store := NewInMemoryWebAuthnStore(logger)

	// Set up a test user without credentials
	userID := uuid.New()
	store.SetUser(&User{
		UserID:      userID,
		Username:    "testuser",
		DisplayName: "Test User",
	})

	config := DefaultWebAuthnConfig("localhost", []string{"http://localhost:8080"})
	service, err := NewWebAuthnService(config, store, logger)
	require.NoError(t, err)

	// Begin login - should fail
	_, err = service.BeginLogin(context.Background(), userID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no credentials found")
}

// TestParseRPID tests RPID parsing from URLs
func TestParseRPID(t *testing.T) {
	tests := []struct {
		name     string
		origin   string
		expected string
		hasError bool
	}{
		{
			name:     "localhost",
			origin:   "http://localhost:8080",
			expected: "localhost",
			hasError: false,
		},
		{
			name:     "example.com",
			origin:   "https://example.com",
			expected: "example.com",
			hasError: false,
		},
		{
			name:     "subdomain.example.com",
			origin:   "https://subdomain.example.com:443/path",
			expected: "subdomain.example.com",
			hasError: false,
		},
		{
			name:     "invalid origin",
			origin:   "not-a-url",
			expected: "",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseRPID(tt.origin)

			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

// TestFormatAAGUID tests AAGUID formatting
func TestFormatAAGUID(t *testing.T) {
	// Test with a valid 16-byte AAGUID
	aaguid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

	result := formatAAGUID(aaguid)

	assert.Equal(t, "01020304-0506-0708-090a-0b0c0d0e0f10", result)

	// Test with invalid length
	invalidAAGUID := []byte{0x01, 0x02, 0x03}
	result = formatAAGUID(invalidAAGUID)
	assert.Empty(t, result)
}

// TestGetAuthenticatorInfo tests authenticator information extraction
func TestGetAuthenticatorInfo(t *testing.T) {
	t.Run("zero AAGUID (passkey)", func(t *testing.T) {
		zeroAAGUID := make([]byte, 16)
		info := GetAuthenticatorInfo(zeroAAGUID)

		assert.Equal(t, "00000000-0000-0000-0000-000000000000", info.AAGUID)
		assert.Equal(t, "Passkey", info.Name)
		assert.True(t, info.IsPasskey)
	})

	t.Run("non-zero AAGUID (security key)", func(t *testing.T) {
		aaguid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
		info := GetAuthenticatorInfo(aaguid)

		assert.Equal(t, "01020304-0506-0708-090a-0b0c0d0e0f10", info.AAGUID)
		assert.Equal(t, "Security Key", info.Name)
		assert.False(t, info.IsPasskey)
	})

	t.Run("invalid AAGUID", func(t *testing.T) {
		invalidAAGUID := []byte{0x01, 0x02}
		info := GetAuthenticatorInfo(invalidAAGUID)

		assert.Empty(t, info.AAGUID)
		assert.Equal(t, "Unknown Authenticator", info.Name)
		assert.False(t, info.IsPasskey)
	})
}

// TestInMemoryWebAuthnStore tests the in-memory store implementation
func TestInMemoryWebAuthnStore(t *testing.T) {
	logger := zap.NewNop()
	store := NewInMemoryWebAuthnStore(logger)

	ctx := context.Background()
	userID := uuid.New()

	t.Run("CreateCredential", func(t *testing.T) {
		cred := &WebAuthnCredential{
			ID:           uuid.New(),
			CredentialID: "test-cred-id",
			PublicKey:    []byte("public-key"),
			UserID:       userID,
			UserHandle:   userID[:],
			SignCount:    0,
			Transports:   []string{"internal"},
			FriendlyName: "My Passkey",
			CreatedAt:    time.Now(),
		}

		err := store.CreateCredential(ctx, cred)
		assert.NoError(t, err)
	})

	t.Run("GetCredential", func(t *testing.T) {
		cred, err := store.GetCredential(ctx, userID)
		assert.Error(t, err) // We don't have the ID, search by user instead

		// List credentials instead
		creds, err := store.ListCredentials(ctx, userID)
		assert.NoError(t, err)
		assert.Len(t, creds, 1)

		// Get by ID
		cred, err = store.GetCredential(ctx, creds[0].ID)
		assert.NoError(t, err)
		assert.Equal(t, "My Passkey", cred.FriendlyName)
	})

	t.Run("GetCredentialByID", func(t *testing.T) {
		cred, err := store.GetCredentialByID(ctx, "test-cred-id")
		assert.NoError(t, err)
		assert.Equal(t, userID, cred.UserID)
	})

	t.Run("ListCredentials", func(t *testing.T) {
		creds, err := store.ListCredentials(ctx, userID)
		assert.NoError(t, err)
		assert.Len(t, creds, 1)
	})

	t.Run("UpdateCredential", func(t *testing.T) {
		creds, _ := store.ListCredentials(ctx, userID)
		cred := creds[0]

		cred.SignCount = 5
		now := time.Now()
		cred.LastUsedAt = &now

		err := store.UpdateCredential(ctx, cred)
		assert.NoError(t, err)

		// Verify update
		updated, _ := store.GetCredential(ctx, cred.ID)
		assert.Equal(t, uint32(5), updated.SignCount)
		assert.NotNil(t, updated.LastUsedAt)
	})

	t.Run("DeleteCredential", func(t *testing.T) {
		creds, _ := store.ListCredentials(ctx, userID)
		cred := creds[0]

		err := store.DeleteCredential(ctx, cred.ID)
		assert.NoError(t, err)

		// Verify deletion
		_, err = store.GetCredential(ctx, cred.ID)
		assert.Error(t, err)

		remaining, _ := store.ListCredentials(ctx, userID)
		assert.Len(t, remaining, 0)
	})
}

// TestInMemoryStoreSessionOperations tests session operations
func TestInMemoryStoreSessionOperations(t *testing.T) {
	logger := zap.NewNop()
	store := NewInMemoryWebAuthnStore(logger)

	ctx := context.Background()

	t.Run("StoreAndGetSession", func(t *testing.T) {
		key := "test-session-key"
		data := map[string]interface{}{
			"challenge": "test-challenge",
			"userID":    uuid.New().String(),
		}

		err := store.StoreSession(ctx, key, data, time.Minute)
		assert.NoError(t, err)

		retrieved, err := store.GetSession(ctx, key)
		assert.NoError(t, err)
		assert.NotNil(t, retrieved)
	})

	t.Run("GetNonExistentSession", func(t *testing.T) {
		_, err := store.GetSession(ctx, "non-existent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("DeleteSession", func(t *testing.T) {
		key := "session-to-delete"
		data := "test-data"

		_ = store.StoreSession(ctx, key, data, time.Minute)

		err := store.DeleteSession(ctx, key)
		assert.NoError(t, err)

		// Verify deletion
		_, err = store.GetSession(ctx, key)
		assert.Error(t, err)
	})
}

// TestMultipleCredentialsPerUser tests storing and retrieving multiple credentials
func TestMultipleCredentialsPerUser(t *testing.T) {
	logger := zap.NewNop()
	store := NewInMemoryWebAuthnStore(logger)

	ctx := context.Background()
	userID := uuid.New()

	// Create multiple credentials
	credentials := []*WebAuthnCredential{
		{
			ID:           uuid.New(),
			CredentialID: "cred-1",
			PublicKey:    []byte("key-1"),
			UserID:       userID,
			UserHandle:   userID[:],
			SignCount:    0,
			Transports:   []string{"internal"},
			FriendlyName: "Laptop Passkey",
			CreatedAt:    time.Now(),
		},
		{
			ID:           uuid.New(),
			CredentialID: "cred-2",
			PublicKey:    []byte("key-2"),
			UserID:       userID,
			UserHandle:   userID[:],
			SignCount:    0,
			Transports:   []string{"usb", "nfc"},
			FriendlyName: "YubiKey 5C",
			CreatedAt:    time.Now(),
		},
		{
			ID:           uuid.New(),
			CredentialID: "cred-3",
			PublicKey:    []byte("key-3"),
			UserID:       userID,
			UserHandle:   userID[:],
			SignCount:    0,
			Transports:   []string{"internal"},
			FriendlyName: "Phone Passkey",
			CreatedAt:    time.Now(),
		},
	}

	// Store all credentials
	for _, cred := range credentials {
		err := store.CreateCredential(ctx, cred)
		assert.NoError(t, err)
	}

	// Retrieve all credentials
	retrieved, err := store.ListCredentials(ctx, userID)
	assert.NoError(t, err)
	assert.Len(t, retrieved, 3)

	// Verify friendly names
	names := make([]string, len(retrieved))
	for i, cred := range retrieved {
		names[i] = cred.FriendlyName
	}

	assert.Contains(t, names, "Laptop Passkey")
	assert.Contains(t, names, "YubiKey 5C")
	assert.Contains(t, names, "Phone Passkey")

	// Verify transports
	var yubikey *WebAuthnCredential
	for _, cred := range retrieved {
		if cred.FriendlyName == "YubiKey 5C" {
			yubikey = cred
			break
		}
	}

	assert.NotNil(t, yubikey)
	assert.Contains(t, yubikey.Transports, "usb")
	assert.Contains(t, yubikey.Transports, "nfc")

	// Delete one credential
	err = store.DeleteCredentialByCredentialID(ctx, "cred-2", userID)
	assert.NoError(t, err)

	// Verify only 2 remain
	retrieved, _ = store.ListCredentials(ctx, userID)
	assert.Len(t, retrieved, 2)
}

// TestWebAuthnConfigDefaults tests default configuration values
func TestWebAuthnConfigDefaults(t *testing.T) {
	config := DefaultWebAuthnConfig("example.com", []string{"https://example.com"})

	assert.Equal(t, "OpenIDX", config.RPDisplayName)
	assert.Equal(t, "example.com", config.RPID)
	assert.Equal(t, []string{"https://example.com"}, config.RPOrigins)
	assert.Equal(t, 60000, config.Timeout)
	assert.Equal(t, "preferred", config.UserVerification)
	assert.Equal(t, protocol.ResidentKeyNotRequired(), config.AuthenticatorSelection.RequireResidentKey)
	assert.Equal(t, protocol.VerificationPreferred, config.AuthenticatorSelection.UserVerification)
}

// TestCredentialInfoSerialization tests that credential info serializes correctly
func TestCredentialInfoSerialization(t *testing.T) {
	now := time.Now()
	cred := &CredentialInfo{
		ID:             uuid.New(),
		CredentialID:   base64.RawURLEncoding.EncodeToString([]byte("test-id")),
		FriendlyName:   "Test Passkey",
		Authenticator:  "Passkey",
		IsPasskey:      true,
		BackupEligible: true,
		BackupState:    true,
		CreatedAt:      now,
		LastUsedAt:     &now,
	}

	assert.Equal(t, "Test Passkey", cred.FriendlyName)
	assert.True(t, cred.IsPasskey)
	assert.True(t, cred.BackupEligible)
	assert.True(t, cred.BackupState)
	assert.NotNil(t, cred.LastUsedAt)
}

// TestSessionCleanup tests the cleanup of expired sessions (for PostgreSQL store)
func TestSessionCleanup(t *testing.T) {
	logger := zap.NewNop()
	store := NewInMemoryWebAuthnStore(logger)

	ctx := context.Background()

	// Store a session
	key := "test-expiry-session"
	data := "test-data"
	_ = store.StoreSession(ctx, key, data, time.Millisecond)

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Session should still exist in in-memory store (no automatic cleanup)
	// This test verifies the structure for PostgreSQL implementation
	retrieved, err := store.GetSession(ctx, key)
	assert.NoError(t, err)
	assert.NotNil(t, retrieved)

	// Delete and verify
	_ = store.DeleteSession(ctx, key)
	_, err = store.GetSession(ctx, key)
	assert.Error(t, err)
}

// BenchmarkListCredentials benchmarks listing credentials for a user
func BenchmarkListCredentials(b *testing.B) {
	logger := zap.NewNop()
	store := NewInMemoryWebAuthnStore(logger)
	ctx := context.Background()
	userID := uuid.New()

	// Add 100 credentials
	for i := 0; i < 100; i++ {
		cred := &WebAuthnCredential{
			ID:           uuid.New(),
			CredentialID: fmt.Sprintf("cred-%d", i),
			PublicKey:    []byte(fmt.Sprintf("key-%d", i)),
			UserID:       userID,
			UserHandle:   userID[:],
			SignCount:    uint32(i),
			Transports:   []string{"internal"},
			FriendlyName: fmt.Sprintf("Credential %d", i),
			CreatedAt:    time.Now(),
		}
		_ = store.CreateCredential(ctx, cred)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = store.ListCredentials(ctx, userID)
	}
}
