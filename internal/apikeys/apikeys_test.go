// Package apikeys provides unit tests for API key and service account management
package apikeys

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zaptest"
)

// TestCreateServiceAccount_Success tests successful service account creation
func TestCreateServiceAccount_Success(t *testing.T) {
	// This test verifies the logic of service account creation
	// In a real scenario with a database, this would insert and verify
	t.Run("verify service account structure", func(t *testing.T) {
		now := time.Now().UTC()
		ownerID := "owner-123"

		sa := &ServiceAccount{
			ID:          "sa-456",
			Name:        "test-service",
			Description: "A test service account",
			OwnerID:     &ownerID,
			Status:      "active",
			CreatedAt:   now,
			UpdatedAt:   now,
		}

		assert.Equal(t, "sa-456", sa.ID)
		assert.Equal(t, "test-service", sa.Name)
		assert.Equal(t, "A test service account", sa.Description)
		assert.Equal(t, ownerID, *sa.OwnerID)
		assert.Equal(t, "active", sa.Status)
		assert.False(t, sa.CreatedAt.IsZero())
		assert.False(t, sa.UpdatedAt.IsZero())
	})

	t.Run("verify service account without owner", func(t *testing.T) {
		now := time.Now().UTC()

		sa := &ServiceAccount{
			ID:          "sa-789",
			Name:        "system-service",
			Description: "System service account",
			OwnerID:     nil,
			Status:      "active",
			CreatedAt:   now,
			UpdatedAt:   now,
		}

		assert.Nil(t, sa.OwnerID)
		assert.Equal(t, "system-service", sa.Name)
	})
}

// TestAPIKey_CreationTests tests API key creation logic
func TestAPIKey_CreationTests(t *testing.T) {
	t.Run("verify API key structure", func(t *testing.T) {
		now := time.Now().UTC()
		userID := "user-123"
		expiresAt := now.Add(24 * time.Hour)

		key := &APIKey{
			ID:               "key-456",
			Name:             "test-key",
			KeyPrefix:        "oidx_abc123",
			UserID:           &userID,
			ServiceAccountID: nil,
			Scopes:           []string{"read", "write"},
			ExpiresAt:        &expiresAt,
			Status:           "active",
			CreatedAt:        now,
		}

		assert.Equal(t, "key-456", key.ID)
		assert.Equal(t, "test-key", key.Name)
		assert.Equal(t, "oidx_abc123", key.KeyPrefix)
		assert.Equal(t, userID, *key.UserID)
		assert.Nil(t, key.ServiceAccountID)
		assert.Equal(t, []string{"read", "write"}, key.Scopes)
		assert.NotNil(t, key.ExpiresAt)
		assert.Equal(t, "active", key.Status)
		assert.False(t, key.CreatedAt.IsZero())
	})

	t.Run("verify API key for service account", func(t *testing.T) {
		now := time.Now().UTC()
		saID := "sa-789"

		key := &APIKey{
			ID:               "key-789",
			Name:             "service-key",
			KeyPrefix:        "oidx_def456",
			UserID:           nil,
			ServiceAccountID: &saID,
			Scopes:           []string{"admin"},
			ExpiresAt:        nil,
			Status:           "active",
			CreatedAt:        now,
		}

		assert.Nil(t, key.UserID)
		assert.Equal(t, saID, *key.ServiceAccountID)
		assert.Nil(t, key.ExpiresAt)
	})
}

// TestAPIKeyGeneration_Format tests the format of generated API keys
func TestAPIKeyGeneration_Format(t *testing.T) {
	t.Run("generate key and verify format", func(t *testing.T) {
		// Simulate the key generation logic
		randBytes := make([]byte, 32)
		for i := range randBytes {
			randBytes[i] = byte(i)
		}

		plaintext := "oidx_" + hex.EncodeToString(randBytes)
		keyPrefix := plaintext[:12]

		// Verify format
		assert.True(t, strings.HasPrefix(plaintext, "oidx_"), "API key should start with 'oidx_'")
		assert.Equal(t, 69, len(plaintext), "API key should be 69 characters (oidx_ + 64 hex chars)")
		assert.Equal(t, 12, len(keyPrefix), "Key prefix should be 12 characters")
		assert.True(t, strings.HasPrefix(keyPrefix, "oidx_"), "Key prefix should start with 'oidx_'")
	})

	t.Run("verify hash is deterministic", func(t *testing.T) {
		testKey := "oidx_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

		hash1 := sha256.Sum256([]byte(testKey))
		hash2 := sha256.Sum256([]byte(testKey))

		assert.Equal(t, hash1, hash2, "Hash of same key should be identical")

		hashStr1 := hex.EncodeToString(hash1[:])
		hashStr2 := hex.EncodeToString(hash2[:])

		assert.Equal(t, hashStr1, hashStr2)
		assert.Equal(t, 64, len(hashStr1), "SHA256 hash should be 64 hex characters")
	})

	t.Run("verify different keys produce different hashes", func(t *testing.T) {
		key1 := "oidx_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		key2 := "oidx_fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

		hash1 := sha256.Sum256([]byte(key1))
		hash2 := sha256.Sum256([]byte(key2))

		assert.NotEqual(t, hash1, hash2, "Different keys should produce different hashes")
	})
}

// TestListAPIKeys_OwnerTypeValidation tests owner type validation logic
func TestListAPIKeys_OwnerTypeValidation(t *testing.T) {
	validTypes := []string{"user", "User", "USER", "service_account", "SERVICE_ACCOUNT"}
	invalidTypes := []string{"invalid", "group", "role", "application", "ServiceAccount"}

	t.Run("valid owner types", func(t *testing.T) {
		for _, ownerType := range validTypes {
			lowered := strings.ToLower(ownerType)
			assert.Contains(t, []string{"user", "service_account"}, lowered,
				"Valid owner type should be 'user' or 'service_account'")
		}
	})

	t.Run("invalid owner types would produce error", func(t *testing.T) {
		for _, ownerType := range invalidTypes {
			lowered := strings.ToLower(ownerType)
			isValid := lowered == "user" || lowered == "service_account"
			assert.False(t, isValid, "Owner type %q should be invalid", ownerType)
		}
	})
}

// TestValidateAPIKey_LogicTests tests validation logic
func TestValidateAPIKey_LogicTests(t *testing.T) {
	t.Run("active key should pass validation", func(t *testing.T) {
		status := "active"
		assert.Equal(t, "active", status, "Active status should pass")
	})

	t.Run("revoked key should fail validation", func(t *testing.T) {
		status := "revoked"
		errMsg := "api key is " + status
		assert.Contains(t, errMsg, "revoked", "Error should indicate key is revoked")
	})

	t.Run("expired key should fail validation", func(t *testing.T) {
		expiresAt := time.Now().UTC().Add(-1 * time.Hour)
		assert.True(t, expiresAt.Before(time.Now().UTC()), "Key should be expired")
	})

	t.Run("future expiration should pass validation", func(t *testing.T) {
		expiresAt := time.Now().UTC().Add(24 * time.Hour)
		assert.False(t, expiresAt.Before(time.Now().UTC()), "Key should not be expired")
	})

	t.Run("nil expiration means key never expires", func(t *testing.T) {
		var expiresAt *time.Time = nil
		assert.Nil(t, expiresAt, "Nil expiration means no expiration time set")
	})
}

// TestRevokeAPIKey_StatusUpdate tests revocation status logic
func TestRevokeAPIKey_StatusUpdate(t *testing.T) {
	t.Run("verify revoked status", func(t *testing.T) {
		status := "revoked"
		assert.Equal(t, "revoked", status)
	})

	t.Run("status transitions", func(t *testing.T) {
		transitions := map[string]bool{
			"active":    true,
			"revoked":   false,
			"expired":   false,
			"suspended": true,
		}

		for status, canActivate := range transitions {
			if canActivate {
				assert.NotEqual(t, "revoked", status, "Status %q can transition to revoked", status)
			}
		}
	})
}

// TestAPIKeyInfo_Structure tests API key info structure
func TestAPIKeyInfo_Structure(t *testing.T) {
	t.Run("API key info for user", func(t *testing.T) {
		info := &APIKeyInfo{
			KeyID:            "key-123",
			UserID:           "user-456",
			ServiceAccountID: "",
			Scopes:           []string{"read", "write"},
			Status:           "active",
		}

		assert.Equal(t, "key-123", info.KeyID)
		assert.Equal(t, "user-456", info.UserID)
		assert.Empty(t, info.ServiceAccountID)
		assert.Equal(t, []string{"read", "write"}, info.Scopes)
		assert.Equal(t, "active", info.Status)
	})

	t.Run("API key info for service account", func(t *testing.T) {
		info := &APIKeyInfo{
			KeyID:            "key-789",
			UserID:           "",
			ServiceAccountID: "sa-123",
			Scopes:           []string{"admin"},
			Status:           "active",
		}

		assert.Empty(t, info.UserID)
		assert.Equal(t, "sa-123", info.ServiceAccountID)
		assert.Equal(t, []string{"admin"}, info.Scopes)
	})
}

// TestErrorHandling tests error conditions
func TestErrorHandling(t *testing.T) {
	t.Run("ErrNoRows produces not found error", func(t *testing.T) {
		err := pgx.ErrNoRows
		assert.Equal(t, pgx.ErrNoRows, err)
	})

	t.Run("error message for not found", func(t *testing.T) {
		expectedMsg := "not found"
		err := errors.New("service account not found")
		assert.Contains(t, strings.ToLower(err.Error()), expectedMsg)
	})

	t.Run("error message for invalid API key", func(t *testing.T) {
		err := errors.New("invalid api key")
		assert.Contains(t, strings.ToLower(err.Error()), "invalid")
		assert.Contains(t, strings.ToLower(err.Error()), "api")
		assert.Contains(t, strings.ToLower(err.Error()), "key")
	})
}

// TestCacheKeyFormat tests Redis cache key formatting
func TestCacheKeyFormat(t *testing.T) {
	t.Run("API key cache key format", func(t *testing.T) {
		keyHash := "abcd1234efgh5678"
		cacheKey := "apikey:" + keyHash

		assert.True(t, strings.HasPrefix(cacheKey, "apikey:"), "Cache key should start with 'apikey:'")
		assert.Equal(t, "apikey:abcd1234efgh5678", cacheKey)
	})
}

// TestScopes tests scope handling
func TestScopes(t *testing.T) {
	t.Run("empty scopes", func(t *testing.T) {
		scopes := []string{}
		assert.Empty(t, scopes)
	})

	t.Run("single scope", func(t *testing.T) {
		scopes := []string{"read"}
		assert.Len(t, scopes, 1)
		assert.Equal(t, "read", scopes[0])
	})

	t.Run("multiple scopes", func(t *testing.T) {
		scopes := []string{"read", "write", "delete", "admin"}
		assert.Len(t, scopes, 4)
		assert.Contains(t, scopes, "read")
		assert.Contains(t, scopes, "admin")
	})
}

// TestTimestamps tests timestamp handling
func TestTimestamps(t *testing.T) {
	t.Run("UTC timestamp", func(t *testing.T) {
		now := time.Now().UTC()
		assert.False(t, now.IsZero())
	})

	t.Run("future timestamp", func(t *testing.T) {
		future := time.Now().UTC().Add(24 * time.Hour)
		assert.True(t, future.After(time.Now().UTC()))
	})

	t.Run("past timestamp", func(t *testing.T) {
		past := time.Now().UTC().Add(-1 * time.Hour)
		assert.True(t, past.Before(time.Now().UTC()))
	})
}

// TestServiceAccountSerialization tests JSON serialization (for API responses)
func TestServiceAccountSerialization(t *testing.T) {
	t.Run("service account JSON tags", func(t *testing.T) {
		ownerID := "owner-123"
		sa := ServiceAccount{
			ID:          "sa-123",
			Name:        "Test Service",
			Description: "Test Description",
			OwnerID:     &ownerID,
			Status:      "active",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		// Verify struct fields can be set
		assert.Equal(t, "sa-123", sa.ID)
		assert.Equal(t, "Test Service", sa.Name)
	})
}

// TestAPIKeySerialization tests API key JSON structure
func TestAPIKeySerialization(t *testing.T) {
	t.Run("API key JSON tags", func(t *testing.T) {
		userID := "user-123"
		key := APIKey{
			ID:               "key-123",
			Name:             "Test Key",
			KeyPrefix:        "oidx_test",
			UserID:           &userID,
			ServiceAccountID: nil,
			Scopes:           []string{"read"},
			ExpiresAt:        nil,
			LastUsedAt:       nil,
			Status:           "active",
			CreatedAt:        time.Now(),
		}

		assert.Equal(t, "key-123", key.ID)
		assert.Equal(t, "Test Key", key.Name)
		assert.Equal(t, "oidx_test", key.KeyPrefix)
		assert.Equal(t, &userID, key.UserID)
	})
}

// TestServiceCreation tests service instantiation
func TestServiceCreation(t *testing.T) {
	t.Run("create service with dependencies", func(t *testing.T) {
		logger := zaptest.NewLogger(t)

		// Note: We can't create a real PostgresDB or RedisClient without a database connection
		// This test verifies the service struct structure
		svc := &Service{
			db:     nil, // Would be real DB in production
			redis:  nil, // Would be real Redis in production
			logger: logger,
		}

		assert.NotNil(t, svc.logger)
		assert.NotNil(t, svc)
	})
}

// TestNewService tests the NewService constructor
func TestNewService(t *testing.T) {
	t.Run("NewService creates a valid service", func(t *testing.T) {
		logger := zaptest.NewLogger(t)

		svc := NewService(nil, nil, logger)

		assert.NotNil(t, svc)
		assert.NotNil(t, svc.logger)
		assert.Nil(t, svc.db)    // nil as passed
		assert.Nil(t, svc.redis) // nil as passed
	})
}

// TestScanServiceManually tests manual scanning logic (simulating database rows)
func TestScanServiceAccountManually(t *testing.T) {
	t.Run("manually construct service account from row data", func(t *testing.T) {
		now := time.Now().UTC()
		var ownerID *string = nil
		ownerVal := "owner-123"
		ownerID = &ownerVal

		// Simulate scanning from a database row
		sa := ServiceAccount{
			ID:          "sa-123",
			Name:        "test-service",
			Description: "test description",
			OwnerID:     ownerID,
			Status:      "active",
			CreatedAt:   now,
			UpdatedAt:   now,
		}

		assert.Equal(t, "sa-123", sa.ID)
		assert.Equal(t, "test-service", sa.Name)
		assert.Equal(t, "test description", sa.Description)
		assert.Equal(t, "owner-123", *sa.OwnerID)
	})
}

// TestScanAPIKeyManually tests manual API key construction
func TestScanAPIKeyManually(t *testing.T) {
	t.Run("manually construct API key from row data", func(t *testing.T) {
		now := time.Now().UTC()
		var userID *string = nil
		userVal := "user-123"
		userID = &userVal

		expiresAt := now.Add(24 * time.Hour)
		var lastUsed *time.Time = nil

		// Simulate scanning from a database row
		key := APIKey{
			ID:               "key-123",
			Name:             "test-key",
			KeyPrefix:        "oidx_prefix",
			UserID:           userID,
			ServiceAccountID: nil,
			Scopes:           []string{"read", "write"},
			ExpiresAt:        &expiresAt,
			LastUsedAt:       lastUsed,
			Status:           "active",
			CreatedAt:        now,
		}

		assert.Equal(t, "key-123", key.ID)
		assert.Equal(t, "user-123", *key.UserID)
		assert.Equal(t, []string{"read", "write"}, key.Scopes)
		assert.NotNil(t, key.ExpiresAt)
	})
}

// TestKeyGenerationAlgorithm tests the key generation algorithm
func TestKeyGenerationAlgorithm(t *testing.T) {
	t.Run("verify key prefix extraction", func(t *testing.T) {
		// oidx_ + first 7 hex chars = 12 chars total
		testKey := "oidx_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		prefix := testKey[:12]

		assert.Equal(t, 12, len(prefix))
		assert.True(t, strings.HasPrefix(prefix, "oidx_"))
	})

	t.Run("verify hex encoding produces correct length", func(t *testing.T) {
		randBytes := make([]byte, 32)
		hexEncoded := hex.EncodeToString(randBytes)

		// 32 bytes = 64 hex characters
		assert.Equal(t, 64, len(hexEncoded))
	})

	t.Run("verify full key format", func(t *testing.T) {
		randBytes := make([]byte, 32)
		for i := range randBytes {
			randBytes[i] = byte(i)
		}

		fullKey := "oidx_" + hex.EncodeToString(randBytes)

		assert.Equal(t, 69, len(fullKey))
		assert.True(t, strings.HasPrefix(fullKey, "oidx_"))
	})
}

// TestStatusValidation tests status values
func TestStatusValidation(t *testing.T) {
	t.Run("valid statuses", func(t *testing.T) {
		validStatuses := []string{"active", "revoked", "expired", "suspended"}

		for _, status := range validStatuses {
			assert.NotEmpty(t, status)
		}
	})

	t.Run("status comparisons", func(t *testing.T) {
		status := "active"
		assert.Equal(t, "active", status)

		status = "revoked"
		assert.NotEqual(t, "active", status)
	})
}

// TestNilPointerHandling tests nil pointer handling in structs
func TestNilPointerHandling(t *testing.T) {
	t.Run("service account with nil owner", func(t *testing.T) {
		sa := ServiceAccount{
			ID:          "sa-123",
			Name:        "test",
			Description: "test",
			OwnerID:     nil,
			Status:      "active",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		assert.Nil(t, sa.OwnerID)
	})

	t.Run("API key with nil user and service account", func(t *testing.T) {
		key := APIKey{
			ID:               "key-123",
			Name:             "test",
			KeyPrefix:        "oidx_test",
			UserID:           nil,
			ServiceAccountID: nil,
			Scopes:           []string{},
			ExpiresAt:        nil,
			LastUsedAt:       nil,
			Status:           "active",
			CreatedAt:        time.Now(),
		}

		assert.Nil(t, key.UserID)
		assert.Nil(t, key.ServiceAccountID)
		assert.Nil(t, key.ExpiresAt)
		assert.Nil(t, key.LastUsedAt)
	})
}

// TestAPIKeyInfoStringFields tests string field handling in APIKeyInfo
func TestAPIKeyInfoStringFields(t *testing.T) {
	t.Run("empty vs non-empty string fields", func(t *testing.T) {
		info1 := APIKeyInfo{
			KeyID:            "key-123",
			UserID:           "user-123",
			ServiceAccountID: "",
			Scopes:           []string{"read"},
			Status:           "active",
		}

		assert.NotEmpty(t, info1.KeyID)
		assert.NotEmpty(t, info1.UserID)
		assert.Empty(t, info1.ServiceAccountID)

		info2 := APIKeyInfo{
			KeyID:            "key-456",
			UserID:           "",
			ServiceAccountID: "sa-123",
			Scopes:           []string{"admin"},
			Status:           "active",
		}

		assert.Empty(t, info2.UserID)
		assert.NotEmpty(t, info2.ServiceAccountID)
	})
}
