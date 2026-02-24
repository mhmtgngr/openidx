// Package oauth provides unit tests for RSA key management and JWKS functionality
package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Test Key Manager

func TestKeyManager_GenerateAndParseKeys(t *testing.T) {
	t.Run("Generate RSA key", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		assert.NotNil(t, key)
		assert.Equal(t, 2048, key.N.BitLen())
	})

	t.Run("Encode and decode private key", func(t *testing.T) {
		originalKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		km := &KeyManager{
			logger: zap.NewNop(),
		}

		// Encode
		pem := km.encodePrivateKey(originalKey)
		assert.NotEmpty(t, pem)
		assert.Contains(t, pem, "RSA PRIVATE KEY")

		// Decode
		decodedKey, err := km.parsePrivateKey(pem)
		require.NoError(t, err)
		assert.Equal(t, originalKey.D, decodedKey.D)
		assert.Equal(t, originalKey.N, decodedKey.N)
	})

	t.Run("Encode and decode public key", func(t *testing.T) {
		originalKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		km := &KeyManager{
			logger: zap.NewNop(),
		}

		// Encode
		pem := km.encodePublicKey(&originalKey.PublicKey)
		assert.NotEmpty(t, pem)
		assert.Contains(t, pem, "PUBLIC KEY")

		// Decode
		decodedKey, err := km.parsePublicKey(pem)
		require.NoError(t, err)
		assert.Equal(t, originalKey.N, decodedKey.N)
		assert.Equal(t, originalKey.E, decodedKey.E)
	})
}

func TestKeyManager_ExponentEncoding(t *testing.T) {
	km := &KeyManager{
		logger: zap.NewNop(),
	}

	tests := []struct {
		name     string
		exponent int
		check    func(*testing.T, string)
	}{
		{
			name:     "Standard exponent 65537",
			exponent: 65537,
			check: func(t *testing.T, encoded string) {
				// 65537 = 0x010001 = {1, 0, 1} trimmed leading zeros = {1, 1}
				decoded, err := base64.RawURLEncoding.DecodeString(encoded)
				require.NoError(t, err)
				assert.Equal(t, []byte{0x01, 0x00, 0x01}, decoded)
			},
		},
		{
			name:     "Small exponent 3",
			exponent: 3,
			check: func(t *testing.T, encoded string) {
				// 3 = 0x03000000 trimmed leading zeros = {3}
				decoded, err := base64.RawURLEncoding.DecodeString(encoded)
				require.NoError(t, err)
				assert.Equal(t, []byte{0x03}, decoded)
			},
		},
		{
			name:     "Exponent 17",
			exponent: 17,
			check: func(t *testing.T, encoded string) {
				// 17 = 0x11000000 trimmed = {17}
				decoded, err := base64.RawURLEncoding.DecodeString(encoded)
				require.NoError(t, err)
				assert.Equal(t, []byte{0x11}, decoded)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := km.encodeExponent(tt.exponent)
			assert.NotEmpty(t, encoded)
			if tt.check != nil {
				tt.check(t, encoded)
			}
		})
	}
}

func TestKeyManager_BuildJWKS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	km := &KeyManager{
		logger: zap.NewNop(),
		currentKey:    key,
		currentKeyID:  "test-key-1",
		publicKeys: map[string]*rsa.PublicKey{
			"test-key-1": &key.PublicKey,
		},
	}

	jwks := km.BuildJWKS()

	require.Len(t, jwks.Keys, 1)

	jwk := jwks.Keys[0]
	assert.Equal(t, "RSA", jwk.Kty)
	assert.Equal(t, "sig", jwk.Use)
	assert.Equal(t, "test-key-1", jwk.Kid)
	assert.Equal(t, "RS256", jwk.Alg)
	assert.NotEmpty(t, jwk.N)
	assert.NotEmpty(t, jwk.E)

	// Verify N is valid base64url
	_, err = base64.RawURLEncoding.DecodeString(jwk.N)
	assert.NoError(t, err)

	// Verify E is valid base64url
	_, err = base64.RawURLEncoding.DecodeString(jwk.E)
	assert.NoError(t, err)
}

func TestKeyManager_HandleJWKS(t *testing.T) {
	gin.SetMode(gin.TestMode)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	km := &KeyManager{
		logger: zap.NewNop(),
		currentKey:    key,
		currentKeyID:  "test-key-1",
		publicKeys: map[string]*rsa.PublicKey{
			"test-key-1": &key.PublicKey,
		},
	}

	router := gin.New()
	router.GET("/.well-known/jwks.json", km.HandleJWKS)
	router.OPTIONS("/.well-known/jwks.json", km.HandleJWKS)

	t.Run("GET request returns JWKS", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))

		var jwks JWKS
		err := json.Unmarshal(w.Body.Bytes(), &jwks)
		require.NoError(t, err)

		assert.Len(t, jwks.Keys, 1)
		assert.Equal(t, "test-key-1", jwks.Keys[0].Kid)
		assert.Equal(t, "RSA", jwks.Keys[0].Kty)
	})

	t.Run("OPTIONS request returns 204", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/.well-known/jwks.json", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "public, max-age=3600", w.Header().Get("Cache-Control"))
	})
}

func TestKeyManager_MultipleKeys(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	km := &KeyManager{
		logger: zap.NewNop(),
		currentKey:    key1,
		currentKeyID:  "test-key-1",
		publicKeys: map[string]*rsa.PublicKey{
			"test-key-1": &key1.PublicKey,
			"test-key-2": &key2.PublicKey, // Old key still valid
		},
	}

	jwks := km.BuildJWKS()

	// Should have 2 keys (current + rotated but still valid)
	assert.Len(t, jwks.Keys, 2)

	// Find current key
	var currentJWK *JWK
	for i := range jwks.Keys {
		if jwks.Keys[i].Kid == "test-key-1" {
			currentJWK = &jwks.Keys[i]
			break
		}
	}
	require.NotNil(t, currentJWK)
	assert.Equal(t, "test-key-1", currentJWK.Kid)
}

func TestKeyManager_KeyRotation(t *testing.T) {
	// This test verifies the key rotation logic without actual database
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	km := &KeyManager{
		logger: zap.NewNop(),
		currentKey:    key1,
		currentKeyID:  "key-1",
		publicKeys: map[string]*rsa.PublicKey{
			"key-1": &key1.PublicKey,
		},
	}

	// Simulate key rotation by updating internal state
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	newKeyID := "key-2"

	km.mu.Lock()
	km.publicKeys[newKeyID] = &key2.PublicKey
	km.currentKey = key2
	km.currentKeyID = newKeyID
	km.mu.Unlock()

	// Verify new key is active
	assert.Equal(t, newKeyID, km.currentKeyID)
	assert.Equal(t, key2, km.currentKey)

	// Verify both keys are in public keys (for overlap period)
	jwks := km.BuildJWKS()
	assert.Len(t, jwks.Keys, 2)
}

func TestKeyManager_ValidateJWT(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	km := &KeyManager{
		logger: zap.NewNop(),
		currentKey:    key,
		currentKeyID:  "test-key-1",
		publicKeys: map[string]*rsa.PublicKey{
			"test-key-1": &key.PublicKey,
		},
	}

	// Create a test JWT
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": "user-123",
		"iss": "https://test.openidx.org",
		"aud": "test-client",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key-1"

	signedToken, err := token.SignedString(key)
	require.NoError(t, err)

	t.Run("Valid JWT is accepted", func(t *testing.T) {
		parsedClaims, err := km.ValidateJWT(signedToken)
		require.NoError(t, err)
		assert.Equal(t, "user-123", (*parsedClaims)["sub"])
	})

	t.Run("JWT without kid is validated with current key", func(t *testing.T) {
		tokenNoKid := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		signedNoKid, err := tokenNoKid.SignedString(key)
		require.NoError(t, err)

		parsedClaims, err := km.ValidateJWT(signedNoKid)
		require.NoError(t, err)
		assert.Equal(t, "user-123", (*parsedClaims)["sub"])
	})

	t.Run("Expired JWT is rejected", func(t *testing.T) {
		expiredClaims := jwt.MapClaims{
			"sub": "user-123",
			"exp": time.Now().Add(-time.Hour).Unix(),
			"iat": time.Now().Add(-2 * time.Hour).Unix(),
		}

		expiredToken := jwt.NewWithClaims(jwt.SigningMethodRS256, expiredClaims)
		expiredToken.Header["kid"] = "test-key-1"
		signedExpired, err := expiredToken.SignedString(key)
		require.NoError(t, err)

		_, err = km.ValidateJWT(signedExpired)
		assert.Error(t, err)
	})
}

func TestKeyManager_HashKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	km := &KeyManager{
		logger: zap.NewNop(),
	}

	fingerprint := km.hashKey(&key.PublicKey)

	assert.NotEmpty(t, fingerprint)

	// Should be valid base64url
	_, err = base64.RawURLEncoding.DecodeString(fingerprint)
	assert.NoError(t, err)

	// Should be SHA-256 length (43 chars in base64url for 32 bytes)
	assert.Equal(t, 43, len(fingerprint))

	// Same key should produce same hash
	fingerprint2 := km.hashKey(&key.PublicKey)
	assert.Equal(t, fingerprint, fingerprint2)

	// Different key should produce different hash
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	fingerprint3 := km.hashKey(&key2.PublicKey)
	assert.NotEqual(t, fingerprint, fingerprint3)
}

func TestKeyManager_KeyRotationStatus(t *testing.T) {
	// This test would need database integration, so we test the structure
	status := &KeyRotationStatus{
		CurrentKeyID:      "test-key-1",
		CurrentKeyVersion: 1,
		CurrentKeyExpires: time.Now().Add(30 * 24 * time.Hour),
		ShouldRotate:      false,
		ActiveKeyCount:    1,
		RotatedKeyCount:   0,
	}

	assert.Equal(t, "test-key-1", status.CurrentKeyID)
	assert.Equal(t, 1, status.CurrentKeyVersion)
	assert.False(t, status.ShouldRotate)
	assert.Equal(t, 1, status.ActiveKeyCount)
	assert.Equal(t, 0, status.RotatedKeyCount)
}

func TestKeyManager_ShouldRotateKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	km := &KeyManager{
		logger: zap.NewNop(),
		currentKey:    key,
		currentKeyID:  "test-key-1",
		publicKeys: map[string]*rsa.PublicKey{
			"test-key-1": &key.PublicKey,
		},
	}

	// Without database, we can't fully test this
	// But we can verify the method exists
	assert.NotNil(t, km.ShouldRotateKey)
}

func TestJWKStructure(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Build JWK manually
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	eBig := big.NewInt(int64(key.E))
	eBytes := eBig.Bytes()
	// Trim leading zeros
	for len(eBytes) > 1 && eBytes[0] == 0 {
		eBytes = eBytes[1:]
	}
	e := base64.RawURLEncoding.EncodeToString(eBytes)

	jwk := JWK{
		Kty: "RSA",
		Use: "sig",
		Kid: "test-key-1",
		Alg: "RS256",
		N:   n,
		E:   e,
	}

	// Verify JSON marshaling
	data, err := json.Marshal(jwk)
	require.NoError(t, err)

	var decoded JWK
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, jwk.Kty, decoded.Kty)
	assert.Equal(t, jwk.Use, decoded.Use)
	assert.Equal(t, jwk.Kid, decoded.Kid)
	assert.Equal(t, jwk.Alg, decoded.Alg)
	assert.Equal(t, jwk.N, decoded.N)
	assert.Equal(t, jwk.E, decoded.E)

	// Verify we can decode N and E back
	nBytes, err := base64.RawURLEncoding.DecodeString(decoded.N)
	require.NoError(t, err)
	assert.Greater(t, len(nBytes), 0)

	eBytesDecoded, err := base64.RawURLEncoding.DecodeString(decoded.E)
	require.NoError(t, err)
	assert.Greater(t, len(eBytesDecoded), 0)
}

func TestJWKSStructure(t *testing.T) {
	jwks := JWKS{
		Keys: []JWK{
			{
				Kty: "RSA",
				Use: "sig",
				Kid: "key-1",
				Alg: "RS256",
			},
			{
				Kty: "RSA",
				Use: "sig",
				Kid: "key-2",
				Alg: "RS256",
			},
		},
	}

	data, err := json.Marshal(jwks)
	require.NoError(t, err)

	var decoded JWKS
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Len(t, decoded.Keys, 2)
	assert.Equal(t, "key-1", decoded.Keys[0].Kid)
	assert.Equal(t, "key-2", decoded.Keys[1].Kid)
}

func TestKeyRotationOverlapPeriod(t *testing.T) {
	// Verify the overlap period is correctly defined
	assert.Equal(t, 24*time.Hour, KeyRotationOverlap)

	// Key lifetime should be 90 days
	assert.Equal(t, 90*24*time.Hour, KeyLifetime)

	// Key size should be 3072 bits (increased from 2048 for better security margin)
	assert.Equal(t, 3072, KeySize)
}

func TestKeyManager_GetPublicKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	km := &KeyManager{
		logger: zap.NewNop(),
		currentKey:    key,
		currentKeyID:  "test-key-1",
		publicKeys: map[string]*rsa.PublicKey{
			"test-key-1": &key.PublicKey,
		},
	}

	t.Run("Get existing public key", func(t *testing.T) {
		retrievedKey, err := km.GetPublicKey("test-key-1")
		require.NoError(t, err)
		assert.Equal(t, key.N, retrievedKey.N)
		assert.Equal(t, key.E, retrievedKey.E)
	})

	t.Run("Get non-existent public key", func(t *testing.T) {
		_, err := km.GetPublicKey("non-existent")
		assert.Error(t, err)
		assert.Equal(t, ErrKeyNotFound, err)
	})
}

func TestKeyManager_GetPublicKeys(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	km := &KeyManager{
		logger: zap.NewNop(),
		currentKey:    key1,
		currentKeyID:  "key-1",
		publicKeys: map[string]*rsa.PublicKey{
			"key-1": &key1.PublicKey,
			"key-2": &key2.PublicKey,
		},
	}

	keys := km.GetPublicKeys()
	assert.Len(t, keys, 2)
	assert.Contains(t, keys, "key-1")
	assert.Contains(t, keys, "key-2")

	// Verify it returns a copy (modifying the map shouldn't affect the original)
	keys["key-3"] = &key1.PublicKey
	_, ok := km.publicKeys["key-3"]
	assert.False(t, ok, "GetPublicKeys should return a copy")
}

func TestKeyManager_GetSigningKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	km := &KeyManager{
		logger: zap.NewNop(),
		currentKey:    key,
		currentKeyID:  "test-key-1",
		publicKeys: map[string]*rsa.PublicKey{
			"test-key-1": &key.PublicKey,
		},
	}

	signingKey := km.GetSigningKey()
	assert.Equal(t, key, signingKey)
}

func TestKeyManager_GetSigningKeyID(t *testing.T) {
	km := &KeyManager{
		logger: zap.NewNop(),
		currentKeyID: "test-key-1",
		publicKeys:    make(map[string]*rsa.PublicKey),
	}

	keyID := km.GetSigningKeyID()
	assert.Equal(t, "test-key-1", keyID)
}

// Test key fingerprint uniqueness

func TestKeyFingerprintUniqueness(t *testing.T) {
	km := &KeyManager{
		logger: zap.NewNop(),
	}

	// Generate multiple keys and verify fingerprints are unique
	fingerprints := make(map[string]bool)
	for i := 0; i < 10; i++ {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		fingerprint := km.hashKey(&key.PublicKey)
		assert.NotEmpty(t, fingerprint)

		// Check uniqueness
		_, exists := fingerprints[fingerprint]
		assert.False(t, exists, "Fingerprint collision detected!")

		fingerprints[fingerprint] = true
	}
}

// Test JWK validation

func TestJWKValidation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	t.Run("Valid JWK can be constructed", func(t *testing.T) {
		jwk := JWK{
			Kty: "RSA",
			Use: "sig",
			Kid: "test-key",
			Alg: "RS256",
			N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			E:   "AQAB", // Standard RSA exponent
		}

		// Verify N can be decoded
		nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
		require.NoError(t, err)
		assert.Equal(t, 256, len(nBytes), "2048-bit RSA key should have 256-byte modulus")

		// Verify E can be decoded
		eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
		require.NoError(t, err)
		assert.Equal(t, []byte{0x01, 0x00, 0x01}, eBytes, "AQAB should decode to 65537")
	})
}

// Test SHA-256 hash consistency

func TestSHA256Consistency(t *testing.T) {
	data := []byte("test data for hashing")

	hash1 := sha256.Sum256(data)
	hash2 := sha256.Sum256(data)

	assert.Equal(t, hash1[:], hash2[:], "SHA-256 should be deterministic")

	// Verify base64url encoding
	encoded1 := base64.RawURLEncoding.EncodeToString(hash1[:])
	encoded2 := base64.RawURLEncoding.EncodeToString(hash2[:])

	assert.Equal(t, encoded1, encoded2)
}
