package oauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	assert.Equal(t, jwk.Kid, decoded.Kid)
	assert.Equal(t, jwk.N, decoded.N)
	assert.Equal(t, jwk.E, decoded.E)
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

func TestEd25519KeyGeneration(t *testing.T) {
	t.Run("Generate Ed25519 key pair", func(t *testing.T) {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		assert.NotNil(t, publicKey)
		assert.NotNil(t, privateKey)
		assert.Equal(t, ed25519.PublicKeySize, len(publicKey))
		assert.Equal(t, ed25519.PrivateKeySize, len(privateKey))
	})

	t.Run("Ed25519 signature roundtrip", func(t *testing.T) {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		message := []byte("test message for Ed25519 signing")
		signature := ed25519.Sign(privateKey, message)

		assert.Equal(t, ed25519.SignatureSize, len(signature))
		assert.True(t, ed25519.Verify(publicKey, message, signature))
	})

	t.Run("Ed25519 signature verification fails with wrong message", func(t *testing.T) {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		message := []byte("original message")
		wrongMessage := []byte("wrong message")
		signature := ed25519.Sign(privateKey, message)

		assert.False(t, ed25519.Verify(publicKey, wrongMessage, signature))
	})
}
