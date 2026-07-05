package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/secretcrypt"
)

// TestKeyManager_PrivateKeyEncryptedAtRest verifies the encrypt-store / load-decrypt
// boundary added for H5: a stored private key is tagged ciphertext (not plaintext
// PEM) and round-trips back to the identical key.
func TestKeyManager_PrivateKeyEncryptedAtRest(t *testing.T) {
	cipher, err := secretcrypt.New("0123456789abcdef0123456789abcdef") // 32 bytes
	require.NoError(t, err)
	km := &KeyManager{logger: zap.NewNop(), cipher: cipher}

	orig, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// What the store path writes to the DB column.
	stored, err := km.keyCipher().Encrypt(km.encodePrivateKey(orig))
	require.NoError(t, err)
	assert.True(t, secretcrypt.IsEncrypted(stored), "stored key must be tagged ciphertext, not plaintext PEM")
	assert.NotContains(t, stored, "RSA PRIVATE KEY", "PEM must not be readable in the stored value")

	// What the load path reads back.
	pem, err := km.keyCipher().Decrypt(stored)
	require.NoError(t, err)
	loaded, err := km.parsePrivateKey(pem)
	require.NoError(t, err)
	assert.Equal(t, orig.D, loaded.D, "decrypted key must equal the original")
}

// TestKeyManager_LegacyPlaintextKeyStillLoads verifies back-compat: a pre-existing
// plaintext PEM row (no tag) is passed through by Decrypt and parses fine, so
// encryption-at-rest doesn't break deployments created before this change.
func TestKeyManager_LegacyPlaintextKeyStillLoads(t *testing.T) {
	cipher, err := secretcrypt.New("0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	km := &KeyManager{logger: zap.NewNop(), cipher: cipher}

	orig, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	legacyPlaintext := km.encodePrivateKey(orig) // untagged PEM, as stored before

	assert.False(t, secretcrypt.IsEncrypted(legacyPlaintext))
	pem, err := km.keyCipher().Decrypt(legacyPlaintext) // passthrough
	require.NoError(t, err)
	loaded, err := km.parsePrivateKey(pem)
	require.NoError(t, err)
	assert.Equal(t, orig.D, loaded.D)
}

// TestKeyManager_NilCipherIsSafe verifies a struct-literal KeyManager with no
// cipher (the test-construction pattern) degrades to plaintext passthrough
// instead of nil-panicking.
func TestKeyManager_NilCipherIsSafe(t *testing.T) {
	km := &KeyManager{logger: zap.NewNop()} // cipher nil
	orig, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	stored, err := km.keyCipher().Encrypt(km.encodePrivateKey(orig))
	require.NoError(t, err)
	// Noop cipher: value stays plaintext PEM.
	assert.Contains(t, stored, "RSA PRIVATE KEY")
	pem, err := km.keyCipher().Decrypt(stored)
	require.NoError(t, err)
	loaded, err := km.parsePrivateKey(pem)
	require.NoError(t, err)
	assert.Equal(t, orig.D, loaded.D)
}
