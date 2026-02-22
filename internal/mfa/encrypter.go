// Package mfa provides encryption utilities for MFA secrets
package mfa

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// AES256GCMEncrypter provides AES-256-GCM encryption for TOTP secrets
type AES256GCMEncrypter struct {
	key []byte
}

// NewAES256GCMEncrypter creates a new encrypter with the provided key
// The key must be 32 bytes for AES-256
func NewAES256GCMEncrypter(key string) (*AES256GCMEncrypter, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes for AES-256, got %d bytes", len(key))
	}

	return &AES256GCMEncrypter{
		key: []byte(key),
	}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM
// Returns a base64-encoded string containing the nonce and ciphertext
func (e *AES256GCMEncrypter) Encrypt(plaintext string) (string, error) {
	// Create cipher block
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	// Encode as base64
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts base64-encoded ciphertext using AES-256-GCM
func (e *AES256GCMEncrypter) Decrypt(ciphertext string) (string, error) {
	// Decode base64
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	// Create cipher block
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Extract nonce
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, cipherData := data[:nonceSize], data[nonceSize:]

	// Decrypt and authenticate
	plaintext, err := gcm.Open(nil, nonce, cipherData, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// NoopEncrypter is a no-op encrypter for testing purposes only
// WARNING: Do not use in production!
type NoopEncrypter struct{}

// NewNoopEncrypter creates a new no-op encrypter
func NewNoopEncrypter() *NoopEncrypter {
	return &NoopEncrypter{}
}

// Encrypt returns the plaintext as-is (no encryption)
func (e *NoopEncrypter) Encrypt(plaintext string) (string, error) {
	return plaintext, nil
}

// Decrypt returns the ciphertext as-is (no decryption)
func (e *NoopEncrypter) Decrypt(ciphertext string) (string, error) {
	return ciphertext, nil
}
