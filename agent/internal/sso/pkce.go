package sso

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// pkce holds a PKCE verifier and its S256 challenge.
type pkce struct {
	verifier  string
	challenge string
}

// newPKCE generates a cryptographically-random verifier (RFC 7636) and its
// SHA-256 (S256) challenge, both base64url without padding.
func newPKCE() (pkce, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return pkce{}, err
	}
	verifier := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	return pkce{
		verifier:  verifier,
		challenge: base64.RawURLEncoding.EncodeToString(sum[:]),
	}, nil
}

// randomState returns a base64url random state value for CSRF protection.
func randomState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
