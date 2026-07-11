// Package oauth - JWKS serialization types for the /.well-known/jwks.json
// endpoint (RFC 7517). The signing key itself is loaded from system_settings
// in NewService; see handleJWKS in service.go for the endpoint.
package oauth

// JWK represents a JSON Web Key per RFC 7517
type JWK struct {
	Kty string `json:"kty"`           // Key type
	Use string `json:"use"`           // Public key use - "sig" or "enc"
	Kid string `json:"kid"`           // Key ID
	Alg string `json:"alg"`           // Algorithm
	N   string `json:"n"`             // Modulus (for RSA)
	E   string `json:"e"`             // Exponent (for RSA)
	Crv string `json:"crv,omitempty"` // Curve (for EC)
	X   string `json:"x,omitempty"`   // X coordinate (for EC)
	Y   string `json:"y,omitempty"`   // Y coordinate (for EC)
}

// JWKS represents a JSON Web Key Set per RFC 7517
type JWKS struct {
	Keys []JWK `json:"keys"`
}
