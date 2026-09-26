package middleware

import (
	"crypto/sha256"
	"crypto/subtle"
)

// InternalTokenHeader carries INTERNAL_SERVICE_TOKEN on a call one OpenIDX
// service makes to another with no user behind it: access-service's policy
// checks against governance, and the events it posts to the audit trail.
const InternalTokenHeader = "X-Internal-Token"

// ValidInternalToken reports whether presented is the configured internal
// service token. An empty configured token matches nothing, so an install
// that has not set INTERNAL_SERVICE_TOKEN has no internal path at all rather
// than one anybody can use.
//
// Both sides are hashed before the comparison so that it takes the same time
// whatever the length of the value a caller sends.
func ValidInternalToken(presented, configured string) bool {
	if configured == "" || presented == "" {
		return false
	}
	p := sha256.Sum256([]byte(presented))
	c := sha256.Sum256([]byte(configured))
	return subtle.ConstantTimeCompare(p[:], c[:]) == 1
}
