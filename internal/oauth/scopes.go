package oauth

import "strings"

// BuildScopeString joins scopes into a single space-delimited string
// (RFC 6749 §3.3 scope serialization). Used by the token flow when
// falling back to the client's registered scopes.
func BuildScopeString(scopes []string) string {
	return strings.Join(scopes, " ")
}
