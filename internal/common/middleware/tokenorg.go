package middleware

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/common/jwksverify"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// ErrWrongOrganization is the refusal for a credential presented to a request
// that resolved to an organization other than the credential's own.
var ErrWrongOrganization = errors.New("token is not valid for this organization")

// platformAdminRole is the role auth.SuperAdminPredicate tests for, and the
// only one whose holder may act outside their own organization.
const platformAdminRole = "super_admin"

// IsPlatformAdmin reports whether roles make their holder a platform admin.
//
// It is the rule auth.SuperAdminPredicate applies for the tenant resolver,
// restated over a role list because not every validator puts a token's roles
// into the gin context that predicate reads; tokenorg_agreement_test.go holds
// the two together.
func IsPlatformAdmin(roles []string) bool {
	for _, r := range roles {
		if r == platformAdminRole {
			return true
		}
	}
	return false
}

// CredentialOrgAllowed reports whether a credential issued in credentialOrg
// may act in the organization the request resolved to.
//
// Row-level security scopes a request to the organization the tenant resolver
// chose -- from X-Org-Slug, or the default-org fallback -- while its roles come
// from the credential, and those are its holder's roles in the credential's
// own organization only. A request for any other organization is refused
// unless the holder is a platform admin, whose role is not tied to one: that is
// how the console's organization switcher works.
//
// A request that has resolved no organization yet passes. That is
// cmd/admin-api, which mounts the resolver after authentication, and there the
// resolver makes this comparison itself (resolveOrgFromRequest).
func CredentialOrgAllowed(c *gin.Context, credentialOrg string, roles []string) bool {
	org, err := orgctx.From(c.Request.Context())
	if err != nil || org.ID == credentialOrg {
		return true
	}
	return IsPlatformAdmin(roles)
}

// CheckTokenOrg binds a verified access token to the request: it returns the
// organization the token names, ErrNoOrganization when it names none, and
// ErrWrongOrganization when the request resolved to another organization and
// the token's roles do not include the platform admin's.
func CheckTokenOrg(c *gin.Context, claims map[string]interface{}) (string, error) {
	orgID, err := jwksverify.TokenOrgID(claims)
	if err != nil {
		return "", err
	}
	if !CredentialOrgAllowed(c, orgID, stringsFromClaim(claims["roles"])) {
		return "", ErrWrongOrganization
	}
	return orgID, nil
}

// AbortForTokenOrg answers a CheckTokenOrg refusal in the shape the validators
// share: 403 for a token of another organization, and 401 for one naming no
// organization, which a fresh sign-in or refresh replaces.
func AbortForTokenOrg(c *gin.Context, err error) {
	if errors.Is(err, ErrWrongOrganization) {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token: " + err.Error()})
}
