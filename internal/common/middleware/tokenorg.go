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

// PlatformAdminRole is the role that makes its holder a platform admin when it
// is held in the install's default organization (IsPlatformAdmin).
const PlatformAdminRole = "super_admin"

// IsPlatformAdmin reports whether a credential makes its holder a platform
// admin: the super_admin role held in the install's default organization.
// orgID is the organization the credential belongs to -- the token's org_id,
// which the issuer signs, or an API key's organization -- never one a request
// names.
//
// The role name alone decides nothing. Roles are created per organization and
// named by that organization's administrators, so any of them can create a
// role called super_admin and hold it; what makes the role the install's is
// the organization it is held in.
//
// It is the one rule every platform-admin decision applies: the exception in
// CredentialOrgAllowed, and auth.SuperAdminPredicate for the tenant resolver,
// which reads the same two facts from the gin context
// (tokenorg_agreement_test.go holds the two together).
//
// It is the narrower of the two rules the default organization carries.
// Crossing into another organization -- this rule -- needs super_admin held in
// the default organization; changing an install-wide setting needs admin or
// super_admin held there (RequirePlatformAdmin, platform_admin.go, whose name
// predates the distinction). Every platform admin may change install-wide
// settings; an admin of the default organization may change them and still
// cannot act in any other organization.
func IsPlatformAdmin(orgID string, roles []string) bool {
	if orgID != DefaultOrgID {
		return false
	}
	for _, r := range roles {
		if r == PlatformAdminRole {
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
// unless the holder is a platform admin (IsPlatformAdmin), whose authority is
// the install's rather than one organization's: that is how the console's
// organization switcher works.
//
// A request that has resolved no organization yet passes. That is
// cmd/admin-api, which mounts the resolver after authentication, and there the
// resolver makes this comparison itself (resolveOrgFromRequest).
func CredentialOrgAllowed(c *gin.Context, credentialOrg string, roles []string) bool {
	org, err := orgctx.From(c.Request.Context())
	if err != nil || org.ID == credentialOrg {
		return true
	}
	return IsPlatformAdmin(credentialOrg, roles)
}

// CheckTokenOrg binds a verified access token to the request: it returns the
// organization the token names, ErrNoOrganization when it names none, and
// ErrWrongOrganization when the request resolved to another organization and
// the token is not a platform admin's.
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
