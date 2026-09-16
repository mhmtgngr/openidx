package middleware

import (
	"fmt"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/common/cell"
)

// BindSubjectClaims puts the caller's identity from a verified token into the
// gin context, in the one place every authorization check downstream reads it.
//
// WHY THIS IS A SHARED FUNCTION AND NOT FOUR COPIES. OPAAuthz builds
// opa.Input.User from c.Get("roles") and c.Get("groups"), and RequireRole reads
// c.Get("roles"). Each service that fronts them has its own authentication
// middleware, and what those middlewares bound had drifted apart:
//
//   - admin-api goes through AuthWithAPIKey / SoftAuth, which bound "roles" but
//     never "groups" -- so authz.rego's admin-group rule could not fire.
//   - governance-service and provisioning-service authenticate with their own
//     openIDXAuthMiddleware, which bound user_id, email and name and NEITHER
//     roles NOR groups. With ENABLE_OPA_AUTHZ on, every role-based rule in
//     authz.rego was evaluated against an empty list, and the policy opens with
//     `default allow := false`: the effect is not a silent hole but a service
//     that denies nearly everything the moment OPA is switched on, which is
//     presumably why nobody had switched it on.
//
// The separation-of-duties `deny` is the one that failed the other way. It
// checks for conflicting roles held together, so an empty role list satisfies
// nothing and the rule has never produced a message.
//
// opa.ResourceContext's doc already records this shape twice, for `owner` and
// for the resource `tenant_id`: a policy written against input the middleware
// does not supply. Those two were removed because nothing COULD fill them.
// These two are different -- the issuer mints "roles" and "groups" onto every
// token (internal/oauth), so the input was always available and simply was not
// passed on -- so they are bound, here, once.
func BindSubjectClaims(c *gin.Context, claims map[string]interface{}) {
	if roles := stringsFromClaim(claims["roles"]); roles != nil {
		c.Set("roles", roles)
	}
	if groups := stringsFromClaim(claims["groups"]); groups != nil {
		c.Set("groups", groups)
	}
	// The cell that minted this token, for cell.Guard. It is bound here rather
	// than read from the header the request arrived with for the reason the
	// whole function exists: what a policy or a guard decides on has to be
	// something the signature covered. A caller can set any header it likes.
	if mintedIn, ok := claims[cell.Claim].(string); ok && mintedIn != "" {
		c.Set(cell.Claim, mintedIn)
	}
}

// stringsFromClaim converts a JSON array claim to []string. It returns nil for
// a claim that is absent or not an array, so the caller leaves the key unset
// rather than binding an empty list: "the token said no groups" and "the token
// carried no groups claim" are the same decision to a policy, but an unset key
// keeps RequireRole's "authentication required" distinguishable from "you are
// authenticated and hold no roles".
func stringsFromClaim(v interface{}) []string {
	raw, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, len(raw))
	for i, item := range raw {
		out[i] = fmt.Sprint(item)
	}
	return out
}
