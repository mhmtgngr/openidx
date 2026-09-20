package oauth

// Which identity claims a token is actually allowed to carry.
//
// WHAT WAS MEASURED. A token whose granted scope was the bare `openid` came
// back carrying `email` and `name`, and `GET /oauth/userinfo` presented with
// that same token returned `email`, `name`, `given_name`, `family_name` and
// `preferred_username`. The scope was recorded, shown on the consent screen
// and written into the token's own `scope` claim — and then read by nothing.
//
// The cause was structural rather than a missed branch: of the three places
// that emit identity claims, `GenerateIDToken` and `GetUserInfo` did not take
// a scope at all, so the grant could not reach them even in principle, and
// `GenerateJWT` took one only to copy it into a claim. The one emitter that
// did enforce it, the SAML flow's own access token, proved the rule was
// understood and simply not applied elsewhere.
//
// That is the shape this repository keeps finding: a control that displays
// without enforcing. The consent screen is the user's contract, and a contract
// that the token endpoint does not read is decoration.
//
// THE RULE (OpenID Connect Core §5.4). `profile` carries `name`,
// `given_name`, `family_name` and `preferred_username`; `email` carries
// `email` and `email_verified`. A claim whose scope was not granted is not
// emitted — not blanked, not nulled, absent, because an absent claim is the
// only form a relying party cannot mistake for "the user has no name".
//
// AN EMPTY SCOPE GRANTS NOTHING, deliberately. `scopeAllowedForClient` reads
// an empty scope as "no scope in particular", which is the right reading for
// deciding whether a request is permitted; reading it as "every scope" here
// would leave a bypass where a client that simply omits `scope` receives more
// than one that asks honestly. This is a behaviour change for such a client,
// and the honest direction: the token response's own `scope` field already
// tells a client exactly what it was granted.
//
// WHAT THIS DOES NOT GATE, and why. `roles`, `groups` and `permissions` stay
// on the access token whatever the scope. They are not OIDC identity claims
// about the end user; they are the authorization facts the resource servers
// behind this issuer read to decide what a request may do. Gating them on
// `profile` would silently turn authorization off for any client that asked
// for `openid` alone — a far worse failure than the one being fixed, and one
// whose own decision (should there be a scope that governs them?) has not been
// made. It is named here so the omission is a recorded choice rather than an
// oversight.

// The scope names this issuer makes decisions on.
//
// They are constants because a scope name repeated as a string literal at each
// decision is a name nobody can rename, and because the decisions themselves
// used to be spelled as SUBSTRING tests, which is the defect these replace:
// `strings.Contains(scope, "openid")` is true of the scope `openidx` — the name
// of this product — and `strings.Contains(scope, "offline_access")` is true of
// any custom scope that merely ends in it. Measured at the real token endpoint:
// a code granted `openidx` was answered with an ID token, and one granted
// `openid offline_access_reports` was answered with a refresh token. Neither
// grant had asked for what it received, and the second hands a long-lived
// credential to a client that did not request offline access.
//
// scopeGrants below splits the string and compares whole scopes, which is what
// RFC 6749 §3.3 means by a space-delimited list.
const (
	scopeProfile       = "profile"
	scopeEmail         = "email"
	scopeOpenID        = "openid"
	scopeOfflineAccess = "offline_access"
)

// scopeGrants reports whether the granted scope carries the named scope. The
// splitting is dynamic registration's splitScope, not a second copy: RFC 6749
// §3.3 makes the string space-delimited, and two spellings of "what are this
// token's scopes" is exactly the drift this tree keeps closing.
func scopeGrants(scope, want string) bool {
	return containsScope(splitScope(scope), want)
}

// profileClaims holds the end-user identity this issuer knows, before the
// scope decides how much of it a given token may carry.
type profileClaims struct {
	Name              string
	GivenName         string
	FamilyName        string
	Email             string
	EmailVerified     bool
	PreferredUsername string
}

// applyScopedClaims writes the identity claims the granted scope allows into
// a claim set, and writes nothing for the ones it does not. It is the single
// place the rule is spelled, so the ID token, the access token and UserInfo
// cannot answer the same question three different ways.
//
// A claim whose value is empty is still written when its scope was granted:
// "the scope was granted and the user has no family name" and "the scope was
// not granted" are different answers, and only the second may be silent.
func applyScopedClaims(claims map[string]interface{}, scope string, p profileClaims) {
	if scopeGrants(scope, scopeProfile) {
		claims["name"] = p.Name
		claims["given_name"] = p.GivenName
		claims["family_name"] = p.FamilyName
		if p.PreferredUsername != "" {
			claims["preferred_username"] = p.PreferredUsername
		}
	}
	if scopeGrants(scope, scopeEmail) {
		claims["email"] = p.Email
		claims["email_verified"] = p.EmailVerified
	}
}

// scopedUserInfo returns the UserInfo response a token with this scope is
// entitled to. `sub` is always present (OIDC Core §5.3.2 requires it and it is
// not a profile claim); everything else is subject to the same rule as above.
func scopedUserInfo(full *UserInfo, scope string) *UserInfo {
	if full == nil {
		return nil
	}
	out := &UserInfo{Sub: full.Sub}
	if scopeGrants(scope, scopeProfile) {
		out.Name = full.Name
		out.GivenName = full.GivenName
		out.FamilyName = full.FamilyName
		out.Picture = full.Picture
		out.PreferredUsername = full.PreferredUsername
	}
	if scopeGrants(scope, scopeEmail) {
		out.Email = full.Email
		out.EmailVerified = full.EmailVerified
	}
	// out.EmailVerified stays nil when `email` was not granted, which is the
	// "you did not ask" of the three states the field carries.
	return out
}
