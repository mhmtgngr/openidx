package jwksverify

import (
	"errors"
	"strings"
)

// AccessTokenType is the JWT "typ" header the issuer puts on every access token
// it mints (RFC 9068 §2.1).
const AccessTokenType = "at+jwt"

// ErrNotAccessToken is returned for a token whose signature verified but which
// is not an access token.
var ErrNotAccessToken = errors.New("not an access token")

// IsAccessToken reports whether a verified token is an access token, judged
// from its JOSE header and its claims. Every validator that accepts a bearer
// for an API asks this once the signature has verified.
//
// A signature says who issued a token, not what it is for. The issuer signs its
// ID tokens, logout tokens, Security Event Tokens and step-up proofs with the
// same key as its access tokens. An ID token in particular carries the user's
// roles and permissions and is handed to every relying party the user signs in
// to, and it travels in logout URLs as id_token_hint. A validator that accepts
// any token the key verifies turns each of those copies into a credential for
// the API.
//
// The header decides. An access token is typed "at+jwt", or
// "application/at+jwt", which RFC 9068 §2.1 also permits, compared without
// regard to case. Any other explicit type (logout+jwt, secevent+jwt) is not an
// access token.
//
// The client_id fallback exists for tokens minted before the issuer typed its
// access tokens. Those carry the signing library's default type, "JWT", and so
// does every ID token; what tells them apart is client_id, which every access
// token the issuer minted names and no ID token has ever carried.
func IsAccessToken(header, claims map[string]interface{}) bool {
	if typ, _ := header["typ"].(string); typ != "" && !strings.EqualFold(typ, "JWT") {
		return strings.EqualFold(typ, AccessTokenType) || strings.EqualFold(typ, "application/"+AccessTokenType)
	}
	clientID, _ := claims["client_id"].(string)
	return clientID != ""
}

// OrgIDClaim is the claim naming the organization an access token was minted
// in: the tenant whose rows the sign-in, refresh or client authentication that
// produced it was scoped to.
const OrgIDClaim = "org_id"

// ErrNoOrganization is returned for an access token that names no
// organization.
var ErrNoOrganization = errors.New("token has no organization; sign in again")

// TokenOrgID returns the organization an access token is bound to.
//
// The roles a token carries are the roles its subject holds in that
// organization and nowhere else, so a validator needs the claim to know where
// the token may be used. A token without it is refused rather than read as the
// default organization: every access token minted before the claim existed
// lacks it, whichever organization it came from, so reading absence as the
// default would let a token from any organization act in the default one.
// Refusing costs one refresh or sign-in after the upgrade, within one
// access-token lifetime.
func TokenOrgID(claims map[string]interface{}) (string, error) {
	if orgID, _ := claims[OrgIDClaim].(string); orgID != "" {
		return orgID, nil
	}
	return "", ErrNoOrganization
}

// APIAccessClaim marks an access token OpenIDX's own APIs accept. The issuer
// sets it, to true, only on the tokens of an application allowed to call those
// APIs (oauth_clients.api_access, the application's "May call the OpenIDX API"
// setting).
const APIAccessClaim = "openidx_api"

// ErrNoAPIAccess is returned for an access token issued to an application that
// may not call OpenIDX's own APIs.
var ErrNoAPIAccess = errors.New("this application may not call the OpenIDX API")

// HasAPIAccess reports whether an access token may call OpenIDX's own APIs.
//
// Every application a user signs in to through OpenIDX receives an access
// token carrying that user's roles, including a third-party application that
// only needed to know who the user is. The roles are a fact about the user;
// whether a token may exercise them on OpenIDX is a decision about the
// application, and this claim records it. A token without the claim -- a
// third-party application's, or one minted before the claim existed -- is
// refused by the APIs, while the endpoints a relying party calls (UserInfo,
// introspection, revocation, logout) keep accepting it.
func HasAPIAccess(claims map[string]interface{}) bool {
	allowed, _ := claims[APIAccessClaim].(bool)
	return allowed
}
