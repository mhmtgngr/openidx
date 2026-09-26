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
