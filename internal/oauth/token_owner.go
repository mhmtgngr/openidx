package oauth

// WHOSE TOKEN IS THIS? The introspection and revocation endpoints answer for
// the CALLER's tokens, not for every token in the tenant.
//
// WHAT WAS MEASURED. Both endpoints already required client authentication,
// and neither looked at which client had authenticated. Two registered
// clients in one tenant, a refresh token issued to the second:
//
//   - `POST /oauth/introspect` from the FIRST client answered
//     `{"active":true,"client_id":"other-app","sub":"<the end user>","scope":"openid offline_access"}`.
//     One application in a tenant could therefore learn WHO is using another
//     application, and with what scope, from a token string alone.
//   - `POST /oauth/revoke` from the FIRST client revoked the second's token.
//     RFC 7009 §2.1 requires the opposite in as many words: the server
//     "verifies whether the token was issued to the client making the
//     revocation request", and refuses if not. Without it any registered
//     client can sign another application's users out.
//
// THE ANSWER FOR A TOKEN THAT IS NOT YOURS IS THE ANSWER FOR A TOKEN THAT DOES
// NOT EXIST. Introspection returns `active: false`, which is exactly what
// RFC 7662 §2.2 prescribes, and revocation returns 200 having done nothing,
// which is what RFC 7009 §2.2 already prescribes for a token the server does
// not recognise.
//
// RFC 7009 §2.2.1 does permit an ERROR for someone else's token, and that was
// the other option here. It is not taken: an error distinguishes "exists but
// is not yours" from "does not exist", which hands a registered client an
// existence oracle over the whole tenant's tokens — and a registered client is
// precisely the attacker in the finding above. Silence costs an honest client
// nothing, because an honest client is asking about its own token.
//
// THE TWO HALVES ARE NOT THE SAME KIND OF DECISION, and saying so matters.
//
// Revocation is a specification MUST. RFC 7009 §2.1 requires the check in as
// many words and there is no legitimate caller for whom it is wrong: nobody
// but the issuing client has business revoking a client's token through this
// endpoint. (The server's own severing paths — logout, reuse detection, an
// administrator disabling a user — do not come through here; they call
// RevokeRefreshToken directly and are unaffected.)
//
// Introspection is a POLICY CHOICE this file makes. RFC 7662 §2.1 requires the
// server to decide whether the caller may introspect a given token, and leaves
// the rule to the deployment. "Only the client the token was issued to" is the
// closed default and the one taken here. It does close a door: RFC 7662 is
// written with RESOURCE SERVERS in mind, and a resource server is not the
// token's client, so a deployment that stood up a separate resource server to
// introspect tokens issued to its front end can no longer do that. Nothing in
// this tree does — verify-service serves its own introspection and does not
// call this endpoint — and the closed default is the right way round for a
// door nobody is using. Re-opening it should mean an explicit per-client
// permission to introspect beyond one's own tokens, not a return to "any
// authenticated client may introspect anything in the tenant", which is what
// the measurement above found.

import "github.com/gin-gonic/gin"

// authenticatedClientKey carries the client id that
// requireTokenEndpointClientAuth verified, from the middleware to the handler.
// The middleware proved who is calling; before this key existed it kept that
// knowledge to itself and the handlers acted for anyone.
const authenticatedClientKey = "oauth.authenticated_client_id"

// authenticatedClientID returns the client id this request authenticated as.
// The empty string means the request did not pass the client-auth middleware,
// which for these two endpoints cannot happen — they are registered behind it
// — and is treated as "owns nothing" rather than "owns everything".
func authenticatedClientID(c *gin.Context) string {
	v, ok := c.Get(authenticatedClientKey)
	if !ok {
		return ""
	}
	id, _ := v.(string)
	return id
}

// callerOwns reports whether the authenticated caller is the client the token
// was issued to. A token whose owner cannot be determined belongs to nobody
// the caller can claim to be, which is the right answer for DISCLOSURE.
func callerOwns(c *gin.Context, tokenClientID string) bool {
	caller := authenticatedClientID(c)
	return caller != "" && tokenClientID != "" && caller == tokenClientID
}

// callerMayRevoke is the same question asked for a DESTRUCTIVE operation, and
// it answers differently in exactly one case: a token that names no client at
// all.
//
// The asymmetry is deliberate. Introspection discloses, so an unattributable
// token is refused — the cost of being wrong is telling someone something.
// Revocation destroys a credential, so an unattributable token is revoked —
// the cost of being wrong is that a token stops working slightly early, and
// the cost of the other error is a credential that cannot be withdrawn at all.
// Failing toward "it still works" is the wrong direction for a kill switch.
//
// In this tree every minted access token names its client: GenerateJWT sets
// both `client_id` and `aud`, and the SAML flow's token sets `aud`. So this
// case is reachable only by a token from outside those paths, and an
// authenticated client still cannot use it to reach a token that DOES name a
// different client.
func callerMayRevoke(c *gin.Context, tokenClientID string) bool {
	if tokenClientID == "" {
		return authenticatedClientID(c) != ""
	}
	return callerOwns(c, tokenClientID)
}
